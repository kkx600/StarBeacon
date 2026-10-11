package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket/pcapgo"
	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/packetarchive"
	"github.com/kkx600/StarBeacon/internal/testpcap"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func packetControllerFixture(t *testing.T) (*PacketArchiveController, *WAL) {
	t.Helper()
	root := t.TempDir()
	w, err := OpenWAL(filepath.Join(root, "agent.db"), "tenant", "sensor", "registration", 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	value := false
	capture := &CaptureSupervisor{WAL: w, state: CaptureState{CaptureSettings: CaptureSettings{Interfaces: []string{}, Threads: 1, Promiscuous: &value}, Counters: map[string]string{}}}
	cfg := config.Config{PacketCapture: true, PacketDir: filepath.Join(root, "packets"), PacketSpoolBytes: 16 << 20, PacketSegmentBytes: 1 << 20, PacketCodec: "zstd", PacketRotateInterval: time.Second}
	p, err := NewPacketArchiveController(cfg, w, capture)
	if err != nil {
		t.Fatal(err)
	}
	w.packetArchives = p
	return p, w
}

func localPacketFixture(t *testing.T, p *PacketArchiveController, id string, prepare bool) (packetarchive.LocalRecord, []byte) {
	t.Helper()
	start := time.Now().UTC()
	header := packetarchive.Capture{ID: id, TenantID: p.WAL.TenantID, SensorID: p.WAL.SensorID, RegistrationID: p.WAL.RegistrationID, RunID: "run_owned", Interface: "eth0", InterfaceMAC: "02:00:00:00:00:01", SettingsSHA256: strings.Repeat("a", 64), StartedAt: start}
	pending, err := p.Spool.Begin(header)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := testpcap.HTTP(false)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := pcapgo.NewReader(bytes.NewReader(fixture))
	if err != nil {
		t.Fatal(err)
	}
	for {
		data, ci, e := reader.ReadPacketData()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		if e = pending.Recorder.Write(ci, data, nil); e != nil {
			t.Fatal(e)
		}
	}
	drops := uint64(0)
	if err = pending.Seal(start.Add(time.Second), "rotation", &drops); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(p.Spool.Dir, id+".raw"))
	if err != nil {
		t.Fatal(err)
	}
	row, err := p.Spool.Record(id)
	if prepare {
		row, err = p.Spool.Prepare(context.Background(), id, "zstd")
	}
	if err != nil {
		t.Fatal(err)
	}
	return row, raw
}

type packetProtocolServer struct {
	sensorv1.UnimplementedSensorServiceServer
	mutate func(*sensorv1.PacketArchiveAck)
	fail   bool
}

// 仅验证官方 gRPC 流和本地回收契约；真实证书授权由独立数据库集成测试负责。
func (s *packetProtocolServer) UploadPacketArchive(stream grpc.ClientStreamingServer[sensorv1.PacketArchiveChunk, sensorv1.PacketArchiveAck]) error {
	if s.fail {
		return status.Error(codes.Unavailable, "测试上报中断")
	}
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	m, err := packetarchive.ParseManifest(first.ManifestJson)
	if err != nil || len(first.Data) != 0 || first.Offset != 0 {
		return status.Error(codes.InvalidArgument, "首块目录无效")
	}
	var data bytes.Buffer
	for {
		chunk, e := stream.Recv()
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		if len(chunk.ManifestJson) != 0 || chunk.Offset != uint64(data.Len()) || len(chunk.Data) < 1 || len(chunk.Data) > 128*1024 {
			return status.Error(codes.InvalidArgument, "后继块偏移无效")
		}
		data.Write(chunk.Data)
	}
	if int64(data.Len()) != m.Encoding.StoredBytes || packetarchive.Digest(data.Bytes()) != m.Encoding.StoredSHA256 {
		return status.Error(codes.DataLoss, "传输摘要不一致")
	}
	_, digest, err := m.JSON()
	if err != nil {
		return err
	}
	ack := &sensorv1.PacketArchiveAck{Id: m.Capture.ID, ManifestSha256: digest, RawSha256: m.Encoding.RawSHA256, StoredSha256: m.Encoding.StoredSHA256, StoredBytes: uint64(data.Len()), ObjectVersion: "version_owned", ExpiresAt: timestamppb.New(time.Now().UTC().AddDate(0, 0, 180))}
	if s.mutate != nil {
		s.mutate(ack)
	}
	return stream.SendAndClose(ack)
}

func packetProtocolClient(t *testing.T, server *packetProtocolServer) sensorv1.SensorServiceClient {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rpc := grpc.NewServer()
	sensorv1.RegisterSensorServiceServer(rpc, server)
	go rpc.Serve(listener)
	t.Cleanup(rpc.Stop)
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return sensorv1.NewSensorServiceClient(conn)
}

func TestPacketUploadConfirmsExactAcknowledgementAndPreservesFailures(t *testing.T) {
	for _, v := range []struct {
		name   string
		mutate func(*sensorv1.PacketArchiveAck)
	}{
		{"identity", func(a *sensorv1.PacketArchiveAck) { a.Id = "other" }},
		{"manifest", func(a *sensorv1.PacketArchiveAck) { a.ManifestSha256 = strings.Repeat("b", 64) }},
		{"raw", func(a *sensorv1.PacketArchiveAck) { a.RawSha256 = strings.Repeat("b", 64) }},
		{"stored", func(a *sensorv1.PacketArchiveAck) { a.StoredSha256 = strings.Repeat("b", 64) }},
		{"size", func(a *sensorv1.PacketArchiveAck) { a.StoredBytes++ }},
		{"size_budget", func(a *sensorv1.PacketArchiveAck) { a.StoredBytes = uint64(packetarchive.MaxStoredBytes + 1) }},
		{"version", func(a *sensorv1.PacketArchiveAck) { a.ObjectVersion = "null" }},
		{"missing_expiry", func(a *sensorv1.PacketArchiveAck) { a.ExpiresAt = nil }},
		{"invalid_expiry", func(a *sensorv1.PacketArchiveAck) { a.ExpiresAt = &timestamppb.Timestamp{Seconds: 253402300800} }},
		{"expired", func(a *sensorv1.PacketArchiveAck) { a.ExpiresAt = timestamppb.New(time.Now().Add(-time.Hour)) }},
	} {
		t.Run(v.name, func(t *testing.T) {
			p, _ := packetControllerFixture(t)
			row, original := localPacketFixture(t, p, "packet_ack", true)
			client := packetProtocolClient(t, &packetProtocolServer{mutate: v.mutate})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := p.uploadOne(ctx, client, row); !errors.Is(err, packetarchive.ErrIntegrity) {
				t.Fatal("异常持久确认被接受", err)
			}
			got, err := os.ReadFile(filepath.Join(p.Spool.Dir, row.ID+".raw"))
			if err != nil || !bytes.Equal(got, original) {
				t.Fatal("异常确认回收或改变了原件", err)
			}
		})
	}
	p, _ := packetControllerFixture(t)
	row, _ := localPacketFixture(t, p, "packet_success", true)
	client := packetProtocolClient(t, &packetProtocolServer{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.uploadOne(ctx, client, row); err != nil {
		t.Fatal(err)
	}
	confirmed, err := p.Spool.Record(row.ID)
	if err != nil || confirmed.State != "confirmed" || confirmed.Acknowledgement.ObjectVersion != "version_owned" {
		t.Fatal("合法持久确认未提交", err)
	}
	if used, err := p.Spool.Reserved(); err != nil || used != 0 {
		t.Fatal("确认原件回收后仍占用额度", used, err)
	}
}

func TestPacketControllerUploadCancellationAndInvalidReceiptQuarantine(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "invalid_receipt", true: "transport_failure"}[fail], func(t *testing.T) {
			p, w := packetControllerFixture(t)
			row, original := localPacketFixture(t, p, "packet_pending", false)
			client := packetProtocolClient(t, &packetProtocolServer{fail: fail, mutate: func(a *sensorv1.PacketArchiveAck) { a.ObjectVersion = "null" }})
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- p.Upload(ctx, client) }()
			deadline := time.Now().Add(5 * time.Second)
			for {
				w.mu.RLock()
				observed := w.failures["packet_upload_unavailable"]
				w.mu.RUnlock()
				if observed {
					break
				}
				if time.Now().After(deadline) {
					cancel()
					t.Fatal("上报异常未进入健康状态")
				}
				time.Sleep(5 * time.Millisecond)
			}
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			current, err := p.Spool.Record(row.ID)
			want := "quarantined"
			if fail {
				want = "ready"
			}
			if err != nil || current.State != want {
				t.Fatal("故障处理改变了原件状态边界", current.State, err)
			}
			got, err := os.ReadFile(filepath.Join(p.Spool.Dir, row.ID+".raw"))
			if err != nil || !bytes.Equal(got, original) {
				t.Fatal("上报失败未保留原件", err)
			}
		})
	}
	p, _ := packetControllerFixture(t)
	client := packetProtocolClient(t, &packetProtocolServer{})
	localPacketFixture(t, p, "packet_loop", false)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Upload(ctx, client) }()
	deadline := time.Now().Add(5 * time.Second)
	for p.Snapshot().LastConfirmedID == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	observed := p.Snapshot()
	cancel()
	if err := <-done; err != nil || observed.LastConfirmedID != "packet_loop" || observed.LastConfirmedAt == nil || observed.ReservedBytes != "0" {
		t.Fatal("上传循环未观测实际确认", observed, err)
	}
}

func TestLocalPacketDirectoryAuthenticationDownloadAuditAndUnavailableStates(t *testing.T) {
	p, w := packetControllerFixture(t)
	identity, err := NewLocalIdentity(w, "packet-local-test-password")
	if err != nil {
		t.Fatal(err)
	}
	u, _, err := identity.Password(context.Background(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := identity.CreateSession(context.Background(), u)
	if err != nil {
		t.Fatal(err)
	}
	auth := httpapi.NewAuth(identity, nil, "http://packet.test", "packet_session", false)
	handler := httpapi.Middleware(LocalHandler(w, auth, w.DB.Path()))
	request := func(path string, authorized bool, expected int) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("GET", path, nil)
		if authorized {
			r.AddCookie(&http.Cookie{Name: "packet_session", Value: token})
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, r)
		if response.Code != expected {
			t.Fatal(path, response.Code, response.Body.String())
		}
		return response
	}
	for _, suffix := range []string{"", "/packet_owned", "/packet_owned/download", "/packet_owned/packets/1"} {
		request("/api/local/v1/packet-archives"+suffix, false, 401)
	}
	w.packetArchives = nil
	response := request("/api/local/v1/packet-archives", true, 200)
	if !strings.Contains(response.Body.String(), `"available":false`) {
		t.Fatal("未配置不能显示已提供原包目录")
	}
	request("/api/local/v1/packet-archives/packet_owned", true, 503)
	request("/api/local/v1/packet-archives/packet_owned/download", true, 503)
	request("/api/local/v1/packet-archives/packet_owned/packets/1", true, 503)
	w.packetArchives = p
	row, original := localPacketFixture(t, p, "packet_owned", true)
	response = request("/api/local/v1/packet-archives", true, 200)
	if !strings.Contains(response.Body.String(), `"available":true`) || strings.Contains(response.Body.String(), `"frames"`) {
		t.Fatal("列表未提供轻量暂存摘要")
	}
	request("/api/local/v1/packet-archives/packet_missing", true, 404)
	request("/api/local/v1/packet-archives/packet_owned", true, 200)
	view := request("/api/local/v1/packet-archives/packet_owned/packets/1", true, 200)
	var inspected packetarchive.PacketInspection
	if err = json.Unmarshal(view.Body.Bytes(), &inspected); err != nil || inspected.ArchiveID != row.ID || inspected.Number != 1 || inspected.Total != row.Capture.Packets || inspected.ManifestSHA256 != row.ManifestSHA256 || inspected.Packet == "" || inspected.ChecksumValidation != "not_checked" || view.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("本机逐包查看没有核对实际回执", inspected, err)
	}
	request("/api/local/v1/packet-archives/packet_owned/packets/1048576", true, 404)
	for _, suffix := range []string{"/0", "/01", "/1048577", "/1?unknown=1"} {
		request("/api/local/v1/packet-archives/packet_owned/packets"+suffix, true, 400)
	}
	response = request("/api/local/v1/packet-archives/packet_owned/download", true, 200)
	if !bytes.Equal(response.Body.Bytes(), original) || response.Header().Get("X-Content-SHA256") != packetarchive.Digest(original) || response.Header().Get("Content-Type") != "application/x-pcapng" || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("本机下载未返回原字节及冻结摘要")
	}
	var audits int
	if err = w.DB.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("local_audits")).ForEach(func(_, value []byte) error {
			var audit LocalAudit
			if err := json.Unmarshal(value, &audit); err != nil {
				return err
			}
			if audit.Action == "pcap.download.request" && audit.Username == "admin" && audit.ObjectID == row.ID && audit.ExpiresAt.Sub(audit.CreatedAt) > 179*24*time.Hour {
				audits++
			}
			return nil
		})
	}); err != nil || audits != 1 {
		t.Fatal("原包下载未保存当前对象访问审计", audits, err)
	}
	files, err := filepath.Glob(filepath.Join(p.Spool.Dir, ".packet-download-*"))
	if err != nil || len(files) != 0 {
		t.Fatal("下载衍生暂存未回收", files, err)
	}
	for i := 0; i < cap(localPacketDownloads); i++ {
		localPacketDownloads <- struct{}{}
	}
	request("/api/local/v1/packet-archives/packet_owned/download", true, 429)
	request("/api/local/v1/packet-archives/packet_owned/packets/1", true, 429)
	for i := 0; i < cap(localPacketDownloads); i++ {
		<-localPacketDownloads
	}
	ack := packetarchive.Acknowledgement{ID: row.ID, ManifestSHA256: row.ManifestSHA256, RawSHA256: row.Manifest.Encoding.RawSHA256, StoredSHA256: row.Manifest.Encoding.StoredSHA256, StoredBytes: row.Manifest.Encoding.StoredBytes, ObjectVersion: "version_owned", ExpiresAt: time.Now().AddDate(0, 0, 180)}
	if err = p.Spool.Confirm(ack); err != nil {
		t.Fatal(err)
	}
	request("/api/local/v1/packet-archives/packet_owned/download", true, 409)
	request("/api/local/v1/packet-archives/packet_owned/packets/1", true, 409)
	localPacketFixture(t, p, "packet_corrupt", true)
	storedPath := filepath.Join(p.Spool.Dir, "packet_corrupt.stored")
	stored, err := os.ReadFile(storedPath)
	if err != nil {
		t.Fatal(err)
	}
	stored[len(stored)/2] ^= 1
	if err = os.Chmod(storedPath, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(storedPath, stored, 0400); err != nil {
		t.Fatal(err)
	}
	request("/api/local/v1/packet-archives/packet_corrupt/download", true, 503)
	request("/api/local/v1/packet-archives/packet_corrupt/packets/1", true, 503)
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	request("/api/local/v1/packet-archives", true, 503)
	if p.Snapshot().Code != "packet_spool_unavailable" {
		t.Fatal("本机存储不可观测时没有明确健康错误")
	}
}

func TestPacketControllerDisabledConfigurationAndCleanShutdown(t *testing.T) {
	p, w := packetControllerFixture(t)
	if _, err := NewPacketArchiveController(config.Config{}, w, p.Capture); !errors.Is(err, packetarchive.ErrIntegrity) {
		t.Fatal(err)
	}
	if _, err := NewPacketArchiveController(p.Config, w, nil); !errors.Is(err, packetarchive.ErrIntegrity) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.Start(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for p.Snapshot().State != "stopped" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	p.Close()
	var snapshot PacketArchiveState
	if json.Unmarshal(p.JSON(), &snapshot) != nil || snapshot.State != "stopped" || snapshot.Code != "" || snapshot.Interfaces == nil {
		t.Fatal("停用采集没有完整结束状态", snapshot)
	}
	for _, input := range []struct{ user, action, object string }{{"", "pcap.download.request", "packet_one"}, {"admin", "bad\noperation", "packet_one"}, {"admin", "pcap.download.request", "../packet"}} {
		if err := w.RecordLocalOperation(ctx, input.user, input.action, input.object, "test_request"); err == nil {
			t.Fatal("无效本机操作审计被接受")
		}
	}
	cancel()
	if err := w.RecordLocalOperation(ctx, "admin", "pcap.download.request", "packet_one", "test_request"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestPacketControllerSnapshotCannotAlterConfirmationTime(t *testing.T) {
	p, _ := packetControllerFixture(t)
	at := time.Now().UTC()
	p.mu.Lock()
	p.state.LastConfirmedAt = &at
	p.state.LastConfirmedID = "packet_confirmed"
	p.mu.Unlock()
	view := p.Snapshot()
	*view.LastConfirmedAt = time.Time{}
	view.Interfaces = append(view.Interfaces, packetarchive.CaptureProgress{})
	after := p.Snapshot()
	if after.LastConfirmedAt == nil || !after.LastConfirmedAt.Equal(at) || len(after.Interfaces) != 0 {
		t.Fatal("页面快照改变了采集器持久确认状态")
	}
}
