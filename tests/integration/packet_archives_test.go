//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket/pcapgo"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/ingest"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/packetarchive"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/testpcap"
	"github.com/kkx600/StarBeacon/internal/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// 仅在本用例的对象读取边界执行一次故障，核对发送原字节前的授权和审计。
type inspectionObjectBoundary struct {
	packetarchive.ObjectStorage
	mu   sync.Mutex
	hook func() error
}

func (s *inspectionObjectBoundary) setHook(hook func() error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hook = hook
}

func (s *inspectionObjectBoundary) Range(ctx context.Context, key, version string, offset, length int64) (io.ReadCloser, error) {
	s.mu.Lock()
	hook := s.hook
	s.hook = nil
	s.mu.Unlock()
	if hook != nil {
		if err := hook(); err != nil {
			return nil, err
		}
	}
	return s.ObjectStorage.Range(ctx, key, version, offset, length)
}

func packetMaterial(t *testing.T, id transport.SensorIdentity, name string) (packetarchive.Manifest, []byte, []byte) {
	t.Helper()
	source, err := testpcap.HTTP(false)
	require(t, err)
	reader, err := pcapgo.NewReader(bytes.NewReader(source))
	require(t, err)
	start := time.Now().UTC().Add(-time.Minute)
	capture := packetarchive.Capture{ID: name, TenantID: id.TenantID, SensorID: id.SensorID, RegistrationID: id.RegistrationID, RunID: "run_owned", Interface: "eth0", InterfaceMAC: "02:00:00:00:00:01", SettingsSHA256: packetarchive.Digest([]byte("frozen-settings")), StartedAt: start}
	var raw bytes.Buffer
	recorder, err := packetarchive.NewRecorder(&raw, capture, 1024*1024)
	require(t, err)
	for {
		data, ci, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		require(t, err)
		require(t, recorder.Write(ci, data, nil))
	}
	drops := uint64(0)
	capture, err = recorder.Seal(start.Add(time.Second), "rotation", &drops)
	require(t, err)
	var stored bytes.Buffer
	encoding, err := packetarchive.EncodeFrames(context.Background(), &stored, bytes.NewReader(raw.Bytes()), "zstd", packetarchive.DefaultFrameBytes)
	require(t, err)
	return packetarchive.Manifest{Capture: capture, Encoding: encoding}, bytes.Clone(raw.Bytes()), bytes.Clone(stored.Bytes())
}

func packetClient(t *testing.T, endpoint, pki, directory string) sensorv1.SensorServiceClient {
	t.Helper()
	tls, err := transport.TLS(filepath.Join(pki, "ca.crt"), filepath.Join(directory, "agent.crt"), filepath.Join(directory, "agent.key"), false)
	require(t, err)
	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(credentials.NewTLS(tls)))
	require(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return sensorv1.NewSensorServiceClient(conn)
}

func sendPacket(t *testing.T, ctx context.Context, client sensorv1.SensorServiceClient, manifest []byte, data []byte, offset uint64) (*sensorv1.PacketArchiveAck, error) {
	t.Helper()
	stream, err := client.UploadPacketArchive(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.CloseSend()
	if err = stream.Send(&sensorv1.PacketArchiveChunk{ManifestJson: manifest}); err != nil {
		return nil, err
	}
	for len(data) > 0 {
		n := min(len(data), 128*1024)
		if err = stream.Send(&sensorv1.PacketArchiveChunk{Data: data[:n], Offset: offset}); err != nil {
			_, final := stream.CloseAndRecv()
			if final != nil {
				return nil, final
			}
			return nil, err
		}
		data = data[n:]
		offset += uint64(n)
	}
	return stream.CloseAndRecv()
}

func TestPacketArchivesMTLSUploadImmutableDownloadRLSAndRetentionRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	password := store.Token()
	for _, v := range []struct{ tenant, user, role string }{{"packet_a", "packet_admin_a", "admin"}, {"packet_b", "packet_admin_b", "admin"}, {"packet_a", "packet_viewer", "viewer"}} {
		require(t, admin.Bootstrap(ctx, f.Owner, v.tenant, "原包验收", v.user, password, v.role))
	}
	root := t.TempDir()
	pki := filepath.Join(root, "pki")
	require(t, admin.DevPKI(pki))
	id, err := admin.Provision(ctx, f.Owner, "packet_a", "sensor_owned", "原包验收探针", pki, filepath.Join(root, "agent-a"))
	require(t, err)
	_, err = admin.Provision(ctx, f.Owner, "packet_b", "sensor_owned", "隔离原包探针", pki, filepath.Join(root, "agent-b"))
	require(t, err)
	objects, err := packetarchive.NewLocalObjects(filepath.Join(root, "objects"))
	require(t, err)
	staging := filepath.Join(root, "staging")
	require(t, os.Mkdir(staging, 0700))
	tls, err := transport.TLS(filepath.Join(pki, "ca.crt"), filepath.Join(pki, "server.crt"), filepath.Join(pki, "server.key"), true)
	require(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require(t, err)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(tls)))
	ingester := &ingest.Server{DB: f.Runtime, ControlOnly: true, Packets: objects, PacketStaging: staging, PacketQuota: 100 << 20}
	sensorv1.RegisterSensorServiceServer(server, ingester)
	go server.Serve(listener)
	defer server.Stop()
	a, b := packetClient(t, listener.Addr().String(), pki, filepath.Join(root, "agent-a")), packetClient(t, listener.Addr().String(), pki, filepath.Join(root, "agent-b"))
	m, raw, stored := packetMaterial(t, id, "packet_transport")
	manifest, manifestSHA, err := m.JSON()
	require(t, err)
	ack, err := sendPacket(t, ctx, a, manifest, stored, 0)
	require(t, err)
	if ack.Id != m.Capture.ID || ack.ManifestSha256 != manifestSHA || ack.RawSha256 != packetarchive.Digest(raw) || ack.StoredSha256 != packetarchive.Digest(stored) || ack.ObjectVersion != packetarchive.Digest(stored) || ack.StoredBytes != uint64(len(stored)) || ack.ExpiresAt.AsTime().Sub(time.Now()) < 179*24*time.Hour {
		t.Fatal("持久确认未绑定对象版本、冻结摘要或默认留存")
	}
	again, err := sendPacket(t, ctx, a, manifest, stored, 0)
	require(t, err)
	if !again.ExpiresAt.AsTime().Equal(ack.ExpiresAt.AsTime()) || again.ObjectVersion != ack.ObjectVersion {
		t.Fatal("幂等上传重置了留存或对象版本")
	}
	if _, err = sendPacket(t, ctx, b, manifest, stored, 0); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("跨租户上传被接受", err)
	}
	adminA, _, err := f.Owner.Password(ctx, "packet_admin_a")
	require(t, err)
	adminB, _, err := f.Owner.Password(ctx, "packet_admin_b")
	require(t, err)
	viewer, _, err := f.Owner.Password(ctx, "packet_viewer")
	require(t, err)
	row, acquired, err := f.Runtime.BeginPacketArchive(ctx, id, m, 100<<20)
	require(t, err)
	if acquired || row.State != "ready" {
		t.Fatal("已持久目录被重复取得传输租约")
	}
	if _, err = f.Runtime.PacketArchive(ctx, adminB, row.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("跨租户目录可读", err)
	}
	if _, err = f.Runtime.PacketArchive(ctx, viewer, row.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("查看者可访问通信原包", err)
	}
	items, next, err := f.Runtime.PacketArchives(ctx, adminA, id.SensorID, "")
	require(t, err)
	if len(items) != 1 || next != "" || items[0].Capture.Packets != 9 {
		t.Fatal("目录摘要与实际捕获不一致")
	}
	inspectionObjects := &inspectionObjectBoundary{ObjectStorage: objects}
	api := &platform.API{DB: f.Runtime, Packets: inspectionObjects, PacketStaging: staging}
	httpA := authenticatedFaultHTTP(t, ctx, f.Runtime, api, "packet_admin_a", password)
	httpB := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, Packets: objects, PacketStaging: staging}, "packet_admin_b", password)
	httpViewer := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, Packets: objects, PacketStaging: staging}, "packet_viewer", password)
	httpA.request("GET", "/packet-archives?sensor_id="+id.SensorID, "", nil, nil, 200)
	httpA.request("GET", "/packet-archives/"+row.ID, "", nil, nil, 200)
	httpB.request("GET", "/packet-archives/"+row.ID, "", nil, nil, 404)
	httpViewer.request("GET", "/packet-archives", "", nil, nil, 403)
	for _, path := range []string{"/packet-archives?unknown=1", "/packet-archives?sensor_id=x&sensor_id=y", "/packet-archives?cursor=bad", "/packet-archives?sensor_id=../bad"} {
		httpA.request("GET", path, "", nil, nil, 400)
	}
	request, err := http.NewRequestWithContext(ctx, "GET", httpA.origin+httpA.prefix+"/packet-archives/"+row.ID+"/download", nil)
	require(t, err)
	response, err := httpA.client.Do(request)
	require(t, err)
	download, err := io.ReadAll(io.LimitReader(response.Body, packetarchive.MaxSegmentBytes+1))
	response.Body.Close()
	require(t, err)
	if response.StatusCode != 200 || response.Header.Get("Content-Type") != "application/x-pcapng" || response.Header.Get("X-Content-SHA256") != packetarchive.Digest(raw) || !bytes.Equal(download, raw) {
		t.Fatal("下载未返回实际原包或摘要")
	}
	var auditCount int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE tenant_id=$1 AND action='pcap.download.request' AND object_id=$2`, id.TenantID, row.ID).Scan(&auditCount))
	if auditCount != 1 {
		t.Fatal("原包访问未审计")
	}
	t.Run("逐包协议查看验证原字节与当前授权", func(t *testing.T) {
		reader, e := pcapgo.NewNgReader(bytes.NewReader(raw), pcapgo.DefaultNgReaderOptions)
		require(t, e)
		for i := 1; i <= 9; i++ {
			want, ci, e := reader.ReadPacketData()
			require(t, e)
			var view packetarchive.PacketInspection
			httpA.request("GET", "/packet-archives/"+row.ID+"/packets/"+strconv.Itoa(i), "", nil, &view, 200)
			got, e := base64.StdEncoding.DecodeString(view.Packet)
			require(t, e)
			if !bytes.Equal(got, want) || view.Number != i || view.Total != 9 || view.ManifestSHA256 != row.ManifestSHA256 || view.PacketSHA256 != packetarchive.Digest(want) || !view.CapturedAt.Equal(ci.Timestamp) || view.ChecksumValidation != "not_checked" || view.PayloadVisibility != "not_decoded" {
				t.Fatal("逐包原文、序号、时间或来源不一致", view)
			}
		}
		httpA.request("GET", "/packet-archives/"+row.ID+"/packets/10", "", nil, nil, 404)
		for _, suffix := range []string{"0", "01", "1048577", "1?unknown=1"} {
			httpA.request("GET", "/packet-archives/"+row.ID+"/packets/"+suffix, "", nil, nil, 400)
		}
		httpB.request("GET", "/packet-archives/"+row.ID+"/packets/1", "", nil, nil, 404)
		httpViewer.request("GET", "/packet-archives/"+row.ID+"/packets/1", "", nil, nil, 403)
		var count int
		require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE tenant_id=$1 AND action='pcap.inspect.request' AND object_id=$2`, id.TenantID, row.ID).Scan(&count))
		if count != 9 {
			t.Fatal("逐包访问没有独立审计", count)
		}
		inspectionObjects.setHook(func() error {
			_, e := f.Owner.Pool.Exec(ctx, `DELETE FROM sessions WHERE user_id=$1`, adminA.ID)
			return e
		})
		httpA.request("GET", "/packet-archives/"+row.ID+"/packets/1", "", nil, nil, 401)
		httpA.login("packet_admin_a", password)
		require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE tenant_id=$1 AND action='pcap.inspect.request' AND object_id=$2`, id.TenantID, row.ID).Scan(&count))
		if count != 9 {
			t.Fatal("读取期间会话被撤销仍返回通信内容或记录成功访问", count)
		}
		require(t, func() error {
			_, e := f.Owner.Pool.Exec(ctx, `CREATE FUNCTION public.packet_inspect_audit_fault() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.action='pcap.inspect.request' THEN RAISE EXCEPTION 'owned_packet_inspect_audit_failure'; END IF; RETURN NEW; END$$; CREATE TRIGGER packet_inspect_audit_fault BEFORE INSERT ON operation_audits FOR EACH ROW EXECUTE FUNCTION public.packet_inspect_audit_fault()`)
			return e
		}())
		httpA.request("GET", "/packet-archives/"+row.ID+"/packets/1", "", nil, nil, 503)
		require(t, func() error {
			_, e := f.Owner.Pool.Exec(ctx, `DROP TRIGGER packet_inspect_audit_fault ON operation_audits; DROP FUNCTION public.packet_inspect_audit_fault()`)
			return e
		}())
		entries, e := os.ReadDir(staging)
		require(t, e)
		if len(entries) != 0 {
			t.Fatal("逐包核验失败后没有回收暂存", entries)
		}
	})
	t.Run("实际会话导出与原包访问隔离", func(t *testing.T) {
		input := packetarchive.SessionRequest{ArchiveIDs: []string{row.ID}, Mode: "full_session", ClientIP: "192.0.2.10", ClientPort: 40000, ServerIP: "198.51.100.20", ServerPort: 80, ClientMAC: "02:00:00:00:00:01", ServerMAC: "02:00:00:00:00:02", VLANs: []uint16{}}
		for _, mode := range []string{"full_session", "snapshot"} {
			input.Mode = mode
			body, e := json.Marshal(input)
			require(t, e)
			req, e := http.NewRequestWithContext(ctx, "POST", httpA.origin+httpA.prefix+"/packet-archives/session-export", bytes.NewReader(body))
			require(t, e)
			req.Header.Set("Origin", httpA.origin)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-CSRF-Token", httpA.csrf)
			res, e := httpA.client.Do(req)
			require(t, e)
			data, e := io.ReadAll(io.LimitReader(res.Body, packetarchive.MaxSegmentBytes+1))
			res.Body.Close()
			require(t, e)
			if res.StatusCode != 200 || res.Header.Get("X-Content-SHA256") != packetarchive.Digest(data) || res.Header.Get("X-Session-Completeness") != mode || res.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("真实导出失败：%d %s", res.StatusCode, data)
			}
			reader, e := pcapgo.NewNgReader(bytes.NewReader(data), pcapgo.DefaultNgReaderOptions)
			require(t, e)
			var report packetarchive.SessionReport
			require(t, json.Unmarshal([]byte(reader.SectionInfo().Comment), &report))
			if report.Completeness != mode || report.Handshake != "verified" || report.Packets != 9 || len(report.Sources) != 1 || report.Sources[0].ObjectVersion != row.ObjectVersion {
				t.Fatalf("导出清单不一致：%+v", report)
			}
			original, e := pcapgo.NewNgReader(bytes.NewReader(raw), pcapgo.DefaultNgReaderOptions)
			require(t, e)
			for i := 0; i < 9; i++ {
				got, ci, e := reader.ReadPacketData()
				require(t, e)
				want, wi, e := original.ReadPacketData()
				require(t, e)
				if !bytes.Equal(got, want) || !ci.Timestamp.Equal(wi.Timestamp) || ci.Length != wi.Length {
					t.Fatal("会话导出重写了原字节或时间")
				}
			}
		}
		httpB.request("POST", "/packet-archives/session-export", "", input, nil, 404)
		httpViewer.request("POST", "/packet-archives/session-export", "", input, nil, 403)
		input.Mode = "full_session"
		input.ServerPort = 443
		var failed struct {
			Code   string                      `json:"code"`
			Report packetarchive.SessionReport `json:"report"`
		}
		httpA.request("POST", "/packet-archives/session-export", "", input, &failed, 422)
		if failed.Code != "session_incomplete" || failed.Report.Packets != 0 || len(failed.Report.Reasons) == 0 {
			t.Fatal("缺口未报告")
		}
		input.ServerPort = 80
		input.ArchiveIDs = append(input.ArchiveIDs, row.ID)
		httpA.request("POST", "/packet-archives/session-export", "", input, nil, 400)
		input.ArchiveIDs = []string{row.ID}
		httpA.request("POST", "/packet-archives/session-export?unexpected=1", "", input, nil, 400)
		input.ArchiveIDs = []string{"packet_missing"}
		httpA.request("POST", "/packet-archives/session-export", "", input, nil, 404)
		require(t, f.Runtime.WithPacketArchives(ctx, adminA, []string{row.ID}, func(rows []store.PacketArchive) error {
			if len(rows) != 1 || rows[0].ID != row.ID {
				t.Fatal("读取身份不一致")
			}
			tx, e := f.Owner.Pool.Begin(ctx)
			require(t, e)
			defer tx.Rollback(ctx)
			_, e = tx.Exec(ctx, "SET LOCAL statement_timeout='100ms'")
			require(t, e)
			_, e = tx.Exec(ctx, `UPDATE packet_archives SET state='deleting' WHERE tenant_id=$1 AND id=$2`, id.TenantID, row.ID)
			var pe *pgconn.PgError
			if !errors.As(e, &pe) || pe.Code != "57014" {
				t.Fatalf("清理可在读取中并发删除：%v", e)
			}
			return nil
		}))
		entries, e := os.ReadDir(staging)
		require(t, e)
		if len(entries) != 0 {
			t.Fatal("导出临时原件或制品未回收")
		}
		var attempts int
		require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE tenant_id=$1 AND action LIKE 'pcap.session.export.%.request'`, id.TenantID).Scan(&attempts))
		if attempts != 3 {
			t.Fatalf("导出访问及失败请求未审计：%d", attempts)
		}
	})
	bad, _, badStored := packetMaterial(t, id, "packet_bad")
	badJSON, _, err := bad.JSON()
	require(t, err)
	for _, attempt := range []struct {
		data   []byte
		offset uint64
		code   codes.Code
	}{{badStored, 1, codes.InvalidArgument}, {badStored[:len(badStored)-1], 0, codes.DataLoss}, {bytes.Repeat([]byte{0}, len(badStored)), 0, codes.DataLoss}} {
		if _, err = sendPacket(t, ctx, a, badJSON, attempt.data, attempt.offset); status.Code(err) != attempt.code {
			t.Fatal("损坏上传未拒绝", status.Code(err), attempt.code)
		}
	}
	if _, err = sendPacket(t, ctx, a, []byte(`{"capture":{},"encoding":{}}`), nil, 0); status.Code(err) != codes.InvalidArgument {
		t.Fatal(err)
	}
	// 状态提交和原包校验必须相互独立：可解压但捕获目录漂移仍应拒绝。
	drift, _, driftStored := packetMaterial(t, id, "packet_drift")
	drift.Capture.InterfaceMAC = "02:00:00:00:00:02"
	driftJSON, _, err := drift.JSON()
	require(t, err)
	if _, err = sendPacket(t, ctx, a, driftJSON, driftStored, 0); status.Code(err) != codes.DataLoss {
		t.Fatal("格式目录漂移未拒绝", err)
	}
	// 未被确认的中断传输仍占用额度；默认留存到期前不清理业务原件。
	var used int64
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT reserved_bytes FROM packet_archive_capacity WHERE tenant_id=$1`, id.TenantID).Scan(&used))
	if used != m.Encoding.StoredBytes+bad.Encoding.StoredBytes+drift.Encoding.StoredBytes {
		t.Fatal("传输失败提前释放了额度", used)
	}
	quota, _, _ := packetMaterial(t, id, "packet_quota")
	if _, _, err = f.Runtime.BeginPacketArchive(ctx, id, quota, used); !errors.Is(err, packetarchive.ErrQuota) {
		t.Fatal("额度不足仍接受了目录", err)
	}
	orphan, _, orphanStored := packetMaterial(t, id, "packet_orphan")
	orphanRow, _, err := f.Runtime.BeginPacketArchive(ctx, id, orphan, 100<<20)
	require(t, err)
	_, err = objects.Put(ctx, orphanRow.ObjectKey, bytes.NewReader(orphanStored), int64(len(orphanStored)), orphan.Encoding.StoredSHA256)
	require(t, err)
	require(t, f.Runtime.ReleasePacketLease(ctx, id, orphanRow))
	require(t, f.Runtime.SweepPacketArchives(ctx, objects))
	if _, err = f.Runtime.PacketArchive(ctx, adminA, row.ID); err != nil {
		t.Fatal("未到期原包被清理", err)
	}
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE packet_archives SET expires_at=now()-interval '1 minute',lease_until=now()-interval '1 minute' WHERE tenant_id=$1`, id.TenantID)
	require(t, err)
	storageErr := errors.New("对象存储中断")
	if err = f.Runtime.SweepPacketArchives(ctx, packetRemovalFailure{ObjectStorage: objects, err: storageErr}); !errors.Is(err, storageErr) {
		t.Fatal("对象删除中断被当作成功", err)
	}
	var stillUsed int64
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT reserved_bytes FROM packet_archive_capacity WHERE tenant_id=$1`, id.TenantID).Scan(&stillUsed))
	if stillUsed < row.Manifest.Encoding.StoredBytes+orphan.Encoding.StoredBytes {
		t.Fatal("对象删除失败提前释放额度")
	}
	require(t, f.Runtime.SweepPacketArchives(ctx, objects))
	var remaining int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM packet_archives WHERE tenant_id=$1`, id.TenantID).Scan(&remaining))
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT reserved_bytes FROM packet_archive_capacity WHERE tenant_id=$1`, id.TenantID).Scan(&stillUsed))
	if remaining != 0 || stillUsed != 0 {
		t.Fatal("到期传输或未知对象版本未恢复回收", remaining, stillUsed)
	}
	files, err := os.ReadDir(objects.Dir)
	require(t, err)
	if len(files) != 0 {
		t.Fatal("对象回收后仍有冻结制品")
	}
	if _, _, err = f.Runtime.BeginPacketArchive(ctx, transport.SensorIdentity{TenantID: id.TenantID, SensorID: id.SensorID, RegistrationID: "revoked"}, m, 100<<20); err == nil {
		t.Fatal("注销注册身份可上传")
	}
	if err = f.Runtime.SweepPacketArchives(ctx, nil); err == nil {
		t.Fatal("没有对象存储仍清理成功")
	}
	staged, err := os.ReadDir(staging)
	require(t, err)
	if len(staged) != 0 {
		t.Fatal("请求结束遗留私有验证临时文件")
	}
}

type packetRemovalFailure struct {
	packetarchive.ObjectStorage
	err error
}

func (v packetRemovalFailure) Remove(context.Context, string, string) error { return v.err }

func TestPacketArchiveDirectoryLeaseQuotaCASAndCustomRetention(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	require(t, admin.Bootstrap(ctx, f.Owner, "packet_lease", "原包租约验收", "packet_owner", store.Token(), "admin"))
	id := transport.SensorIdentity{TenantID: "packet_lease", SensorID: "sensor_lease", RegistrationID: "registration_lease"}
	_, err := f.Owner.Pool.Exec(ctx, `INSERT INTO sensors(tenant_id,id,name,registration_id) VALUES($1,$2,'租约探针',$3);`, id.TenantID, id.SensorID, id.RegistrationID)
	require(t, err)
	_, err = f.Owner.Pool.Exec(ctx, `INSERT INTO retention_policies(tenant_id,category,days,revision) VALUES($1,'pcap',30,1) ON CONFLICT(tenant_id,category) DO UPDATE SET days=30`, id.TenantID)
	require(t, err)
	m, _, _ := packetMaterial(t, id, "packet_lease_one")
	row, acquired, err := f.Runtime.BeginPacketArchive(ctx, id, m, 100<<20)
	require(t, err)
	if !acquired || row.ExpiresAt.Sub(row.CreatedAt) < 29*24*time.Hour || row.ExpiresAt.Sub(row.CreatedAt) > 31*24*time.Hour {
		t.Fatal("自定义留存或租约未生效")
	}
	if _, _, err = f.Runtime.BeginPacketArchive(ctx, id, m, 100<<20); !errors.Is(err, store.ErrPacketBusy) {
		t.Fatal("并发传输未互斥", err)
	}
	drift := m
	drift.Capture.Interface = "eth1"
	if _, _, err = f.Runtime.BeginPacketArchive(ctx, id, drift, 100<<20); !errors.Is(err, store.ErrConflict) {
		t.Fatal("同 ID 的目录漂移未拒绝", err)
	}
	if _, err = f.Runtime.CompletePacketArchive(ctx, id, row); !errors.Is(err, store.ErrConflict) {
		t.Fatal("对象版本未提交即确认完成", err)
	}
	if err = f.Runtime.RegisterPacketObject(ctx, id, row, "null"); !errors.Is(err, packetarchive.ErrIntegrity) {
		t.Fatal("可变空版本被接受", err)
	}
	stale := row
	stale.LeaseToken = "stale"
	if err = f.Runtime.RegisterPacketObject(ctx, id, stale, "version_one"); !errors.Is(err, store.ErrConflict) {
		t.Fatal("过期租约可提交版本", err)
	}
	require(t, f.Runtime.ReleasePacketLease(ctx, id, row))
	retry, acquired, err := f.Runtime.BeginPacketArchive(ctx, id, m, 100<<20)
	require(t, err)
	if !acquired || retry.LeaseToken == row.LeaseToken || !retry.ExpiresAt.Equal(row.ExpiresAt) {
		t.Fatal("恢复租约未冻结留存或替换旧令牌")
	}
	require(t, f.Runtime.RegisterPacketObject(ctx, id, retry, "version_one"))
	if err = f.Runtime.RegisterPacketObject(ctx, id, retry, "version_two"); !errors.Is(err, store.ErrConflict) {
		t.Fatal("目录对象版本可被覆盖")
	}
	require(t, f.Owner.TenantTx(ctx, id.TenantID, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE sensors SET active=false WHERE tenant_id=$1 AND id=$2`, id.TenantID, id.SensorID)
		return e
	}))
	if _, err = f.Runtime.CompletePacketArchive(ctx, id, retry); !errors.Is(err, store.ErrSensorInactive) {
		t.Fatal("停用探针仍可完成持久确认", err)
	}
	if _, _, err = f.Runtime.BeginPacketArchive(ctx, id, m, 100<<20); !errors.Is(err, store.ErrSensorInactive) {
		t.Fatal(err)
	}
	u, _, err := f.Owner.Password(ctx, "packet_owner")
	require(t, err)
	for _, v := range []struct{ sensor, cursor string }{{"id.invalid", ""}, {"", "bad"}, {"", string(bytes.Repeat([]byte("x"), 1025))}} {
		if _, _, err = f.Runtime.PacketArchives(ctx, u, v.sensor, v.cursor); err == nil {
			t.Fatal("非法目录分页被接受")
		}
	}
	if _, _, err = f.Runtime.PacketArchives(ctx, model.Principal{TenantID: id.TenantID, Role: "viewer"}, "", ""); err == nil {
		t.Fatal("查看者原包枚举未拒绝")
	}
}

func TestPacketSensorQualificationLocksWithoutTenantWritePrivilege(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	require(t, admin.Bootstrap(ctx, f.Owner, "packet_lock", "原包资格验收", "packet_locker", store.Token(), "admin"))
	require(t, admin.Bootstrap(ctx, f.Owner, "packet_other", "隔离租户", "packet_other_user", store.Token(), "admin"))
	root := t.TempDir()
	require(t, admin.DevPKI(filepath.Join(root, "pki")))
	id, err := admin.Provision(ctx, f.Owner, "packet_lock", "packet_sensor", "资格验收探针", filepath.Join(root, "pki"), filepath.Join(root, "agent"))
	require(t, err)
	var count int
	require(t, f.Runtime.TenantTx(ctx, "packet_other", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM public.lock_packet_sensor($1,$2)`, id.SensorID, id.RegistrationID).Scan(&count)
	}))
	if count != 0 {
		t.Fatal("受限函数返回了其他租户的探针资格")
	}
	require(t, f.Runtime.TenantTx(ctx, id.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM public.lock_packet_sensor($1,$2)`, id.SensorID, "registration_other").Scan(&count)
	}))
	if count != 0 {
		t.Fatal("受限函数接受了其他注册代次")
	}
	err = f.Runtime.TenantTx(ctx, id.TenantID, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE tenants SET active=false WHERE id=$1`, id.TenantID)
		return e
	})
	var sqlErr *pgconn.PgError
	if !errors.As(err, &sqlErr) || sqlErr.Code != "42501" {
		t.Fatal("在线账号获得了租户写权限", err)
	}
	tx, err := f.Runtime.Pool.Begin(ctx)
	require(t, err)
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `SELECT set_config('starbeacon.tenant_id',$1,true)`, id.TenantID)
	require(t, err)
	var sensor string
	require(t, tx.QueryRow(ctx, `SELECT public.lock_packet_sensor($1,$2)`, id.SensorID, id.RegistrationID).Scan(&sensor))
	if sensor != id.SensorID {
		t.Fatal("探针资格未绑定冻结身份")
	}
	for _, table := range []string{"tenants", "sensors"} {
		blocked, e := f.Owner.Pool.Begin(ctx)
		require(t, e)
		_, e = blocked.Exec(ctx, `SET LOCAL statement_timeout='100ms'`)
		require(t, e)
		_, e = blocked.Exec(ctx, `SELECT set_config('starbeacon.tenant_id',$1,true)`, id.TenantID)
		require(t, e)
		if table == "tenants" {
			_, e = blocked.Exec(ctx, `UPDATE tenants SET active=false WHERE id=$1`, id.TenantID)
		} else {
			_, e = blocked.Exec(ctx, `UPDATE sensors SET active=false WHERE tenant_id=$1 AND id=$2`, id.TenantID, id.SensorID)
		}
		_ = blocked.Rollback(ctx)
		if !errors.As(e, &sqlErr) || sqlErr.Code != "57014" {
			t.Fatal("资格事务未阻止并发停用", table, e)
		}
	}
	require(t, tx.Commit(ctx))
	require(t, f.Owner.TenantTx(ctx, id.TenantID, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE tenants SET active=false WHERE id=$1`, id.TenantID)
		return e
	}))
	require(t, f.Runtime.TenantTx(ctx, id.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM public.lock_packet_sensor($1,$2)`, id.SensorID, id.RegistrationID).Scan(&count)
	}))
	if count != 0 {
		t.Fatal("停用租户仍具有原包上传资格")
	}
}
