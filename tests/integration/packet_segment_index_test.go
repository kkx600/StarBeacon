//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket/pcapgo"
	"github.com/jackc/pgx/v5"
	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/ingest"
	"github.com/kkx600/StarBeacon/internal/packetarchive"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/testpcap"
	"github.com/kkx600/StarBeacon/internal/transport"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type archiveRange struct{ offset, length int64 }

type segmentRangeLog struct {
	packetarchive.ObjectStorage
	mu     sync.Mutex
	ranges []archiveRange
}

func (s *segmentRangeLog) Range(ctx context.Context, key, version string, offset, length int64) (io.ReadCloser, error) {
	s.mu.Lock()
	s.ranges = append(s.ranges, archiveRange{offset, length})
	s.mu.Unlock()
	return s.ObjectStorage.Range(ctx, key, version, offset, length)
}

func (s *segmentRangeLog) take() []archiveRange {
	s.mu.Lock()
	defer s.mu.Unlock()
	ranges := s.ranges
	s.ranges = nil
	return ranges
}

func TestPackedPacketArchiveWarmHTTPRangeLatencyAndIndexRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	const tenant, other, username = "warm_test", "warm_other", "packet_admin"
	password := store.Token()
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "温层归档验收", username, password, "admin"))
	require(t, admin.Bootstrap(ctx, f.Owner, other, "跨租户验收", other, password, "admin"))
	root := t.TempDir()
	pki, sensor, staging := filepath.Join(root, "pki"), filepath.Join(root, "sensor"), filepath.Join(root, "staging")
	require(t, os.Mkdir(staging, 0700))
	require(t, admin.DevPKI(pki, nil))
	id, err := admin.Provision(ctx, f.Owner, tenant, "sensor_owned", "温层归档采集器", pki, sensor)
	require(t, err)
	objects, err := packetarchive.NewLocalObjects(filepath.Join(root, "objects"))
	require(t, err)
	ranges := &segmentRangeLog{ObjectStorage: objects}
	tls, err := transport.TLS(filepath.Join(pki, "ca.crt"), filepath.Join(pki, "server.crt"), filepath.Join(pki, "server.key"), true)
	require(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require(t, err)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(tls)))
	sensorv1.RegisterSensorServiceServer(server, &ingest.Server{DB: f.Runtime, ControlOnly: true, Packets: objects, PacketStaging: staging})
	go server.Serve(listener)
	defer server.Stop()

	db, err := bolt.Open(filepath.Join(root, "queue.db"), 0600, nil)
	require(t, err)
	defer db.Close()
	spool, err := packetarchive.NewSpool(db, filepath.Join(root, "spool"), tenant, id.SensorID, id.RegistrationID, 64<<20, 8<<20)
	require(t, err)
	spool.RetentionFile = filepath.Join(root, "policy.json")
	require(t, os.WriteFile(spool.RetentionFile, []byte(`{"network_domain":"warm_test","revision":1,"mode":"full"}`), 0600))
	frames, selected, err := testpcap.IndexedSegment()
	require(t, err)
	begin := frames[0].Info.Timestamp.Add(-time.Second)
	capture := packetarchive.Capture{ID: "warm_indexed", TenantID: tenant, SensorID: id.SensorID, RegistrationID: id.RegistrationID,
		RunID: "run_owned", Interface: "eth0", InterfaceMAC: "02:00:00:00:00:01", SettingsSHA256: packetarchive.Digest([]byte("warm-settings")), StartedAt: begin}
	pending, err := spool.Begin(capture)
	require(t, err)
	for _, frame := range frames {
		require(t, pending.Recorder.Write(frame.Info, frame.Raw, nil))
	}
	drops := uint64(0)
	require(t, pending.Seal(frames[len(frames)-1].Info.Timestamp.Add(time.Second), "rotation", &drops))
	row, err := spool.Prepare(ctx, pending.ID, "zstd")
	require(t, err)
	if row.Manifest == nil || row.Manifest.Encoding.Schema != packetarchive.PackedSchema || len(row.Manifest.Encoding.Frames) < 5 {
		t.Fatal("采集器未生成分段归档")
	}
	file, _, err := spool.OpenStored(row.ID)
	require(t, err)
	stored, err := io.ReadAll(file)
	file.Close()
	require(t, err)
	manifest, manifestSHA, err := row.Manifest.JSON()
	require(t, err)
	client := packetClient(t, listener.Addr().String(), pki, sensor)
	ack, err := sendPacket(t, ctx, client, manifest, stored, 0)
	require(t, err)
	if ack.ManifestSha256 != manifestSHA || ack.ObjectVersion != row.Manifest.Encoding.StoredSHA256 {
		t.Fatal("上传确认未绑定分段清单和对象版本")
	}
	loadIndex := func() packetarchive.IndexRecord {
		t.Helper()
		var record packetarchive.IndexRecord
		require(t, f.Owner.Pool.QueryRow(ctx, `SELECT data,index_sha256 FROM packet_archive_flow_indexes
			WHERE tenant_id=$1 AND archive_id=$2 AND object_version=$3 AND manifest_sha256=$4`,
			tenant, row.ID, ack.ObjectVersion, manifestSHA).Scan(&record.Data, &record.SHA256))
		return record
	}
	checkIndex := func() {
		t.Helper()
		record := loadIndex()
		if record.SHA256 != row.Index.SHA256 || !bytes.Equal(record.Data, row.Index.Data) {
			t.Fatal("平台索引与采集器的派生索引不一致")
		}
	}
	checkIndex()
	require(t, f.Runtime.TenantTx(ctx, other, func(tx pgx.Tx) error {
		var count int
		err := tx.QueryRow(ctx, "SELECT count(*) FROM packet_archive_flow_indexes WHERE archive_id=$1", row.ID).Scan(&count)
		if count != 0 {
			t.Fatal("跨租户查询读到了分段索引")
		}
		return err
	}))

	httpA := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, Packets: ranges, PacketStaging: staging}, username, password)
	httpB := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, Packets: ranges, PacketStaging: staging}, other, password)
	query := packetarchive.SessionRequest{ArchiveIDs: []string{row.ID}, Mode: "full_session", ClientIP: "192.0.2.10", ClientPort: 40000, ServerIP: "198.51.100.20", ServerPort: 80, ClientMAC: "02:00:00:00:00:01", ServerMAC: "02:00:00:00:00:02", VLANs: []uint16{}}
	httpB.request("POST", "/packet-archives/session-export", "", query, nil, 404)
	if len(ranges.take()) != 0 {
		t.Fatal("跨租户请求触发了对象读取")
	}
	body, err := json.Marshal(query)
	require(t, err)
	download := func() time.Duration {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, httpA.origin+httpA.prefix+"/packet-archives/session-export", bytes.NewReader(body))
		require(t, err)
		request.Header.Set("Origin", httpA.origin)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-CSRF-Token", httpA.csrf)
		started := time.Now()
		response, err := httpA.client.Do(request)
		require(t, err)
		raw, err := io.ReadAll(io.LimitReader(response.Body, packetarchive.MaxSegmentBytes+1))
		response.Body.Close()
		elapsed := time.Since(started)
		require(t, err)
		if response.StatusCode != 200 || response.Header.Get("X-Content-SHA256") != packetarchive.Digest(raw) || response.Header.Get("X-Session-Completeness") != query.Mode {
			t.Fatalf("温层响应未通过核验：%d %s", response.StatusCode, raw)
		}
		reader, err := pcapgo.NewNgReader(bytes.NewReader(raw), pcapgo.DefaultNgReaderOptions)
		require(t, err)
		var report packetarchive.SessionReport
		require(t, json.Unmarshal([]byte(reader.SectionInfo().Comment), &report))
		if len(report.Sources) != 1 || report.Sources[0].ObjectVersion != ack.ObjectVersion || report.Sources[0].ManifestSHA256 != manifestSHA {
			t.Fatal("会话未保留对象版本与归档清单证据")
		}
		for _, want := range selected {
			got, info, err := reader.ReadPacketData()
			require(t, err)
			if !bytes.Equal(got, want.Raw) || !info.Timestamp.Equal(want.Info.Timestamp) {
				t.Fatal("温层返回了不同的源帧或捕获时间")
			}
		}
		if _, _, err = reader.ReadPacketData(); err != io.EOF {
			t.Fatal("温层混入了其他报文")
		}
		return elapsed
	}
	encoding := row.Manifest.Encoding
	target := archiveRange{encoding.Frames[1].StoredOffset, encoding.Frames[1].StoredLength}
	samples := make([]time.Duration, 40)
	for i := range samples {
		samples[i] = download()
		if got := ranges.take(); !slices.Equal(got, []archiveRange{target}) {
			t.Fatalf("温层检索必须只读取一帧：%v", got)
		}
	}
	slices.Sort(samples)
	t.Logf("分段取回实测 温层 %d 次 HTTP 完整导出，P95 %s，索引 %d 字节／存储 %d 字节，原始 %d 字节，Range %d 字节（1／%d 帧）",
		len(samples), samples[37], len(row.Index.Data), encoding.StoredBytes, encoding.RawBytes, target.length, len(encoding.Frames))
	_, err = f.Owner.Pool.Exec(ctx, "UPDATE packet_archive_flow_indexes SET data=$1 WHERE tenant_id=$2 AND archive_id=$3", []byte("damaged"), tenant, row.ID)
	require(t, err)
	if bytes.Equal(loadIndex().Data, row.Index.Data) {
		t.Fatal("未构造出损坏索引")
	}
	download()
	all := make([]archiveRange, 0, len(encoding.Frames)+1)
	for _, frame := range encoding.Frames {
		all = append(all, archiveRange{frame.StoredOffset, frame.StoredLength})
	}
	all = append(all, target)
	if got := ranges.take(); !slices.Equal(got, all) {
		t.Fatalf("恢复索引未按冻结版本完整读取后再选帧：%v", got)
	}
	checkIndex()
	download()
	if got := ranges.take(); !slices.Equal(got, []archiveRange{target}) {
		t.Fatalf("恢复后的请求仍读取了无关帧：%v", got)
	}
	files, err := os.ReadDir(staging)
	require(t, err)
	if len(files) != 0 {
		t.Fatal("归档上传或索引恢复遗留暂存文件", files)
	}
}
