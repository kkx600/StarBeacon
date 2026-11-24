package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket/pcapgo"
	"github.com/kkx600/StarBeacon/internal/clientip"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/packetarchive"
	"github.com/kkx600/StarBeacon/internal/testpcap"
)

func TestLocalIndexedPacketSessionAuthorizationAndLatency(t *testing.T) {
	ctx := context.Background()
	p, w := packetControllerFixture(t)
	p.Spool.SegmentBytes, p.Spool.Quota = 8<<20, 64<<20
	legacy, _ := localPacketFixture(t, p, "legacy_archive", true)
	if legacy.Manifest == nil || legacy.Manifest.Encoding.Schema == packetarchive.PackedSchema {
		t.Fatal("未生成旧格式归档")
	}
	p.Spool.RetentionFile = filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(p.Spool.RetentionFile, []byte(`{"network_domain":"hot_test","revision":1,"mode":"full"}`), 0600); err != nil {
		t.Fatal(err)
	}
	frames, selected, err := testpcap.IndexedSegment()
	if err != nil {
		t.Fatal(err)
	}
	begin := frames[0].Info.Timestamp.Add(-time.Second)
	capture := packetarchive.Capture{ID: "hot_archive", TenantID: w.TenantID, SensorID: w.SensorID, RegistrationID: w.RegistrationID,
		RunID: "run_owned", Interface: "eth0", InterfaceMAC: "02:00:00:00:00:01", SettingsSHA256: strings.Repeat("a", 64), StartedAt: begin}
	pending, err := p.Spool.Begin(capture)
	if err != nil {
		t.Fatal(err)
	}
	for _, frame := range frames {
		if err = pending.Recorder.Write(frame.Info, frame.Raw, nil); err != nil {
			t.Fatal(err)
		}
	}
	drops := uint64(0)
	if err = pending.Seal(frames[len(frames)-1].Info.Timestamp.Add(time.Second), "rotation", &drops); err != nil {
		t.Fatal(err)
	}
	row, err := p.Spool.Prepare(ctx, pending.ID, "zstd")
	if err != nil {
		t.Fatal(err)
	}
	id, err := NewLocalIdentity(w, "packet-session-local-acceptance")
	if err != nil {
		t.Fatal(err)
	}
	user, _, err := id.Password(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	token, csrfToken, err := id.CreateSession(ctx, user)
	if err != nil {
		t.Fatal(err)
	}
	auth := httpapi.NewAuth(id, nil, "http://packet.test", "packet_session", false)
	query := packetarchive.SessionRequest{ArchiveIDs: []string{row.ID}, Mode: "full_session", ClientIP: "192.0.2.10", ClientPort: 40000, ServerIP: "198.51.100.20", ServerPort: 80, ClientMAC: "02:00:00:00:00:01", ServerMAC: "02:00:00:00:00:02", VLANs: []uint16{}}
	body, err := json.Marshal(query)
	if err != nil {
		t.Fatal(err)
	}
	disabled := httptest.NewRequest(http.MethodPost, "/api/local/v1/packet-archives/session-export", bytes.NewReader(body))
	disabled.Header.Set("Content-Type", "application/json")
	disabled.Header.Set("Origin", "http://packet.test")
	disabled.Header.Set("X-CSRF-Token", csrfToken)
	disabled.AddCookie(&http.Cookie{Name: "packet_session", Value: token})
	response := httptest.NewRecorder()
	w.packetArchives = nil
	LocalHandler(w, auth, w.DB.Path()).ServeHTTP(response, disabled)
	w.packetArchives = p
	if response.Code != 503 {
		t.Fatal("停用原包捕获后仍可导出", response.Code)
	}
	server := httptest.NewServer(httpapi.Middleware(LocalHandler(w, auth, w.DB.Path()), clientip.Policy{}))
	defer server.Close()
	call := func(suffix string, cookie, csrf bool, want int) ([]byte, http.Header) {
		t.Helper()
		body, err := json.Marshal(query)
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/api/local/v1/packet-archives/session-export"+suffix, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "http://packet.test")
		if cookie {
			request.AddCookie(&http.Cookie{Name: "packet_session", Value: token})
		}
		if csrf {
			request.Header.Set("X-CSRF-Token", csrfToken)
		}
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(response.Body)
		if response.StatusCode != want || err != nil {
			t.Fatalf("本机导出响应 %d，期望 %d，读取错误 %v", response.StatusCode, want, err)
		}
		return raw, response.Header
	}
	call("", false, false, 401)
	call("", true, false, 403)
	call("?extra=1", true, true, 400)
	for i := 0; i < cap(localPacketDownloads); i++ {
		localPacketDownloads <- struct{}{}
	}
	call("", true, true, 429)
	for i := 0; i < cap(localPacketDownloads); i++ {
		<-localPacketDownloads
	}
	query.ArchiveIDs[0] = "missing"
	call("", true, true, 409)
	query.ArchiveIDs[0] = row.ID
	query.ClientPort = 1234
	call("", true, true, 422)
	query.ClientPort = 40000
	samples := make([]time.Duration, 40)
	for i := range samples {
		started := time.Now()
		raw, headers := call("", true, true, 200)
		samples[i] = time.Since(started)
		if headers.Get("X-Content-SHA256") != packetarchive.Digest(raw) || headers.Get("X-Session-Completeness") != "full_session" {
			t.Fatal("热层下载证据未核验")
		}
		reader, err := pcapgo.NewNgReader(bytes.NewReader(raw), pcapgo.DefaultNgReaderOptions)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range selected {
			raw, ci, err := reader.ReadPacketData()
			if err != nil || !bytes.Equal(raw, want.Raw) || !ci.Timestamp.Equal(want.Info.Timestamp) {
				t.Fatal("热层取回改变源报文", err)
			}
		}
		if _, _, err = reader.ReadPacketData(); err != io.EOF {
			t.Fatal("热层取回混入背景流", err)
		}
	}
	slices.Sort(samples)
	t.Logf("分段取回实测 热层 %d 次 HTTP 完整导出，P95 %s，索引 %d 字节／存储 %d 字节，原始 %d 字节",
		len(samples), samples[37], len(row.Index.Data), row.Manifest.Encoding.StoredBytes, row.Manifest.Encoding.RawBytes)
	query.ArchiveIDs[0] = legacy.ID
	call("", true, true, 200)
	query.ArchiveIDs[0] = row.ID
	if err = os.Rename(filepath.Join(p.Spool.Dir, row.ID+".stored"), filepath.Join(p.Spool.Dir, row.ID+".saved")); err != nil {
		t.Fatal(err)
	}
	call("", true, true, 409)
	if err = os.Rename(filepath.Join(p.Spool.Dir, row.ID+".saved"), filepath.Join(p.Spool.Dir, row.ID+".stored")); err != nil {
		t.Fatal(err)
	}
	ack := packetarchive.Acknowledgement{ID: row.ID, ManifestSHA256: row.ManifestSHA256, RawSHA256: row.Manifest.Encoding.RawSHA256,
		StoredSHA256: row.Manifest.Encoding.StoredSHA256, StoredBytes: row.Manifest.Encoding.StoredBytes, ObjectVersion: "approved_version", ExpiresAt: time.Now().Add(time.Hour)}
	if err = p.Spool.Confirm(ack); err != nil {
		t.Fatal(err)
	}
	call("", true, true, 409)
}
