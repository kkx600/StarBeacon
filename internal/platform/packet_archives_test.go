package platform

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kkx600/StarBeacon/internal/packetarchive"
	"github.com/kkx600/StarBeacon/internal/store"
)

func TestPacketHTTPRejectsUnavailableStorageAndAmbiguousScope(t *testing.T) {
	api := &API{}
	for _, input := range []struct {
		path    string
		handler http.HandlerFunc
		body    string
		status  int
		code    string
	}{
		{"/api/v1/packet-archives/session-export", api.exportPacketSession, `{}`, 400, "invalid_session_export"},
		{"/api/v1/packet-archives/session-export?mode=snapshot", api.exportPacketSession, `{}`, 400, "invalid_session_export"},
		{"/api/v1/packet-archives/download", api.downloadPacketArchive, "", 503, "packet_storage_unavailable"},
		{"/api/v1/packet-archives?unknown=x", api.packetArchives, "", 400, "invalid_request"},
		{"/api/v1/packet-archives?sensor_id=a&sensor_id=b", api.packetArchives, "", 400, "invalid_request"},
		{"/api/v1/packet-archives?cursor=a&cursor=b", api.packetArchives, "", 400, "invalid_request"},
		{"/api/v1/packet-archives?sensor_id=a&cursor=b&unknown=c", api.packetArchives, "", 400, "invalid_request"},
		{"/api/v1/packet-archives/invalid", api.packetArchive, "", 404, "not_found"},
	} {
		t.Run(input.path, func(t *testing.T) {
			r := httptest.NewRequest("POST", input.path, strings.NewReader(input.body))
			r.SetPathValue("id", "../outside")
			response := httptest.NewRecorder()
			input.handler(response, r)
			if response.Code != input.status || !strings.Contains(response.Body.String(), input.code) {
				t.Fatal("提前校验未阻止读取原包", response.Code, response.Body.String())
			}
		})
	}
	request := packetarchive.SessionRequest{ArchiveIDs: []string{"packet_owned"}, Mode: "full_session", ClientIP: "192.0.2.10", ClientPort: 40000, ServerIP: "198.51.100.20", ServerPort: 80, ClientMAC: "02:00:00:00:00:01", ServerMAC: "02:00:00:00:00:02", VLANs: []uint16{}}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/packet-archives/session-export", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	api.exportPacketSession(response, r)
	if response.Code != 503 || !strings.Contains(response.Body.String(), "packet_storage_unavailable") {
		t.Fatal("未配置仍进入原包读取", response.Code)
	}
}

func TestPacketInspectionHTTPRejectsInvalidNumberScopeStorageAndBusyReads(t *testing.T) {
	objects, err := packetarchive.NewLocalObjects(filepath.Join(t.TempDir(), "objects"))
	if err != nil {
		t.Fatal(err)
	}
	api := &API{DB: &store.Postgres{}, Packets: objects, PacketStaging: t.TempDir()}
	for _, raw := range []string{"0", "01", "-1", "1.5", "1048577"} {
		r := httptest.NewRequest("GET", "/api/v1/packet-archives/packet_one/packets/"+raw, nil)
		r.SetPathValue("id", "packet_one")
		r.SetPathValue("number", raw)
		w := httptest.NewRecorder()
		api.inspectPacketArchive(w, r)
		if w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_packet_number") {
			t.Fatal("无效序号访问了存储", w.Code, w.Body.String())
		}
	}
	for _, path := range []string{"/packets/1?unknown=1", "/packets/1?number=1&number=2"} {
		r := httptest.NewRequest("GET", path, nil)
		r.SetPathValue("id", "packet_one")
		r.SetPathValue("number", "1")
		w := httptest.NewRecorder()
		api.inspectPacketArchive(w, r)
		if w.Code != 400 {
			t.Fatal("含糊筛选被接受", w.Code)
		}
	}
	r := httptest.NewRequest("GET", "/packets/1", nil)
	r.SetPathValue("id", "packet_one")
	r.SetPathValue("number", "1")
	w := httptest.NewRecorder()
	(&API{}).inspectPacketArchive(w, r)
	if w.Code != 503 {
		t.Fatal("未配置来源仍接受查询", w.Code)
	}
	for range cap(packetDownloads) {
		packetDownloads <- struct{}{}
	}
	defer func() {
		for range cap(packetDownloads) {
			<-packetDownloads
		}
	}()
	w = httptest.NewRecorder()
	api.inspectPacketArchive(w, r)
	if w.Code != 429 || !strings.Contains(w.Body.String(), "packet_download_busy") {
		t.Fatal("已满预算仍读取原包", w.Code)
	}
}

func TestPacketHTTPBudgetsRejectBeforeDatabaseAndObjectAccess(t *testing.T) {
	objects, err := packetarchive.NewLocalObjects(filepath.Join(t.TempDir(), "objects"))
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Packets: objects, PacketStaging: t.TempDir()}
	request := packetarchive.SessionRequest{ArchiveIDs: []string{"packet_owned"}, Mode: "full_session", ClientIP: "192.0.2.10", ClientPort: 40000, ServerIP: "198.51.100.20", ServerPort: 80, ClientMAC: "02:00:00:00:00:01", ServerMAC: "02:00:00:00:00:02", VLANs: []uint16{}}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, budget := range []struct {
		semaphore chan struct{}
		handler   http.HandlerFunc
		body      []byte
		code      string
	}{{sessionExports, api.exportPacketSession, body, "session_export_busy"}, {packetDownloads, api.downloadPacketArchive, nil, "packet_download_busy"}} {
		t.Run(budget.code, func(t *testing.T) {
			if len(budget.semaphore) != 0 {
				t.Fatal("独立额度已被占用")
			}
			for i := 0; i < cap(budget.semaphore); i++ {
				budget.semaphore <- struct{}{}
			}
			defer func() {
				for i := 0; i < cap(budget.semaphore); i++ {
					<-budget.semaphore
				}
			}()
			response := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/api/v1/packet-archives/session-export", bytes.NewReader(budget.body))
			r.Header.Set("Content-Type", "application/json")
			budget.handler(response, r)
			if response.Code != 429 || !strings.Contains(response.Body.String(), budget.code) {
				t.Fatal("超过处理预算仍访问数据库", response.Code, response.Body.String())
			}
		})
	}
}
