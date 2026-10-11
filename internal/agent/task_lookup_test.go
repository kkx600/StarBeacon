package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	bolt "go.etcd.io/bbolt"
)

func archivedLocalTask(m *TaskManager, id string, started time.Time) LocalTask {
	finished := started.Add(time.Second)
	digest := control.Digest([]byte(id))
	return LocalTask{Origin: "platform", Command: control.Command{ID: id, TenantID: m.WAL.TenantID, SensorID: m.WAL.SensorID, RegistrationID: m.WAL.RegistrationID, Kind: "diagnostics", IssuedAt: started.Add(-time.Second), ExpiresAt: started.Add(time.Minute), Payload: json.RawMessage(`{"private_test_marker":"never_return_command"}`)}, SHA256: digest, Acknowledged: true, Receipt: control.Receipt{CommandID: id, CommandSHA256: digest, State: "succeeded", StartedAt: started, FinishedAt: &finished, Result: json.RawMessage(`{"packets":9}`)}}
}

func saveArchivedTask(t *testing.T, m *TaskManager, row LocalTask) {
	t.Helper()
	if err := m.WAL.DB.Update(func(tx *bolt.Tx) error { return m.putTask(tx, row) }); err != nil {
		t.Fatal(err)
	}
}

func TestLocalTaskPrimaryLookupOutsideRecentWindowAndReadOnly(t *testing.T) {
	m, _ := taskFixture(t, terminalRunner{})
	now := time.Now().UTC().Add(-time.Hour)
	for i := 0; i < 205; i++ {
		saveArchivedTask(t, m, archivedLocalTask(m, fmt.Sprintf("task_history_%03d", i), now.Add(time.Duration(i)*time.Second)))
	}
	list, err := m.List()
	if err != nil || len(list) != 200 || list[0].ID != "task_history_204" || list[199].ID != "task_history_005" {
		t.Fatal("近期列表窗口不正确", len(list), err)
	}
	row, err := m.Task("task_history_000")
	if err != nil || row.ID != "task_history_000" || row.RetentionProtected || !row.RetainUntil.Equal(now.AddDate(0, 0, 180)) || row.ExpiresAt.After(time.Now()) {
		t.Fatal("历史详情被近期列表或执行截止阻断", row, err)
	}
	raw, _ := json.Marshal(row)
	if strings.Contains(string(raw), "never_return_command") || strings.Contains(string(raw), `"command":`) || len(m.queue) != 0 {
		t.Fatal("档案读取泄露命令或重新入队")
	}
	row.Receipt.Result[0] = '['
	again, err := m.Task(row.ID)
	if err != nil || string(again.Receipt.Result) != `{"packets":9}` {
		t.Fatal("事务外返回值修改了原存储", err)
	}
}

func TestLocalTaskRetentionFreezeLegacyRecoveryAndProtectedResults(t *testing.T) {
	m, priv := taskFixture(t, terminalRunner{})
	m.RetentionDays = 7
	raw, sig := signedFixtureCommand(t, m, priv, "task_retention_frozen", time.Now().UTC().Add(-2*time.Minute))
	if err := m.Accept(raw, sig); err != nil {
		t.Fatal(err)
	}
	row, err := m.Task("task_retention_frozen")
	if err != nil || !row.RetainUntil.Equal(row.Receipt.StartedAt.AddDate(0, 0, 7)) || !row.RetentionProtected {
		t.Fatal("任务留存期限未按接收策略冻结", row, err)
	}
	m.RetentionDays = 1
	again, err := m.Task(row.ID)
	if err != nil || !again.RetainUntil.Equal(row.RetainUntil) {
		t.Fatal("策略变化覆盖历史任务期限", err)
	}
	old := time.Now().UTC().AddDate(0, 0, -181)
	for _, state := range []string{"running", "unknown", "failed", "succeeded"} {
		v := archivedLocalTask(m, "task_retained_"+state, old)
		v.Receipt.State = state
		v.Acknowledged = state != "failed"
		if state == "running" {
			v.Receipt.FinishedAt = nil
		}
		saveArchivedTask(t, m, v)
		_, err := m.Task(v.Command.ID)
		if state == "succeeded" {
			if !errors.Is(err, ErrLocalTaskNotFound) {
				t.Fatal("到期已确认档案仍公开", err)
			}
		} else if err != nil {
			t.Fatal("受确认保护的记录不可追溯", state, err)
		}
	}
	legacy := archivedLocalTask(m, "task_legacy", time.Now().UTC().Add(-time.Hour))
	legacy.Origin = ""
	saveArchivedTask(t, m, legacy)
	recovered, err := NewTaskManager(m.WAL, m.PublicKey, terminalRunner{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := recovered.Task(legacy.Command.ID)
	if err != nil || result.Origin != "platform" || !result.RetainUntil.Equal(legacy.Receipt.StartedAt.AddDate(0, 0, 180)) {
		t.Fatal("旧档案期限或来源未兼容", result, err)
	}
	if err := m.WAL.DB.View(func(tx *bolt.Tx) error {
		var stored LocalTask
		if err := json.Unmarshal(tx.Bucket([]byte("sensor_tasks")).Get([]byte(legacy.Command.ID)), &stored); err != nil {
			return err
		}
		if stored.RetainUntil.IsZero() {
			t.Fatal("旧档案期限未持久恢复")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.WAL.DB.Update(func(tx *bolt.Tx) error { return recovered.prune(tx, time.Now().UTC()) }); err != nil {
		t.Fatal(err)
	}
	if _, err := recovered.Task("task_retained_succeeded"); !errors.Is(err, ErrLocalTaskNotFound) {
		t.Fatal("到期记录未清理", err)
	}
	for _, state := range []string{"running", "unknown", "failed"} {
		if _, err := recovered.Task("task_retained_" + state); err != nil {
			t.Fatal("保护记录被清理", state, err)
		}
	}
}

func TestLocalTaskCorruptBindingAndStorageFailure(t *testing.T) {
	m, _ := taskFixture(t, terminalRunner{})
	cases := map[string]func(*LocalTask){
		"id":               func(v *LocalTask) { v.Command.ID = "task_other" },
		"tenant":           func(v *LocalTask) { v.Command.TenantID = "tenant_other" },
		"sensor":           func(v *LocalTask) { v.Command.SensorID = "sensor_other" },
		"registration":     func(v *LocalTask) { v.Command.RegistrationID = "reg_other" },
		"receipt_id":       func(v *LocalTask) { v.Receipt.CommandID = "task_other" },
		"receipt_sha":      func(v *LocalTask) { v.Receipt.CommandSHA256 = control.Digest([]byte("other")) },
		"sha_format":       func(v *LocalTask) { v.SHA256 = strings.Repeat("G", 64); v.Receipt.CommandSHA256 = v.SHA256 },
		"start":            func(v *LocalTask) { v.Receipt.StartedAt = time.Time{} },
		"issued":           func(v *LocalTask) { v.Command.IssuedAt = time.Time{} },
		"execution":        func(v *LocalTask) { v.Command.ExpiresAt = v.Command.IssuedAt },
		"retention":        func(v *LocalTask) { v.RetainUntil = v.Receipt.StartedAt },
		"origin":           func(v *LocalTask) { v.Origin = "external" },
		"local_kind":       func(v *LocalTask) { v.Origin = "local" },
		"kind":             func(v *LocalTask) { v.Command.Kind = "shell" },
		"state":            func(v *LocalTask) { v.Receipt.State = "approved" },
		"end":              func(v *LocalTask) { v.Receipt.FinishedAt = nil },
		"end_before_start": func(v *LocalTask) { v.Receipt.FinishedAt = &v.Command.IssuedAt },
	}
	for name, damage := range cases {
		t.Run(name, func(t *testing.T) {
			v := archivedLocalTask(m, "task_damaged", time.Now().UTC().Add(-time.Minute))
			damage(&v)
			raw, _ := json.Marshal(v)
			if err := m.WAL.DB.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("sensor_tasks")).Put([]byte("task_damaged"), raw) }); err != nil {
				t.Fatal(err)
			}
			if _, err := m.Task("task_damaged"); err == nil || errors.Is(err, ErrLocalTaskNotFound) {
				t.Fatal("损坏记录被当作有效或不存在", err)
			}
		})
	}
	if err := m.WAL.DB.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("sensor_tasks")).Put([]byte("task_json"), []byte("{"))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Task("task_json"); err == nil {
		t.Fatal("损坏 JSON 被读取")
	}
	for _, id := range []string{"task_absent", "bad/id", "UPPER"} {
		if _, err := m.Task(id); !errors.Is(err, ErrLocalTaskNotFound) {
			t.Fatal("缺失或无效主键未明确拒绝", id, err)
		}
	}
	if err := m.WAL.DB.Update(func(tx *bolt.Tx) error { return tx.DeleteBucket([]byte("sensor_tasks")) }); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Task("task_absent"); err == nil || errors.Is(err, ErrLocalTaskNotFound) {
		t.Fatal("缺失存储桶冒充对象不存在", err)
	}
	if err := m.WAL.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Task("task_absent"); !errors.Is(err, bolt.ErrDatabaseNotOpen) {
		t.Fatal("关闭存储被掩盖", err)
	}
}

func TestLocalTaskLookupHTTPAuthenticationAndFailureCodes(t *testing.T) {
	m, _ := taskFixture(t, terminalRunner{})
	saveArchivedTask(t, m, archivedLocalTask(m, "task_http", time.Now().UTC().Add(-time.Minute)))
	identity, err := NewLocalIdentity(m.WAL, "task-lookup-test-password")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server := httptest.NewServer(httpapi.Middleware(mux))
	defer server.Close()
	auth := httpapi.NewAuth(identity, nil, server.URL, "local_lookup_session", false)
	mux.Handle("/", LocalHandler(m.WAL, auth, m.WAL.DB.Path(), m))
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	get := func(path string, status int) []byte {
		t.Helper()
		resp, err := client.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
		if err != nil || resp.StatusCode != status {
			t.Fatalf("详情状态 %d，期望 %d：%s，%v", resp.StatusCode, status, raw, err)
		}
		return raw
	}
	get("/api/local/v1/tasks/task_http", 401)
	request, _ := http.NewRequest("POST", server.URL+"/api/local/v1/auth/login", strings.NewReader(`{"username":"admin","password":"task-lookup-test-password"}`))
	request.Header.Set("Origin", server.URL)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("本地登录失败", response.StatusCode)
	}
	var row LocalTaskSummary
	if err := json.Unmarshal(get("/api/local/v1/tasks/task_http", 200), &row); err != nil || row.ID != "task_http" {
		t.Fatal("详情回执未绑定请求主键", err)
	}
	get("/api/local/v1/tasks/task_missing", 404)
	get("/api/local/v1/tasks/UPPER", 400)
	get("/api/local/v1/tasks/task_http?limit=200", 400)
	identity.mu.Lock()
	for key, session := range identity.sessions {
		session.Principal.Role = "viewer"
		identity.sessions[key] = session
	}
	identity.mu.Unlock()
	get("/api/local/v1/tasks/task_http", 403)
	identity.mu.Lock()
	for key, session := range identity.sessions {
		session.Principal.Role = "admin"
		identity.sessions[key] = session
	}
	identity.mu.Unlock()
	if err := m.WAL.Close(); err != nil {
		t.Fatal(err)
	}
	get("/api/local/v1/tasks/task_http", 503)
}

func TestLocalReplayLookupDoesNotAcquirePlatformAuthority(t *testing.T) {
	m, _ := taskFixture(t, localReplayRunner{})
	payload, _ := control.ReplayPayload(control.Replay{SampleID: "sample_lookup", SampleSHA256: control.Digest([]byte("pcap")), SampleSize: 24, RuleMode: "registered"})
	id, err := m.SubmitLocal(payload, "local_lookup_request")
	if err != nil {
		t.Fatal(err)
	}
	before, err := m.Task(id)
	if err != nil || before.Origin != "local" || before.State != "running" || !before.RetentionProtected {
		t.Fatal("本地任务身份丢失", before, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		row, err := m.Task(id)
		if err != nil {
			t.Fatal(err)
		}
		if row.State == "succeeded" {
			if !row.Acknowledged || row.RetentionProtected || row.Origin != "local" {
				t.Fatal("本地终态确认语义错误", row)
			}
			pending, err := m.Pending()
			if err != nil || len(pending) != 0 {
				t.Fatal("本地详情读取产生平台回执", err)
			}
			if err := m.WAL.DB.View(func(tx *bolt.Tx) error {
				var task LocalTask
				if err := json.Unmarshal(tx.Bucket([]byte("sensor_tasks")).Get([]byte(id)), &task); err != nil {
					return err
				}
				if len(task.Command.Payload) != 0 && string(task.Command.Payload) != "null" {
					t.Fatal("完成本地重放仍保留执行载荷")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("本地详情未观察到实际执行终态")
}
