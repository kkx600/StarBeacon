package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/application"
	"github.com/kkx600/StarBeacon/internal/control"
	bolt "go.etcd.io/bbolt"
)

func applicationTestCommand(id string, state application.State, host string) control.Command {
	d := application.Definition{SchemaVersion: application.Schema, ProductID: "owned_files", ProductName: "业务文件服务", CategoryID: "cloud_storage", Protocols: []string{"http", "tls"}, Any: []application.Condition{{Field: "http.host", Op: "domain_suffix", Value: host}, {Field: "tls.sni", Op: "eq", Value: host}}, All: []application.Condition{}, Exclude: []application.Condition{}}
	versions := []application.Version{{ID: "app_files", Revision: 1, Definition: d}}
	p := application.Package{SchemaVersion: application.PackageSchema, DeploymentInput: application.DeploymentInput{ExpectedRegistrationID: "reg_a", ExpectedStateSHA256: state.StateSHA256, RulesSHA256: application.Digest(versions)}, Versions: versions}
	raw, _ := json.Marshal(p)
	now := time.Now().UTC()
	return control.Command{ID: id, TenantID: "tenant_a", SensorID: "sensor_a", RegistrationID: "reg_a", Kind: "applications.apply", IssuedAt: now, ExpiresAt: now.Add(time.Minute), Payload: raw}
}

func TestApplicationDeploymentHistoryAllowsFollowingSignedTasks(t *testing.T) {
	w, err := OpenWAL(filepath.Join(t.TempDir(), "wal.db"), "tenant_a", "sensor_a", "reg_a", 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	s, err := NewApplicationService(w)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewTaskManager(w, pub, &Engine{WAL: w, Applications: s})
	if err != nil {
		t.Fatal(err)
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
	install := applicationTestCommand("application_history", s.Snapshot(), "files.example")
	diagnostic := install
	diagnostic.ID, diagnostic.Kind, diagnostic.Payload = "task_after_application", "diagnostics", json.RawMessage(`{}`)
	for _, command := range []control.Command{install, diagnostic} {
		raw, signature, err := control.Encode(command, priv)
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Accept(raw, signature); err != nil {
			t.Fatal("已安装的应用档案阻断后续任务", err)
		}
		deadline := time.Now().Add(2 * time.Second)
		var terminal []byte
		for time.Now().Before(deadline) {
			pending, err := m.Pending()
			if err != nil {
				t.Fatal(err)
			}
			for _, receipt := range pending {
				var r control.Receipt
				if json.Unmarshal(receipt, &r) == nil && r.CommandID == command.ID && r.State != "running" {
					if r.State != "succeeded" {
						t.Fatal("签名任务未完成", r.State, r.Code)
					}
					terminal = receipt
				}
			}
			if terminal != nil {
				break
			}
			time.Sleep(time.Millisecond)
		}
		if terminal == nil {
			t.Fatal("签名任务未产生完成回执")
		}
		if err := m.Confirm(command.ID, control.HashBytes(terminal)); err != nil {
			t.Fatal(err)
		}
		row, err := m.Task(command.ID)
		if err != nil || row.Kind != command.Kind || row.State != "succeeded" || !row.Acknowledged {
			t.Fatal("确认后的任务档案无法查询", row, err)
		}
	}
	if err := m.Sweep(context.Background()); err != nil || s.Snapshot().DeploymentID != install.ID {
		t.Fatal("任务维护损坏当前应用配置", err)
	}
	rows, err := m.List()
	if err != nil || len(rows) != 2 {
		t.Fatal("连续任务档案缺失", rows, err)
	}
}

func TestApplicationDeploymentCASRestartAndFrozenWAL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wal.db")
	w, err := OpenWAL(path, "tenant_a", "sensor_a", "reg_a", 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	s, err := NewApplicationService(w)
	if err != nil {
		t.Fatal(err)
	}
	if s.Snapshot() != application.EmptyState() || w.DB.NoSync {
		t.Fatal("初始状态或耐久级别不一致")
	}
	if raw, err := s.Attribute([]byte(`{}`), time.Now()); err != nil || len(raw) != 0 {
		t.Fatal("未配置仍分类")
	}
	c := applicationTestCommand("deployment_first", s.Snapshot(), "files.example")
	raw, code, err := s.Apply(context.Background(), c)
	if err != nil || code != "" {
		t.Fatal(code, err)
	}
	var installed application.State
	if json.Unmarshal(raw, &installed) != nil || installed.Validate() != nil || installed.RuleCount != 1 {
		t.Fatal("安装回执缺失")
	}
	copyState := s.Snapshot()
	*copyState.InstalledAt = time.Time{}
	if s.Snapshot().InstalledAt.IsZero() {
		t.Fatal("快照被外部修改")
	}
	duplicate, _, err := s.Apply(context.Background(), c)
	if err != nil || string(duplicate) != string(raw) {
		t.Fatal("原任务未返回原安装结果", err)
	}
	changed := c
	changed.ExpiresAt = changed.ExpiresAt.Add(time.Second)
	if _, code, err := s.Apply(context.Background(), changed); err == nil || code != "application_state_conflict" {
		t.Fatal("任务标识未绑定完整参数")
	}
	eve := []byte(`{"timestamp":"` + time.Now().UTC().Format(time.RFC3339Nano) + `","event_type":"http","flow_id":42,"http":{"hostname":"files.example","http_method":"GET","url":"/documents"}}`)
	evePath := filepath.Join(dir, "eve.json")
	if err := os.WriteFile(evePath, append(eve, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	reader := &EVEReader{WAL: w, Path: evePath, Attribute: s.Attribute, Route: func(context.Context, string) (string, error) { return "route_owned", nil }}
	if err := reader.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := w.Next("context")
	if err != nil || len(b.Records) != 1 || string(b.Records[0].Payload) != string(eve) {
		t.Fatal("原始 EVE 被改写", err)
	}
	a, err := application.ReadAttribution(b.Records[0].ApplicationJson)
	if err != nil || a.DeploymentID != c.ID || a.ProductID != "owned_files" || a.Result.Status != "candidate" {
		t.Fatal("实际元数据分类未持久保存", err)
	}
	oldMetadata := string(b.Records[0].ApplicationJson)
	first := applicationTestCommand("deployment_second", s.Snapshot(), "other.example")
	second := applicationTestCommand("deployment_conflict", s.Snapshot(), "third.example")
	var wg sync.WaitGroup
	success := make(chan bool, 2)
	for _, command := range []control.Command{first, second} {
		wg.Go(func() {
			_, code, err := s.Apply(context.Background(), command)
			if err != nil && code != "application_state_conflict" {
				t.Error(code, err)
			}
			success <- err == nil
		})
	}
	wg.Wait()
	close(success)
	count := 0
	for ok := range success {
		if ok {
			count++
		}
	}
	if count != 1 {
		t.Fatal("并发发布覆盖了状态")
	}
	next := s.Snapshot()
	b, err = w.Next("context")
	if err != nil || string(b.Records[0].ApplicationJson) != oldMetadata {
		t.Fatal("规则变更重新归因旧 WAL", err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	w, err = OpenWAL(path, "tenant_a", "sensor_a", "reg_a", 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := NewApplicationService(w)
	if err != nil || restored.Snapshot().StateSHA256 != next.StateSHA256 {
		t.Fatal("重启未恢复原快照", err)
	}
	b, err = w.Next("context")
	if err != nil || string(b.Records[0].ApplicationJson) != oldMetadata {
		t.Fatal("重启改写了待传分类", err)
	}
	metadata, err := restored.Attribute(eve, time.Now().UTC())
	a, _ = application.ReadAttribution(metadata)
	if err != nil || a.Result.Status != "unknown" {
		t.Fatal("当前快照与新事件未绑定", err)
	}
}

func TestApplicationDeploymentFailuresDoNotChangeActiveSnapshot(t *testing.T) {
	w, err := OpenWAL(filepath.Join(t.TempDir(), "wal.db"), "tenant_a", "sensor_a", "reg_a", 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	s, err := NewApplicationService(w)
	if err != nil {
		t.Fatal(err)
	}
	c := applicationTestCommand("deployment_owned", s.Snapshot(), "files.example")
	for _, change := range []func(*control.Command){func(c *control.Command) { c.Kind = "diagnostics" }, func(c *control.Command) { c.TenantID = "foreign" }, func(c *control.Command) { c.Payload = json.RawMessage(`{}`) }, func(c *control.Command) { c.ExpiresAt = time.Now().Add(-time.Second) }, func(c *control.Command) {
		c.IssuedAt = time.Now().Add(2 * time.Minute)
		c.ExpiresAt = c.IssuedAt.Add(time.Minute)
	}} {
		bad := c
		change(&bad)
		if _, _, err := s.Apply(context.Background(), bad); err == nil || s.Snapshot() != application.EmptyState() {
			t.Fatal("失败任务改变了分类状态")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, code, err := s.Apply(ctx, c); err == nil || code != "application_apply_cancelled" {
		t.Fatal("取消任务未拒绝")
	}
	engine := &Engine{WAL: w}
	if _, code, err := engine.Execute(context.Background(), c); err == nil || code != "application_service_unavailable" {
		t.Fatal("不可用能力执行成功")
	}
	engine.Applications = s
	found := false
	for _, capability := range engine.Capabilities() {
		found = found || capability == "applications.apply"
	}
	if !found {
		t.Fatal("运行能力未声明")
	}
	if _, code, err := engine.Execute(context.Background(), c); err != nil || code != "" {
		t.Fatal(code, err)
	}
	if _, err := s.Attribute([]byte(`{`), time.Now()); err != nil {
		t.Fatal("原始损坏 JSON 被分类服务阻塞")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewApplicationService(w); err == nil {
		t.Fatal("关闭存储被当作空规则")
	}
	c = applicationTestCommand("deployment_storage", s.Snapshot(), "other.example")
	if _, code, err := s.Apply(context.Background(), c); err == nil || code != "application_storage_unavailable" {
		t.Fatal("存储失败被隐瞒", code, err)
	}
}

func TestApplicationRestoreRejectsCorruptIdentityAndBindings(t *testing.T) {
	for _, mode := range []string{"json", "identity", "hash", "state", "package"} {
		t.Run(mode, func(t *testing.T) {
			w, err := OpenWAL(filepath.Join(t.TempDir(), "wal.db"), "tenant_a", "sensor_a", "reg_a", 4*1024*1024)
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			s, err := NewApplicationService(w)
			if err != nil {
				t.Fatal(err)
			}
			c := applicationTestCommand("deployment_owned", s.Snapshot(), "files.example")
			if _, _, err := s.Apply(context.Background(), c); err != nil {
				t.Fatal(err)
			}
			if err := w.DB.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte("local_config"))
				var record applicationInstalled
				raw := b.Get([]byte("application_rules"))
				if mode == "json" {
					return b.Put([]byte("application_rules"), []byte(`{`))
				}
				if err := json.Unmarshal(raw, &record); err != nil {
					return err
				}
				switch mode {
				case "identity":
					record.Command.SensorID = "foreign"
				case "hash":
					record.SHA256 = ""
				case "state":
					record.State.RuleCount = 0
				case "package":
					record.State.RulesSHA256 = application.Digest([]application.Version{})
					record.State.StateSHA256 = application.StateDigest(record.State.DeploymentID, record.State.RulesSHA256)
				}
				encoded, err := json.Marshal(record)
				if err != nil {
					return err
				}
				return b.Put([]byte("application_rules"), encoded)
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := NewApplicationService(w); err == nil {
				t.Fatal("损坏的配置被继续使用")
			}
		})
	}
}
