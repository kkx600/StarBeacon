package collectorupdate

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var fixedTime = time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)

func testKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, key
}

func testELF() []byte {
	raw := make([]byte, 40)
	copy(raw, []byte{0x7f, 'E', 'L', 'F', 2, 1})
	raw[18] = 62
	if runtime.GOARCH == "arm64" {
		raw[18] = 183
	}
	return raw
}

func checksum(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

type zipItem struct {
	name string
	raw  []byte
	mode os.FileMode
}

func items(generation int64) []zipItem {
	binary := testELF()
	binary[25] = byte(generation)
	m := manifest{SchemaVersion: 1, Version: "v0.1.0", Commit: strings.Repeat("a", 40), OS: "linux", Arch: runtime.GOARCH}
	m.Binaries = map[string]struct {
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	}{"starbeacon-agent": {SHA256: checksum(binary), Size: int64(len(binary))}}
	raw, _ := json.Marshal(m)
	return []zipItem{{"starbeacon-collector/bin/starbeacon-agent", binary, 0755}, {"starbeacon-collector/manifest.json", raw, 0644}, {"starbeacon-collector/www/index.html", []byte("<html>StarBeacon</html>"), 0644}}
}

func writeZIP(t *testing.T, key ed25519.PrivateKey, generation int64, entries []zipItem) (string, Envelope) {
	t.Helper()
	var buffer bytes.Buffer
	z := zip.NewWriter(&buffer)
	for _, item := range entries {
		header := &zip.FileHeader{Name: item.name, Method: zip.Deflate}
		header.SetMode(item.mode)
		file, err := z.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(item.raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	raw := buffer.Bytes()
	name := filepath.Join(t.TempDir(), "collector.zip")
	if err := os.WriteFile(name, raw, 0600); err != nil {
		t.Fatal(err)
	}
	p := Proof{SchemaVersion: 1, Generation: generation, Version: "v0.1.0", Commit: strings.Repeat("a", 40), Arch: runtime.GOARCH, SHA256: checksum(raw), Size: int64(len(raw)), DataSchema: 1, IssuedAt: fixedTime.Add(-time.Hour), ExpiresAt: fixedTime.Add(time.Hour)}
	e, err := Sign(p, key)
	if err != nil {
		t.Fatal(err)
	}
	return name, e
}

func TestSignedCollectorBundleAuthenticityBudgetAndPathBoundaries(t *testing.T) {
	pub, key := testKeys(t)
	archive, envelope := writeZIP(t, key, 1, items(1))
	root := t.TempDir()
	release, err := Stage(context.Background(), root, archive, envelope, pub, fixedTime)
	if err != nil || release.validate() != nil || release.Proof != envelope.Proof {
		t.Fatalf("签名制品不能暂存：%+v %v", release, err)
	}
	info, err := os.Stat(release.binary(root))
	if err != nil || info.Mode().Perm() != 0755 {
		t.Fatal("采集器执行权限不正确", err)
	}
	if _, err = Stage(context.Background(), root, archive, envelope, pub, fixedTime); err == nil {
		t.Fatal("重复版本目录被覆盖")
	}
	for name, mutate := range map[string]func(*Proof){
		"schema": func(p *Proof) { p.SchemaVersion = 2 }, "generation": func(p *Proof) { p.Generation = 0 },
		"version": func(p *Proof) { p.Version = "latest" }, "commit": func(p *Proof) { p.Commit = "head" },
		"arch": func(p *Proof) { p.Arch = "x86" }, "hash": func(p *Proof) { p.SHA256 = "invalid" },
		"size": func(p *Proof) { p.Size = MaxArchiveBytes + 1 }, "data_schema": func(p *Proof) { p.DataSchema = 2 },
		"time": func(p *Proof) { p.ExpiresAt = p.IssuedAt }, "time_budget": func(p *Proof) { p.ExpiresAt = p.IssuedAt.Add(31 * 24 * time.Hour) },
	} {
		t.Run(name, func(t *testing.T) {
			p := envelope.Proof
			mutate(&p)
			if _, err := Sign(p, key); err == nil {
				t.Fatal("接受无效签名参数")
			}
			if err := (Envelope{Proof: p}).Verify(pub, fixedTime); err == nil {
				t.Fatal("接受无效制品身份")
			}
		})
	}
	if _, err := Sign(envelope.Proof, nil); err == nil {
		t.Fatal("缺失私钥仍签发")
	}
	for _, now := range []time.Time{fixedTime.Add(-2 * time.Hour), fixedTime.Add(time.Hour)} {
		if err := envelope.Verify(pub, now); err == nil {
			t.Fatal("接受尚未生效或过期签名")
		}
	}
	other, _ := testKeys(t)
	if err := envelope.Verify(other, fixedTime); err == nil {
		t.Fatal("接受其他发布方")
	}
	for _, name := range []string{"starbeacon-collector/../escape", "/absolute", "starbeacon-collector/a\\b", "starbeacon-collector/a/./b"} {
		entries := append(items(2), zipItem{name, []byte("invalid"), 0644})
		archive, proof := writeZIP(t, key, 2, entries)
		if _, err := Stage(context.Background(), t.TempDir(), archive, proof, pub, fixedTime); err == nil {
			t.Fatal("接受越界文件", name)
		}
	}
	for name, entries := range map[string][]zipItem{
		"duplicate":        append(items(2), items(2)[0]),
		"symlink":          append(items(2), zipItem{"starbeacon-collector/www/link", []byte("/etc/passwd"), os.ModeSymlink | 0777}),
		"device":           append(items(2), zipItem{"starbeacon-collector/device", nil, os.ModeDevice | 0600}),
		"manifest_missing": {items(2)[0], items(2)[2]},
		"binary_missing":   {items(2)[1], items(2)[2]},
		"manifest_corrupt": {items(2)[0], {"starbeacon-collector/manifest.json", []byte("{"), 0644}},
		"file_parent":      append(items(2), zipItem{"starbeacon-collector/www/index.html/child", []byte("x"), 0644}),
	} {
		t.Run(name, func(t *testing.T) {
			archive, proof := writeZIP(t, key, 2, entries)
			if _, err := Stage(context.Background(), t.TempDir(), archive, proof, pub, fixedTime); err == nil {
				t.Fatal("接受无效 ZIP")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Stage(ctx, t.TempDir(), archive, envelope, pub, fixedTime); !errors.Is(err, context.Canceled) {
		t.Fatal("忽略取消", err)
	}
	if err := os.WriteFile(archive, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Stage(context.Background(), t.TempDir(), archive, envelope, pub, fixedTime); err == nil {
		t.Fatal("读取被替换的 ZIP")
	}
}

type fixtureRuntime struct {
	root       string
	calls      []string
	failStop   bool
	failStart  map[int64]bool
	failVerify map[int64]bool
}

func (r *fixtureRuntime) Prepare(context.Context, *Release) error { return nil }

func (r *fixtureRuntime) Stop(context.Context) error {
	r.calls = append(r.calls, "stop")
	if r.failStop {
		return errors.New("停止结果未知")
	}
	return nil
}
func (r *fixtureRuntime) Start(_ context.Context, v Release) error {
	r.calls = append(r.calls, "start")
	if err := BootGuard(r.root); err != nil {
		return err
	}
	if r.failStart[v.Proof.Generation] {
		return errors.New("启动失败")
	}
	return nil
}
func (r *fixtureRuntime) Verify(_ context.Context, v Release) error {
	r.calls = append(r.calls, "verify")
	if r.failVerify[v.Proof.Generation] {
		return errors.New("健康核对失败")
	}
	return nil
}

func managerFixture(t *testing.T) (*Manager, *fixtureRuntime, ed25519.PrivateKey) {
	t.Helper()
	pub, key := testKeys(t)
	root := t.TempDir()
	r := &fixtureRuntime{root: root, failStart: map[int64]bool{}, failVerify: map[int64]bool{}}
	m := &Manager{Root: root, Instance: "collector_test", Mode: "docker", BindingSHA256: strings.Repeat("a", 64), Key: pub, Runtime: r, RetentionDays: 180, Guard: func(context.Context) error { return nil }, Now: func() time.Time { return fixedTime }}
	return m, r, key
}

func applyFixture(t *testing.T, m *Manager, key ed25519.PrivateKey, generation, revision int64) State {
	t.Helper()
	name, proof := writeZIP(t, key, generation, items(generation))
	s, err := m.Apply(context.Background(), name, proof, "update_"+string(rune('a'+generation)), revision)
	if err != nil {
		t.Fatal(err, s)
	}
	return s
}

func TestCollectorMaintenanceInstallUpdateRollbackAndRequestIdentity(t *testing.T) {
	m, r, key := managerFixture(t)
	ctx := context.Background()
	name, proof := writeZIP(t, key, 1, items(1))
	s, err := m.Apply(ctx, name, proof, "request_initial", 0)
	if err != nil || s.Revision != 1 || s.MaxGeneration != 1 || s.Current == nil || s.Previous != nil || s.Operation.Phase != "committed" {
		t.Fatal(s, err)
	}
	if err := BootGuard(m.Root); err != nil {
		t.Fatal("已提交版本不可启动", err)
	}
	calls := len(r.calls)
	confirmed, err := m.Apply(ctx, name, proof, "request_initial", 0)
	if err != nil || confirmed.Revision != 1 || len(r.calls) != calls {
		t.Fatal("确认重复执行维护", confirmed, err)
	}
	proof.Proof.SHA256 = strings.Repeat("b", 64)
	if _, err := m.Apply(ctx, name, proof, "request_initial", 1); !errors.Is(err, ErrConflict) {
		t.Fatal("同键不同请求未冲突", err)
	}
	if _, err := m.Rollback(ctx, "rollback_none", 1); err == nil {
		t.Fatal("没有已核验前版本仍回退")
	}
	s = applyFixture(t, m, key, 2, 1)
	if s.Previous == nil || s.Previous.Proof.Generation != 1 || s.Current.Proof.Generation != 2 {
		t.Fatal(s)
	}
	rolled, err := m.Rollback(ctx, "rollback_first", 2)
	if err != nil || rolled.Revision != 3 || rolled.Current.Proof.Generation != 1 || rolled.Previous.Proof.Generation != 2 || rolled.MaxGeneration != 2 {
		t.Fatal(rolled, err)
	}
	calls = len(r.calls)
	if _, err := m.Rollback(ctx, "rollback_first", 0); err != nil || len(r.calls) != calls {
		t.Fatal("回退重试重复执行", err)
	}
	if _, err := m.Apply(ctx, name, proof, "request_downgrade", 3); !errors.Is(err, ErrConflict) {
		t.Fatal("回退后降低发布代次水位", err)
	}
	if _, err := m.Rollback(ctx, "rollback_other", 1); !errors.Is(err, ErrConflict) {
		t.Fatal("忽略 CAS", err)
	}
	lock, err := m.lock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Status(); err != nil {
		t.Fatal("只读维护状态被执行锁阻塞", err)
	}
	if _, err := m.Rollback(ctx, "concurrent_rollback", 3); !errors.Is(err, ErrConflict) {
		t.Fatal("维护锁允许并发写操作", err)
	}
	lock.Close()
	if state, err := m.Status(); err != nil || state.Revision != 3 {
		t.Fatal(state, err)
	}
}

func TestCollectorMaintenanceFailureRestorationAndCrashRecovery(t *testing.T) {
	for _, failure := range []string{"health", "start", "guard", "stop", "restore_start", "restore_health"} {
		t.Run(failure, func(t *testing.T) {
			m, r, key := managerFixture(t)
			applyFixture(t, m, key, 1, 0)
			switch failure {
			case "health":
				r.failVerify[2] = true
			case "start":
				r.failStart[2] = true
			case "guard":
				m.Guard = func(context.Context) error { return errors.New("仍有有效租约") }
			case "stop":
				r.failStop = true
			case "restore_start":
				r.failStart[1], r.failVerify[2] = true, true
			case "restore_health":
				r.failVerify[1], r.failVerify[2] = true, true
			}
			name, proof := writeZIP(t, key, 2, items(2))
			s, err := m.Apply(context.Background(), name, proof, "request_failure", 1)
			if err == nil || s.Current == nil || s.Current.Proof.Generation != 1 || s.MaxGeneration != 2 {
				t.Fatal("失败被标记为成功", s, err)
			}
			unconfirmed := failure == "stop" || strings.HasPrefix(failure, "restore_")
			if unconfirmed {
				if s.Operation.Phase != "unknown" || s.Operation.FinishedAt != nil || !errors.Is(BootGuard(m.Root), ErrRecoveryRequired) {
					t.Fatal("未核实状态允许自动启动", s)
				}
				if _, err := m.Apply(context.Background(), name, proof, "request_blocked", 1); !errors.Is(err, ErrRecoveryRequired) {
					t.Fatal("中断后继续写新升级", err)
				}
				r.failStop = false
				r.failStart, r.failVerify = map[int64]bool{}, map[int64]bool{}
				m.Guard = func(context.Context) error { return nil }
				resumed := *m
				s, err = resumed.Recover(context.Background())
				if err != nil || s.Operation.Phase != "restored" || s.Operation.FinishedAt == nil || s.Operation.Code != "execution_interrupted" {
					t.Fatal("中断恢复缺少明确核验结果", s, err)
				}
			} else if s.Operation.Phase != "restored" || s.Operation.FinishedAt == nil {
				t.Fatal("失败没有恢复前版本", s)
			}
			if err := BootGuard(m.Root); err != nil {
				t.Fatal("恢复后不能启动前版本", err)
			}
			if _, err := m.Apply(context.Background(), name, proof, "request_failure", 1); err == nil {
				t.Fatal("原失败请求被确认成功")
			}
			if _, err := m.Recover(context.Background()); err != nil {
				t.Fatal("重复恢复应只读", err)
			}
		})
	}
}

func TestCollectorMaintenanceStateBindingCancellationAndInstalledBytes(t *testing.T) {
	m, _, key := managerFixture(t)
	s := applyFixture(t, m, key, 1, 0)
	for _, mutate := range []func(*State){
		func(s *State) { s.Instance = "other" }, func(s *State) { s.Mode = "systemd" }, func(s *State) { s.SchemaVersion = 2 },
		func(s *State) { s.MaxGeneration = 0 }, func(s *State) { s.Current.Directory = "../../escape" },
		func(s *State) { s.Operation.Phase = "unrecognized" }, func(s *State) { s.Operation.FinishedAt = nil },
		func(s *State) { s.Operation.Kind = "shell" }, func(s *State) { s.Operation.ID = "../x" },
		func(s *State) { s.Operation.RetainUntil = s.Operation.StartedAt },
	} {
		raw, _ := json.Marshal(s)
		var changed State
		json.Unmarshal(raw, &changed)
		mutate(&changed)
		if err := m.save(changed); err != nil {
			t.Fatal(err)
		}
		if _, err := m.Status(); err == nil {
			t.Fatal("接受不匹配的持久状态", changed)
		}
	}
	if err := m.save(s); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	name, proof := writeZIP(t, key, 2, items(2))
	if _, err := m.Apply(ctx, name, proof, "cancelled_update", 1); !errors.Is(err, context.Canceled) {
		t.Fatal("忽略取消", err)
	}
	if _, err := m.Rollback(ctx, "../escape", 1); !errors.Is(err, ErrConflict) {
		t.Fatal("非法任务身份", err)
	}
	if err := os.WriteFile(s.Current.binary(m.Root), []byte("invalid"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := BootGuard(m.Root); err == nil {
		t.Fatal("启动已更改的程序")
	}
	for _, mutate := range []func(*Manager){func(m *Manager) { m.Root = "/" }, func(m *Manager) { m.Instance = "../bad" }, func(m *Manager) { m.Runtime = nil }, func(m *Manager) { m.Guard = nil }, func(m *Manager) { m.RetentionDays = 0 }} {
		bad := *m
		mutate(&bad)
		if _, err := bad.Status(); err == nil {
			t.Fatal("接受无效部署配置")
		}
	}
}

func TestCollectorBundleRejectsCorruptionAndDeclaredExpansionBudget(t *testing.T) {
	pub, key := testKeys(t)
	for _, reason := range []string{"binary_hash", "binary_size", "elf", "manifest_identity", "checksum", "zip", "expansion"} {
		t.Run(reason, func(t *testing.T) {
			entries := items(1)
			switch reason {
			case "binary_hash":
				entries[0].raw[22]++
			case "binary_size":
				entries[0].raw = append(entries[0].raw, 1)
			case "elf":
				entries[0].raw[0] = 0
				var m manifest
				json.Unmarshal(entries[1].raw, &m)
				v := m.Binaries["starbeacon-agent"]
				v.SHA256 = checksum(entries[0].raw)
				m.Binaries["starbeacon-agent"] = v
				entries[1].raw, _ = json.Marshal(m)
			case "manifest_identity":
				entries[1].raw = bytes.ReplaceAll(entries[1].raw, []byte("linux"), []byte("other"))
			}
			archive, proof := writeZIP(t, key, 1, entries)
			if reason == "checksum" {
				proof.Proof.SHA256 = strings.Repeat("f", 64)
				proof, _ = Sign(proof.Proof, key)
			}
			if reason == "zip" || reason == "expansion" {
				raw, _ := os.ReadFile(archive)
				if reason == "zip" {
					raw[0] = 'x'
				} else {
					offset := bytes.Index(raw, []byte{0x50, 0x4b, 0x01, 0x02})
					binary.LittleEndian.PutUint32(raw[offset+24:offset+28], 129<<20)
				}
				os.WriteFile(archive, raw, 0600)
				proof.Proof.SHA256 = checksum(raw)
				proof, _ = Sign(proof.Proof, key)
			}
			if _, err := Stage(context.Background(), t.TempDir(), archive, proof, pub, fixedTime); err == nil {
				t.Fatal("接受损坏制品")
			}
		})
	}
}
