package collectorupdate

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/response"
	bolt "go.etcd.io/bbolt"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	base := t.TempDir()
	return Config{SchemaVersion: 1, Instance: "collector_test", Mode: "systemd", Root: filepath.Join(base, "program"), DataDir: filepath.Join(base, "data"), ConfigDir: filepath.Join(base, "config"), PublicKey: filepath.Join(base, "release.pub"), UID: 65532, GID: 65532, ReadyURL: "https://127.0.0.1:28081/readyz", ReadyCA: filepath.Join(base, "config/ca.crt")}
}

func TestCollectorDeploymentConfigurationAndServiceIsolation(t *testing.T) {
	c := testConfig(t)
	if err := c.Validate(); err != nil || c.RetentionDays != 180 {
		t.Fatal(c, err)
	}
	unit, err := c.Unit()
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"User=65532", "CapabilityBoundingSet=CAP_NET_RAW", "AmbientCapabilities=CAP_NET_RAW", "NoNewPrivileges=yes", "ProtectSystem=strict", "KillMode=control-group", "maintenance-boot", "TasksMax=512", "UMask=0077"} {
		if !strings.Contains(unit, required) {
			t.Fatal("缺少服务隔离", required)
		}
	}
	for name, mutate := range map[string]func(*Config){
		"identity": func(c *Config) { c.Instance = "../../other" }, "uid": func(c *Config) { c.UID = 0 },
		"gid": func(c *Config) { c.GID = 0 }, "schema": func(c *Config) { c.SchemaVersion = 2 },
		"retention": func(c *Config) { c.RetentionDays = 3651 }, "mode": func(c *Config) { c.Mode = "shell" },
		"path": func(c *Config) { c.Root = "/opt/a b" }, "root": func(c *Config) { c.Root = "/" },
		"parent": func(c *Config) { c.Root += "/../invalid" }, "overlap": func(c *Config) { c.DataDir = c.Root + "/data" },
		"same_path": func(c *Config) { c.ConfigDir = c.DataDir }, "query": func(c *Config) { c.ReadyURL += "?token=x" },
		"public_health": func(c *Config) { c.ReadyURL = "http://192.0.2.1:8080/readyz" }, "dns_health": func(c *Config) { c.ReadyURL = "http://localhost:8080/readyz" },
		"password_health": func(c *Config) { c.ReadyURL = "http://admin:password@127.0.0.1:8080/readyz" }, "http": func(c *Config) { c.ReadyURL = "http://127.0.0.1:8080/readyz" },
		"health_path": func(c *Config) { c.ReadyURL = "http://127.0.0.1:8080/" }, "fragment": func(c *Config) { c.ReadyURL += "#x" },
		"host_docker": func(c *Config) { c.DockerImage = "sha256:" + strings.Repeat("a", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := c
			mutate(&bad)
			if err := bad.Validate(); err == nil {
				t.Fatal("接受无效部署配置")
			}
			if _, err := bad.Unit(); err == nil {
				t.Fatal("无效配置仍生成主机服务")
			}
		})
	}
	c.Mode = "docker"
	c.DockerImage, c.DockerNetwork = "sha256:"+strings.Repeat("a", 64), "none"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Unit(); err == nil {
		t.Fatal("容器配置生成主机服务")
	}
	for _, image := range []string{"latest", "registry/image:tag", "sha256:bad"} {
		bad := c
		bad.DockerImage = image
		if err := bad.Validate(); err == nil {
			t.Fatal("接受可变镜像")
		}
	}
	c.DockerNetwork = "container:other"
	if err := c.Validate(); err == nil {
		t.Fatal("接管其他容器网络命名空间")
	}
}

func TestCollectorServiceRuntimeFixedCommandsAndOwnership(t *testing.T) {
	ctx := context.Background()
	pub, key := testKeys(t)
	c := testConfig(t)
	archive, proof := writeZIP(t, key, 1, items(1))
	release, err := Stage(ctx, c.Root, archive, proof, pub, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	r := &ServiceRuntime{Config: c, run: func(_ context.Context, program string, args ...string) ([]byte, error) {
		if program != "/usr/bin/systemctl" {
			t.Fatal("执行了非固定管理程序", program)
		}
		calls = append(calls, args)
		if args[0] == "show" {
			return []byte("0\n"), nil
		}
		return nil, nil
	}}
	if err := r.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := r.Prepare(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(ctx, release); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 4 || calls[0][0] != "stop" || calls[0][1] != "starbeacon-agent-collector_test.service" {
		t.Fatal(calls)
	}
	if err := r.observe(ctx, release); err == nil {
		t.Fatal("无实际主机 PID 仍确认成功")
	}
	c.Mode, c.DockerImage, c.DockerNetwork = "docker", "sha256:"+strings.Repeat("a", 64), "none"
	r.Config = c
	containerPresent := false
	fail := ""
	r.run = func(_ context.Context, program string, args ...string) ([]byte, error) {
		if program != "/usr/bin/docker" {
			t.Fatal("执行了非固定容器管理程序")
		}
		calls = append(calls, args)
		if len(args) == 0 || args[0] == fail {
			return nil, errors.New("管理失败")
		}
		switch args[0] {
		case "image":
			return []byte(`{"/var/lib/engine":{}}`), nil
		case "container":
			if containerPresent {
				return []byte("aabbccddee00\n"), nil
			}
			return nil, nil
		case "inspect":
			if strings.Contains(args[2], ".Config.Labels") {
				return []byte("collector_test"), nil
			}
			return []byte("true true true\n"), nil
		case "exec":
			if args[len(args)-1] == "--version" {
				return []byte("StarBeacon agent v0.1.0 (" + strings.Repeat("a", 40) + ")"), nil
			}
			return nil, nil
		case "run":
			joined := strings.Join(args, " ")
			for _, item := range []string{"--init", "--read-only", "--pids-limit=512", "--cap-drop=ALL", "--cap-add=NET_RAW", "--security-opt=no-new-privileges:true", "--pull=never", "--user 0:0", "maintenance-run", "readonly"} {
				if !strings.Contains(joined, item) {
					t.Fatal("容器缺少限制", item)
				}
			}
			if !strings.Contains(joined, "type=volume,dst=/var/lib/engine,readonly") {
				t.Fatal("镜像声明的卷仍可隐式写入")
			}
			if strings.Contains(joined, "docker.sock") || strings.Contains(joined, "--privileged") || strings.Contains(joined, "NET_ADMIN") {
				t.Fatal("采集器取得宿主维护权限")
			}
			containerPresent = true
		case "rm":
			if len(args) != 3 || args[1] != "--volumes" {
				t.Fatal("专属匿名卷没有随受管容器回收")
			}
			containerPresent = false
		}
		return nil, nil
	}
	if err := r.Stop(ctx); err != nil {
		t.Fatal("不存在的专属容器无法安装", err)
	}
	if err := r.Prepare(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(ctx, release); err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(ctx, release); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(ctx, release); err == nil {
		t.Fatal("覆盖已经存在的容器")
	}
	if r.Prepare(ctx, nil) == nil || r.Prepare(ctx, &release) == nil {
		t.Fatal("首次安装接管既有容器或信任没有 journal 的程序")
	}
	if err := r.Stop(ctx); err != nil || containerPresent {
		t.Fatal(err)
	}
	for _, command := range []string{"container", "run", "inspect", "stop", "rm", "exec"} {
		fail = command
		containerPresent = command != "run"
		if command == "run" {
			if err := r.Start(ctx, release); err == nil {
				t.Fatal("忽略启动失败")
			}
		} else if command == "exec" {
			if err := r.observe(ctx, release); err == nil {
				t.Fatal("忽略回读失败")
			}
		} else if err := r.Stop(ctx); err == nil {
			t.Fatal("忽略停止或归属失败", command)
		}
	}
	r.run = func(context.Context, string, ...string) ([]byte, error) { return []byte("foreign_container"), nil }
	if _, err := r.container(ctx); err == nil {
		t.Fatal("接管无法唯一识别的容器")
	}
	step := 0
	r.run = func(context.Context, string, ...string) ([]byte, error) {
		step++
		if step == 1 {
			return []byte("aabbccddee00"), nil
		}
		return []byte("foreign_owner"), nil
	}
	if err := r.Stop(ctx); err == nil || step != 2 {
		t.Fatal("删除了其他实例的同名容器")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := r.Verify(cancelled, release); err == nil {
		t.Fatal("取消后的回读被视为成功")
	}
	r.Config.Mode = "unsupported"
	if r.Start(ctx, release) == nil || r.Stop(ctx) == nil || r.Verify(ctx, release) == nil {
		t.Fatal("未验证运行配置")
	}
	if r.Prepare(ctx, nil) == nil {
		t.Fatal("未验证准备配置")
	}
}

func TestCollectorNativeCommandBoundariesAndReadiness(t *testing.T) {
	ctx := context.Background()
	if _, err := command(ctx, "/usr/bin/true"); err != nil {
		t.Fatal(err)
	}
	if _, err := command(ctx, "/usr/bin/false"); err == nil {
		t.Fatal("忽略退出失败")
	}
	if (&ServiceRuntime{}).runner() == nil {
		t.Fatal("缺少实际命令执行器")
	}
	var output limitedOutput
	if n, err := output.Write([]byte("ok")); err != nil || n != 2 {
		t.Fatal(err)
	}
	if _, err := output.Write(make([]byte, 64<<10)); err == nil {
		t.Fatal("管理输出没有预算")
	}
	status := 200
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
	address := server.URL + "/readyz"
	if err := Probe(ctx, address); err != nil {
		t.Fatal(err)
	}
	status = 503
	if err := Probe(ctx, address); err == nil {
		t.Fatal("未就绪误报健康")
	}
	status = 302
	if err := Probe(ctx, address); err == nil {
		t.Fatal("就绪重定向被接受")
	}
	server.Close()
	if Probe(ctx, address) == nil || Probe(ctx, "https://127.0.0.1:443/readyz") == nil {
		t.Fatal("错误就绪地址被接受")
	}
}

func newGuardWAL(t *testing.T) (string, *bolt.DB) {
	t.Helper()
	directory := t.TempDir()
	db, err := bolt.Open(filepath.Join(directory, "agent.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range []string{"meta", "alerts", "context", "sensor_tasks", "response_leases"} {
			if _, err := tx.CreateBucket([]byte(name)); err != nil {
				return err
			}
		}
		meta := tx.Bucket([]byte("meta"))
		for key, value := range map[string][]byte{"identity": []byte("tenant_local/sensor_local/registration_local"), "epoch": []byte("wal_local"), "pending_count": make([]byte, 8)} {
			if err := meta.Put([]byte(key), value); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return directory, db
}

func TestCollectorMaintenanceProtectsWALTasksAndRevocationResponsibility(t *testing.T) {
	ctx := context.Background()
	if err := GuardData(ctx, t.TempDir()); err != nil {
		t.Fatal("首次安装无 WAL", err)
	}
	for _, kind := range []string{"valid", "active", "pending", "unknown", "expired", "revoked", "running_task", "unknown_task", "bad_task", "count_mismatch", "bad_identity", "journal", "metadata_missing"} {
		t.Run(kind, func(t *testing.T) {
			directory, db := newGuardWAL(t)
			err := db.Update(func(tx *bolt.Tx) error {
				switch kind {
				case "active", "pending", "unknown", "expired", "revoked":
					a := response.Action{SchemaVersion: response.ActionSchema, ConnectorID: "connector_test", ConfigSHA256: strings.Repeat("a", 64), DeviceID: "device_test", LeaseID: "lease_test", OwnerSHA256: response.Owner("tenant_local", "sensor_local", "registration_local", "lease_test"), TargetIP: "198.51.100.10", RequestedAt: fixedTime, ExpiresAt: fixedTime.Add(time.Minute), Reason: "维护准入验证"}
					checked := fixedTime.Add(2 * time.Minute)
					result := response.Result{SchemaVersion: "response.result.v1", ConnectorID: a.ConnectorID, ConfigSHA256: a.ConfigSHA256, Verified: true, Effect: "not_observed", Observation: response.Lease{SchemaVersion: response.LeaseSchema, DeviceID: a.DeviceID, LeaseID: a.LeaseID, OwnerSHA256: a.OwnerSHA256, TargetIP: a.TargetIP, ExpiresAt: a.ExpiresAt, State: kind, ObservedAt: checked}}
					raw, _ := json.Marshal(map[string]any{"action": a, "result": result, "status": kind, "checked_at": checked, "retain_until": fixedTime.AddDate(0, 0, 180)})
					return tx.Bucket([]byte("response_leases")).Put([]byte("lease_test"), raw)
				case "running_task", "unknown_task", "bad_task":
					state := strings.TrimSuffix(kind, "_task")
					return tx.Bucket([]byte("sensor_tasks")).Put([]byte("task_test"), []byte(`{"receipt":{"state":"`+state+`"}}`))
				case "count_mismatch":
					return tx.Bucket([]byte("alerts")).Put([]byte("event"), []byte("bytes"))
				case "bad_identity":
					return tx.Bucket([]byte("meta")).Put([]byte("identity"), []byte("//"))
				case "metadata_missing":
					return tx.DeleteBucket([]byte("meta"))
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			db.Close()
			if kind == "journal" {
				os.WriteFile(filepath.Join(directory, "rule-transaction.json"), []byte("{}"), 0600)
			}
			before, _ := fileDigest(filepath.Join(directory, "agent.db"))
			err = GuardData(ctx, directory)
			pass := kind == "valid" || kind == "expired" || kind == "revoked"
			if (err == nil) != pass {
				t.Fatal("维护准入结果错误", kind, err)
			}
			after, _ := fileDigest(filepath.Join(directory, "agent.db"))
			if before != after {
				t.Fatal("维护检查修改了业务数据")
			}
		})
	}
	directory, db := newGuardWAL(t)
	defer db.Close()
	if GuardData(ctx, directory) == nil {
		t.Fatal("运行中 WAL 被绕过")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if !errors.Is(GuardData(cancelled, directory), context.Canceled) {
		t.Fatal("忽略维护取消")
	}
	other := t.TempDir()
	if err := os.Mkdir(filepath.Join(other, "agent.db"), 0700); err != nil {
		t.Fatal(err)
	}
	if GuardData(ctx, other) == nil {
		t.Fatal("接受非普通 WAL")
	}
}

func TestCollectorOfflineSigningKeysAndEnvironment(t *testing.T) {
	pub, key := testKeys(t)
	base := t.TempDir()
	private, public := filepath.Join(base, "release.key"), filepath.Join(base, "release.pub")
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	privateRaw := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	publicRaw := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	os.WriteFile(private, privateRaw, 0600)
	os.WriteFile(public, publicRaw, 0644)
	actual, err := publicKey(public)
	if err != nil || !bytes.Equal(actual, pub) {
		t.Fatal(err)
	}
	archive, _ := writeZIP(t, key, 1, items(1))
	var out bytes.Buffer
	args := []string{"sign", "--archive", archive, "--key", private, "--generation", "1", "--version", "v0.1.0", "--commit", strings.Repeat("a", 40)}
	if err := CLI(context.Background(), args, &out, &out); err != nil {
		t.Fatal(err)
	}
	var proof Envelope
	if err := json.Unmarshal(out.Bytes(), &proof); err != nil || proof.Verify(pub, time.Now().UTC()) != nil {
		t.Fatal("签名 CLI 未生成可核验制品", err)
	}
	for _, args := range [][]string{nil, {"sign", "--unknown"}, {"status", "extra"}, {"sign", "--key", private}, {"status", "--config", "/does/not/exist"}} {
		if err := CLI(context.Background(), args, &out, &out); err == nil {
			t.Fatal("接受无效 CLI", args)
		}
	}
	for _, raw := range [][]byte{[]byte("invalid"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("invalid")}), append(publicRaw, []byte("trailing")...)} {
		os.WriteFile(public, raw, 0644)
		if _, err := publicKey(public); err == nil {
			t.Fatal("接受无效发布公钥")
		}
	}
	for _, raw := range [][]byte{[]byte("invalid"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("invalid")}), append(privateRaw, []byte("trailing")...)} {
		os.WriteFile(private, raw, 0600)
		if signArchive(archive, private, proof.Proof, &out) == nil {
			t.Fatal("接受无效发布私钥")
		}
	}
	os.WriteFile(private, privateRaw, 0644)
	os.Chmod(private, 0644)
	if signArchive(archive, private, proof.Proof, &out) == nil {
		t.Fatal("接受可被其他用户读取的私钥")
	}
	if trustedFile(base) == nil || trustedFile("/does/not/exist") == nil {
		t.Fatal("非文件或缺失密钥被接受")
	}
	c := testConfig(t)
	os.MkdirAll(c.ConfigDir, 0755)
	os.MkdirAll(c.DataDir, 0700)
	valid := "SB_MODE=production\nSB_STATE_PATH=" + filepath.Join(c.DataDir, "agent.db") + "\nSB_LOCAL_PASSWORD_FILE=" + filepath.Join(c.ConfigDir, "password") + "\n"
	for _, value := range []string{valid, valid + "SB_MODE=production\n", strings.ReplaceAll(valid, "production", "development"), strings.ReplaceAll(valid, "agent.db", "other.db"), valid + "SB_VALUE=$(id)\n", valid + "FOREIGN=value\n", valid + "SB_BAD NAME=value\n", valid + "SB_QUOTED=\"value\"\n", "SB_MODE=production\n"} {
		os.WriteFile(filepath.Join(c.ConfigDir, "agent.env"), []byte(value), 0600)
		if err := validateDirectories(c); (err == nil) != (value == valid) {
			t.Fatal(value, err)
		}
	}
	if _, err := fileDigest("/does/not/exist"); err == nil {
		t.Fatal("缺失文件仍返回摘要")
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		if CLI(context.Background(), []string{"render-unit", "--config", public}, &out, &out) == nil {
			t.Fatal("非设备管理员执行主机维护")
		}
	}
}

func TestCollectorRuntimeImageVolumesCannotShadowManagedState(t *testing.T) {
	c := testConfig(t)
	c.Mode, c.DockerImage, c.DockerNetwork = "docker", "sha256:"+strings.Repeat("a", 64), "none"
	r := &ServiceRuntime{Config: c}
	for _, target := range []string{"/", c.DataDir, c.DataDir + "/nested", filepath.Dir(c.DataDir), "/tmp/work", "/proc/sys", "/dev/device", "/path,option=bad", "/x/../escape"} {
		r.run = func(context.Context, string, ...string) ([]byte, error) {
			return json.Marshal(map[string]any{target: map[string]any{}})
		}
		if _, err := r.imageVolumes(context.Background()); err == nil {
			t.Fatal("镜像卷可以遮蔽受管路径", target)
		}
	}
	for _, raw := range []string{"invalid", "null", `{}`} {
		r.run = func(context.Context, string, ...string) ([]byte, error) { return []byte(raw), nil }
		_, err := r.imageVolumes(context.Background())
		if (err != nil) != (raw == "invalid") {
			t.Fatal(raw, err)
		}
	}
	r.run = func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("镜像不可用") }
	if _, err := r.imageVolumes(context.Background()); err == nil {
		t.Fatal("忽略镜像读取失败")
	}
}
