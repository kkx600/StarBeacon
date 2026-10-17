package collectorupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/kkx600/StarBeacon/internal/control"
	"golang.org/x/sys/unix"
)

// CLI 是现场管理员使用的独立入口；采集器服务不持有 Docker socket 或服务管理权限。
func CLI(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("用法：maintenance status|render-unit|apply|rollback|recover|cleanup|sign --config <部署配置>")
	}
	operation := args[0]
	flags := flag.NewFlagSet("maintenance "+operation, flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "root 管理的部署配置")
	archive := flags.String("archive", "", "离线采集器 ZIP")
	proofPath := flags.String("proof", "", "独立发布签名 JSON")
	id := flags.String("request-id", "", "维护请求身份，重试保持不变")
	revision := flags.Int64("expected-revision", -1, "维护状态修订")
	keyPath := flags.String("key", "", "离线发布私钥 PKCS#8 PEM")
	generation := flags.Int64("generation", 0, "严格递增的发布代次")
	version := flags.String("version", "", "制品版本")
	commit := flags.String("commit", "", "完整源码提交")
	arch := flags.String("arch", runtime.GOARCH, "Linux 架构")
	keyDir := flags.String("key-dir", "", "独立发布密钥的私有目录")
	execute := flags.Bool("execute", false, "实际回收已到期的维护记录和历史制品；cleanup 默认仅预览")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("维护命令不接受额外位置参数")
	}
	if *execute && operation != "cleanup" {
		return errors.New("--execute 仅用于维护回收")
	}
	if operation == "sign" {
		return signArchive(*archive, *keyPath, Proof{SchemaVersion: 1, Generation: *generation, Version: *version, Commit: *commit, Arch: *arch, DataSchema: 1}, stdout)
	}
	if operation == "keys" {
		if !filepath.IsAbs(*keyDir) {
			return errors.New("发布密钥目录必须为绝对路径")
		}
		if err := os.MkdirAll(*keyDir, 0700); err != nil {
			return err
		}
		return control.GenerateKeys(filepath.Join(*keyDir, "release.key"), filepath.Join(*keyDir, "release.pub"))
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("运行维护命令需要 Linux 设备的部署管理员权限")
	}
	var config Config
	if err := trustedJSON(*configPath, &config); err != nil {
		return err
	}
	if err := config.Validate(); err != nil {
		return err
	}
	if operation == "render-unit" {
		unit, err := config.Unit()
		if err != nil {
			return err
		}
		_, err = io.WriteString(stdout, unit)
		return err
	}
	key, err := publicKey(config.PublicKey)
	if err != nil {
		return err
	}
	if err := validateDirectories(config); err != nil {
		return err
	}
	r := &ServiceRuntime{Config: config}
	binding, err := config.binding()
	if err != nil {
		return err
	}
	m := &Manager{Root: config.Root, Instance: config.Instance, Mode: config.Mode, BindingSHA256: binding, Key: key, Runtime: r, Guard: func(ctx context.Context) error { return GuardData(ctx, config.DataDir) }, RetentionDays: config.RetentionDays}
	if operation == "cleanup" {
		return executeCleanup(ctx, m, *execute, stdout)
	}
	return executeMaintenance(ctx, m, operation, *archive, *proofPath, *id, *revision, stdout)
}

func executeCleanup(ctx context.Context, m *Manager, execute bool, stdout io.Writer) error {
	report, err := m.Cleanup(ctx, execute)
	if report.SchemaVersion != 0 {
		err = errors.Join(err, json.NewEncoder(stdout).Encode(report))
	}
	return err
}

func (c Config) binding() (string, error) {
	environment, err := os.ReadFile(filepath.Join(c.ConfigDir, "agent.env"))
	if err != nil {
		return "", err
	}
	c.RetentionDays = 0
	environmentSHA := sha256.Sum256(environment)
	raw, _ := json.Marshal(struct {
		Config            Config `json:"config"`
		EnvironmentSHA256 string `json:"environment_sha256"`
	}{c, hex.EncodeToString(environmentSHA[:])})
	binding := sha256.Sum256(raw)
	return hex.EncodeToString(binding[:]), nil
}

func executeMaintenance(ctx context.Context, m *Manager, operation, archive, proofPath, id string, revision int64, stdout io.Writer) error {
	var state State
	var err error
	switch operation {
	case "status":
		state, err = m.Status()
	case "apply":
		var proof Envelope
		if err = m.initialize(); err == nil {
			err = bootstrap(m.Root)
		}
		if err == nil {
			err = readJSON(proofPath, &proof)
		}
		if err == nil {
			state, err = m.Apply(ctx, archive, proof, id, revision)
		}
	case "rollback":
		state, err = m.Rollback(ctx, id, revision)
	case "recover":
		state, err = m.Recover(ctx)
	default:
		return errors.New("未知采集器维护命令")
	}
	if state.SchemaVersion != 0 {
		if writeErr := json.NewEncoder(stdout).Encode(state); writeErr != nil {
			return errors.Join(err, writeErr)
		}
	}
	return err
}

func trustedJSON(path string, value any) error {
	if err := trustedFile(path); err != nil {
		return err
	}
	return readJSON(path, value)
}

func trustedFile(name string) error {
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > 2<<20 {
		return errors.New("部署配置或密钥必须为受保护的普通文件")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("部署配置或密钥不属于当前部署管理员")
	}
	return nil
}

func publicKey(name string) (ed25519.PublicKey, error) {
	if err := trustedFile(name); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PUBLIC KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("发布公钥必须为唯一的 PKIX PEM")
	}
	value, err := x509.ParsePKIXPublicKey(block.Bytes)
	key, ok := value.(ed25519.PublicKey)
	if err != nil || !ok {
		return nil, errors.New("发布公钥必须为 Ed25519")
	}
	return key, nil
}

func signArchive(archive, keyPath string, p Proof, out io.Writer) error {
	if err := trustedFile(keyPath); err != nil {
		return err
	}
	info, _ := os.Stat(keyPath)
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("发布私钥只允许当前管理员读取")
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return errors.New("发布私钥必须为唯一的 PKCS#8 PEM")
	}
	value, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := value.(ed25519.PrivateKey)
	if err != nil || !ok {
		return errors.New("发布私钥必须为 Ed25519")
	}
	file, err := os.OpenFile(archive, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	archiveInfo, err := file.Stat()
	if err != nil || !archiveInfo.Mode().IsRegular() || archiveInfo.Size() > MaxArchiveBytes {
		return errors.New("待签 ZIP 类型或容量无效")
	}
	p.SHA256, err = fileDigest(archive)
	if err != nil {
		return err
	}
	p.Size, p.IssuedAt = archiveInfo.Size(), time.Now().UTC()
	p.ExpiresAt = p.IssuedAt.Add(7 * 24 * time.Hour)
	envelope, err := Sign(p, key)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(envelope)
}

func validateDirectories(c Config) error {
	for _, name := range []string{c.ConfigDir, c.DataDir} {
		info, err := os.Lstat(name)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
			return errors.New("采集器配置与业务数据目录必须已创建且禁止其他用户写入")
		}
	}
	if err := trustedFile(filepath.Join(c.ConfigDir, "agent.env")); err != nil {
		return err
	}
	// 两种运行方式使用共同的无展开环境格式，防止 shell、Compose 与 systemd 解释差异。
	raw, err := os.ReadFile(filepath.Join(c.ConfigDir, "agent.env"))
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || !regexpEnvKey(key) || seen[key] || strings.ContainsAny(value, "\x00\r\"'`$\\% \t") {
			return errors.New("agent.env 必须为唯一 SB_键=字面值，不接受引号、展开或空白")
		}
		seen[key] = true
		if key == "SB_MODE" && value != "production" {
			return errors.New("维护部署只接受生产运行模式")
		}
		if key == "SB_STATE_PATH" && value != filepath.Join(c.DataDir, "agent.db") {
			return errors.New("WAL 必须绑定本部署数据目录内的 agent.db")
		}
	}
	if !seen["SB_STATE_PATH"] || !seen["SB_LOCAL_PASSWORD_FILE"] || !seen["SB_MODE"] || strings.Contains(string(raw), "SB_MODE=development") {
		return fmt.Errorf("采集器环境必须明确配置生产模式、WAL 和本地密码文件")
	}
	return nil
}

func regexpEnvKey(key string) bool {
	if !strings.HasPrefix(key, "SB_") || len(key) < 4 {
		return false
	}
	for _, c := range key {
		if c != '_' && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
