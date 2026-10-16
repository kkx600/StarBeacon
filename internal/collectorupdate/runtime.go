package collectorupdate

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"golang.org/x/sys/unix"
)

var absolutePath = regexp.MustCompile(`^/[A-Za-z0-9_./-]+$`)
var imagePattern = regexp.MustCompile(`^(?:[A-Za-z0-9][A-Za-z0-9./:_-]*@)?sha256:[a-f0-9]{64}$`)

type Config struct {
	SchemaVersion int    `json:"schema_version"`
	Instance      string `json:"instance"`
	Mode          string `json:"mode"`
	Root          string `json:"root"`
	DataDir       string `json:"data_dir"`
	ConfigDir     string `json:"config_dir"`
	PublicKey     string `json:"public_key"`
	UID           int    `json:"uid"`
	GID           int    `json:"gid"`
	ReadyURL      string `json:"ready_url"`
	ReadyCA       string `json:"ready_ca"`
	RetentionDays int    `json:"retention_days"`
	DockerImage   string `json:"docker_image,omitempty"`
	DockerNetwork string `json:"docker_network,omitempty"`
}

func (c *Config) Validate() error {
	if c.RetentionDays == 0 {
		c.RetentionDays = 180
	}
	if c.SchemaVersion != 1 || !contract.ValidID(c.Instance) || len(c.Instance) > 48 || (c.Mode != "systemd" && c.Mode != "docker") || c.UID < 1 || c.GID < 1 || c.RetentionDays < 1 || c.RetentionDays > 3650 {
		return errors.New("采集器部署身份、运行方式或保留期无效")
	}
	for _, name := range []string{c.Root, c.DataDir, c.ConfigDir, c.PublicKey, c.ReadyCA} {
		if !absolutePath.MatchString(name) || filepath.Clean(name) != name || name == "/" {
			return errors.New("部署路径必须为规范的绝对路径，只接受字母、数字及常规路径符号")
		}
	}
	for i, first := range []string{c.Root, c.DataDir, c.ConfigDir} {
		for j, second := range []string{c.Root, c.DataDir, c.ConfigDir} {
			if i != j && (first == second || strings.HasPrefix(first, second+"/")) {
				return errors.New("程序、配置与业务数据目录必须独立")
			}
		}
	}
	u, err := url.Parse(c.ReadyURL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/readyz" || u.Port() == "" || !net.ParseIP(u.Hostname()).IsLoopback() {
		return errors.New("生产就绪探测必须为明确端口和 CA 的本机 HTTPS /readyz")
	}
	if c.Mode == "docker" && (!imagePattern.MatchString(c.DockerImage) || c.DockerNetwork != "none" && c.DockerNetwork != "host" && !contract.ValidID(c.DockerNetwork)) {
		return errors.New("容器必须使用不可变镜像摘要和明确网络，不接受网络命名空间参数")
	}
	if c.Mode == "systemd" && (c.DockerImage != "" || c.DockerNetwork != "") {
		return errors.New("主机服务不接受容器配置")
	}
	return nil
}

// Unit 不赋予管理网络、宿主挂载或内核配置权限；部署管理员负责配置外部检测依赖。
func (c Config) Unit() (string, error) {
	if err := c.Validate(); err != nil || c.Mode != "systemd" {
		return "", errors.New("仅主机部署可生成 systemd 服务")
	}
	return fmt.Sprintf(`[Unit]
Description=StarBeacon Collector %s
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=exec
User=%d
Group=%d
EnvironmentFile=%s/agent.env
ExecCondition=%s/maintenance/starbeacon-agent maintenance-boot --root %s
ExecStart=%s/current/bin/starbeacon-agent
WorkingDirectory=%s
Restart=on-failure
RestartSec=5
TimeoutStopSec=45
KillMode=control-group
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_RAW
AmbientCapabilities=CAP_NET_RAW
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ReadWritePaths=%s
LimitNOFILE=65536
TasksMax=512

[Install]
WantedBy=multi-user.target
`, c.Instance, c.UID, c.GID, c.ConfigDir, c.Root, c.Root, c.Root, c.DataDir, c.DataDir), nil
}

type commandRunner func(context.Context, string, ...string) ([]byte, error)

type ServiceRuntime struct {
	Config Config
	run    commandRunner
}

func command(ctx context.Context, name string, args ...string) ([]byte, error) {
	call, cancel := context.WithTimeout(ctx, 50*time.Second)
	defer cancel()
	cmd := exec.CommandContext(call, name, args...)
	cmd.WaitDelay = 3 * time.Second
	// 不把设备环境、凭据或子进程错误原文写入回执。
	var out limitedOutput
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, errors.New("服务管理命令失败，请在设备审计中核对运行状态")
	}
	return out.bytes, nil
}

type limitedOutput struct{ bytes []byte }

func (o *limitedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if len(o.bytes)+n > 64<<10 {
		return 0, errors.New("服务管理输出超限")
	}
	o.bytes = append(o.bytes, p...)
	return n, nil
}

func (r *ServiceRuntime) runner() commandRunner {
	if r.run != nil {
		return r.run
	}
	return command
}

func (r *ServiceRuntime) unit() string { return "starbeacon-agent-" + r.Config.Instance + ".service" }
func (r *ServiceRuntime) name() string { return "starbeacon-collector-" + r.Config.Instance }

func (r *ServiceRuntime) container(ctx context.Context) (string, error) {
	raw, err := r.runner()(ctx, "/usr/bin/docker", "container", "ls", "--all", "--filter", "name=^/"+r.name()+"$", "--format", "{{.ID}}")
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(raw))
	if id == "" {
		return "", nil
	}
	if !regexp.MustCompile(`^[a-f0-9]{12,64}$`).MatchString(id) {
		return "", errors.New("容器身份不唯一")
	}
	label, err := r.runner()(ctx, "/usr/bin/docker", "inspect", "--format", `{{index .Config.Labels "io.starbeacon.collector.instance"}}`, id)
	if err != nil || strings.TrimSpace(string(label)) != r.Config.Instance {
		return "", errors.New("同名容器不属于当前采集器，禁止接管")
	}
	return id, nil
}

func (r *ServiceRuntime) Prepare(ctx context.Context, current *Release) error {
	if err := r.Config.Validate(); err != nil {
		return err
	}
	if current != nil {
		// 当前程序损坏或退出也必须能够回退；准入核对选择身份，启动再核对目标字节。
		selected, err := os.Readlink(filepath.Join(r.Config.Root, "current"))
		if current.validate() != nil || err != nil || selected != filepath.Join("releases", current.Directory) {
			return errors.New("当前程序选择与持久部署身份不一致")
		}
		return nil
	}
	if r.Config.Mode == "docker" {
		id, err := r.container(ctx)
		if err != nil || id != "" {
			return errors.New("首次安装不接管既有容器；请保留原部署并使用独立实例")
		}
		return nil
	}
	raw, err := r.runner()(ctx, "/usr/bin/systemctl", "show", "--property=MainPID", "--value", r.unit())
	if err != nil || strings.TrimSpace(string(raw)) != "0" {
		return errors.New("首次安装不接管正在运行的主机服务")
	}
	return nil
}

func (r *ServiceRuntime) Stop(ctx context.Context) error {
	if err := r.Config.Validate(); err != nil {
		return err
	}
	if r.Config.Mode == "systemd" {
		if _, err := r.runner()(ctx, "/usr/bin/systemctl", "stop", r.unit()); err != nil {
			return err
		}
		raw, err := r.runner()(ctx, "/usr/bin/systemctl", "show", "--property=MainPID", "--value", r.unit())
		if err != nil || strings.TrimSpace(string(raw)) != "0" {
			return errors.New("采集器主机进程停止结果未确认")
		}
		return nil
	}
	id, err := r.container(ctx)
	if err != nil || id == "" {
		return err
	}
	if _, err = r.runner()(ctx, "/usr/bin/docker", "stop", "--timeout", "45", id); err != nil {
		return err
	}
	_, err = r.runner()(ctx, "/usr/bin/docker", "rm", "--volumes", id)
	return err
}

func (r *ServiceRuntime) Start(ctx context.Context, release Release) error {
	if err := r.Config.Validate(); err != nil {
		return err
	}
	if err := verifyBinary(release.binary(r.Config.Root), release); err != nil {
		return err
	}
	if r.Config.Mode == "systemd" {
		_, err := r.runner()(ctx, "/usr/bin/systemctl", "start", r.unit())
		return err
	}
	id, err := r.container(ctx)
	if err != nil || id != "" {
		return errors.New("目标容器未清理或身份无法核对")
	}
	volumes, err := r.imageVolumes(ctx)
	if err != nil {
		return err
	}
	args := []string{"run", "--detach", "--pull=never", "--init", "--read-only", "--pids-limit=512", "--memory=4g", "--cap-drop=ALL", "--cap-add=NET_RAW", "--cap-add=SETUID", "--cap-add=SETGID", "--cap-add=SETPCAP", "--security-opt=no-new-privileges:true", "--restart=unless-stopped", "--log-driver=local", "--log-opt=max-size=10m", "--log-opt=max-file=3", "--stop-timeout=45", "--name", r.name(), "--label", "io.starbeacon.collector.instance=" + r.Config.Instance, "--user", "0:0", "--network", r.Config.DockerNetwork, "--tmpfs", "/tmp:rw,nosuid,nodev,size=268435456,mode=1777", "--env-file", filepath.Join(r.Config.ConfigDir, "agent.env"), "--mount", "type=bind,src=" + r.Config.ConfigDir + ",dst=" + r.Config.ConfigDir + ",readonly", "--mount", "type=bind,src=" + r.Config.DataDir + ",dst=" + r.Config.DataDir, "--mount", "type=bind,src=" + r.Config.Root + ",dst=" + r.Config.Root + ",readonly", "--mount", "type=bind,src=" + release.binary(r.Config.Root) + ",dst=/starbeacon/starbeacon-agent,readonly", "--entrypoint", filepath.Join(r.Config.Root, "maintenance/starbeacon-agent"), r.Config.DockerImage, "maintenance-run", "--root", r.Config.Root, "--binary", "/starbeacon/starbeacon-agent", "--uid", strconv.Itoa(r.Config.UID), "--gid", strconv.Itoa(r.Config.GID)}
	// 镜像声明的 VOLUME 不随只读根自动只读；将其限制为可回收的只读镜像内容。
	// 所有业务写入必须位于显式数据绑定，不能在匿名卷中隐式保留状态。
	position := slices.Index(args, r.Config.DockerImage)
	for _, target := range volumes {
		args = slices.Insert(args, position, "--mount", "type=volume,dst="+target+",readonly")
		position += 2
	}
	_, err = r.runner()(ctx, "/usr/bin/docker", args...)
	return err
}

func (r *ServiceRuntime) imageVolumes(ctx context.Context) ([]string, error) {
	raw, err := r.runner()(ctx, "/usr/bin/docker", "image", "inspect", "--format", "{{json .Config.Volumes}}", r.Config.DockerImage)
	if err != nil {
		return nil, err
	}
	var volumes map[string]json.RawMessage
	if json.Unmarshal(raw, &volumes) != nil || len(volumes) > 32 {
		return nil, errors.New("运行镜像的卷声明不可核对或超过预算")
	}
	var targets []string
	for target := range volumes {
		if !absolutePath.MatchString(target) || filepath.Clean(target) != target || target == "/" {
			return nil, errors.New("运行镜像包含不受支持的卷路径")
		}
		for _, bound := range []string{r.Config.Root, r.Config.DataDir, r.Config.ConfigDir, "/starbeacon", "/tmp", "/proc", "/sys", "/dev"} {
			if target == bound || strings.HasPrefix(target, bound+"/") || strings.HasPrefix(bound, target+"/") {
				return nil, errors.New("运行镜像的卷声明与受管路径冲突")
			}
		}
		targets = append(targets, target)
	}
	slices.Sort(targets)
	return targets, nil
}

func (r *ServiceRuntime) Verify(ctx context.Context, release Release) error {
	if err := r.Config.Validate(); err != nil {
		return err
	}
	call, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := r.observe(call, release); err == nil {
			return nil
		}
		select {
		case <-call.Done():
			return errors.New("采集器实际程序或就绪状态未通过核验")
		case <-ticker.C:
		}
	}
}

func (r *ServiceRuntime) observe(ctx context.Context, release Release) error {
	if r.Config.Mode == "docker" {
		id, err := r.container(ctx)
		if err != nil || id == "" {
			return errors.New("采集器容器不存在")
		}
		raw, err := r.runner()(ctx, "/usr/bin/docker", "inspect", "--format", "{{.State.Running}} {{.HostConfig.Init}} {{.HostConfig.ReadonlyRootfs}}", id)
		if err != nil || strings.TrimSpace(string(raw)) != "true true true" {
			return errors.New("采集器容器未运行或隔离不匹配")
		}
		raw, err = r.runner()(ctx, "/usr/bin/docker", "exec", "--user", fmt.Sprintf("%d:%d", r.Config.UID, r.Config.GID), id, "/starbeacon/starbeacon-agent", "--version")
		if err != nil || strings.TrimSpace(string(raw)) != fmt.Sprintf("StarBeacon agent %s (%s)", release.Proof.Version, release.Proof.Commit) {
			return errors.New("采集器容器程序版本不匹配")
		}
		_, err = r.runner()(ctx, "/usr/bin/docker", "exec", "--user", fmt.Sprintf("%d:%d", r.Config.UID, r.Config.GID), id, "/starbeacon/starbeacon-agent", "maintenance-probe", "--url", r.Config.ReadyURL, "--ca", r.Config.ReadyCA)
		return err
	}
	raw, err := r.runner()(ctx, "/usr/bin/systemctl", "show", "--property=MainPID", "--value", r.unit())
	if err != nil {
		return err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid < 1 {
		return errors.New("采集器主机进程不存在")
	}
	if err = verifyBinary(filepath.Join("/proc", strconv.Itoa(pid), "exe"), release); err != nil {
		return err
	}
	return Probe(ctx, r.Config.ReadyURL, r.Config.ReadyCA)
}

// 明文探测只用于独立本机诊断；正式部署配置始终要求 HTTPS 与显式 CA。
func Probe(ctx context.Context, address string, ca ...string) error {
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "http" && u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/readyz" || u.Port() == "" || !net.ParseIP(u.Hostname()).IsLoopback() || len(ca) > 1 {
		return errors.New("就绪探测只接受明确端口的本机 /readyz")
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	if u.Scheme == "https" {
		if len(ca) != 1 || !absolutePath.MatchString(ca[0]) {
			return errors.New("TLS 就绪探测缺少 CA")
		}
		info, err := os.Lstat(ca[0])
		if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
			return errors.New("TLS 就绪 CA 类型或容量无效")
		}
		raw, err := os.ReadFile(ca[0])
		pool := x509.NewCertPool()
		if err != nil || !pool.AppendCertsFromPEM(raw) {
			return errors.New("TLS 就绪 CA 内容无效")
		}
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return err
	}
	res, err := client.Do(req)
	if err != nil {
		return errors.New("采集器本机就绪检查连接失败")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return errors.New("采集器本机未就绪")
	}
	return nil
}

func fileDigest(name string) (string, error) {
	f, err := os.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxArchiveBytes {
		return "", errors.New("摘要输入类型或容量无效")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, MaxArchiveBytes+1))
	if n > MaxArchiveBytes {
		return "", errors.New("摘要输入读取超过容量")
	}
	return hex.EncodeToString(h.Sum(nil)), err
}
