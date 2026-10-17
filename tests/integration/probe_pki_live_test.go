//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/agent"
	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/ingest"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/probepki"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

func TestProbePKIRealStepCAEnrollmentAutomaticRenewalAndLiveRevocation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Minute)
	defer cancel()
	f, u, _, password := accountFixture(t, ctx)
	for _, key := range []string{"SB_TEST_STEP_CA_URL", "SB_TEST_STEP_CA_ROOT", "SB_TEST_STEP_CA_JWK", "SB_TEST_MANAGEMENT_BINARY"} {
		if os.Getenv(key) == "" {
			t.Fatal("真实证书验收要求独立 step-ca 容器及管理工具：", key)
		}
	}
	ca, err := probepki.NewStep(probepki.StepConfig{URL: os.Getenv("SB_TEST_STEP_CA_URL"), RootFile: os.Getenv("SB_TEST_STEP_CA_ROOT"), JWKFile: os.Getenv("SB_TEST_STEP_CA_JWK"), Provisioner: "starbeacon-probes", Lifetime: 5 * time.Minute})
	require(t, err)
	work := t.TempDir()
	serverPKI := filepath.Join(work, "server-pki")
	require(t, admin.DevPKI(serverPKI))
	rootFile := filepath.Join(serverPKI, "ca.crt")
	serverTLS, err := transport.TLS(rootFile, filepath.Join(serverPKI, "server.crt"), filepath.Join(serverPKI, "server.key"), true)
	require(t, err)
	stepRoot, err := os.ReadFile(os.Getenv("SB_TEST_STEP_CA_ROOT"))
	require(t, err)
	serverTLS.ClientCAs = x509.NewCertPool()
	if !serverTLS.ClientCAs.AppendCertsFromPEM(stepRoot) {
		t.Fatal("探针信任根无效")
	}
	auth := httpapi.NewAuth(f.Runtime, nil, "", "pki_live_session", false)
	api := &platform.API{DB: f.Runtime, Auth: auth, Authority: ca}
	web := httptest.NewUnstartedServer(httpapi.Middleware(api.Handler()))
	web.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: serverTLS.Certificates}
	web.StartTLS()
	defer web.Close()
	auth.Origin = web.URL
	jar, err := cookiejar.New(nil)
	require(t, err)
	client := web.Client()
	client.Jar = jar
	client.Timeout = 10 * time.Second
	h := &liveHTTP{t: t, ctx: ctx, client: client, origin: web.URL, prefix: "/api/v1"}
	h.login(u.Username, password)
	id := transport.SensorIdentity{TenantID: u.TenantID, SensorID: "real_managed_probe", RegistrationID: "real_managed_registration"}
	token, err := probepki.NewCredential(id, "real_enrollment")
	require(t, err)
	var enrollment probepki.Enrollment
	h.request("POST", "/sensor-enrollments", "real_enrollment", probepki.EnrollmentInput{Token: token, Name: "证书验收探针", TTLSeconds: 3600}, &enrollment, 200)
	tokenFile := filepath.Join(work, "enrollment.token")
	require(t, os.WriteFile(tokenFile, []byte(token+"\n"), 0600))
	identityDir := filepath.Join(work, "identity")
	command := exec.CommandContext(ctx, os.Getenv("SB_TEST_MANAGEMENT_BINARY"), "enroll-agent", "--dir", identityDir, "--token-file", tokenFile, "--ca-file", os.Getenv("SB_TEST_STEP_CA_ROOT"), "--platform-ca-file", rootFile, "--platform-url", web.URL)
	command.Env = []string{"PATH=" + os.Getenv("PATH")}
	if cover := os.Getenv("SB_TEST_BINARY_COVERDIR"); cover != "" {
		command.Env = append(command.Env, "GOCOVERDIR="+cover)
	}
	var output, diagnostic bytes.Buffer
	command.Stdout = &output
	command.Stderr = &diagnostic
	err = command.Run()
	if err != nil {
		t.Fatal("实际注册工具未成功", err, diagnostic.String())
	}
	var initial probepki.LocalStatus
	require(t, json.Unmarshal(output.Bytes(), &initial))
	if initial.Fingerprint == "" || initial.SensorID != id.SensorID {
		t.Fatal("注册没有持久身份回执")
	}
	oldBundle, err := os.ReadFile(filepath.Join(identityDir, "identity.pem"))
	require(t, err)
	oldPair, err := tls.X509KeyPair(oldBundle, oldBundle)
	require(t, err)
	rootPEM, err := os.ReadFile(rootFile)
	require(t, err)
	serverRoots := x509.NewCertPool()
	serverRoots.AppendCertsFromPEM(rootPEM)
	connect := func(service *ingest.Server) (string, *grpc.ClientConn) {
		t.Helper()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require(t, err)
		server := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS.Clone())))
		sensorv1.RegisterSensorServiceServer(server, service)
		go func() { _ = server.Serve(listener) }()
		t.Cleanup(server.Stop)
		conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: serverRoots, Certificates: []tls.Certificate{oldPair}})))
		require(t, err)
		t.Cleanup(func() { conn.Close() })
		return listener.Addr().String(), conn
	}
	controlAddr, oldConn := connect(&ingest.Server{DB: f.Runtime, ControlOnly: true, Authority: ca})
	ingestAddr, _ := connect(&ingest.Server{DB: f.Runtime})
	oldClient := sensorv1.NewSensorServiceClient(oldConn)
	if _, err = oldClient.CertificateStatus(ctx, &sensorv1.CertificateStatusRequest{}); err != nil {
		t.Fatal("实际签发证书未通过 mTLS", err)
	}
	if _, err = oldClient.RenewCertificate(ctx, &sensorv1.CertificateRenewalRequest{CsrPem: "invalid"}); status.Code(err) != codes.InvalidArgument {
		t.Fatal("非法续签 CSR 未拒绝", err)
	}
	csr, _, err := probepki.NewCSR(id)
	require(t, err)
	if _, err = oldClient.RenewCertificate(ctx, &sensorv1.CertificateRenewalRequest{CsrPem: csr}); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("窗口外的真实续签未拒绝", err)
	}
	// 不回拨证书、数据库或调度时间，等待 5 分钟证书按真实时钟进入最后三分之一。
	localListener, err := net.Listen("tcp", "127.0.0.1:0")
	require(t, err)
	localAddr := localListener.Addr().String()
	localListener.Close()
	eve := filepath.Join(work, "eve.json")
	require(t, os.WriteFile(eve, nil, 0600))
	localPassword := store.Token()
	cfg := config.Config{Mode: "development", HTTPAddr: localAddr, AllowedOrigin: "http://" + localAddr, TenantID: id.TenantID, SensorID: id.SensorID, RegistrationID: id.RegistrationID, TLSCA: rootFile, TLSCert: filepath.Join(identityDir, "identity.pem"), TLSKey: filepath.Join(identityDir, "identity.pem"), IdentityDir: identityDir, IdentityRoot: os.Getenv("SB_TEST_STEP_CA_ROOT"), PlatformAddr: controlAddr, IngestAddr: ingestAddr, EVEPath: eve, StatePath: filepath.Join(work, "agent.db"), WALBytes: 16 * 1024 * 1024, LocalPassword: localPassword, CookieName: "pki_local_session", HeartbeatInterval: 10 * time.Second, ReplayDir: filepath.Join(work, "replay"), ReplayBytes: 100 * 1024 * 1024, ReplayRetentionDays: 180, TaskRetentionDays: 180}
	run, stopAgent := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- agent.Run(run, cfg) }()
	defer func() {
		stopAgent()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Error(err)
			}
		case <-time.After(10 * time.Second):
			t.Error("采集器未按期限退出")
		}
	}()
	localJar, err := cookiejar.New(nil)
	require(t, err)
	localHTTP := &liveHTTP{t: t, ctx: ctx, client: &http.Client{Jar: localJar, Timeout: 3 * time.Second}, origin: cfg.AllowedOrigin, prefix: "/api/local/v1"}
	readyDeadline := time.Now().Add(10 * time.Second)
	for {
		res, err := localHTTP.client.Get(cfg.AllowedOrigin + "/healthz")
		if err == nil {
			res.Body.Close()
			if res.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(readyDeadline) {
			t.Fatal("真实采集器本地服务未启动")
		}
		time.Sleep(100 * time.Millisecond)
	}
	localHTTP.login("admin", localPassword)
	var current probepki.LocalStatus
	started := time.Now()
	for time.Since(started) < 5*time.Minute {
		localHTTP.request("GET", "/identity", "", nil, &current, 200)
		if current.Fingerprint != "" && current.Fingerprint != initial.Fingerprint {
			break
		}
		select {
		case err := <-done:
			t.Fatal("自动续签前采集器退出", err)
		case <-ctx.Done():
			t.Fatal("真实续签超时")
		case <-time.After(time.Second):
		}
	}
	if current.Fingerprint == initial.Fingerprint || current.Fingerprint == "" || !current.NotAfter.After(initial.NotAfter.Add(time.Minute)) {
		t.Fatal("真实时钟内未完成自动续签和身份切换")
	}
	t.Logf("真实 step-ca 自动续签、两端认证和连接切换：%.3f 秒", time.Since(started).Seconds())
	newBundle, err := os.ReadFile(filepath.Join(identityDir, "identity.pem"))
	require(t, err)
	newPair, err := tls.X509KeyPair(newBundle, newBundle)
	require(t, err)
	newConn, err := grpc.NewClient(controlAddr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: serverRoots, Certificates: []tls.Certificate{newPair}})))
	require(t, err)
	defer newConn.Close()
	newClient := sensorv1.NewSensorServiceClient(newConn)
	proof, err := newClient.CertificateStatus(ctx, &sensorv1.CertificateStatusRequest{})
	require(t, err)
	if proof.FingerprintSha256 != current.Fingerprint {
		t.Fatal("新证书连接身份不一致")
	}
	oldStream, err := oldClient.Control(ctx)
	require(t, err)
	health, _ := json.Marshal(model.HostHealth{ObservedAt: time.Now().UTC()})
	require(t, oldStream.Send(&sensorv1.AgentMessage{SensorId: id.SensorID, SensorRegistrationId: id.RegistrationID, MessageId: "old_overlap", Kind: sensorv1.AgentMessageKind_AGENT_MESSAGE_KIND_HEARTBEAT, PayloadSchema: "host.health.v1", PayloadJson: health}))
	_, err = oldStream.Recv()
	require(t, err)
	items, _, err := f.Runtime.ProbeCertificates(ctx, u, id.SensorID, "")
	require(t, err)
	if len(items) != 2 {
		t.Fatal("证书轮换缺少两份独立签发记录")
	}
	var oldID string
	for _, c := range items {
		if c.Fingerprint == initial.Fingerprint {
			oldID = c.ID
		}
	}
	var revoked probepki.Certificate
	h.request("POST", "/sensor-certificates/"+oldID+"/revoke", "real_revoke", struct{}{}, &revoked, 200)
	if revoked.RevokedAt == nil || revoked.CARevocation != "confirmed" {
		t.Fatal("真实 CA 吊销未取得确认")
	}
	// 旧连接未重握手；五秒控制核验仍必须停止它。
	closed := make(chan error, 1)
	go func() { _, err := oldStream.Recv(); closed <- err }()
	select {
	case err := <-closed:
		if status.Code(err) != codes.PermissionDenied {
			t.Fatal("吊销没有拒绝旧控制流", err)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("旧控制流未及时关闭")
	}
	if _, err = oldClient.CertificateStatus(ctx, &sensorv1.CertificateStatusRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatal("吊销后的既有连接仍通过认证", err)
	}
	if _, err = newClient.CertificateStatus(ctx, &sensorv1.CertificateStatusRequest{}); err != nil {
		t.Fatal("吊销旧证书错误影响新证书", err)
	}
	h.request("PATCH", "/sensors/"+id.SensorID, "stop_real_probe", map[string]bool{"active": false}, nil, 200)
	if _, err = newClient.CertificateStatus(ctx, &sensorv1.CertificateStatusRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatal("停用探针仍允许新证书通信", err)
	}
}
