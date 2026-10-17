//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/probepki"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/transport"
)

// 事务故障使用测试 CA；真实 step-ca 的协议及自动续签由独立服务用例核对。
type probeTestAuthority struct {
	t     *testing.T
	root  *x509.Certificate
	key   ed25519.PrivateKey
	roots *x509.CertPool
	fail  atomic.Bool
}

func newProbeTestAuthority(t *testing.T) *probeTestAuthority {
	t.Helper()
	dir := t.TempDir()
	require(t, admin.DevPKI(dir))
	raw, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	require(t, err)
	block, _ := pem.Decode(raw)
	root, err := x509.ParseCertificate(block.Bytes)
	require(t, err)
	rawKey, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	require(t, err)
	block, _ = pem.Decode(rawKey)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return &probeTestAuthority{t: t, root: root, key: key.(ed25519.PrivateKey), roots: roots}
}
func (a *probeTestAuthority) Sign(_ context.Context, j probepki.Job) (probepki.Certificate, error) {
	if a.fail.Load() {
		return probepki.Certificate{}, errors.New("测试 CA 中断")
	}
	csr, err := probepki.ParseCSR(j.CSR, j.Identity)
	if err != nil {
		return probepki.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return probepki.Certificate{}, err
	}
	now := time.Now()
	leaf := &x509.Certificate{SerialNumber: serial, Subject: csr.Subject, URIs: csr.URIs, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, a.root, csr.PublicKey, a.key)
	if err != nil {
		return probepki.Certificate{}, err
	}
	chain := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.root.Raw}))
	c, err := probepki.VerifyChain(chain, j.CSR, j.Identity, a.roots, now, time.Hour)
	c.ID = j.ID
	return c, err
}
func (a *probeTestAuthority) Revoke(context.Context, string, string) error {
	if a.fail.Load() {
		return errors.New("测试 CA 中断")
	}
	return nil
}

func TestProbeEnrollmentHTTPTransactionProofIsolationAndRevocation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, u, other, password := accountFixture(t, ctx)
	ca := newProbeTestAuthority(t)
	a := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, Authority: ca}, u.Username, password)
	b := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, Authority: ca}, other.Username, password)
	id := transport.SensorIdentity{TenantID: u.TenantID, SensorID: "managed_probe", RegistrationID: "managed_registration"}
	token, err := probepki.NewCredential(id, "enroll_primary")
	require(t, err)
	input := probepki.EnrollmentInput{Token: token, Name: "办公探针", TTLSeconds: 3600}
	var enrollment, retry probepki.Enrollment
	a.request("POST", "/sensor-enrollments", "enroll_create", input, &enrollment, 200)
	a.request("POST", "/sensor-enrollments", "enroll_retry", input, &retry, 200)
	if enrollment.ID != retry.ID || !enrollment.CreatedAt.Equal(retry.CreatedAt) {
		t.Fatal("同一令牌重试重复登记")
	}
	b.request("POST", "/sensor-enrollments", "foreign_enroll", input, nil, 403)
	changed := input
	changed.Name = "另一名称"
	a.request("POST", "/sensor-enrollments", "enroll_conflict", changed, nil, 409)
	noCSRF := *a
	noCSRF.csrf = ""
	noCSRF.request("POST", "/sensor-enrollments", "csrf_enroll", input, nil, 403)
	var page struct {
		Items        []probepki.Enrollment `json:"items"`
		Next         string                `json:"next_cursor"`
		CAConfigured bool                  `json:"ca_configured"`
	}
	a.request("GET", "/sensor-enrollments", "", nil, &page, 200)
	if len(page.Items) != 1 || !page.CAConfigured || page.Items[0].State != "unused" {
		t.Fatal("注册目录未反映实际状态")
	}
	b.request("GET", "/sensor-enrollments", "", nil, &page, 200)
	if len(page.Items) != 0 {
		t.Fatal("跨租户令牌目录可见")
	}
	csr, _, err := probepki.NewCSR(id)
	require(t, err)
	exchange := probepki.Exchange{Token: token, CSR: csr}
	post := func(body probepki.Exchange, origin string, want int) probepki.Certificate {
		t.Helper()
		raw, _ := json.Marshal(body)
		r, err := http.NewRequestWithContext(ctx, "POST", a.origin+"/api/v1/sensor-enrollments/exchange", bytes.NewReader(raw))
		require(t, err)
		r.Header.Set("Content-Type", "application/json")
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		res, err := http.DefaultClient.Do(r)
		require(t, err)
		defer res.Body.Close()
		if res.StatusCode != want {
			t.Fatalf("交换状态错误：%d，预期 %d", res.StatusCode, want)
		}
		var c probepki.Certificate
		if want == 200 {
			require(t, json.NewDecoder(res.Body).Decode(&c))
		}
		return c
	}
	post(exchange, a.origin, 403)
	cert := post(exchange, "", 200)
	same := post(exchange, "", 200)
	if cert.Fingerprint != same.Fingerprint || cert.Chain != same.Chain {
		t.Fatal("精确 CSR 重试重新签发")
	}
	csrOther, _, _ := probepki.NewCSR(id)
	post(probepki.Exchange{Token: token, CSR: csrOther}, "", 409)
	if err = f.Runtime.SensorCertificateActive(ctx, id, cert.Fingerprint, cert.NotAfter); err != nil {
		t.Fatal("登记证书未通过身份检查", err)
	}
	if err = f.Runtime.SensorCertificateActive(ctx, id, store.Hash("unregistered"), cert.NotAfter); !errors.Is(err, store.ErrSensorInactive) {
		t.Fatal("同一 CA 的未登记证书可用")
	}
	if err = f.Runtime.SensorCertificateActive(ctx, id, cert.Fingerprint, time.Now().Add(-time.Second)); !errors.Is(err, store.ErrSensorInactive) {
		t.Fatal("已过期长连接证书可用")
	}
	if _, _, err = f.Runtime.BeginProbeRenewal(ctx, id, cert.Fingerprint, csrOther); !errors.Is(err, probepki.ErrNotDue) {
		t.Fatal("窗口外提前续签", err)
	}
	var certificates struct {
		Items []probepki.Certificate `json:"items"`
		Next  string                 `json:"next_cursor"`
	}
	a.request("GET", "/sensors/managed_probe/certificates", "", nil, &certificates, 200)
	if len(certificates.Items) != 1 || certificates.Items[0].Chain != "" {
		t.Fatal("目录遗漏或泄漏完整证书材料")
	}
	b.request("POST", "/sensor-certificates/"+cert.ID+"/revoke", "foreign_revoke", struct{}{}, nil, 404)
	ca.fail.Store(true)
	var revoked probepki.Certificate
	a.request("POST", "/sensor-certificates/"+cert.ID+"/revoke", "revoke_unknown", struct{}{}, &revoked, 200)
	if revoked.RevokedAt == nil || revoked.CARevocation != "unknown" {
		t.Fatal("CA 中断被报告为已确认吊销")
	}
	if err = f.Runtime.SensorCertificateActive(ctx, id, cert.Fingerprint, cert.NotAfter); !errors.Is(err, store.ErrSensorInactive) {
		t.Fatal("CA 中断回滚了平台吊销")
	}
	ca.fail.Store(false)
	a.request("POST", "/sensor-certificates/"+cert.ID+"/revoke", "revoke_confirm", struct{}{}, &revoked, 200)
	if revoked.CARevocation != "confirmed" {
		t.Fatal("独立 CA 确认未保存")
	}
	post(exchange, "", 409)
	a.request("POST", "/sensor-enrollments/enroll_primary/revoke", "enroll_revoke", struct{}{}, nil, 200)
	a.request("POST", "/sensor-enrollments/enroll_primary/revoke", "enroll_revoke_retry", struct{}{}, nil, 200)
	post(exchange, "", 403)
	for _, path := range []string{"/sensor-enrollments?bad=x", "/sensor-enrollments?cursor=a&cursor=b", "/sensors/managed_probe/certificates?bad=1"} {
		a.request("GET", path, "", nil, nil, 400)
	}
	// 注册令牌仅保存摘要，证书和操作默认留存均至少 180 天。
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		var hash string
		var expires time.Time
		var managed bool
		if err := tx.QueryRow(ctx, `SELECT e.token_hash,e.retain_until,s.certificate_managed FROM probe_enrollments e JOIN sensors s ON s.tenant_id=e.tenant_id AND s.id=e.sensor_id WHERE e.tenant_id=$1 AND e.id=$2`, u.TenantID, enrollment.ID).Scan(&hash, &expires, &managed); err != nil {
			return err
		}
		if hash == token || hash != store.Hash(token) || time.Until(expires) < 179*24*time.Hour || !managed {
			t.Fatal("令牌、默认留存或身份管理状态错误")
		}
		return nil
	}))
	if _, _, err = f.Runtime.ProbeCertificates(ctx, model.Principal{ID: u.ID, TenantID: u.TenantID, Role: "viewer"}, id.SensorID, ""); err == nil {
		t.Fatal("只读角色读取证书管理目录")
	}
}

func TestProbeEnrollmentSigningOutcomesAndConcurrentBinding(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	f, u, _, _ := accountFixture(t, ctx)
	ca := newProbeTestAuthority(t)
	id := transport.SensorIdentity{TenantID: u.TenantID, SensorID: "concurrent_probe", RegistrationID: "current_registration"}
	token, _ := probepki.NewCredential(id, "concurrent_enrollment")
	_, err := f.Runtime.CreateProbeEnrollment(ctx, u, probepki.EnrollmentInput{Token: token, Name: "并发探针", TTLSeconds: 3600})
	require(t, err)
	csr, _, _ := probepki.NewCSR(id)
	var wg sync.WaitGroup
	outcomes := make(chan error, 2)
	jobs := make(chan probepki.Job, 2)
	for range 2 {
		wg.Go(func() {
			j, send, err := f.Runtime.BeginProbeEnrollment(ctx, probepki.Exchange{Token: token, CSR: csr})
			if send {
				jobs <- j
			}
			outcomes <- err
		})
	}
	wg.Wait()
	close(outcomes)
	close(jobs)
	accepted, conflict := 0, 0
	for err := range outcomes {
		if err == nil {
			accepted++
		} else if errors.Is(err, probepki.ErrConflict) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if accepted != 1 || conflict != 1 {
		t.Fatal("同一令牌并发提交产生多次签发")
	}
	job := <-jobs
	_, err = f.Runtime.FinishProbeCertificate(ctx, job, probepki.Certificate{}, errors.New("CA 回执中断"))
	if !errors.Is(err, probepki.ErrConflict) {
		t.Fatal("签发中断未保留未知结果", err)
	}
	if _, _, err = f.Runtime.BeginProbeEnrollment(ctx, probepki.Exchange{Token: token, CSR: csr}); !errors.Is(err, probepki.ErrConflict) {
		t.Fatal("未知签发被自动重试")
	}
	// 原 token 未变更；管理员可撤销并创建独立凭据，不能更改现有探针的注册代次。
	other := id
	other.RegistrationID = "foreign_registration"
	badToken, _ := probepki.NewCredential(other, "wrong_registration")
	if _, err = f.Runtime.CreateProbeEnrollment(ctx, u, probepki.EnrollmentInput{Token: badToken, Name: "并发探针", TTLSeconds: 3600}); !errors.Is(err, store.ErrConflict) {
		t.Fatal("注册令牌覆盖当前代次", err)
	}
	token2, _ := probepki.NewCredential(id, "recovery_enrollment")
	_, err = f.Runtime.CreateProbeEnrollment(ctx, u, probepki.EnrollmentInput{Token: token2, Name: "并发探针", TTLSeconds: 3600})
	require(t, err)
	job, send, err := f.Runtime.BeginProbeEnrollment(ctx, probepki.Exchange{Token: token2, CSR: csr})
	require(t, err)
	if !send {
		t.Fatal("独立授权未进入签发")
	}
	issued, err := ca.Sign(ctx, job)
	require(t, err)
	require(t, f.Runtime.RevokeProbeEnrollment(ctx, u, "recovery_enrollment"))
	if _, err = f.Runtime.FinishProbeCertificate(ctx, job, issued, nil); err == nil {
		t.Fatal("签发期间撤销令牌后仍启用证书")
	}
	viewer := u
	viewer.Role = "viewer"
	if _, err = f.Runtime.CreateProbeEnrollment(ctx, viewer, probepki.EnrollmentInput{Token: token, Name: "并发探针", TTLSeconds: 3600}); !errors.Is(err, probepki.ErrInput) {
		t.Fatal("只读身份可以创建注册授权", err)
	}
	unknown, _ := probepki.NewCredential(id, "absent_enrollment")
	if _, _, err = f.Runtime.BeginProbeEnrollment(ctx, probepki.Exchange{Token: unknown, CSR: csr}); !errors.Is(err, probepki.ErrDenied) {
		t.Fatal("未登记的凭据可以签发", err)
	}
	if _, _, err = f.Runtime.BeginProbeRenewal(ctx, id, strings.Repeat("0", 64), csr); !errors.Is(err, probepki.ErrDenied) {
		t.Fatal("未登记的父证书可以续签", err)
	}
	for index := range 3 {
		credential, _ := probepki.NewCredential(id, fmt.Sprintf("quota_enrollment_%d", index))
		_, err = f.Runtime.CreateProbeEnrollment(ctx, u, probepki.EnrollmentInput{Token: credential, Name: "并发探针", TTLSeconds: 3600})
		require(t, err)
	}
	credential, _ := probepki.NewCredential(id, "quota_excess_enrollment")
	if _, err = f.Runtime.CreateProbeEnrollment(ctx, u, probepki.EnrollmentInput{Token: credential, Name: "并发探针", TTLSeconds: 3600}); !errors.Is(err, probepki.ErrQuota) {
		t.Fatal("同一探针超过四个有效授权", err)
	}
	if _, _, err = f.Runtime.ProbeCertificates(ctx, u, "invalid.probe", ""); !errors.Is(err, probepki.ErrInput) {
		t.Fatal("证书目录接受非法探针标识", err)
	}
	if _, _, err = f.Runtime.ProbeEnrollments(ctx, u, "invalid.cursor"); !errors.Is(err, probepki.ErrInput) {
		t.Fatal("注册目录接受非法游标", err)
	}
	if _, err = f.Runtime.RevokeProbeCertificate(ctx, u, "invalid.certificate"); !errors.Is(err, probepki.ErrInput) {
		t.Fatal("吊销接受非法证书标识", err)
	}
	if err = f.Runtime.RevokeProbeEnrollment(ctx, u, "invalid.enrollment"); !errors.Is(err, probepki.ErrInput) {
		t.Fatal("撤销接受非法注册标识", err)
	}
}

func TestProbeRevocationDoesNotHoldCertificateRowWhileWaitingForSigner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	f, u, _, _ := accountFixture(t, ctx)
	ca := newProbeTestAuthority(t)
	id := transport.SensorIdentity{TenantID: u.TenantID, SensorID: "lock_order_probe", RegistrationID: "lock_order_registration"}
	token, _ := probepki.NewCredential(id, "lock_order_enrollment")
	_, err := f.Runtime.CreateProbeEnrollment(ctx, u, probepki.EnrollmentInput{Token: token, Name: "证书并发核对", TTLSeconds: 3600})
	require(t, err)
	csr, _, _ := probepki.NewCSR(id)
	job, send, err := f.Runtime.BeginProbeEnrollment(ctx, probepki.Exchange{Token: token, CSR: csr})
	require(t, err)
	if !send {
		t.Fatal("签发未进入预期状态")
	}
	issued, err := ca.Sign(ctx, job)
	require(t, err)
	cert, err := f.Runtime.FinishProbeCertificate(ctx, job, issued, nil)
	require(t, err)
	finished := make(chan error, 1)
	err = f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		key := id.TenantID + "/probe-certificates/" + id.SensorID
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, key); err != nil {
			return err
		}
		go func() { _, err := f.Runtime.RevokeProbeCertificate(ctx, u, cert.ID); finished <- err }()
		deadline := time.Now().Add(5 * time.Second)
		for {
			var waiting bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted AND classid=((hashtextextended($1,0)>>32)&4294967295)::oid AND objid=(hashtextextended($1,0)&4294967295)::oid AND objsubid=1)`, key).Scan(&waiting); err != nil {
				return err
			}
			if waiting {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("未观察到当前探针的并发吊销等待")
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(20 * time.Millisecond):
			}
		}
		// 持有签发锁时证书行仍可取得，吊销不能形成“行锁→探针锁”的反向等待。
		var locked string
		return tx.QueryRow(ctx, `SELECT id FROM probe_certificates WHERE tenant_id=$1 AND id=$2 FOR UPDATE NOWAIT`, u.TenantID, cert.ID).Scan(&locked)
	})
	require(t, err)
	select {
	case err := <-finished:
		require(t, err)
	case <-ctx.Done():
		t.Fatal("吊销未在签发锁释放后完成")
	}
	if err = f.Runtime.SensorCertificateActive(ctx, id, cert.Fingerprint, cert.NotAfter); !errors.Is(err, store.ErrSensorInactive) {
		t.Fatal("并发吊销没有生效", err)
	}
}

func TestProbeCertificateFinalizationSerializesWithCredentialAuthorityChanges(t *testing.T) {
	for _, change := range []string{"enrollment", "administrator"} {
		t.Run(change, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			f, u, _, _ := accountFixture(t, ctx)
			ca := newProbeTestAuthority(t)
			id := transport.SensorIdentity{TenantID: u.TenantID, SensorID: "finalization_probe", RegistrationID: "finalization_registration"}
			token, _ := probepki.NewCredential(id, "finalization_enrollment")
			_, err := f.Runtime.CreateProbeEnrollment(ctx, u, probepki.EnrollmentInput{Token: token, Name: "签发授权核对", TTLSeconds: 3600})
			require(t, err)
			csr, _, _ := probepki.NewCSR(id)
			job, _, err := f.Runtime.BeginProbeEnrollment(ctx, probepki.Exchange{Token: token, CSR: csr})
			require(t, err)
			issued, err := ca.Sign(ctx, job)
			require(t, err)
			finished := make(chan error, 1)
			err = f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
				key := u.TenantID + "/users"
				if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, key); err != nil {
					return err
				}
				go func() { _, err := f.Runtime.FinishProbeCertificate(ctx, job, issued, nil); finished <- err }()
				deadline := time.Now().Add(5 * time.Second)
				for {
					var waiting bool
					if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted AND classid=((hashtextextended($1,0)>>32)&4294967295)::oid AND objid=(hashtextextended($1,0)&4294967295)::oid AND objsubid=1)`, key).Scan(&waiting); err != nil {
						return err
					}
					if waiting {
						break
					}
					if time.Now().After(deadline) {
						return fmt.Errorf("签发收尾未等待当前授权事务")
					}
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-time.After(20 * time.Millisecond):
					}
				}
				// 测试所有者只模拟持有授权锁的管理员事务，不将直接 SQL 当作产品管理入口。
				if change == "enrollment" {
					_, err := tx.Exec(ctx, `UPDATE probe_enrollments SET revoked=true WHERE tenant_id=$1 AND id='finalization_enrollment'`, u.TenantID)
					return err
				}
				_, err := tx.Exec(ctx, `UPDATE users SET role='viewer' WHERE tenant_id=$1 AND id=$2`, u.TenantID, u.ID)
				return err
			})
			require(t, err)
			select {
			case err := <-finished:
				if err == nil {
					t.Fatal("授权撤销后仍然登记签发证书")
				}
			case <-ctx.Done():
				t.Fatal("签发收尾未释放授权等待")
			}
			require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
				var state string
				var fingerprint *string
				if err := tx.QueryRow(ctx, `SELECT state,fingerprint FROM probe_certificates WHERE tenant_id=$1 AND id=$2`, u.TenantID, job.ID).Scan(&state, &fingerprint); err != nil {
					return err
				}
				if state != "unknown" || fingerprint != nil {
					return fmt.Errorf("撤销授权后的 CA 结果被记录为可用身份")
				}
				return nil
			}))
		})
	}
}

func TestProbeCertificateDirectoriesPaginateWithoutDuplicateOrPrivateMaterials(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, u, _, password := accountFixture(t, ctx)
	ca := newProbeTestAuthority(t)
	h := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, Authority: ca}, u.Username, password)
	id := transport.SensorIdentity{TenantID: u.TenantID, SensorID: "paged_probe", RegistrationID: "paged_registration"}
	csr, _, err := probepki.NewCSR(id)
	require(t, err)
	if _, send, err := f.Runtime.BeginProbeEnrollment(ctx, probepki.Exchange{Token: "invalid", CSR: csr}); !errors.Is(err, probepki.ErrInput) || send {
		t.Fatal("无效令牌进入签发", err)
	}
	absent := id
	absent.SensorID = "unregistered_probe"
	absentToken, _ := probepki.NewCredential(absent, "unregistered_enrollment")
	absentCSR, _, err := probepki.NewCSR(absent)
	require(t, err)
	if _, send, err := f.Runtime.BeginProbeEnrollment(ctx, probepki.Exchange{Token: absentToken, CSR: absentCSR}); !errors.Is(err, probepki.ErrDenied) || send {
		t.Fatal("设备可以自行登记探针身份", err)
	}
	for index := range 21 {
		token, err := probepki.NewCredential(id, fmt.Sprintf("paged_enrollment_%02d", index))
		require(t, err)
		_, err = f.Runtime.CreateProbeEnrollment(ctx, u, probepki.EnrollmentInput{Token: token, Name: "分页验收探针", TTLSeconds: 3600})
		require(t, err)
		if index == 0 {
			if _, send, err := f.Runtime.BeginProbeEnrollment(ctx, probepki.Exchange{Token: token, CSR: "invalid"}); !errors.Is(err, probepki.ErrInput) || send {
				t.Fatal("无效 CSR 进入签发", err)
			}
		}
		job, send, err := f.Runtime.BeginProbeEnrollment(ctx, probepki.Exchange{Token: token, CSR: csr})
		require(t, err)
		if !send {
			t.Fatal("独立授权未产生独立签发记录")
		}
		cert, err := ca.Sign(ctx, job)
		require(t, err)
		if index == 0 {
			wrong := cert
			wrong.ID = "another_job"
			if _, err := f.Runtime.FinishProbeCertificate(ctx, job, wrong, nil); !errors.Is(err, probepki.ErrInput) {
				t.Fatal("错误签发绑定被接受", err)
			}
		}
		_, err = f.Runtime.FinishProbeCertificate(ctx, job, cert, nil)
		require(t, err)
		// 首次注册授权撤销不吊销已签发证书；连续取得独立授权以验证跨页目录。
		require(t, f.Runtime.RevokeProbeEnrollment(ctx, u, fmt.Sprintf("paged_enrollment_%02d", index)))
	}
	for _, path := range []string{"/sensor-enrollments", "/sensors/paged_probe/certificates"} {
		seen := map[string]bool{}
		cursor := ""
		for pageIndex := range 2 {
			var page struct {
				Items []json.RawMessage `json:"items"`
				Next  string            `json:"next_cursor"`
			}
			query := path
			if cursor != "" {
				query += "?cursor=" + cursor
			}
			h.request("GET", query, "", nil, &page, 200)
			want := 20
			if pageIndex == 1 {
				want = 1
			}
			if len(page.Items) != want || (pageIndex == 0) != (page.Next != "") {
				t.Fatal("目录分页边界或结束游标错误", path, len(page.Items), page.Next)
			}
			for _, raw := range page.Items {
				var item struct{ ID string }
				require(t, json.Unmarshal(raw, &item))
				if item.ID == "" || seen[item.ID] || strings.Contains(string(raw), "-----BEGIN") || strings.Contains(string(raw), "csr_pem") || strings.Contains(string(raw), "chain_pem") {
					t.Fatal("目录记录重复或返回签发材料", path)
				}
				seen[item.ID] = true
			}
			cursor = page.Next
		}
		if len(seen) != 21 {
			t.Fatal("目录跨页丢失记录", path, len(seen))
		}
	}
	viewer := u
	viewer.Role = "viewer"
	if _, _, err := f.Runtime.ProbeEnrollments(ctx, viewer, ""); err == nil {
		t.Fatal("只读身份读取注册授权目录")
	}
}
