package platform

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/probepki"
)

var probeExchanges = make(chan struct{}, 16)

func (a *API) registerProbeCertificates(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/sensor-enrollments", a.Auth.Require(true, a.probeEnrollments))
	m.HandleFunc("POST /api/v1/sensor-enrollments", a.Auth.Require(true, a.createProbeEnrollment))
	m.HandleFunc("POST /api/v1/sensor-enrollments/exchange", a.exchangeProbeEnrollment)
	m.HandleFunc("POST /api/v1/sensor-enrollments/{id}/revoke", a.Auth.Require(true, a.revokeProbeEnrollment))
	m.HandleFunc("GET /api/v1/sensors/{id}/certificates", a.Auth.Require(true, a.probeCertificates))
	m.HandleFunc("POST /api/v1/sensor-certificates/{id}/revoke", a.Auth.Require(true, a.revokeProbeCertificate))
}

func (a *API) probeEnrollments(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if len(q) > 1 || len(q["cursor"]) > 1 || len(q) == 1 && !q.Has("cursor") {
		probeFailure(w, r, probepki.ErrInput)
		return
	}
	if a.DB == nil {
		httpapi.Fail(w, r, 503, "storage_unavailable", "注册目录暂不可用")
		return
	}
	items, next, err := a.DB.ProbeEnrollments(r.Context(), httpapi.Principal(r), q.Get("cursor"))
	if err != nil {
		probeFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, map[string]any{"items": items, "next_cursor": next, "ca_configured": a.Authority != nil})
}
func probeFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, probepki.ErrInput):
		httpapi.Fail(w, r, 400, "invalid_probe_certificate", "请核对注册绑定、令牌和 CSR")
	case errors.Is(err, probepki.ErrDenied):
		httpapi.Fail(w, r, 403, "probe_credential_unavailable", "注册凭据或探针状态不可用")
	case errors.Is(err, probepki.ErrConflict):
		httpapi.Fail(w, r, 409, "certificate_result_unconfirmed", "CSR 已绑定，或签发结果尚未核实，请保留原提交并联系管理员")
	case errors.Is(err, probepki.ErrQuota):
		httpapi.Fail(w, r, 429, "probe_certificate_quota", "注册操作超过额度，请稍后再试")
	default:
		operationError(w, r, err)
	}
}
func (a *API) probeCAReady(w http.ResponseWriter, r *http.Request) bool {
	if a.DB == nil || a.Authority == nil {
		httpapi.Fail(w, r, 503, "probe_ca_unavailable", "探针证书签发服务未配置")
		return false
	}
	return true
}
func probeDecode(w http.ResponseWriter, r *http.Request, target any, fields []string) bool {
	var raw bytes.Buffer
	r.Body = http.MaxBytesReader(w, r.Body, 24576)
	r.Body = io.NopCloser(io.TeeReader(r.Body, &raw))
	if r.URL.RawQuery != "" || httpapi.Decode(w, r, target) != nil || contract.JSONFields(raw.String(), fields, 24576) != nil {
		probeFailure(w, r, probepki.ErrInput)
		return false
	}
	return true
}
func (a *API) createProbeEnrollment(w http.ResponseWriter, r *http.Request) {
	var input probepki.EnrollmentInput
	if !probeDecode(w, r, &input, []string{"token", "name", "ttl_seconds"}) {
		return
	}
	if input.Validate() != nil {
		probeFailure(w, r, probepki.ErrInput)
		return
	}
	if !a.probeCAReady(w, r) {
		return
	}
	out, err := a.DB.CreateProbeEnrollment(r.Context(), httpapi.Principal(r), input)
	if err != nil {
		probeFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, out)
}
func (a *API) exchangeProbeEnrollment(w http.ResponseWriter, r *http.Request) {
	// 此入口只接受设备持有的独立注册凭据，不继承浏览器会话权限。
	if r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") != "" {
		httpapi.Fail(w, r, 403, "device_enrollment_required", "请使用探针注册工具提交 CSR")
		return
	}
	select {
	case probeExchanges <- struct{}{}:
		defer func() { <-probeExchanges }()
	default:
		httpapi.Fail(w, r, 429, "probe_ca_busy", "注册请求繁忙，请保留原 CSR 稍后重试")
		return
	}
	var input probepki.Exchange
	if !probeDecode(w, r, &input, []string{"token", "csr_pem"}) {
		return
	}
	if !a.probeCAReady(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	j, send, err := a.DB.BeginProbeEnrollment(ctx, input)
	if err != nil {
		probeFailure(w, r, err)
		return
	}
	c := j.Certificate
	if send {
		issued, signErr := a.Authority.Sign(ctx, j)
		finish, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		c, err = a.DB.FinishProbeCertificate(finish, j, issued, signErr)
		stop()
		if err != nil {
			probeFailure(w, r, err)
			return
		}
	}
	httpapi.JSON(w, 200, c)
}
func (a *API) probeCertificates(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if len(q) > 1 || len(q["cursor"]) > 1 || len(q) == 1 && !q.Has("cursor") {
		probeFailure(w, r, probepki.ErrInput)
		return
	}
	if a.DB == nil {
		httpapi.Fail(w, r, 503, "storage_unavailable", "证书目录暂不可用")
		return
	}
	items, next, err := a.DB.ProbeCertificates(r.Context(), httpapi.Principal(r), r.PathValue("id"), q.Get("cursor"))
	if err != nil {
		probeFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, map[string]any{"items": items, "next_cursor": next})
}
func (a *API) revokeProbeEnrollment(w http.ResponseWriter, r *http.Request) {
	var input struct{}
	if !probeDecode(w, r, &input, []string{}) {
		return
	}
	if a.DB == nil {
		httpapi.Fail(w, r, 503, "storage_unavailable", "注册目录暂不可用")
		return
	}
	if err := a.DB.RevokeProbeEnrollment(r.Context(), httpapi.Principal(r), r.PathValue("id")); err != nil {
		probeFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, map[string]bool{"revoked": true})
}
func (a *API) revokeProbeCertificate(w http.ResponseWriter, r *http.Request) {
	var input struct{}
	if !probeDecode(w, r, &input, []string{}) {
		return
	}
	if a.DB == nil {
		httpapi.Fail(w, r, 503, "storage_unavailable", "证书目录暂不可用")
		return
	}
	u := httpapi.Principal(r)
	c, err := a.DB.RevokeProbeCertificate(r.Context(), u, r.PathValue("id"))
	if err != nil {
		probeFailure(w, r, err)
		return
	}
	if c.CARevocation != "confirmed" && a.Authority != nil {
		call, stop := context.WithTimeout(r.Context(), 10*time.Second)
		err = a.Authority.Revoke(call, c.Serial, "revoke_"+c.ID)
		stop()
		finish, done := context.WithTimeout(context.WithoutCancel(r.Context()), 3*time.Second)
		persist := a.DB.SetProbeCARevocation(finish, u.TenantID, c.ID, err == nil)
		done()
		c.CARevocation = "unknown"
		if err == nil && persist == nil {
			c.CARevocation = "confirmed"
		}
	}
	// 平台拒绝该指纹已在事务中生效；CA 不可用不撤销本地吊销。
	httpapi.JSON(w, 200, c)
}
