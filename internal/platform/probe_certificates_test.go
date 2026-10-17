package platform

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/probepki"
	"github.com/kkx600/StarBeacon/internal/transport"
)

func TestProbeCertificateHTTPRejectsMalformedAndUnavailableOperations(t *testing.T) {
	a := &API{}
	token, err := probepki.NewCredential(transport.SensorIdentity{TenantID: "tenant", SensorID: "probe", RegistrationID: "reg"}, "enroll")
	if err != nil {
		t.Fatal(err)
	}
	valid, _ := json.Marshal(probepki.EnrollmentInput{Token: token, Name: "办公探针", TTLSeconds: 3600})
	for _, body := range []string{"null", "[]", "{}", `{"token":"a","token":"b"}`, `{"unexpected":true}`, strings.Repeat(" ", 24577), string(valid)} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/v1/sensor-enrollments", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		a.createProbeEnrollment(w, r)
		want := 400
		if body == string(valid) {
			want = 503
		}
		if w.Code != want {
			t.Fatal("注册输入未按契约拒绝", w.Code, want)
		}
	}
	for _, handler := range []http.HandlerFunc{a.probeEnrollments, a.probeCertificates} {
		for _, path := range []string{"/?unknown=1", "/?cursor=a&cursor=b", "/?cursor=a&other=b", "/"} {
			w := httptest.NewRecorder()
			handler(w, httptest.NewRequest("GET", path, nil))
			want := 400
			if path == "/" {
				want = 503
			}
			if w.Code != want {
				t.Fatal("目录参数或依赖状态不符", w.Code)
			}
		}
	}
	for _, handler := range []http.HandlerFunc{a.revokeProbeEnrollment, a.revokeProbeCertificate, a.exchangeProbeEnrollment} {
		for _, item := range []struct {
			path, body string
			want       int
		}{{"/", "{}", 503}, {"/?extra=1", "{}", 400}, {"/", `{"extra":true}`, 400}} {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("POST", item.path, strings.NewReader(item.body))
			r.Header.Set("Content-Type", "application/json")
			handler(w, r)
			if w.Code != item.want {
				t.Fatal("设备交换或撤销请求越过边界", w.Code, item.want)
			}
		}
	}
	for _, header := range []string{"Origin", "Sec-Fetch-Site"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
		r.Header.Set(header, "https://console.example")
		a.exchangeProbeEnrollment(w, r)
		if w.Code != 403 {
			t.Fatal("浏览器上下文允许设备注册")
		}
	}
	for range cap(probeExchanges) {
		probeExchanges <- struct{}{}
	}
	defer func() {
		for range cap(probeExchanges) {
			<-probeExchanges
		}
	}()
	w := httptest.NewRecorder()
	a.exchangeProbeEnrollment(w, httptest.NewRequest("POST", "/", strings.NewReader(`{}`)))
	if w.Code != 429 {
		t.Fatal("注册入口未执行全局并发额度")
	}
}

func TestProbeCertificateHTTPFailurePreservesMeaningWithoutCredentials(t *testing.T) {
	for _, item := range []struct {
		err  error
		want int
	}{{probepki.ErrInput, 400}, {probepki.ErrDenied, 403}, {probepki.ErrConflict, 409}, {probepki.ErrQuota, 429}, {pgx.ErrNoRows, 404}, {errors.New("private authority diagnostic"), 503}} {
		w := httptest.NewRecorder()
		probeFailure(w, httptest.NewRequest("GET", "/", nil), item.err)
		if w.Code != item.want || strings.Contains(w.Body.String(), "private authority diagnostic") {
			t.Fatal("签发错误状态或信息边界错误", w.Code, item.want)
		}
	}
}
