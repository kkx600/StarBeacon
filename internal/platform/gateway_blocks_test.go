package platform

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/gatewayblock"
	"github.com/kkx600/StarBeacon/internal/store"
)

func TestGatewayBlockAPIRejectsMalformedAndUnserviceableRequests(t *testing.T) {
	a := &API{DB: nil}
	digest := strings.Repeat("a", 64)
	review := `{"policy_id":"policy_gateway","policy_revision":1,"assessment_revision":2,"raw_sha256":"` + digest + `"}`
	settings := `{"expected_revision":0,"enabled":true,"per_minute":3}`
	cases := []struct {
		name                       string
		handler                    http.HandlerFunc
		method, query, id, request string
		keys                       []string
		status                     int
	}{
		{name: "设置拒绝查询项", handler: a.gatewayBlockSettings, method: "GET", query: "?tenant=other", status: 400},
		{name: "设置读取缺少数据库", handler: a.gatewayBlockSettings, method: "GET", status: 503},
		{name: "设置重复键", handler: a.saveGatewayBlockSettings, method: "PUT", request: `{"expected_revision":0,"enabled":true,"enabled":false,"per_minute":3}`, status: 400},
		{name: "设置上限缺失", handler: a.saveGatewayBlockSettings, method: "PUT", request: `{"expected_revision":0,"enabled":true}`, status: 400},
		{name: "设置尾随数据", handler: a.saveGatewayBlockSettings, method: "PUT", request: settings + "{}", status: 400},
		{name: "设置写入缺少数据库", handler: a.saveGatewayBlockSettings, method: "PUT", request: settings, status: 503},
		{name: "目录重复游标", handler: a.gatewayBlockPolicies, method: "GET", query: "?cursor=policy_a&cursor=policy_b", status: 400},
		{name: "目录无效页长", handler: a.gatewayBlockPolicies, method: "GET", query: "?limit=0", status: 400},
		{name: "目录读取缺少数据库", handler: a.gatewayBlockPolicies, method: "GET", query: "?limit=10&cursor=policy_a", status: 503},
		{name: "策略拒绝额外字段", handler: a.saveGatewayBlockPolicy, method: "PUT", id: "policy_gateway", request: `{"expected_revision":0,"definition":{"definition":{}}}`, status: 400},
		{name: "请求身份无效", handler: a.gatewayBlockRequest, method: "GET", id: "a/b", status: 400},
		{name: "请求读取缺少数据库", handler: a.gatewayBlockRequest, method: "GET", id: "gateway_request", status: 503},
		{name: "研判重复幂等键", handler: a.createGatewayBlockReview, method: "POST", id: digest, request: review, keys: []string{"approve_gateway", "other_gateway"}, status: 400},
		{name: "研判拒绝改写告警摘要", handler: a.createGatewayBlockReview, method: "POST", id: digest, request: strings.ReplaceAll(review, digest, "raw"), keys: []string{"approve_gateway"}, status: 400},
		{name: "研判提交缺少数据库", handler: a.createGatewayBlockReview, method: "POST", id: digest, request: review, keys: []string{"approve_gateway"}, status: 503},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/api/v1/test"+tc.query, strings.NewReader(tc.request))
			req.SetPathValue("id", tc.id)
			req.Header.Set("Content-Type", "application/json")
			for _, key := range tc.keys {
				req.Header.Add("Idempotency-Key", key)
			}
			w := httptest.NewRecorder()
			tc.handler.ServeHTTP(w, req)
			if w.Code != tc.status {
				t.Fatalf("预期 HTTP %d，得到 %d：%s", tc.status, w.Code, w.Body.String())
			}
		})
	}
}

func TestGatewayBlockAPIErrorContract(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{gatewayblock.ErrInput, 400, "invalid_gateway_block"},
		{gatewayblock.ErrPermission, 403, "gateway_block_forbidden"},
		{pgx.ErrNoRows, 404, "not_found"},
		{store.ErrConflict, 409, "gateway_block_conflict"},
		{store.ErrAlertIdentity, 409, "gateway_block_conflict"},
		{gatewayblock.ErrLimit, 429, "gateway_block_limit"},
		{errors.New("测试内部错误"), 503, "gateway_block_unavailable"},
	} {
		w := httptest.NewRecorder()
		gatewayFailure(w, httptest.NewRequest("GET", "/api/v1/gateway-block/settings", nil), tc.err)
		var body struct{ Code string }
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != tc.status || body.Code != tc.code || strings.Contains(w.Body.String(), "测试内部错误") {
			t.Fatal("网关失败响应有误", tc.err, w.Code, w.Body.String(), err)
		}
	}
}

func TestGatewayBlockReviewRequiresVerifiedAlertStoreAndSigning(t *testing.T) {
	a := &API{DB: &store.Postgres{}, ES: &store.Elasticsearch{}}
	digest := strings.Repeat("a", 64)
	input := `{"policy_id":"policy_gateway","policy_revision":1,"assessment_revision":2,"raw_sha256":"` + digest + `"}`
	r := httptest.NewRequest("POST", "/api/v1/alerts/"+digest+"/gateway-blocks", strings.NewReader(input))
	r.SetPathValue("id", digest)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", "approve_gateway")
	w := httptest.NewRecorder()
	a.createGatewayBlockReview(w, r)
	if w.Code != 503 || !strings.Contains(w.Body.String(), "gateway_block_unavailable") {
		t.Fatal("缺少签名时仍进入告警或网关请求读写", w.Code, w.Body.String())
	}
}
