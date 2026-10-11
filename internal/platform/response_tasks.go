package platform

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/response"
)

func (a *API) createResponseTask(w http.ResponseWriter, r *http.Request) {
	if len(a.Signer) == 0 {
		httpapi.Fail(w, r, 503, "signer_unavailable", "平台任务签名密钥未配置")
		return
	}
	keys := r.Header.Values("Idempotency-Key")
	if len(keys) != 1 || !contract.ValidID(keys[0]) || len(keys[0]) < 8 {
		httpapi.Fail(w, r, 400, "idempotency_key_required", "需要唯一的 8–64 字符规范请求键")
		return
	}
	if r.URL.RawQuery != "" || !contract.ValidID(r.PathValue("id")) {
		httpapi.Fail(w, r, 400, "invalid_request", "联动任务不接受查询参数，探针标识须为规范格式")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
	var input response.Request
	fields := []string{"kind", "connector_id", "config_sha256", "target_ip", "ttl_seconds", "reason", "original_task_id"}
	if err != nil || contract.JSONFields(string(raw), fields, 8192) != nil || json.Unmarshal(raw, &input) != nil || input.Intent.Validate(input.Kind) != nil {
		httpapi.Fail(w, r, 400, "invalid_response_request", "请选择联动设备、单个 IP、期限和操作依据；回读或解除须引用原封禁任务")
		return
	}
	u := httpapi.Principal(r)
	id, err := a.DB.CreateResponseTask(r.Context(), u, r.PathValue("id"), keys[0], input, a.Signer)
	if err != nil {
		switch {
		case errors.Is(err, response.ErrInput):
			httpapi.Fail(w, r, 400, "invalid_response_request", err.Error())
		case errors.Is(err, response.ErrPermission):
			httpapi.Fail(w, r, 403, "permission_denied", err.Error())
		case errors.Is(err, response.ErrQuota):
			httpapi.Fail(w, r, 429, "response_quota_exhausted", err.Error())
		case errors.Is(err, response.ErrUnavailable):
			httpapi.Fail(w, r, 409, "response_device_unavailable", "探针或联动设备尚未就绪，或授权已变化，请刷新后核对")
		default:
			operationError(w, r, err)
		}
		return
	}
	a.Wakeup.Notify(u.TenantID, r.PathValue("id"))
	httpapi.JSON(w, 202, map[string]string{"id": id})
}
