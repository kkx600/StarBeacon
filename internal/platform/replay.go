package platform

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/replay"
	"github.com/kkx600/StarBeacon/internal/store"
)

func (a *API) registerReplay(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/replay/samples", a.Auth.Require(true, a.replaySamples))
	m.HandleFunc("POST /api/v1/replay/samples", a.Auth.Require(true, a.importSample))
	m.HandleFunc("POST /api/v1/replay/samples/http", a.Auth.Require(true, a.importHTTPRaw))
}
func (a *API) replaySamples(w http.ResponseWriter, r *http.Request) {
	items, e := a.DB.Samples(r.Context(), httpapi.Principal(r).TenantID)
	if e != nil {
		operationError(w, r, e)
		return
	}
	httpapi.JSON(w, 200, map[string]any{"items": items, "available": a.Samples != nil, "max_bytes": replay.MaxSampleBytes})
}
func (a *API) importSample(w http.ResponseWriter, r *http.Request) {
	if a.Samples == nil {
		httpapi.Fail(w, r, 503, "sample_storage_unavailable", "平台样本存储未配置")
		return
	}
	body, size, name, e := replay.UploadBody(w, r)
	if e != nil {
		httpapi.Fail(w, r, 400, "invalid_sample", e.Error())
		return
	}
	a.persistSample(w, r, body, size, name, nil)
}

func (a *API) importHTTPRaw(w http.ResponseWriter, r *http.Request) {
	if a.Samples == nil {
		httpapi.Fail(w, r, 503, "sample_storage_unavailable", "平台样本存储未配置")
		return
	}
	body, size, name, origin, err := replay.HTTPUpload(w, r, time.Now())
	if err != nil {
		httpapi.Fail(w, r, 400, "invalid_http_raw", err.Error())
		return
	}
	a.persistSample(w, r, body, size, name, origin)
}

func (a *API) persistSample(w http.ResponseWriter, r *http.Request, body io.Reader, size int64, name string, origin *replay.Origin) {
	u := httpapi.Principal(r)
	v := replay.Sample{ID: store.RandomID("sample_"), Name: name, Size: size, Origin: origin}
	if e := a.DB.ReserveSample(r.Context(), u, v, a.SampleQuota); e != nil {
		if errors.Is(e, replay.ErrQuota) {
			httpapi.Fail(w, r, 409, "sample_quota_exceeded", e.Error())
		} else {
			operationError(w, r, e)
		}
		return
	}
	complete := false
	defer func() {
		if complete {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if a.Samples.Remove(ctx, replay.Key(u.TenantID, v.ID)) == nil {
			_ = a.DB.RemoveSampleRow(ctx, u.TenantID, v.ID)
		}
	}()
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	var e error
	v.SHA256, v.Format, e = a.Samples.Put(ctx, replay.Key(u.TenantID, v.ID), body, size)
	if e != nil {
		if errors.Is(e, replay.ErrQuota) {
			httpapi.Fail(w, r, 409, "sample_quota_exceeded", e.Error())
		} else {
			httpapi.Fail(w, r, 422, "sample_import_failed", "样本导入失败，请核对文件格式、长度和存储状态")
		}
		return
	}
	if e = a.DB.CompleteSample(ctx, u, v.ID, v.SHA256, v.Format, httpapi.RequestID(r)); e != nil {
		operationError(w, r, e)
		return
	}
	complete = true
	v, e = a.DB.Sample(ctx, u.TenantID, v.ID)
	if e != nil {
		operationError(w, r, e)
		return
	}
	httpapi.JSON(w, 201, v)
}
