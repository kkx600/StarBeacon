package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/replay"
	"github.com/kkx600/StarBeacon/internal/store"
	bolt "go.etcd.io/bbolt"
)

type ReplayService struct {
	WAL           *WAL
	Storage       *replay.LocalStorage
	Tasks         *TaskManager
	Engine        *Engine
	RetentionDays int
}

func (s *ReplayService) Sample(id string) (replay.Sample, error) {
	var v replay.Sample
	e := s.WAL.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("replay_samples"))
		if b == nil || b.Get([]byte(id)) == nil {
			return errors.New("样本不存在")
		}
		return json.Unmarshal(b.Get([]byte(id)), &v)
	})
	if e == nil && !v.ExpiresAt.After(time.Now()) {
		e = errors.New("样本已过期")
	}
	return v, e
}
func (s *ReplayService) Register(m *http.ServeMux, auth *httpapi.Auth) {
	m.HandleFunc("GET /api/local/v1/replay/samples", auth.Require(true, func(w http.ResponseWriter, r *http.Request) {
		items := []replay.Sample{}
		e := s.WAL.DB.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte("replay_samples"))
			if b == nil {
				return nil
			}
			cursor := b.Cursor()
			for k, v := cursor.Last(); k != nil; k, v = cursor.Prev() {
				var sample replay.Sample
				if e := json.Unmarshal(v, &sample); e != nil {
					return e
				}
				if sample.ExpiresAt.After(time.Now()) {
					items = append(items, sample)
				}
			}
			return nil
		})
		if e != nil {
			httpapi.Fail(w, r, 503, "storage_unavailable", "样本索引不可用")
			return
		}
		sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.After(items[j].CreatedAt) })
		if len(items) > 200 {
			items = items[:200]
		}
		httpapi.JSON(w, 200, map[string]any{"items": items, "available": s.Engine.ReplayAvailable(), "registered_rules_available": s.Engine.Config.SuricataRulesPath != "", "max_bytes": replay.MaxSampleBytes})
	}))
	m.HandleFunc("POST /api/local/v1/replay/samples", auth.Require(true, func(w http.ResponseWriter, r *http.Request) {
		body, size, name, e := replay.UploadBody(w, r)
		if e != nil {
			httpapi.Fail(w, r, 400, "invalid_sample", e.Error())
			return
		}
		now := time.Now().UTC()
		sample := replay.Sample{ID: store.RandomID("sample_"), Name: name, Size: size, CreatedAt: now, ExpiresAt: now.AddDate(0, 0, s.RetentionDays)}
		sample.SHA256, sample.Format, e = s.Storage.Put(r.Context(), replay.Key(s.WAL.TenantID, sample.ID), body, size)
		if e != nil {
			code := 422
			if errors.Is(e, replay.ErrQuota) {
				code = 409
			}
			httpapi.Fail(w, r, code, "sample_import_failed", "样本导入失败，请核对文件格式、长度或存储额度")
			return
		}
		raw, _ := json.Marshal(sample)
		e = s.WAL.DB.Update(func(tx *bolt.Tx) error {
			b, e := tx.CreateBucketIfNotExists([]byte("replay_samples"))
			if e != nil {
				return e
			}
			if e = b.Put([]byte(sample.ID), raw); e != nil {
				return e
			}
			return appendAudit(tx, LocalAudit{Username: httpapi.Principal(r).Username, Action: "replay.sample.import", RequestID: httpapi.RequestID(r), CreatedAt: now, ExpiresAt: now.AddDate(0, 0, 180)})
		})
		if e != nil {
			_ = s.Storage.Remove(context.Background(), replay.Key(s.WAL.TenantID, sample.ID))
			httpapi.Fail(w, r, 503, "storage_unavailable", "样本索引保存失败")
			return
		}
		httpapi.JSON(w, 201, sample)
	}))
	m.HandleFunc("POST /api/local/v1/replay/tasks", auth.Require(true, func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			SampleID string `json:"sample_id"`
			RuleMode string `json:"rule_mode"`
			Rules    string `json:"rules"`
		}
		if e := httpapi.Decode(w, r, &input); e != nil {
			httpapi.Fail(w, r, 400, "invalid_request", "重放参数无效")
			return
		}
		key := r.Header.Get("Idempotency-Key")
		if len(key) < 8 || len(key) > 128 {
			httpapi.Fail(w, r, 400, "idempotency_key_required", "需要提供 8–128 字符的幂等键")
			return
		}
		if !s.Engine.ReplayAvailable() {
			httpapi.Fail(w, r, 409, "replay_isolation_unavailable", "离线重放引擎或隔离环境未配置")
			return
		}
		sample, e := s.Sample(input.SampleID)
		if e != nil {
			httpapi.Fail(w, r, 404, "not_found", "样本不存在或已过期")
			return
		}
		p := control.Replay{SampleID: sample.ID, SampleSize: sample.Size, SampleSHA256: sample.SHA256, RuleMode: input.RuleMode}
		if input.RuleMode == "package" {
			if e = store.ValidateRules(input.Rules); e != nil {
				httpapi.Fail(w, r, 400, "invalid_rules", e.Error())
				return
			}
			p.Package = &control.RulePackage{PackageID: "local_rules", Revision: 1, EngineVersion: "8.0.7", Text: input.Rules, SHA256: control.Digest([]byte(input.Rules))}
		} else if input.RuleMode != "registered" || input.Rules != "" || s.Engine.Config.SuricataRulesPath == "" {
			httpapi.Fail(w, r, 400, "invalid_rules", "请选择登记规则快照或输入指定规则")
			return
		}
		payload, e := control.ReplayPayload(p)
		if e != nil {
			httpapi.Fail(w, r, 400, "invalid_rules", e.Error())
			return
		}
		id, e := s.Tasks.SubmitLocal(payload, key)
		if e != nil {
			httpapi.Fail(w, r, 409, "task_conflict", "重放任务参数冲突或设备执行队列已满")
			return
		}
		httpapi.JSON(w, 202, map[string]string{"id": id})
	}))
}
func (s *ReplayService) Sweep(ctx context.Context) error {
	keys := []string{}
	err := s.WAL.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("replay_samples"))
		if b == nil {
			return nil
		}
		cursor := b.Cursor()
		for k, raw := cursor.First(); k != nil; k, raw = cursor.Next() {
			if e := ctx.Err(); e != nil {
				return e
			}
			var v replay.Sample
			if e := json.Unmarshal(raw, &v); e != nil {
				return e
			}
			if v.ExpiresAt.Add(5 * time.Minute).Before(time.Now()) {
				if e := s.Storage.Remove(ctx, replay.Key(s.WAL.TenantID, v.ID)); e != nil {
					return e
				}
				if e := cursor.Delete(); e != nil {
					return e
				}
			} else {
				keys = append(keys, replay.Key(s.WAL.TenantID, v.ID))
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return s.Storage.PurgeOrphans(ctx, keys)
}
