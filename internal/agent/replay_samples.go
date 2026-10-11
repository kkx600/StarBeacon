package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/model"
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

// 未完成导入与待回收记录只用于本地容量核算，不作为可重放样本发布。
type localSample struct {
	replay.Sample
	State string `json:"state,omitempty"`
}

func (s *ReplayService) reserveSample(ctx context.Context, sample replay.Sample) error {
	if sample.Origin != nil && !sample.Origin.Valid() {
		return errors.New("样本来源描述无效")
	}
	return s.WAL.DB.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b, err := tx.CreateBucketIfNotExists([]byte("replay_samples"))
		if err != nil {
			return err
		}
		if b.Stats().KeyN >= replay.MaxSamples {
			return replay.ErrQuota
		}
		if b.Get([]byte(sample.ID)) != nil {
			return errors.New("样本身份已存在")
		}
		raw, err := json.Marshal(localSample{Sample: sample, State: "uploading"})
		if err != nil {
			return err
		}
		return b.Put([]byte(sample.ID), raw)
	})
}

func (s *ReplayService) removePendingSample(id string) error {
	return s.WAL.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("replay_samples"))
		if b == nil || b.Get([]byte(id)) == nil {
			return nil
		}
		var sample localSample
		if err := json.Unmarshal(b.Get([]byte(id)), &sample); err != nil {
			return err
		}
		if sample.State != "uploading" {
			return nil
		}
		return b.Delete([]byte(id))
	})
}

func (s *ReplayService) Sample(id string) (replay.Sample, error) {
	var v replay.Sample
	e := s.WAL.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("replay_samples"))
		if b == nil || b.Get([]byte(id)) == nil {
			return errors.New("样本不存在")
		}
		var sample localSample
		if err := json.Unmarshal(b.Get([]byte(id)), &sample); err != nil {
			return err
		}
		if sample.State != "" || sample.SHA256 == "" || sample.Origin != nil && !sample.Origin.Valid() {
			return errors.New("样本未发布")
		}
		v = sample.Sample
		return nil
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
				var sample localSample
				if e := json.Unmarshal(v, &sample); e != nil {
					return e
				}
				if sample.State == "" && sample.SHA256 != "" && sample.ExpiresAt.After(time.Now()) {
					items = append(items, sample.Sample)
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
	importer := func(httpRaw bool) http.HandlerFunc {
		return auth.Require(true, func(w http.ResponseWriter, r *http.Request) {
			now := time.Now().UTC()
			var body io.Reader
			var size int64
			var name string
			var origin *replay.Origin
			var e error
			if httpRaw {
				body, size, name, origin, e = replay.HTTPUpload(w, r, now)
			} else {
				body, size, name, e = replay.UploadBody(w, r)
			}
			if e != nil {
				httpapi.Fail(w, r, 400, "invalid_sample", e.Error())
				return
			}
			sample := replay.Sample{ID: store.RandomID("sample_"), Name: name, Size: size, CreatedAt: now, ExpiresAt: now.AddDate(0, 0, s.RetentionDays), Origin: origin}
			if e = s.reserveSample(r.Context(), sample); e != nil {
				if errors.Is(e, replay.ErrQuota) {
					httpapi.Fail(w, r, 409, "sample_limit", "本地样本数量达到上限，请等待留存清理")
				} else {
					httpapi.Fail(w, r, 503, "storage_unavailable", "样本名额预留失败")
				}
				return
			}
			published := false
			defer func() {
				if published {
					return
				}
				cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				// 对象删除成功后才释放预留，失败记录由后续有界清理重试。
				if s.Storage.Remove(cleanup, replay.Key(s.WAL.TenantID, sample.ID)) == nil {
					_ = s.removePendingSample(sample.ID)
				}
			}()
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
				if err := r.Context().Err(); err != nil {
					return err
				}
				b := tx.Bucket([]byte("replay_samples"))
				var reserved localSample
				if b == nil || b.Get([]byte(sample.ID)) == nil {
					return errors.New("样本预留已失效")
				}
				if e := json.Unmarshal(b.Get([]byte(sample.ID)), &reserved); e != nil {
					return e
				}
				if reserved.State != "uploading" {
					return errors.New("样本预留已失效")
				}
				if e = b.Put([]byte(sample.ID), raw); e != nil {
					return e
				}
				meta := model.RequestMetadataFrom(r.Context())
				return appendAudit(tx, LocalAudit{Username: httpapi.Principal(r).Username, Action: "replay.sample.import", RequestID: httpapi.RequestID(r), SourceIP: meta.SourceIP, UserAgent: meta.UserAgent, CreatedAt: now, ExpiresAt: now.AddDate(0, 0, 180)})
			})
			if e != nil {
				httpapi.Fail(w, r, 503, "storage_unavailable", "样本索引保存失败")
				return
			}
			published = true
			httpapi.JSON(w, 201, sample)
		})
	}
	m.HandleFunc("POST /api/local/v1/replay/samples", importer(false))
	m.HandleFunc("POST /api/local/v1/replay/samples/http", importer(true))
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
		p := control.Replay{SampleID: sample.ID, SampleSize: sample.Size, SampleSHA256: sample.SHA256, RuleMode: input.RuleMode, Origin: sample.Origin}
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
	type candidate struct {
		id  string
		raw []byte
	}
	candidates := []candidate{}
	now := time.Now()
	err := s.WAL.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("replay_samples"))
		if b == nil {
			return nil
		}
		cursor := b.Cursor()
		for k, raw := cursor.First(); k != nil && len(candidates) < 100; k, raw = cursor.Next() {
			if e := ctx.Err(); e != nil {
				return e
			}
			var v localSample
			if e := json.Unmarshal(raw, &v); e != nil {
				return e
			}
			if v.ID != string(k) {
				return errors.New("样本索引身份不一致")
			}
			if v.State == "deleting" || v.ExpiresAt.Add(5*time.Minute).Before(now) || (v.State == "uploading" && v.CreatedAt.Before(now.Add(-time.Hour))) {
				candidates = append(candidates, candidate{id: v.ID, raw: bytes.Clone(raw)})
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	// 磁盘操作不持有 WAL 写事务；回收标记在崩溃后可重试，并保留容量核算。
	for _, item := range candidates {
		var marked []byte
		err = s.WAL.DB.Update(func(tx *bolt.Tx) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			b := tx.Bucket([]byte("replay_samples"))
			if !bytes.Equal(b.Get([]byte(item.id)), item.raw) {
				return nil
			}
			var sample localSample
			if err := json.Unmarshal(item.raw, &sample); err != nil {
				return err
			}
			sample.State = "deleting"
			var err error
			marked, err = json.Marshal(sample)
			if err != nil {
				return err
			}
			return b.Put([]byte(item.id), marked)
		})
		if err != nil {
			return err
		}
		if marked == nil {
			continue
		}
		if err = s.Storage.Remove(ctx, replay.Key(s.WAL.TenantID, item.id)); err != nil {
			return err
		}
		if err = s.WAL.DB.Update(func(tx *bolt.Tx) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			b := tx.Bucket([]byte("replay_samples"))
			if !bytes.Equal(b.Get([]byte(item.id)), marked) {
				return nil
			}
			return b.Delete([]byte(item.id))
		}); err != nil {
			return err
		}
	}
	keys := []string{}
	if err = s.WAL.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("replay_samples"))
		if b == nil {
			return nil
		}
		return b.ForEach(func(id, _ []byte) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			keys = append(keys, replay.Key(s.WAL.TenantID, string(id)))
			return nil
		})
	}); err != nil {
		return err
	}
	return s.Storage.PurgeOrphans(ctx, keys)
}
