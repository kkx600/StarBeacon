package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"

	bolt "go.etcd.io/bbolt"
)

type LocalAudit struct {
	Username  string    `json:"username"`
	Action    string    `json:"action"`
	RequestID string    `json:"request_id,omitempty"`
	SourceIP  string    `json:"source_ip,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	ObjectID  string    `json:"object_id,omitempty"`
	Success   *bool     `json:"success,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (w *WAL) RecordLocalOperation(ctx context.Context, username, action, object, request string) error {
	if len(username) < 1 || len(username) > 64 || len(action) < 1 || len(action) > 128 || strings.ContainsAny(username+action, "\x00\r\n") || !contract.ValidID(object) {
		return errors.New("本机操作审计参数无效")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return w.DB.Update(func(tx *bolt.Tx) error {
		meta := model.RequestMetadataFrom(ctx)
		return appendAudit(tx, LocalAudit{Username: username, Action: action, ObjectID: object, RequestID: request, SourceIP: meta.SourceIP, UserAgent: meta.UserAgent, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().AddDate(0, 0, 180)})
	})
}

func appendAudit(tx *bolt.Tx, audit LocalAudit) error {
	b, e := tx.CreateBucketIfNotExists([]byte("local_audits"))
	if e != nil {
		return e
	}
	id, e := b.NextSequence()
	if e != nil {
		return e
	}
	raw, e := json.Marshal(audit)
	if e != nil {
		return e
	}
	if e = b.Put(key(id), raw); e != nil {
		return e
	}
	// 按递增键清理到期记录；写入和清理共享事务，最多处理 256 条避免长事务。
	c := b.Cursor()
	k, v := c.First()
	for n := 0; k != nil && n < 256; n++ {
		var item LocalAudit
		if e = json.Unmarshal(v, &item); e != nil {
			return e
		}
		expires := item.ExpiresAt
		if expires.IsZero() {
			expires = item.CreatedAt.AddDate(0, 0, 180)
		}
		if time.Now().Before(expires) {
			break
		}
		if e = c.Delete(); e != nil {
			return e
		}
		k, v = c.Next()
	}
	return nil
}
