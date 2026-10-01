package agent

import (
	"encoding/json"
	"time"

	bolt "go.etcd.io/bbolt"
)

type LocalAudit struct {
	Username  string    `json:"username"`
	Action    string    `json:"action"`
	RequestID string    `json:"request_id,omitempty"`
	Success   *bool     `json:"success,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
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
