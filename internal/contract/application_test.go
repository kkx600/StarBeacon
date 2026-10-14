package contract

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"
)

func TestApplicationProofHashAndBatchIdentity(t *testing.T) {
	b := batch()
	baseline := bytes.Clone(BatchDigest(b))
	r := b.Records[0]
	r.ApplicationJson = []byte(`{"origin":"suricata_visible_metadata"}`)
	h := sha256.Sum256(r.ApplicationJson)
	r.ApplicationSha256 = h[:]
	Seal(b)
	if bytes.Equal(baseline, b.BatchSha256) || Validate("tenant_test", "sensor_test", "sr_test", b) != nil {
		t.Fatal("分类未参与批次摘要或有效数据被拒绝")
	}
	for _, mode := range []string{"payload", "hash", "absent", "oversized", "json"} {
		t.Run(mode, func(t *testing.T) {
			original, hash := bytes.Clone(r.ApplicationJson), bytes.Clone(r.ApplicationSha256)
			defer func() { r.ApplicationJson, r.ApplicationSha256 = original, hash; Seal(b) }()
			switch mode {
			case "payload":
				r.ApplicationJson = []byte(`{"origin":"forged"}`)
			case "hash":
				r.ApplicationSha256 = nil
			case "absent":
				r.ApplicationJson = nil
			case "oversized":
				r.ApplicationJson = []byte(strings.Repeat(" ", MaxApplicationBytes) + `{}`)
				h := sha256.Sum256(r.ApplicationJson)
				r.ApplicationSha256 = h[:]
			case "json":
				r.ApplicationJson = []byte(`{`)
				h := sha256.Sum256(r.ApplicationJson)
				r.ApplicationSha256 = h[:]
			}
			Seal(b)
			if Validate("tenant_test", "sensor_test", "sr_test", b) == nil {
				t.Fatal("分类内容或摘要错误未拒绝")
			}
		})
	}
	r.ApplicationJson, r.ApplicationSha256 = nil, nil
	Seal(b)
	if !bytes.Equal(baseline, b.BatchSha256) {
		t.Fatal("没有分类的旧批次摘要被改变")
	}
}
