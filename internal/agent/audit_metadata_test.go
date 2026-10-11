package agent

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/kkx600/StarBeacon/internal/model"
	bolt "go.etcd.io/bbolt"
)

func TestLocalOperationMetadataAndCancelledConfigurationTransaction(t *testing.T) {
	w, err := OpenWAL(filepath.Join(t.TempDir(), "audit.db"), "tenant_audit", "sensor_audit", "registration_audit", 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	meta := model.RequestMetadata{SourceIP: "192.0.2.11", UserAgent: "StarBeacon采集器验收", RequestID: "request_login"}
	ctx := model.WithRequestMetadata(context.Background(), meta)
	if err = w.RecordLocalOperation(ctx, "admin", "pcap.download.request", "packet_owned", "request_operation"); err != nil {
		t.Fatal(err)
	}
	if err = w.SaveLocalConfigWithContext(ctx, []byte(`{"interfaces":[]}`), "admin", "request_config"); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err = w.SaveLocalConfigWithContext(cancelled, []byte(`{"interfaces":["invalid"]}`), "admin", "request_cancelled"); !errors.Is(err, context.Canceled) {
		t.Fatal("已取消请求提交本机配置", err)
	}
	config, err := w.LocalConfig()
	if err != nil || string(config) != `{"interfaces":[]}` {
		t.Fatal("取消请求覆盖了已有配置")
	}
	count := 0
	if err = w.DB.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("local_audits")).ForEach(func(_, value []byte) error {
			var record LocalAudit
			if err := json.Unmarshal(value, &record); err != nil {
				return err
			}
			count++
			if record.SourceIP != meta.SourceIP || record.UserAgent != meta.UserAgent || record.RequestID == "request_cancelled" {
				t.Error("审计元数据缺失或事务取消仍生成审计")
			}
			return nil
		})
	}); err != nil || count != 2 {
		t.Fatal("本机操作审计事务不正确", err, count)
	}
}
