package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/contract"
)

const eveSample = `{"timestamp":"2026-10-01T00:00:00Z","event_type":"alert","src_ip":"192.0.2.1","dest_ip":"10.0.0.1","alert":{"signature_id":10001,"severity":1}}`

func readerFor(t *testing.T, max uint64) (*WAL, *EVEReader, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	if e := os.WriteFile(path, []byte(eveSample+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	w, e := OpenWAL(filepath.Join(dir, "wal.db"), "tenant_test", "sensor_test", "sr_test", max)
	if e != nil {
		t.Fatal(e)
	}
	r := &EVEReader{WAL: w, Path: path, Route: func(context.Context, string) (string, error) { return "route_test", nil }}
	t.Cleanup(func() { r.Close(); w.Close() })
	return w, r, path
}
func TestSourceCheckpointWaitsForCompleteLineAndDurableWAL(t *testing.T) {
	w, r, path := readerFor(t, 4096)
	if e := os.WriteFile(path, []byte(eveSample), 0600); e != nil {
		t.Fatal(e)
	}
	if e := r.Poll(context.Background()); e != nil {
		t.Fatal(e)
	}
	count, _, _ := w.Stats()
	if count != 0 {
		t.Fatal("半行进入了队列")
	}
	if e := os.WriteFile(path, []byte(eveSample+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := r.Poll(context.Background()); e != nil {
		t.Fatal(e)
	}
	s, _ := w.Source()
	if s.Offset != uint64(len(eveSample)+1) {
		t.Fatal("检查点不对应完整来源区间")
	}
	b, _ := w.Next("alerts")
	if e := contract.Validate("tenant_test", "sensor_test", "sr_test", b); e != nil {
		t.Fatal(e)
	}
}
func TestWrongAckDoesNotReleaseWALAndRestartKeepsIdentity(t *testing.T) {
	w, r, _ := readerFor(t, 4096)
	if e := r.Poll(context.Background()); e != nil {
		t.Fatal(e)
	}
	first, _ := w.Next("alerts")
	a := &sensorv1.IngestAck{BatchId: first.BatchId, ProducerEpoch: first.ProducerEpoch, SensorRegistrationId: first.SensorRegistrationId, StreamId: first.StreamId, BatchSha256: first.BatchSha256, Status: sensorv1.AckStatus_ACK_STATUS_ACCEPTED, AcceptedRanges: []*sensorv1.SequenceRange{{First: 1, Last: 2}}}
	if w.Confirm(first, a) == nil {
		t.Fatal("越界确认释放数据")
	}
	count, _, _ := w.Stats()
	if count != 1 {
		t.Fatal("待传事件丢失")
	}
	path := w.DB.Path()
	w.Close()
	restored, e := OpenWAL(path, "tenant_test", "sensor_test", "sr_test", 4096)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { restored.Close() })
	retry, _ := restored.Next("alerts")
	if retry.BatchId != first.BatchId || retry.Records[0].EventId != first.Records[0].EventId {
		t.Fatal("重启改变稳定身份")
	}
	a.AcceptedRanges = contract.Ranges(retry.Records)
	if e = restored.Confirm(retry, a); e != nil {
		t.Fatal(e)
	}
	count, _, _ = restored.Stats()
	if count != 0 {
		t.Fatal("合法确认未回收数据")
	}
}
func TestWALFullPreservesSourceOffset(t *testing.T) {
	w, r, _ := readerFor(t, 1)
	if !errors.Is(r.Poll(context.Background()), ErrWALFull) {
		t.Fatal("容量背压未发生")
	}
	s, _ := w.Source()
	if s.Offset != 0 {
		t.Fatal("磁盘队列失败后推进检查点")
	}
}
func TestLogRotationDrainsOldFileBeforeNewGeneration(t *testing.T) {
	w, r, path := readerFor(t, 8192)
	if e := r.Poll(context.Background()); e != nil {
		t.Fatal(e)
	}
	old, _ := w.Source()
	if e := os.Rename(path, path+".1"); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, []byte(eveSample+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := r.Poll(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e := r.Poll(context.Background()); e != nil {
		t.Fatal(e)
	}
	now, _ := w.Source()
	if now.Generation == old.Generation {
		t.Fatal("轮转没有产生新的来源代次")
	}
	b, _ := w.Next("alerts")
	if len(b.Records) != 2 || b.Records[0].EventId == b.Records[1].EventId {
		t.Fatal("真实重复行被合并或丢失")
	}
}
func TestRegistrationCannotTakeOverExistingWAL(t *testing.T) {
	w, _, _ := readerFor(t, 8192)
	path := w.DB.Path()
	w.Close()
	other, e := OpenWAL(path, "tenant_other", "sensor_test", "sr_other", 8192)
	if e == nil {
		other.Close()
		t.Fatal("新身份接管了旧队列")
	}
}

func TestBatchCommitRollsBackAllRecordsAtQuota(t *testing.T) {
	w, r, path := readerFor(t, 1000)
	if e := os.WriteFile(path, []byte(strings.Repeat(eveSample+"\n", 4)), 0600); e != nil {
		t.Fatal(e)
	}
	if e := r.Poll(context.Background()); !errors.Is(e, ErrWALFull) {
		t.Fatalf("期望容量背压，实际 %v", e)
	}
	count, _, e := w.Stats()
	if e != nil || count != 0 {
		t.Fatal("失败事务留下部分事件")
	}
	s, _ := w.Source()
	if s.Offset != 0 {
		t.Fatal("失败事务推进了来源")
	}
	w.MaxBytes = 8192
	if e = r.Poll(context.Background()); e != nil {
		t.Fatal(e)
	}
	b, e := w.Next("alerts")
	if e != nil || len(b.Records) != 4 || b.Records[0].Sequence != 1 {
		t.Fatal("重试丢失或跳过事件")
	}
}

func TestCopyTruncateWithChangedPrefixCreatesGeneration(t *testing.T) {
	w, r, path := readerFor(t, 8192)
	if e := r.Poll(context.Background()); e != nil {
		t.Fatal(e)
	}
	old, _ := w.Source()
	replacement := strings.Replace(eveSample, "192.0.2.1", "192.0.2.2", 1) + "\n"
	if e := os.WriteFile(path, []byte(replacement), 0600); e != nil {
		t.Fatal(e)
	}
	if e := r.Poll(context.Background()); e != nil {
		t.Fatal(e)
	}
	s, _ := w.Source()
	if s.Generation == old.Generation {
		t.Fatal("来源覆盖产生了身份碰撞")
	}
	b, _ := w.Next("alerts")
	if len(b.Records) != 2 {
		t.Fatal("覆盖后的记录被跳过")
	}
}

func TestEmptyLineCanBeUploadedForQuarantine(t *testing.T) {
	w, r, path := readerFor(t, 8192)
	if e := os.WriteFile(path, []byte("\n"+eveSample+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := r.Poll(context.Background()); e != nil {
		t.Fatal(e)
	}
	b, e := w.Next("context")
	if e != nil {
		t.Fatal(e)
	}
	if e = contract.Validate("tenant_test", "sensor_test", "sr_test", b); e != nil {
		t.Fatal("空行阻塞了批次上传", e)
	}
	if string(b.Records[0].Payload) != "\n" {
		t.Fatal("空行原始字节未保留")
	}
}

func BenchmarkEVEToDurableWAL(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "eve.json")
	file, e := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		b.Fatal(e)
	}
	defer file.Close()
	w, e := OpenWAL(filepath.Join(dir, "wal.db"), "tenant_test", "sensor_test", "sr_test", 256*1024*1024)
	if e != nil {
		b.Fatal(e)
	}
	defer w.Close()
	r := &EVEReader{WAL: w, Path: path, Route: func(context.Context, string) (string, error) { return "route_test", nil }}
	defer r.Close()
	data := []byte(strings.Repeat(eveSample+"\n", 100))
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, e = file.Write(data); e != nil {
			b.Fatal(e)
		}
		if e = r.Poll(context.Background()); e != nil {
			b.Fatal(e)
		}
		batch, e := w.Next("alerts")
		if e != nil {
			b.Fatal(e)
		}
		ack := &sensorv1.IngestAck{BatchId: batch.BatchId, ProducerEpoch: batch.ProducerEpoch, SensorRegistrationId: batch.SensorRegistrationId, StreamId: batch.StreamId, BatchSha256: batch.BatchSha256, Status: sensorv1.AckStatus_ACK_STATUS_ACCEPTED, AcceptedRanges: contract.Ranges(batch.Records)}
		if e = w.Confirm(batch, ack); e != nil {
			b.Fatal(e)
		}
	}
}
