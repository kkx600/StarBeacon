package replay

import (
	"bytes"
	"context"
	"encoding/binary"
	"github.com/kkx600/StarBeacon/internal/testpcap"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSampleIntegrityAndMalformedContainer(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, e := NewLocal(filepath.Join(dir, "samples"), MaxSampleBytes)
	if e != nil {
		t.Fatal(e)
	}
	for _, ng := range []bool{false, true} {
		raw, e := testpcap.HTTP(ng)
		if e != nil {
			t.Fatal(e)
		}
		key := Key("tenant_test", "sample_pcap")
		if ng {
			key = Key("tenant_test", "sample_ng")
		}
		sha, _, e := s.Put(ctx, key, bytes.NewReader(raw), int64(len(raw)))
		if e != nil || len(sha) != 64 {
			t.Fatal(e)
		}
		path, _ := s.path(key)
		meta, e := Inspect(ctx, path)
		if e != nil || meta.Packets != 9 || meta.TruncatedPackets != 0 || len(meta.MACs) != 2 {
			t.Fatal(meta, e)
		}
		if _, _, e = s.Put(ctx, key, bytes.NewReader(raw), int64(len(raw))); e == nil {
			t.Fatal("重复对象被覆盖")
		}
		bad := append([]byte(nil), raw[:len(raw)-1]...)
		badPath := filepath.Join(dir, "malformed.pcap")
		os.WriteFile(badPath, bad, 0600)
		if _, e = Inspect(ctx, badPath); e == nil {
			t.Fatal("截断的容器被接受")
		}
		os.Remove(badPath)
	}
	raw, _ := testpcap.HTTP(false)
	binary.LittleEndian.PutUint32(raw[16:20], 0xffffffff)
	path := filepath.Join(dir, "oversized.pcap")
	os.WriteFile(path, raw, 0600)
	if _, e = Inspect(ctx, path); e == nil {
		t.Fatal("超大 snaplen 未拒绝")
	}
	if _, _, e = s.Put(ctx, Key("tenant_test", "sample_bad"), bytes.NewReader([]byte("PK archive data not a packet capture")), 36); e == nil {
		t.Fatal("压缩包被接受")
	}
	if _, e = s.Open(ctx, "../private/key"); e == nil {
		t.Fatal("对象路径可越界")
	}
}
func TestSampleQuotaDoesNotEvictRetainedObject(t *testing.T) {
	ctx := context.Background()
	s, e := NewLocal(filepath.Join(t.TempDir(), "samples"), MaxSampleBytes)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := testpcap.HTTP(false)
	key := Key("tenant_test", "sample_good")
	if _, _, e = s.Put(ctx, key, bytes.NewReader(raw), int64(len(raw))); e != nil {
		t.Fatal(e)
	}
	f, e := os.Create(filepath.Join(s.Dir, "retained.pcap"))
	if e != nil {
		t.Fatal(e)
	}
	if e = f.Truncate(MaxSampleBytes); e != nil {
		t.Fatal(e)
	}
	f.Close()
	if _, _, e = s.Put(ctx, Key("tenant_test", "sample_full"), bytes.NewReader(raw), int64(len(raw))); e != ErrQuota {
		t.Fatal("额度满时未拒绝", e)
	}
	if r, e := s.Open(ctx, key); e != nil {
		t.Fatal("保留中的样本被提前删除", e)
	} else {
		r.Close()
	}
}

func TestObjectIdentityAndOrphanRecovery(t *testing.T) {
	ctx := context.Background()
	s, e := NewLocal(filepath.Join(t.TempDir(), "samples"), MaxSampleBytes)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := testpcap.HTTP(false)
	keys := []string{Key("tenant_a_b", "sample_c"), Key("tenant_a", "b_sample_c")}
	for _, key := range keys {
		if _, _, e = s.Put(ctx, key, bytes.NewReader(raw), int64(len(raw))); e != nil {
			t.Fatal(e)
		}
	}
	a, _ := s.path(keys[0])
	b, _ := s.path(keys[1])
	if a == b {
		t.Fatal("对象身份存在拼接碰撞")
	}
	old := time.Now().Add(-2 * time.Hour)
	if e = os.Chtimes(b, old, old); e != nil {
		t.Fatal(e)
	}
	if e = s.PurgeOrphans(ctx, keys[:1]); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(a); e != nil {
		t.Fatal("索引中的对象被删除", e)
	}
	if _, e = os.Stat(b); !os.IsNotExist(e) {
		t.Fatal("未清理过期孤儿对象", e)
	}
	if _, e = Filename("bad\tname.pcap"); e == nil {
		t.Fatal("文件名控制字符未拒绝")
	}
}
