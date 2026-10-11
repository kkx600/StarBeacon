package packetarchive

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func testObjectKey(data []byte) string {
	return "pcap/tenant_one/sensor_one/registration_one/packet_one/" + Digest(data)
}

func TestLocalObjectsImmutableConcurrencyRangeAndVersionRecovery(t *testing.T) {
	objects, err := NewLocalObjects(filepath.Join(t.TempDir(), "objects"))
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("immutable original packets"), 2000)
	key, digest := testObjectKey(data), Digest(data)
	ctx := context.Background()
	if version, exists, err := objects.Locate(ctx, key, int64(len(data)), digest); err != nil || exists || version != "" {
		t.Fatal(version, exists, err)
	}
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Go(func() {
			version, err := objects.Put(ctx, key, bytes.NewReader(data), int64(len(data)), digest)
			if err != nil || version != digest {
				t.Error(version, err)
			}
		})
	}
	group.Wait()
	if version, exists, err := objects.Locate(ctx, key, int64(len(data)), digest); err != nil || !exists || version != digest {
		t.Fatal(version, exists, err)
	}
	f, err := objects.Range(ctx, key, digest, 11, 900)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(f)
	f.Close()
	if err != nil || !bytes.Equal(got, data[11:911]) {
		t.Fatal("存储范围读取不一致", err)
	}
	for _, v := range []struct {
		key, version   string
		offset, length int64
	}{{key, Digest([]byte("another")), 0, 1}, {"../packet", digest, 0, 1}, {key, digest, -1, 1}, {key, digest, 0, 0}, {key, digest, int64(len(data)), 1}, {key, digest, MaxStoredBytes, 2}} {
		if f, err := objects.Range(ctx, v.key, v.version, v.offset, v.length); err == nil {
			f.Close()
			t.Fatal("非法对象范围被接受")
		}
	}
	if _, _, err := objects.Locate(ctx, key, int64(len(data)-1), digest); err == nil {
		t.Fatal("版本定位未核对实际长度")
	}
	if err = objects.Remove(ctx, key, digest); err != nil {
		t.Fatal(err)
	}
	if err = objects.Remove(ctx, key, digest); err != nil {
		t.Fatal("重复指定版本删除不幂等", err)
	}
	if _, exists, err := objects.Locate(ctx, key, int64(len(data)), digest); err != nil || exists {
		t.Fatal(exists, err)
	}
}

func TestLocalObjectsRejectsCorruptionSymlinksPermissionsAndCancellation(t *testing.T) {
	ctx := context.Background()
	data := []byte("actual raw capture")
	key, digest := testObjectKey(data), Digest(data)
	objects, err := NewLocalObjects(filepath.Join(t.TempDir(), "objects"))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct {
		key, digest string
		size        int64
		reader      io.Reader
	}{{key, digest, 0, bytes.NewReader(data)}, {key, digest, MaxStoredBytes + 1, bytes.NewReader(data)}, {key, digest, int64(len(data)), nil}, {key, Digest([]byte("wrong")), int64(len(data)), bytes.NewReader(data)}, {key, digest, int64(len(data)), bytes.NewReader([]byte("different"))}, {key, digest, int64(len(data)), bytes.NewReader(append(bytes.Clone(data), 0))}, {key, digest, int64(len(data)), errReader{}}} {
		if _, err := objects.Put(ctx, v.key, v.reader, v.size, v.digest); err == nil {
			t.Fatal("无效存储制品被接受")
		}
	}
	entries, err := os.ReadDir(objects.Dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("验证失败遗留了暂存制品", err)
	}
	path, _ := objects.path(key, digest)
	if err = os.Symlink(filepath.Join(t.TempDir(), "victim"), path); err != nil {
		t.Fatal(err)
	}
	if _, err = objects.Put(ctx, key, bytes.NewReader(data), int64(len(data)), digest); err == nil {
		t.Fatal("符号链接对象被覆盖")
	}
	if err = objects.Remove(ctx, key, digest); err == nil {
		t.Fatal("符号链接被当作归档对象删除")
	}
	if _, _, err = objects.Locate(ctx, key, int64(len(data)), digest); err == nil {
		t.Fatal("符号链接被当作对象缺失")
	}
	os.Remove(path)
	if _, err = objects.Put(ctx, key, bytes.NewReader(data), int64(len(data)), digest); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, bytes.Repeat([]byte{0}, len(data)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = objects.Put(ctx, key, bytes.NewReader(data), int64(len(data)), digest); err == nil {
		t.Fatal("既有受损版本被当作幂等成功")
	}
	if _, _, err = objects.Locate(ctx, key, int64(len(data)), digest); err == nil {
		t.Fatal("受损版本定位成功")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = objects.Range(canceled, key, digest, 0, 1); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err = objects.Remove(canceled, key, digest); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, _, err = objects.Locate(canceled, key, int64(len(data)), digest); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	public := t.TempDir()
	if err = os.Chmod(public, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err = NewLocalObjects(public); err == nil {
		t.Fatal("公共权限原包目录被接受")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("读取中断") }

type emptyReader struct{}

func (emptyReader) Read([]byte) (int, error) { return 0, nil }
func TestObjectCopyHonorsCancellationShortWritesAndNoProgress(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := copyContext(ctx, io.Discard, bytes.NewReader([]byte{1})); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := copyContext(context.Background(), shortWriter{}, bytes.NewReader([]byte{1, 2})); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	if _, err := copyContext(context.Background(), io.Discard, emptyReader{}); !errors.Is(err, io.ErrNoProgress) {
		t.Fatal(err)
	}
}
