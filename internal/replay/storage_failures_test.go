package replay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/testpcap"
)

type interruptedReader struct {
	prefix *bytes.Reader
	cause  error
}

func (r interruptedReader) Read(p []byte) (int, error) {
	n, err := r.prefix.Read(p)
	if err == io.EOF {
		return 0, r.cause
	}
	return n, err
}

func TestUploadAndFilenameRejectInvalidMetadata(t *testing.T) {
	for _, name := range []string{"", "../sample.pcap", "a/b.pcap", "a\\b.pcap", " a.pcap", "a.pcap ", "a\n.pcap", string([]byte{0xff}), strings.Repeat("中", 129)} {
		if _, err := Filename(name); err == nil {
			t.Fatal("不安全文件名被接受", name)
		}
	}
	if _, err := format(make([]byte, 23)); err == nil {
		t.Fatal("不完整捕获文件头被接受")
	}
	for _, tc := range []struct {
		length      int64
		ctype, name string
	}{{-1, "application/octet-stream", "sample.pcap"}, {MaxSampleBytes + 1, "application/octet-stream", "sample.pcap"}, {24, "application/json", "sample.pcap"}, {24, "application/octet-stream", "%zz"}, {24, "application/octet-stream", "..%2Fsample.pcap"}} {
		r := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader("data"))
		r.ContentLength = tc.length
		r.Header.Set("Content-Type", tc.ctype)
		r.Header.Set("X-Filename", tc.name)
		if _, _, _, err := UploadBody(httptest.NewRecorder(), r); err == nil {
			t.Fatal("不合法上传元数据被接受", tc)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(strings.Repeat("x", 24)))
	r.Header.Set("Content-Type", "application/octet-stream")
	r.Header.Set("X-Filename", url.PathEscape("规则验证.pcap"))
	body, size, name, err := UploadBody(httptest.NewRecorder(), r)
	if err != nil || size != 24 || name != "规则验证.pcap" {
		t.Fatal("中文合法文件名被拒绝", err)
	}
	raw, err := io.ReadAll(body)
	if err != nil || len(raw) != 24 {
		t.Fatal(err)
	}
}

func TestLocalStorageFailuresLeaveNoPublishedOrTemporarySample(t *testing.T) {
	data, err := testpcap.HTTP(false)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"invalid_key", "small_size", "large_size", "short_header", "short_body", "long_body", "interrupted", "cancelled", "directory_entry", "removed_directory"} {
		t.Run(mode, func(t *testing.T) {
			s, err := NewLocal(filepath.Join(t.TempDir(), "samples"), MaxSampleBytes)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			key := Key("tenant_bound", "sample_bound")
			size := int64(len(data))
			var reader io.Reader = bytes.NewReader(data)
			switch mode {
			case "invalid_key":
				key = "../escape"
			case "small_size":
				size = 23
			case "large_size":
				size = MaxSampleBytes + 1
			case "short_header":
				reader = bytes.NewReader(data[:10])
			case "short_body":
				reader = bytes.NewReader(data[:len(data)-1])
			case "long_body":
				reader = bytes.NewReader(append(append([]byte(nil), data...), byte(0)))
			case "interrupted":
				reader = interruptedReader{bytes.NewReader(data[:30]), errors.New("source disconnected")}
			case "cancelled":
				cancel()
			case "directory_entry":
				if err = os.Mkdir(filepath.Join(s.Dir, "foreign"), 0700); err != nil {
					t.Fatal(err)
				}
			case "removed_directory":
				if err = os.Remove(s.Dir); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err = s.Put(ctx, key, reader, size); err == nil {
				t.Fatal("失败上传被视为成功")
			}
			entries, err := os.ReadDir(s.Dir)
			if mode == "removed_directory" {
				if !os.IsNotExist(err) {
					t.Fatal(err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if entry.Name() != "foreign" {
					t.Fatal("失败上传留下对象或临时文件", entry.Name())
				}
			}
		})
	}
	if _, err = NewLocal(filepath.Join(t.TempDir(), "quota"), MaxSampleBytes-1); !errors.Is(err, ErrQuota) {
		t.Fatal("过小存储额度被接受", err)
	}
	for _, mode := range []string{"public_directory", "symlink", "parent_file"} {
		t.Run(mode, func(t *testing.T) {
			base := t.TempDir()
			dir := filepath.Join(base, "samples")
			switch mode {
			case "public_directory":
				os.Mkdir(dir, 0755)
			case "symlink":
				os.Symlink(base, dir)
			case "parent_file":
				os.WriteFile(dir, []byte("file"), 0600)
				dir = filepath.Join(dir, "nested")
			}
			if _, err := NewLocal(dir, MaxSampleBytes); err == nil {
				t.Fatal("不安全存储目录被接受")
			}
		})
	}
}

func TestSampleReadDeleteCancellationAndBoundedOrphanCleanup(t *testing.T) {
	s, err := NewLocal(filepath.Join(t.TempDir(), "samples"), MaxSampleBytes)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	key := Key("tenant_bound", "sample_bound")
	if _, err = s.Open(ctx, key); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err = s.Remove(ctx, key); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err = s.Remove(context.Background(), "../escape"); err == nil {
		t.Fatal("删除身份未校验")
	}
	if err = s.Remove(context.Background(), key); err != nil {
		t.Fatal("不存在对象删除不幂等", err)
	}
	path, _ := s.path(key)
	if err = os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Open(context.Background(), key); err == nil {
		t.Fatal("目录可被作为捕获文件读取")
	}
	if err = os.WriteFile(filepath.Join(path, "child"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.Remove(context.Background(), key); err == nil {
		t.Fatal("不可删除对象仍确认删除成功")
	}
	if err = s.PurgeOrphans(context.Background(), []string{"invalid"}); err == nil {
		t.Fatal("无效索引键参与孤儿清理")
	}
	if err = s.PurgeOrphans(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err = syncDirectory(filepath.Join(s.Dir, "missing")); err == nil {
		t.Fatal("目录刷盘失败被吞掉")
	}
	old := time.Now().Add(-2 * time.Hour)
	for i := 0; i < 101; i++ {
		p := filepath.Join(s.Dir, fmt.Sprintf("upload-%04d", i))
		if err = os.WriteFile(p, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
		if err = os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.PurgeOrphans(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(s.Dir)
	if err != nil || len(entries) != 2 {
		t.Fatal("单轮孤儿清理超出或未达到 100 个对象边界", len(entries), err)
	}
	if err = s.PurgeOrphans(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	entries, _ = os.ReadDir(s.Dir)
	if len(entries) != 1 {
		t.Fatal("后续轮次未回收剩余对象")
	}
}

// 协议夹具验证 SDK 与持久化适配器的错误边界；服务商可用性须另行验收。
func TestS3AdapterRoundTripAndFailureCleansPrivateStaging(t *testing.T) {
	data, err := testpcap.HTTP(false)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	objects := map[string][]byte{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if _, ok := r.URL.Query()["location"]; ok {
			w.Header().Set("Content-Type", "application/xml")
			io.WriteString(w, `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">us-east-1</LocationConstraint>`)
			return
		}
		if strings.Contains(r.URL.Path, "sample_denied") {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(403)
			io.WriteString(w, `<Error><Code>AccessDenied</Code><Message>fixture denied</Message></Error>`)
			return
		}
		switch r.Method {
		case http.MethodPut:
			if r.Header.Get("X-Amz-Meta-Sha256") != control.Digest(data) || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
				t.Error("S3 上传丢失摘要或签名")
			}
			var body io.Reader = r.Body
			if strings.Contains(r.Header.Get("Content-Encoding"), "aws-chunked") {
				body = httputil.NewChunkedReader(body)
			}
			raw, err := io.ReadAll(body)
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			objects[r.URL.Path] = raw
			w.Header().Set("ETag", `"fixture-etag"`)
		case http.MethodGet, http.MethodHead:
			raw, ok := objects[r.URL.Path]
			if !ok {
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(404)
				io.WriteString(w, `<Error><Code>NoSuchKey</Code></Error>`)
				return
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
			w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
			w.Header().Set("ETag", `"fixture-etag"`)
			if r.Method == http.MethodGet {
				w.Write(raw)
			}
		case http.MethodDelete:
			delete(objects, r.URL.Path)
			w.WriteHeader(204)
		default:
			w.WriteHeader(405)
		}
	}))
	defer server.Close()
	staging, err := NewLocal(filepath.Join(t.TempDir(), "staging"), MaxSampleBytes)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewS3(strings.TrimPrefix(server.URL, "http://"), "test-access-only", "test-secret-only", "samples", false, staging)
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	key := Key("tenant_bound", "sample_bound")
	sha, kind, err := s.Put(ctx, key, bytes.NewReader(data), int64(len(data)))
	if err != nil || sha != control.Digest(data) || kind != "pcap" {
		t.Fatal("S3 上传未完成", err)
	}
	f, err := s.Open(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(f)
	f.Close()
	if err != nil || !bytes.Equal(raw, data) {
		t.Fatal("S3 读取未保持原始字节", err)
	}
	if err = s.Remove(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Open(ctx, key); err == nil {
		t.Fatal("已删除对象仍可读取")
	}
	if _, _, err = s.Put(ctx, Key("tenant_bound", "sample_denied"), bytes.NewReader(data), int64(len(data))); err == nil {
		t.Fatal("S3 拒绝写入仍返回成功")
	}
	entries, err := os.ReadDir(staging.Dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("S3 成功或失败后暂存文件未清理", err)
	}
	if _, _, err = s.Put(ctx, key, bytes.NewReader(data), 23); err == nil {
		t.Fatal("S3 绕过本地样本边界")
	}
	if _, err = s.Open(ctx, "../escape"); err == nil {
		t.Fatal("S3 读取键未校验")
	}
	if err = s.Remove(ctx, "../escape"); err == nil {
		t.Fatal("S3 删除键未校验")
	}
	if _, err = NewS3("http://invalid.example/path", "a", "b", "samples", false, staging); err == nil {
		t.Fatal("非法 S3 endpoint 被接受")
	}
	s.Bucket = "INVALID"
	if _, err = s.Open(ctx, key); err == nil {
		t.Fatal("SDK 桶名错误被吞掉")
	}
}
