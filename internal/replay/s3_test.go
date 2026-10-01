package replay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/testpcap"
)

// 使用受控 HTTP 服务检查 SDK 适配和暂存回收，不代替真实 S3 发行物验收。
func TestS3SampleRoundTripAndStagingCleanup(t *testing.T) {
	var mu sync.Mutex
	objects := map[string][]byte{}
	requests := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		requests = append(requests, r.Method+" "+r.URL.Path)
		if r.Method == http.MethodGet && r.URL.Query().Has("location") {
			w.Header().Set("Content-Type", "application/xml")
			io.WriteString(w, `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">us-east-1</LocationConstraint>`)
			return
		}
		switch r.Method {
		case http.MethodPut:
			if r.URL.Path == "/samples/" || r.URL.Path == "/samples" {
				t.Error("适配器尝试创建 bucket")
				http.Error(w, "forbidden", 403)
				return
			}
			body, e := io.ReadAll(r.Body)
			if e != nil {
				t.Error(e)
				w.WriteHeader(500)
				return
			}
			if strings.HasPrefix(r.Header.Get("X-Amz-Content-Sha256"), "STREAMING-") || strings.Contains(r.Header.Get("Content-Encoding"), "aws-chunked") {
				body, e = decodeS3TestChunks(body)
				if e != nil {
					t.Error(e)
					w.WriteHeader(400)
					return
				}
			}
			objects[r.URL.Path] = body
			hash := md5.Sum(body)
			w.Header().Set("ETag", `"`+hex.EncodeToString(hash[:])+`"`)
		case http.MethodHead, http.MethodGet:
			body, ok := objects[r.URL.Path]
			if !ok {
				http.Error(w, "missing", 404)
				return
			}
			w.Header().Set("Content-Length", fmt.Sprint(len(body)))
			w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
			w.Header().Set("ETag", `"00000000000000000000000000000000"`)
			if r.Method == http.MethodGet {
				w.Write(body)
			}
		case http.MethodDelete:
			delete(objects, r.URL.Path)
			w.WriteHeader(204)
		default:
			t.Error("非预期请求", r.Method)
			w.WriteHeader(400)
		}
	}))
	defer server.Close()
	staging, e := NewLocal(filepath.Join(t.TempDir(), "staging"), MaxSampleBytes)
	if e != nil {
		t.Fatal(e)
	}
	s, e := NewS3(strings.TrimPrefix(server.URL, "http://"), "test-access", "test-secret", "samples", false, staging)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := testpcap.HTTP(false)
	key := Key("tenant_test", "sample_test")
	sha, kind, e := s.Put(context.Background(), key, bytes.NewReader(raw), int64(len(raw)))
	if e != nil || kind != "pcap" || len(sha) != 64 {
		t.Fatal(sha, kind, e)
	}
	if _, e = staging.Open(context.Background(), key); !os.IsNotExist(e) {
		t.Fatal("S3 上传结束后未回收暂存", e)
	}
	obj, e := s.Open(context.Background(), key)
	if e != nil {
		t.Fatal(e)
	}
	received, e := io.ReadAll(obj)
	obj.Close()
	if e != nil || !bytes.Equal(received, raw) {
		t.Fatal("S3 取回内容不一致", e)
	}
	if e = s.Remove(context.Background(), key); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Open(context.Background(), key); e == nil {
		t.Fatal("不存在的 S3 对象被接受")
	}
}

// S3 的签名分块属于对象服务协议，HTTP 服务需先还原对象字节。
func decodeS3TestChunks(raw []byte) ([]byte, error) {
	reader := bufio.NewReader(bytes.NewReader(raw))
	var out bytes.Buffer
	for {
		line, e := reader.ReadString('\n')
		if e != nil {
			return nil, e
		}
		value := strings.Split(strings.TrimSpace(line), ";")[0]
		size, e := strconv.ParseInt(value, 16, 64)
		if e != nil || size < 0 || size > MaxSampleBytes {
			return nil, fmt.Errorf("S3 分块长度无效")
		}
		if size == 0 {
			return out.Bytes(), nil
		}
		if _, e = io.CopyN(&out, reader, size); e != nil {
			return nil, e
		}
		crlf := make([]byte, 2)
		if _, e = io.ReadFull(reader, crlf); e != nil || string(crlf) != "\r\n" {
			return nil, fmt.Errorf("S3 分块边界无效")
		}
	}
}
