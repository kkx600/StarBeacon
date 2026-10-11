package packetarchive

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// 使用 SDK 的真实 HTTPS 请求核对版本、条件写和 Range 协议；不代表某个存储厂商已经验收。
type ownedS3Fixture struct {
	mu          sync.Mutex
	data        []byte
	version     string
	enabled     bool
	corrupt     bool
	ignoreRange bool
	denied      bool
	puts        int
	deletes     []string
	conditional string
}

func fixtureS3(t *testing.T) (*S3Objects, *ownedS3Fixture) {
	t.Helper()
	f := &ownedS3Fixture{enabled: true}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("Last-Modified", "Fri, 02 Oct 2026 00:00:00 GMT")
		w.Header().Set("ETag", `"opaque-etag"`)
		if r.Header.Get("Authorization") == "" {
			t.Error("SDK 请求未签名")
		}
		failure := func(code string, status int) {
			w.Header().Set("X-Amz-Error-Code", code)
			w.WriteHeader(status)
			fmt.Fprintf(w, "<Error><Code>%s</Code><Message>owned fixture</Message></Error>", code)
		}
		if f.denied {
			failure("AccessDenied", 403)
			return
		}
		if _, ok := r.URL.Query()["versioning"]; ok {
			state := "Suspended"
			if f.enabled {
				state = "Enabled"
			}
			fmt.Fprintf(w, `<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>%s</Status></VersioningConfiguration>`, state)
			return
		}
		switch r.Method {
		case "HEAD":
			if f.data == nil {
				failure("NoSuchKey", 404)
				return
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(f.data)))
			w.Header().Set("X-Amz-Version-Id", f.version)
			w.Header().Set("ETag", `"opaque-etag"`)
			w.Header().Set("Last-Modified", "Fri, 02 Oct 2026 00:00:00 GMT")
		case "PUT":
			f.conditional = r.Header.Get("If-None-Match")
			if f.data != nil {
				failure("PreconditionFailed", 412)
				return
			}
			data, err := io.ReadAll(io.LimitReader(r.Body, MaxStoredBytes+1))
			if err != nil {
				t.Error(err)
				failure("InvalidRequest", 400)
				return
			}
			f.data = bytes.Clone(data)
			f.puts++
			if f.version == "" {
				f.version = "owned-immutable-version"
			}
			w.Header().Set("X-Amz-Version-Id", f.version)
			w.Header().Set("ETag", `"opaque-etag"`)
		case "GET":
			if f.data == nil {
				failure("NoSuchKey", 404)
				return
			}
			if r.URL.Query().Get("versionId") != f.version {
				t.Error("读取没有绑定具体版本")
				failure("NoSuchVersion", 404)
				return
			}
			data := bytes.Clone(f.data)
			if f.corrupt && len(data) > 0 {
				data[0] ^= 1
			}
			if header := r.Header.Get("Range"); header != "" && !f.ignoreRange {
				var start, end int
				if _, err := fmt.Sscanf(header, "bytes=%d-%d", &start, &end); err != nil || start < 0 || end >= len(data) || end < start {
					failure("InvalidRange", 416)
					return
				}
				w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(data)))
				data = data[start : end+1]
				w.Header().Set("Content-Length", strconv.Itoa(len(data)))
				w.Header().Set("X-Amz-Version-Id", f.version)
				w.WriteHeader(206)
			} else {
				w.Header().Set("Content-Length", strconv.Itoa(len(data)))
				w.Header().Set("X-Amz-Version-Id", f.version)
			}
			_, _ = w.Write(data)
		case "DELETE":
			version := r.URL.Query().Get("versionId")
			if version != f.version {
				failure("NoSuchVersion", 404)
				return
			}
			f.deletes = append(f.deletes, version)
			f.data = nil
			w.WriteHeader(204)
		default:
			failure("InvalidRequest", 400)
		}
	}))
	t.Cleanup(server.Close)
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client, err := minio.New(endpoint.Host, &minio.Options{Creds: credentials.NewStaticV4("owned-access", "owned-secret", ""), Secure: true, Region: "us-east-1", Transport: server.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	return &S3Objects{Client: client, Bucket: "packet-evidence"}, f
}

func TestS3ObjectsOfficialSDKPinsVersionAndVerifiesActualBytes(t *testing.T) {
	objects, f := fixtureS3(t)
	ctx := context.Background()
	data := bytes.Repeat([]byte("original"), 1000)
	key, digest := testObjectKey(data), Digest(data)
	if _, exists, err := objects.Locate(ctx, key, int64(len(data)), digest); err != nil || exists {
		t.Fatal(exists, err)
	}
	version, err := objects.Put(ctx, key, bytes.NewReader(data), int64(len(data)), digest)
	if err != nil {
		t.Fatal(err)
	}
	if version != "owned-immutable-version" {
		t.Fatal(version)
	}
	if again, err := objects.Put(ctx, key, errReader{}, int64(len(data)), digest); err != nil || again != version {
		t.Fatal("重复写没有核对实际固定版本", again, err)
	}
	if found, exists, err := objects.Locate(ctx, key, int64(len(data)), digest); err != nil || !exists || found != version {
		t.Fatal(found, exists, err)
	}
	f.mu.Lock()
	puts, conditional := f.puts, f.conditional
	f.mu.Unlock()
	if puts != 1 || conditional != "*" {
		t.Fatal("对象被重复覆盖或缺少条件写", puts, conditional)
	}
	rangeReader, err := objects.Range(ctx, key, version, 17, 83)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rangeReader)
	rangeReader.Close()
	if err != nil || !bytes.Equal(got, data[17:100]) {
		t.Fatal("SDK Range 未保持存储偏移", err)
	}
	if err = objects.Remove(ctx, key, version); err != nil {
		t.Fatal(err)
	}
	if err = objects.Remove(ctx, key, version); err != nil {
		t.Fatal("已不存在的具体版本不能幂等回收", err)
	}
	f.mu.Lock()
	deletes := append([]string(nil), f.deletes...)
	f.mu.Unlock()
	if len(deletes) != 2 || deletes[0] != version {
		t.Fatal("删除未绑定具体版本")
	}
}

func TestS3ObjectsRejectsDisabledVersioningChangedBytesAndDeniedLookup(t *testing.T) {
	for _, name := range []string{"disabled", "mutable-version", "corrupt", "denied"} {
		t.Run(name, func(t *testing.T) {
			objects, f := fixtureS3(t)
			data := []byte("original capture bytes")
			key, digest := testObjectKey(data), Digest(data)
			f.enabled = name != "disabled"
			f.corrupt = name == "corrupt"
			f.denied = name == "denied"
			if name == "mutable-version" {
				f.version = "null"
			}
			if _, err := objects.Put(context.Background(), key, bytes.NewReader(data), int64(len(data)), digest); err == nil {
				t.Fatal("不可确认对象版本被接受")
			}
			if name == "denied" {
				if _, _, err := objects.Locate(context.Background(), key, int64(len(data)), digest); err == nil {
					t.Fatal("拒绝访问被解释成确定缺失")
				}
				if err := objects.Remove(context.Background(), key, "version"); err == nil {
					t.Fatal("拒绝删除被当作成功")
				}
			}
			if name == "corrupt" {
				if _, _, err := objects.Locate(context.Background(), key, int64(len(data)), digest); err == nil {
					t.Fatal("受损版本被确认")
				}
			}
		})
	}
}

func TestS3ObjectsRejectsInvalidAddressesVersionsAndRanges(t *testing.T) {
	if _, err := NewS3Objects("", "access", "secret", "bucket", true); err == nil {
		t.Fatal("配置缺失被接受")
	}
	if _, err := NewS3Objects("http://host/unsupported", "access", "secret", "bucket", true); err == nil {
		t.Fatal("非法端点被接受")
	}
	if _, err := NewS3Objects("s3.example:9000", "access", "secret", "bucket", true); err != nil {
		t.Fatal(err)
	}
	objects, f := fixtureS3(t)
	_ = f
	ctx := context.Background()
	data := []byte("capture")
	key, digest := testObjectKey(data), Digest(data)
	for _, version := range []string{"", "null", "version\n", strings.Repeat("v", 1025)} {
		if ValidObjectVersion(version) {
			t.Fatal("非法版本合法")
		}
		if _, err := objects.Range(ctx, key, version, 0, 1); err == nil {
			t.Fatal("非法读取版本被接受")
		}
		if err := objects.Remove(ctx, key, version); err == nil {
			t.Fatal("非法删除版本被接受")
		}
	}
	for _, v := range []struct {
		key            string
		offset, length int64
	}{{"../capture", 0, 1}, {key, -1, 1}, {key, 0, 0}, {key, MaxStoredBytes, 1}} {
		if _, err := objects.Range(ctx, v.key, "version", v.offset, v.length); err == nil {
			t.Fatal("非法范围被接受")
		}
	}
	if _, err := objects.Put(ctx, key, nil, int64(len(data)), digest); err == nil {
		t.Fatal("缺失制品被接受")
	}
	if _, _, err := objects.Locate(ctx, "../capture", int64(len(data)), digest); err == nil {
		t.Fatal("非法对象键可恢复")
	}
}
