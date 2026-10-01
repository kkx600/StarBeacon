// Package replay 管理离线重放样本；样本内容不进入实时告警管道。
package replay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

const MaxSampleBytes int64 = 100 * 1024 * 1024
const MaxSamples = 10000

var ErrQuota = errors.New("样本存储额度不足，请调整额度或等待保留期结束")

type Sample struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	SHA256    string    `json:"sha256"`
	Format    string    `json:"format"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}
type Storage interface {
	Put(context.Context, string, io.Reader, int64) (string, string, error)
	Open(context.Context, string) (io.ReadCloser, error)
	Remove(context.Context, string) error
}

func Key(tenant, id string) string { return tenant + "/" + id }
func validKey(key string) bool {
	parts := strings.Split(key, "/")
	return len(parts) == 2 && contract.ValidID(parts[0]) && contract.ValidID(parts[1])
}
func Filename(name string) (string, error) {
	if !utf8.ValidString(name) || len([]rune(name)) == 0 || len([]rune(name)) > 128 || strings.ContainsAny(name, "/\\\x00\r\n") || strings.TrimSpace(name) != name {
		return "", errors.New("文件名无效")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", errors.New("文件名包含控制字符")
		}
	}
	return name, nil
}
func format(header []byte) (string, error) {
	if len(header) < 24 {
		return "", errors.New("PCAP 文件头不完整")
	}
	switch {
	case bytes.Equal(header[:4], []byte{0x0a, 0x0d, 0x0d, 0x0a}):
		return "pcapng", nil
	case bytes.Equal(header[:4], []byte{0xd4, 0xc3, 0xb2, 0xa1}), bytes.Equal(header[:4], []byte{0xa1, 0xb2, 0xc3, 0xd4}), bytes.Equal(header[:4], []byte{0x4d, 0x3c, 0xb2, 0xa1}), bytes.Equal(header[:4], []byte{0xa1, 0xb2, 0x3c, 0x4d}):
		return "pcap", nil
	default:
		return "", errors.New("仅支持原始 PCAP 或 PCAPNG，不支持压缩包")
	}
}

// UploadBody 在身份验证之后设置大文件请求的单独期限，不扩大其他 API 的请求上限。
func UploadBody(w http.ResponseWriter, r *http.Request) (io.Reader, int64, string, error) {
	size := r.ContentLength
	if size < 24 || size > MaxSampleBytes {
		return nil, 0, "", errors.New("样本必须为 24 字节至 100 MiB，且提供 Content-Length")
	}
	if r.Header.Get("Content-Type") != "application/octet-stream" {
		return nil, 0, "", errors.New("样本上传要求 application/octet-stream")
	}
	name, e := url.PathUnescape(r.Header.Get("X-Filename"))
	if e != nil {
		return nil, 0, "", errors.New("文件名编码无效")
	}
	name, e = Filename(name)
	if e != nil {
		return nil, 0, "", e
	}
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(5 * time.Minute))
	_ = rc.SetWriteDeadline(time.Now().Add(6 * time.Minute))
	return http.MaxBytesReader(w, r.Body, MaxSampleBytes), size, name, nil
}

type LocalStorage struct {
	Dir   string
	Quota int64
	mu    sync.Mutex
}

func NewLocal(dir string, quota int64) (*LocalStorage, error) {
	dir, e := filepath.Abs(dir)
	if e != nil {
		return nil, e
	}
	if quota < MaxSampleBytes {
		return nil, ErrQuota
	}
	if e = os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	i, e := os.Lstat(dir)
	if e != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 || i.Mode().Perm()&0077 != 0 {
		return nil, errors.New("样本目录必须仅所有者可访问且不是符号链接")
	}
	return &LocalStorage{Dir: dir, Quota: quota}, nil
}
func (s *LocalStorage) path(key string) (string, error) {
	if !validKey(key) {
		return "", errors.New("样本身份无效")
	}
	return filepath.Join(s.Dir, objectFilename(key)), nil
}

func objectFilename(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:]) + ".pcap"
}

type contextReader struct {
	context.Context
	r io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if e := r.Context.Err(); e != nil {
		return 0, e
	}
	return r.r.Read(p)
}
func (s *LocalStorage) Put(ctx context.Context, key string, r io.Reader, size int64) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	path, e := s.path(key)
	if e != nil {
		return "", "", e
	}
	if size < 24 || size > MaxSampleBytes {
		return "", "", errors.New("样本大小超出上限")
	}
	entries, e := os.ReadDir(s.Dir)
	if e != nil {
		return "", "", e
	}
	if len(entries) >= MaxSamples {
		return "", "", ErrQuota
	}
	var used int64
	for _, v := range entries {
		info, e := v.Info()
		if e != nil {
			return "", "", e
		}
		if !info.Mode().IsRegular() {
			return "", "", errors.New("样本目录包含非普通文件")
		}
		used += info.Size()
	}
	if used+size > s.Quota {
		return "", "", ErrQuota
	}
	if _, e = os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
		return "", "", errors.New("样本身份已存在")
	}
	f, e := os.CreateTemp(s.Dir, "upload-")
	if e != nil {
		return "", "", e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	defer f.Close()
	header := make([]byte, 24)
	if _, e = io.ReadFull(contextReader{ctx, r}, header); e != nil {
		return "", "", e
	}
	kind, e := format(header)
	if e != nil {
		return "", "", e
	}
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(f, h), io.LimitReader(contextReader{ctx, io.MultiReader(bytes.NewReader(header), r)}, size+1))
	if e != nil {
		return "", "", e
	}
	if n != size {
		return "", "", errors.New("样本长度与声明不一致")
	}
	if e = f.Sync(); e != nil {
		return "", "", e
	}
	if e = f.Close(); e != nil {
		return "", "", e
	}
	if e = os.Rename(tmp, path); e != nil {
		return "", "", e
	}
	d, e := os.Open(s.Dir)
	if e != nil {
		return "", "", e
	}
	defer d.Close()
	if e = d.Sync(); e != nil {
		return "", "", errors.Join(e, os.Remove(path))
	}
	return hex.EncodeToString(h.Sum(nil)), kind, nil
}
func (s *LocalStorage) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	path, e := s.path(key)
	if e != nil {
		return nil, e
	}
	info, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("样本不是普通文件")
	}
	return os.Open(path)
}
func (s *LocalStorage) Remove(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := ctx.Err(); e != nil {
		return e
	}
	path, e := s.path(key)
	if e != nil {
		return e
	}
	e = os.Remove(path)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	return syncDirectory(s.Dir)
}

func syncDirectory(dir string) error {
	d, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}

// PurgeOrphans 只清理私有目录中超过一小时且没有索引的业务对象和上传临时文件。
func (s *LocalStorage) PurgeOrphans(ctx context.Context, keys []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	keep := make(map[string]bool, len(keys))
	for _, key := range keys {
		if !validKey(key) {
			return errors.New("样本身份无效")
		}
		keep[objectFilename(key)] = true
	}
	entries, e := os.ReadDir(s.Dir)
	if e != nil {
		return e
	}
	removed := 0
	for _, entry := range entries {
		if e = ctx.Err(); e != nil {
			return e
		}
		name := entry.Name()
		hashName := len(name) == 69 && strings.HasSuffix(name, ".pcap")
		if hashName {
			_, e = hex.DecodeString(name[:64])
			hashName = e == nil
		}
		if keep[name] || (!hashName && !strings.HasPrefix(name, "upload-")) {
			continue
		}
		info, e := entry.Info()
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() || !info.ModTime().Before(time.Now().Add(-time.Hour)) {
			continue
		}
		if e = os.Remove(filepath.Join(s.Dir, name)); e != nil {
			return e
		}
		removed++
		if removed >= 100 {
			break
		}
	}
	if removed > 0 {
		return syncDirectory(s.Dir)
	}
	return nil
}

type S3Storage struct {
	Client  *minio.Client
	Bucket  string
	Staging *LocalStorage
}

func NewS3(endpoint, access, secret, bucket string, secure bool, staging *LocalStorage) (*S3Storage, error) {
	client, e := minio.New(endpoint, &minio.Options{Creds: credentials.NewStaticV4(access, secret, ""), Secure: secure})
	if e != nil {
		return nil, e
	}
	return &S3Storage{client, bucket, staging}, nil
}
func (s *S3Storage) Put(ctx context.Context, key string, r io.Reader, size int64) (string, string, error) {
	sha, kind, e := s.Staging.Put(ctx, key, r, size)
	if e != nil {
		return "", "", e
	}
	defer s.Staging.Remove(context.Background(), key)
	f, e := s.Staging.Open(ctx, key)
	if e != nil {
		return "", "", e
	}
	defer f.Close()
	info, e := s.Client.PutObject(ctx, s.Bucket, key, f, size, minio.PutObjectOptions{ContentType: "application/vnd.tcpdump.pcap", DisableMultipart: true, UserMetadata: map[string]string{"sha256": sha}})
	if e != nil {
		return "", "", e
	}
	if info.Size != size {
		return "", "", errors.New("对象存储长度不一致")
	}
	return sha, kind, nil
}
func (s *S3Storage) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	if !validKey(key) {
		return nil, errors.New("样本身份无效")
	}
	obj, e := s.Client.GetObject(ctx, s.Bucket, key, minio.GetObjectOptions{})
	if e != nil {
		return nil, e
	}
	if _, e = obj.Stat(); e != nil {
		obj.Close()
		return nil, e
	}
	return obj, nil
}
func (s *S3Storage) Remove(ctx context.Context, key string) error {
	if !validKey(key) {
		return errors.New("样本身份无效")
	}
	return s.Client.RemoveObject(ctx, s.Bucket, key, minio.RemoveObjectOptions{})
}
