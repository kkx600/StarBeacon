package packetarchive

import (
	"context"
	"errors"
	"io"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func splitObjectKey(value string) []string { return strings.Split(value, "/") }

type S3Objects struct {
	Client *minio.Client
	Bucket string
}

func NewS3Objects(endpoint, access, secret, bucket string, secure bool) (*S3Objects, error) {
	if endpoint == "" || bucket == "" || access == "" || secret == "" {
		return nil, ErrIntegrity
	}
	client, err := minio.New(endpoint, &minio.Options{Creds: credentials.NewStaticV4(access, secret, ""), Secure: secure})
	if err != nil {
		return nil, err
	}
	return &S3Objects{client, bucket}, nil
}
func ValidObjectVersion(version string) bool {
	return version != "" && version != "null" && len(version) <= 1024 && !strings.ContainsAny(version, "\x00\r\n")
}
func (s *S3Objects) existing(ctx context.Context, key string, size int64, digest string) (string, error) {
	info, err := s.Client.StatObject(ctx, s.Bucket, key, minio.StatObjectOptions{})
	if err != nil {
		return "", err
	}
	if !ValidObjectVersion(info.VersionID) || info.Size != size {
		return "", ErrIntegrity
	}
	object, err := s.Client.GetObject(ctx, s.Bucket, key, minio.GetObjectOptions{VersionID: info.VersionID})
	if err != nil {
		return "", err
	}
	defer object.Close()
	if err = verifyStored(ctx, object, size, digest); err != nil {
		return "", err
	}
	return info.VersionID, nil
}
func (s *S3Objects) Put(ctx context.Context, key string, source io.Reader, size int64, digest string) (string, error) {
	if !validObjectKey(key) || splitObjectKey(key)[5] != digest || size < 1 || size > MaxStoredBytes || source == nil {
		return "", ErrIntegrity
	}
	if version, err := s.existing(ctx, key, size, digest); err == nil {
		return version, nil
	} else {
		code := minio.ToErrorResponse(err).Code
		if code != "NoSuchKey" && code != "NoSuchObject" {
			return "", err
		}
	}
	policy, err := s.Client.GetBucketVersioning(ctx, s.Bucket)
	if err != nil {
		return "", err
	}
	if !policy.Enabled() {
		return "", ErrIntegrity
	}
	options := minio.PutObjectOptions{ContentType: "application/octet-stream", DisableMultipart: true, UserMetadata: map[string]string{"stored-sha256": digest}}
	options.SetMatchETagExcept("*")
	result, err := s.Client.PutObject(ctx, s.Bucket, key, source, size, options)
	if err != nil {
		if minio.ToErrorResponse(err).Code == "PreconditionFailed" {
			return s.existing(ctx, key, size, digest)
		}
		return "", err
	}
	if !ValidObjectVersion(result.VersionID) {
		return "", ErrIntegrity
	}
	// 再读取指定返回版本并核对 SHA-256；服务返回的 ETag 与元数据都不足以确认原包完整性。
	object, err := s.Client.GetObject(ctx, s.Bucket, key, minio.GetObjectOptions{VersionID: result.VersionID})
	if err != nil {
		return "", err
	}
	defer object.Close()
	if err = verifyStored(ctx, object, size, digest); err != nil {
		return "", err
	}
	return result.VersionID, nil
}
func (s *S3Objects) Range(ctx context.Context, key, version string, offset, length int64) (io.ReadCloser, error) {
	if !validObjectKey(key) || !ValidObjectVersion(version) || offset < 0 || length < 1 || offset > MaxStoredBytes-length {
		return nil, ErrIntegrity
	}
	options := minio.GetObjectOptions{VersionID: version}
	if err := options.SetRange(offset, offset+length-1); err != nil {
		return nil, err
	}
	return s.Client.GetObject(ctx, s.Bucket, key, options)
}
func (s *S3Objects) Remove(ctx context.Context, key, version string) error {
	if !validObjectKey(key) || !ValidObjectVersion(version) {
		return ErrIntegrity
	}
	err := s.Client.RemoveObject(ctx, s.Bucket, key, minio.RemoveObjectOptions{VersionID: version})
	if err == nil {
		return nil
	}
	response := minio.ToErrorResponse(err)
	if response.Code == "NoSuchKey" || response.Code == "NoSuchVersion" {
		return nil
	}
	return errors.New("指定原包对象版本未能回收")
}

func (s *S3Objects) Locate(ctx context.Context, key string, size int64, digest string) (string, bool, error) {
	if !validObjectKey(key) || splitObjectKey(key)[5] != digest || size < 1 || size > MaxStoredBytes {
		return "", false, ErrIntegrity
	}
	version, err := s.existing(ctx, key, size, digest)
	if err == nil {
		return version, true, nil
	}
	code := minio.ToErrorResponse(err).Code
	if code == "NoSuchKey" || code == "NoSuchObject" {
		return "", false, nil
	}
	return "", false, err
}
