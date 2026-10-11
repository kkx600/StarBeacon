package packetarchive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/kkx600/StarBeacon/internal/contract"
)

// ObjectStorage 以不可变版本读取，业务代码不会把 ETag 当作内容摘要或用原始偏移读取压缩对象。
type ObjectStorage interface {
	Put(context.Context, string, io.Reader, int64, string) (string, error)
	Range(context.Context, string, string, int64, int64) (io.ReadCloser, error)
	Remove(context.Context, string, string) error
	// Locate 仅核对这个冻结键的实际版本或确定缺失，不以超时或权限错误推断对象不存在。
	Locate(context.Context, string, int64, string) (version string, exists bool, err error)
}

func ObjectKey(m Manifest) string {
	return "pcap/" + m.Capture.TenantID + "/" + m.Capture.SensorID + "/" + m.Capture.RegistrationID + "/" + m.Capture.ID + "/" + m.Encoding.StoredSHA256
}
func validObjectKey(key string) bool {
	parts := splitObjectKey(key)
	return len(parts) == 6 && parts[0] == "pcap" && contract.ValidID(parts[1]) && contract.ValidID(parts[2]) && contract.ValidID(parts[3]) && contract.ValidID(parts[4]) && validDigest(parts[5])
}

type LocalObjects struct{ Dir string }

func NewLocalObjects(dir string) (*LocalObjects, error) {
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(absolute, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrIntegrity
	}
	return &LocalObjects{absolute}, nil
}
func (s *LocalObjects) path(key, version string) (string, error) {
	if !validObjectKey(key) || !validDigest(version) || splitObjectKey(key)[5] != version {
		return "", ErrIntegrity
	}
	return filepath.Join(s.Dir, Digest([]byte(key))+"-"+version+".stored"), nil
}
func (s *LocalObjects) Put(ctx context.Context, key string, source io.Reader, size int64, digest string) (string, error) {
	target, err := s.path(key, digest)
	if err != nil || size < 1 || size > MaxStoredBytes || source == nil {
		return "", ErrIntegrity
	}
	if f, e := openFile(target, MaxStoredBytes); e == nil {
		defer f.Close()
		if err = verifyStored(ctx, f, size, digest); err != nil {
			return "", err
		}
		return digest, nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return "", e
	}
	f, err := os.CreateTemp(s.Dir, ".packet-object-")
	if err != nil {
		return "", err
	}
	temporary := f.Name()
	defer os.Remove(temporary)
	defer f.Close()
	hash := sha256.New()
	n, err := copyContext(ctx, io.MultiWriter(f, hash), io.LimitReader(source, size+1))
	if err != nil {
		return "", err
	}
	if n != size || hex.EncodeToString(hash.Sum(nil)) != digest {
		return "", ErrIntegrity
	}
	if err = f.Sync(); err == nil {
		err = f.Chmod(0400)
	}
	if err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	// Link 具有不覆盖既有不可变对象的语义；并发同一键只接受已核验的相同版本。
	if err = os.Link(temporary, target); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return "", err
		}
		existing, e := openFile(target, MaxStoredBytes)
		if e != nil {
			return "", e
		}
		defer existing.Close()
		if e = verifyStored(ctx, existing, size, digest); e != nil {
			return "", e
		}
	}
	if err = syncDirectory(s.Dir); err != nil {
		return "", err
	}
	return digest, nil
}
func (s *LocalObjects) Range(ctx context.Context, key, version string, offset, length int64) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if offset < 0 || length < 1 || offset > MaxStoredBytes-length {
		return nil, ErrIntegrity
	}
	path, err := s.path(key, version)
	if err != nil {
		return nil, err
	}
	f, err := openFile(path, MaxStoredBytes)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || offset > info.Size()-length {
		f.Close()
		return nil, ErrIntegrity
	}
	return &sectionFile{Reader: io.NewSectionReader(f, offset, length), file: f}, nil
}
func (s *LocalObjects) Remove(ctx context.Context, key, version string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path, err := s.path(key, version)
	if err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return ErrIntegrity
	}
	if err = os.Remove(path); err != nil {
		return err
	}
	return syncDirectory(s.Dir)
}

func (s *LocalObjects) Locate(ctx context.Context, key string, size int64, digest string) (string, bool, error) {
	path, err := s.path(key, digest)
	if err != nil || size < 1 || size > MaxStoredBytes {
		return "", false, ErrIntegrity
	}
	f, err := openFile(path, MaxStoredBytes)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	defer f.Close()
	if err = verifyStored(ctx, f, size, digest); err != nil {
		return "", false, err
	}
	return digest, true, nil
}

type sectionFile struct {
	io.Reader
	file *os.File
}

func (f *sectionFile) Close() error { return f.file.Close() }

func verifyStored(ctx context.Context, source io.Reader, size int64, digest string) error {
	hash := sha256.New()
	n, err := copyContext(ctx, hash, io.LimitReader(source, size+1))
	if err != nil {
		return err
	}
	if n != size || hex.EncodeToString(hash.Sum(nil)) != digest {
		return ErrIntegrity
	}
	return nil
}
func copyContext(ctx context.Context, target io.Writer, source io.Reader) (int64, error) {
	var total int64
	buffer := make([]byte, 128*1024)
	empty := 0
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, err := source.Read(buffer)
		if n > 0 {
			empty = 0
			written, e := target.Write(buffer[:n])
			total += int64(written)
			if e != nil {
				return total, e
			}
			if written != n {
				return total, io.ErrShortWrite
			}
		} else if err == nil {
			empty++
			if empty >= 100 {
				return total, io.ErrNoProgress
			}
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}
