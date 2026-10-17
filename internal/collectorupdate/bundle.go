// Package collectorupdate 管理离线签名采集器制品和可恢复的程序切换，不修改业务数据格式。
package collectorupdate

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const MaxArchiveBytes int64 = 256 << 20
const MaxExpandedBytes int64 = 512 << 20
const maxFiles = 20000

var versionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?$`)
var commitPattern = regexp.MustCompile(`^[a-f0-9]{40}$`)
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// Proof 使用独立签名域；发布签名不继承设备命令或注册密钥的信任。
type Proof struct {
	SchemaVersion int       `json:"schema_version"`
	Generation    int64     `json:"generation"`
	Version       string    `json:"version"`
	Commit        string    `json:"commit"`
	Arch          string    `json:"arch"`
	SHA256        string    `json:"sha256"`
	Size          int64     `json:"size"`
	DataSchema    int       `json:"data_schema"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type Envelope struct {
	Proof     Proof  `json:"proof"`
	Signature []byte `json:"signature"`
}

func (p Proof) validate() error {
	if p.SchemaVersion != 1 || p.Generation < 1 || !versionPattern.MatchString(p.Version) || !commitPattern.MatchString(p.Commit) || !digestPattern.MatchString(p.SHA256) || p.Size < 1 || p.Size > MaxArchiveBytes || p.DataSchema != 1 || (p.Arch != "amd64" && p.Arch != "arm64") || p.IssuedAt.IsZero() || !p.ExpiresAt.After(p.IssuedAt) || p.ExpiresAt.Sub(p.IssuedAt) > 30*24*time.Hour {
		return errors.New("采集器制品身份、代次、数据格式或授权期限无效")
	}
	return nil
}

func proofBytes(p Proof) []byte {
	raw, _ := json.Marshal(p)
	return append([]byte("StarBeacon/collector.release.v1\x00"), raw...)
}

func Sign(p Proof, key ed25519.PrivateKey) (Envelope, error) {
	if err := p.validate(); err != nil {
		return Envelope{}, err
	}
	if len(key) != ed25519.PrivateKeySize {
		return Envelope{}, errors.New("发布私钥无效")
	}
	return Envelope{Proof: p, Signature: ed25519.Sign(key, proofBytes(p))}, nil
}

func (e Envelope) Verify(key ed25519.PublicKey, now time.Time) error {
	if err := e.Proof.validate(); err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, proofBytes(e.Proof), e.Signature) {
		return errors.New("采集器制品签名无效")
	}
	if e.Proof.Arch != runtime.GOARCH || e.Proof.IssuedAt.After(now.Add(time.Minute)) || !e.Proof.ExpiresAt.After(now) {
		return errors.New("采集器制品架构或授权时间不匹配")
	}
	return nil
}

type manifest struct {
	SchemaVersion int    `json:"schema_version"`
	Version       string `json:"version"`
	Commit        string `json:"commit"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	Binaries      map[string]struct {
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	} `json:"binaries"`
}

type Release struct {
	Proof        Proof  `json:"proof"`
	Directory    string `json:"directory"`
	BinarySHA256 string `json:"binary_sha256"`
}

func (r Release) binary(root string) string {
	return filepath.Join(root, "releases", r.Directory, "bin", "starbeacon-agent")
}

func (r Release) validate() error {
	if r.Proof.validate() != nil || r.Directory != fmt.Sprintf("%d-%s", r.Proof.Generation, r.Proof.SHA256) || !digestPattern.MatchString(r.BinarySHA256) {
		return errors.New("已安装制品的身份绑定无效")
	}
	return nil
}

// Stage 先核对整个 ZIP 的签名摘要，再在独立目录中有界解包；既有版本不覆盖。
func Stage(ctx context.Context, root, archive string, envelope Envelope, key ed25519.PublicKey, now time.Time) (Release, error) {
	return stage(ctx, root, archive, envelope, key, now, 180)
}

func stage(ctx context.Context, root, archive string, envelope Envelope, key ed25519.PublicKey, now time.Time, retentionDays int) (Release, error) {
	var result Release
	if retentionDays < 1 || retentionDays > 3650 {
		return result, errors.New("维护制品保留期必须为 1–3650 天")
	}
	if err := envelope.Verify(key, now); err != nil {
		return result, err
	}
	f, err := os.OpenFile(archive, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return result, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != envelope.Proof.Size {
		return result, errors.New("采集器 ZIP 类型或长度不匹配")
	}
	result = Release{Proof: envelope.Proof, Directory: fmt.Sprintf("%d-%s", envelope.Proof.Generation, envelope.Proof.SHA256)}
	base := filepath.Join(root, "releases")
	if err = os.MkdirAll(base, 0755); err != nil {
		return Release{}, err
	}
	var disk unix.Statfs_t
	if err = unix.Statfs(base, &disk); err != nil {
		return Release{}, err
	}
	if disk.Bavail*uint64(disk.Bsize) < uint64(envelope.Proof.Size)+(64<<20) {
		return Release{}, errors.New("制品校验快照空间不足，至少保留 64 MiB 维护余量")
	}
	// 摘要与解包必须使用同一份私有字节，源文件仍可被其它进程通过原 inode 改写。
	snapshot, err := snapshotArchive(ctx, base, f, envelope.Proof)
	if err != nil {
		return Release{}, err
	}
	defer func() { snapshot.Close(); os.Remove(snapshot.Name()) }()
	z, err := zip.NewReader(snapshot, envelope.Proof.Size)
	if err != nil || len(z.File) < 2 || len(z.File) > maxFiles {
		return Release{}, errors.New("采集器 ZIP 结构或文件数量无效")
	}
	target := filepath.Join(base, result.Directory)
	if _, err = os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		return Release{}, errors.New("同名制品目录已存在，禁止覆盖")
	}
	if _, err = os.Lstat(filepath.Join(root, "reclaim", result.Directory+".json")); !errors.Is(err, os.ErrNotExist) {
		return Release{}, errors.New("同名制品仍有未完成回收，禁止重新暂存")
	}
	scratch, err := os.MkdirTemp(base, ".stage-")
	if err != nil {
		return Release{}, err
	}
	defer os.RemoveAll(scratch)
	destination, err := os.OpenRoot(scratch)
	if err != nil {
		return Release{}, err
	}
	defer destination.Close()
	var total uint64
	seen := map[string]bool{}
	// 先检查所有条目与磁盘余量，避免在解压到一半时才发现压缩炸弹或空间不足。
	for _, entry := range z.File {
		if err = ctx.Err(); err != nil {
			return Release{}, err
		}
		name := strings.TrimSuffix(entry.Name, "/")
		if !strings.HasPrefix(name, "starbeacon-collector/") || path.Clean(name) != name || strings.ContainsAny(name, "\\\x00\r\n") || len(name) > 1024 || entry.Mode()&os.ModeType != 0 && !entry.Mode().IsDir() || seen[name] || entry.UncompressedSize64 > 128<<20 {
			return Release{}, errors.New("采集器 ZIP 包含越界、重复、链接或超限文件")
		}
		seen[name] = true
		total += entry.UncompressedSize64
		if total > uint64(MaxExpandedBytes) {
			return Release{}, errors.New("采集器 ZIP 解压预算超限")
		}
		if name == "starbeacon-collector/manifest.json" && entry.UncompressedSize64 > 2<<20 {
			return Release{}, errors.New("采集器来源清单超过容量")
		}
	}
	if err = unix.Statfs(base, &disk); err != nil {
		return Release{}, err
	}
	if disk.Bavail*uint64(disk.Bsize) < total+64<<20 {
		return Release{}, errors.New("制品暂存空间不足，至少保留 64 MiB 维护余量")
	}
	for _, entry := range z.File {
		if err = ctx.Err(); err != nil {
			return Release{}, err
		}
		name := strings.TrimSuffix(entry.Name, "/")
		name = strings.TrimPrefix(name, "starbeacon-collector/")
		if entry.Mode().IsDir() {
			err = destination.MkdirAll(name, 0755)
		} else {
			err = extract(destination, name, entry)
		}
		if err != nil {
			return Release{}, err
		}
	}
	raw, err := destination.ReadFile("manifest.json")
	if err != nil || len(raw) > 2<<20 {
		return Release{}, errors.New("采集器制品缺少有界来源清单")
	}
	var m manifest
	if json.Unmarshal(raw, &m) != nil || m.SchemaVersion != 1 || m.OS != "linux" || m.Version != result.Proof.Version || m.Commit != result.Proof.Commit || m.Arch != result.Proof.Arch || len(m.Binaries) != 1 {
		return Release{}, errors.New("采集器来源清单与签名不一致")
	}
	binary, ok := m.Binaries["starbeacon-agent"]
	if !ok || !digestPattern.MatchString(binary.SHA256) {
		return Release{}, errors.New("采集器来源清单没有唯一程序身份")
	}
	result.BinarySHA256 = binary.SHA256
	binaryInfo, err := destination.Stat("bin/starbeacon-agent")
	if err != nil || binaryInfo.Size() != binary.Size {
		return Release{}, errors.New("采集器程序长度与来源清单不一致")
	}
	if err = verifyBinary(filepath.Join(scratch, "bin/starbeacon-agent"), result); err != nil {
		return Release{}, err
	}
	// 过期依据随完整制品一起发布，暂存后尚未执行切换的制品也能独立回收。
	if err = atomicJSON(filepath.Join(scratch, releaseRetentionFile), releaseRetention{SchemaVersion: 1, Release: result, StagedAt: now, RetainUntil: now.AddDate(0, 0, retentionDays)}); err != nil {
		return Release{}, err
	}
	if err = os.Chmod(scratch, 0755); err != nil {
		return Release{}, err
	}
	if err = syncTree(scratch); err != nil {
		return Release{}, err
	}
	if err = os.Rename(scratch, target); err != nil {
		return Release{}, err
	}
	return result, syncDirectory(base)
}

func snapshotArchive(ctx context.Context, directory string, input io.Reader, proof Proof) (_ *os.File, err error) {
	file, err := os.CreateTemp(directory, ".archive-")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			file.Close()
			os.Remove(file.Name())
		}
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(file, h), io.LimitReader(archiveInput{ctx, input}, proof.Size+1))
	if err != nil {
		return nil, err
	}
	if n != proof.Size || hex.EncodeToString(h.Sum(nil)) != proof.SHA256 {
		return nil, errors.New("采集器 ZIP 快照长度或摘要不匹配")
	}
	return file, nil
}

type archiveInput struct {
	context.Context
	io.Reader
}

func (r archiveInput) Read(p []byte) (int, error) {
	if err := r.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(p)
}

func syncTree(root string) error {
	var directories []string
	if err := filepath.WalkDir(root, func(name string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			directories = append(directories, name)
		}
		return nil
	}); err != nil {
		return err
	}
	// 文件已单独同步；从叶目录到根目录持久化目录项后才能发布整个版本。
	for index := len(directories) - 1; index >= 0; index-- {
		if err := syncDirectory(directories[index]); err != nil {
			return err
		}
	}
	return nil
}

func extract(root *os.Root, name string, entry *zip.File) error {
	if err := root.MkdirAll(filepath.Dir(name), 0755); err != nil {
		return err
	}
	input, err := entry.Open()
	if err != nil {
		return err
	}
	defer input.Close()
	mode := os.FileMode(0644)
	if name == "bin/starbeacon-agent" {
		mode = 0755
	}
	output, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	n, copyErr := io.Copy(output, io.LimitReader(input, int64(entry.UncompressedSize64)+1))
	syncErr := output.Sync()
	closeErr := output.Close()
	if uint64(n) != entry.UncompressedSize64 {
		return errors.New("采集器 ZIP 解压长度不一致")
	}
	return errors.Join(copyErr, syncErr, closeErr)
}

func verifyBinary(name string, release Release) error {
	f, err := os.OpenFile(name, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 20 || info.Size() > 128<<20 {
		return errors.New("采集器程序类型或体积无效")
	}
	header := make([]byte, 20)
	if _, err = io.ReadFull(f, header); err != nil {
		return err
	}
	machine := byte(62)
	if release.Proof.Arch == "arm64" {
		machine = 183
	}
	if !bytes.Equal(header[:6], []byte{0x7f, 'E', 'L', 'F', 2, 1}) || header[18] != machine || header[19] != 0 {
		return errors.New("采集器程序不是目标 Linux ELF")
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != release.BinarySHA256 {
		return errors.New("采集器程序摘要不匹配")
	}
	return nil
}
