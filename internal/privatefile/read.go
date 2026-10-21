// Package privatefile 读取服务预先指定的私有文件，不接受链接或特殊文件。
package privatefile

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

var ErrPrivate = errors.New("私有文件不可读取或权限无效")

func Read(path string, limit int64) ([]byte, error) {
	if limit < 1 || !filepath.IsAbs(path) {
		return nil, ErrPrivate
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > limit {
		return nil, ErrPrivate
	}
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrPrivate
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || opened.Mode().Perm()&0077 != 0 || !opened.Mode().IsRegular() || opened.Size() > limit {
		return nil, ErrPrivate
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, ErrPrivate
	}
	return raw, nil
}
