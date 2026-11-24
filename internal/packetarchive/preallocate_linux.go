//go:build linux

package packetarchive

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func preallocateCapture(file *os.File, bytes int64) error {
	err := unix.Fallocate(int(file.Fd()), unix.FALLOC_FL_KEEP_SIZE, 0, bytes)
	switch {
	case errors.Is(err, unix.EOPNOTSUPP), errors.Is(err, unix.ENOSYS):
		return nil
	case errors.Is(err, unix.ENOSPC), errors.Is(err, unix.EDQUOT):
		return ErrQuota
	default:
		return err
	}
}
