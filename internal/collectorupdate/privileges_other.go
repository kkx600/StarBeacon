//go:build !linux

package collectorupdate

import "errors"

func dropCapturePrivileges(uid, gid int) error {
	return errors.New("抓包权限转换只适用于 Linux")
}
