//go:build !linux

package agent

import "syscall"

func captureProcessAttributes() *syscall.SysProcAttr { return nil }
