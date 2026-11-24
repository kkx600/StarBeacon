//go:build !linux

package packetarchive

import "os"

func preallocateCapture(_ *os.File, _ int64) error { return nil }
