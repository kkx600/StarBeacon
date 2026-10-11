//go:build !linux

package packetarchive

import "golang.org/x/net/bpf"

func OpenSource(_ string, _ bool, _ []bpf.RawInstruction) (PacketSource, string, error) {
	return nil, "", ErrIntegrity
}
