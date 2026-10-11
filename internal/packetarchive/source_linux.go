//go:build linux

package packetarchive

import (
	"errors"
	"net"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"golang.org/x/net/bpf"
)

type afSource struct{ handle *afpacket.TPacket }

func OpenSource(name string, promiscuous bool, filter []bpf.RawInstruction) (PacketSource, string, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil || len(iface.HardwareAddr) != 6 || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return nil, "", ErrIntegrity
	}
	// 每接口独立 16 MiB 环；不共享检测引擎的 fanout，避免从其收包队列分走报文。
	// 使用 1 MiB frame 为 snaplen 与内核报文头留出空间，明确记录超过 snaplen 的截断。
	handle, err := afpacket.NewTPacket(afpacket.OptInterface(name), afpacket.SocketRaw, afpacket.TPacketVersion3, afpacket.OptFrameSize(1024*1024), afpacket.OptBlockSize(4*1024*1024), afpacket.OptNumBlocks(4), afpacket.OptBlockTimeout(10*time.Millisecond), afpacket.OptPollTimeout(100*time.Millisecond), afpacket.OptAddVLANHeader(false))
	if err != nil {
		return nil, "", err
	}
	if len(filter) > 0 {
		err = handle.SetBPF(filter)
	}
	if err == nil {
		err = handle.SetPromiscuous(promiscuous)
	}
	if err != nil {
		handle.Close()
		return nil, "", err
	}
	return &afSource{handle}, iface.HardwareAddr.String(), nil
}
func (s *afSource) Read() ([]byte, gopacket.CaptureInfo, *uint16, error) {
	raw, ci, err := s.handle.ZeroCopyReadPacketData()
	if errors.Is(err, afpacket.ErrTimeout) {
		return nil, ci, nil, ErrPollTimeout
	}
	if err != nil {
		return nil, ci, nil, err
	}
	var vlan *uint16
	for _, value := range ci.AncillaryData {
		if v, ok := value.(afpacket.AncillaryVLAN); ok {
			if v.VLAN < 0 || v.VLAN > 4095 {
				return nil, ci, nil, ErrIntegrity
			}
			id := uint16(v.VLAN)
			vlan = &id
		}
	}
	ci.InterfaceIndex = 0
	return raw, ci, vlan, nil
}
func (s *afSource) Drops() (*uint64, error) {
	_, stats, err := s.handle.SocketStats()
	if err != nil {
		return nil, err
	}
	drops := uint64(stats.Drops())
	return &drops, nil
}
func (s *afSource) Close() { s.handle.Close() }
