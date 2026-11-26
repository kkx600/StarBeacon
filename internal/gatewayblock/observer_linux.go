package gatewayblock

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

func observeEgress(ctx context.Context, name string, flow Flow, verified, lease time.Time) Observation {
	o := Observation{State: FlowUnknown, Code: "observer_unavailable", Interface: name, StartedAt: verified, FinishedAt: verified}
	if !lease.After(time.Now().Add(ObserveWindow + time.Second)) {
		o.Code = "window_short"
		return o
	}
	iface, err := net.InterfaceByName(name)
	if err != nil || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) != 6 {
		return o
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return o
	}
	defer unix.Close(fd)
	protocol := binary.NativeEndian.Uint16([]byte{0, unix.ETH_P_ALL})
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: iface.Index, Protocol: protocol}); err != nil {
		return o
	}
	start := time.Now()
	if start.After(verified.Add(time.Second)) {
		return o
	}
	o.StartedAt = start.UTC()
	if code := sampleEgress(ctx, fd, iface.Index, start.Add(ObserveWindow), flow, &o); code != "" {
		o.Code = code
	} else if current, err := net.InterfaceByName(name); err != nil || current.Index != iface.Index ||
		current.Flags&net.FlagUp == 0 || !bytes.Equal(iface.HardwareAddr, current.HardwareAddr) {
		o.Code = "observer_changed"
	} else if o.OriginalPackets > 0 || o.Reconnect != nil {
		o.State, o.Code = FlowContinued, ""
	} else if o.EgressPackets > 0 {
		o.State, o.Code = FlowPaused, ""
	} else {
		o.Code = "egress_idle"
	}
	o.FinishedAt = time.Now().UTC()
	return o
}

func sampleEgress(ctx context.Context, fd, iface int, until time.Time, flow Flow, o *Observation) string {
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	var prefix [128]byte
	for time.Now().Before(until) {
		if ctx.Err() != nil {
			return "observer_unavailable"
		}
		n, address, err := unix.Recvfrom(fd, prefix[:], unix.MSG_TRUNC)
		if errors.Is(err, unix.EAGAIN) {
			wait := max(1, int(min(time.Until(until), 100*time.Millisecond)/time.Millisecond))
			if _, err := unix.Poll(poll, wait); err != nil && !errors.Is(err, unix.EINTR) {
				return "observer_unavailable"
			}
			if poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
				return "observer_unavailable"
			}
			continue
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return "observer_unavailable"
		}
		link, ok := address.(*unix.SockaddrLinklayer)
		if !ok || link.Ifindex != iface || link.Pkttype != unix.PACKET_OUTGOING {
			continue
		}
		var raw [2]byte
		binary.NativeEndian.PutUint16(raw[:], link.Protocol)
		switch binary.BigEndian.Uint16(raw[:]) {
		case unix.ETH_P_IP, unix.ETH_P_IPV6:
		default:
			continue
		}
		o.EgressPackets++
		if o.EgressPackets >= maxEgressPackets {
			return "packet_loss"
		}
		if !o.countPacket(prefix[:min(n, len(prefix))], n, flow) {
			return "packet_format"
		}
	}
	// 窗口结束时仍有排队报文时不能证明窗口完整。
	if ready, err := unix.Poll(poll, 0); err != nil || ready != 0 {
		return "packet_loss"
	}
	stats, err := unix.GetsockoptTpacketStats(fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
	if err != nil || stats.Drops != 0 {
		return "packet_loss"
	}
	return ""
}
