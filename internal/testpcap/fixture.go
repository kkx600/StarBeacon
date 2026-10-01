// Package testpcap 构造离线验收流量，不向真实网络发送数据。
package testpcap

import (
	"bytes"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"net"
	"time"
)

func HTTP(ng bool) ([]byte, error) {
	var output bytes.Buffer
	var write func(gopacket.CaptureInfo, []byte) error
	var flush func() error
	if ng {
		w, e := pcapgo.NewNgWriter(&output, layers.LinkTypeEthernet)
		if e != nil {
			return nil, e
		}
		write = w.WritePacket
		flush = w.Flush
	} else {
		w := pcapgo.NewWriter(&output)
		if e := w.WriteFileHeader(65535, layers.LinkTypeEthernet); e != nil {
			return nil, e
		}
		write = w.WritePacket
		flush = func() error { return nil }
	}
	request := []byte("GET /starbeacon/validation HTTP/1.1\r\nHost: replay.example\r\nConnection: close\r\n\r\n")
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
	type frame struct {
		server                 bool
		seq, ack               uint32
		syn, ackFlag, psh, fin bool
		payload                []byte
	}
	c, s := uint32(1000), uint32(5000)
	frames := []frame{{false, c, 0, true, false, false, false, nil}, {true, s, c + 1, true, true, false, false, nil}, {false, c + 1, s + 1, false, true, false, false, nil}, {false, c + 1, s + 1, false, true, true, false, request}, {true, s + 1, c + 1 + uint32(len(request)), false, true, false, false, nil}, {true, s + 1, c + 1 + uint32(len(request)), false, true, true, false, response}, {false, c + 1 + uint32(len(request)), s + 1 + uint32(len(response)), false, true, false, true, nil}, {true, s + 1 + uint32(len(response)), c + 2 + uint32(len(request)), false, true, false, true, nil}, {false, c + 2 + uint32(len(request)), s + 2 + uint32(len(response)), false, true, false, false, nil}}
	for i, f := range frames {
		src, dst := net.ParseIP("192.0.2.10"), net.ParseIP("198.51.100.20")
		srcMAC, dstMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}, net.HardwareAddr{0x02, 0, 0, 0, 0, 2}
		srcPort, dstPort := layers.TCPPort(40000), layers.TCPPort(80)
		if f.server {
			src, dst = dst, src
			srcMAC, dstMAC = dstMAC, srcMAC
			srcPort, dstPort = dstPort, srcPort
		}
		eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, TTL: 64, Id: uint16(i), SrcIP: src, DstIP: dst, Protocol: layers.IPProtocolTCP}
		tcp := &layers.TCP{SrcPort: srcPort, DstPort: dstPort, Seq: f.seq, Ack: f.ack, SYN: f.syn, ACK: f.ackFlag, PSH: f.psh, FIN: f.fin, Window: 65535}
		if e := tcp.SetNetworkLayerForChecksum(ip); e != nil {
			return nil, e
		}
		buffer := gopacket.NewSerializeBuffer()
		if e := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload(f.payload)); e != nil {
			return nil, e
		}
		data := buffer.Bytes()
		if e := write(gopacket.CaptureInfo{Timestamp: time.Date(2026, 10, 2, 0, 0, 0, i*1000000, time.UTC), CaptureLength: len(data), Length: len(data)}, data); e != nil {
			return nil, e
		}
	}
	if e := flush(); e != nil {
		return nil, e
	}
	return output.Bytes(), nil
}
