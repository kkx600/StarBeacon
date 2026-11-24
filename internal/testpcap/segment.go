package testpcap

import (
	"bytes"
	"io"
	"math/rand/v2"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

type SegmentFrame struct {
	Raw  []byte
	Info gopacket.CaptureInfo
}

// IndexedSegment 交织一条完整 HTTP 会话及两条无业务含义的背景流。
func IndexedSegment() (all, selected []SegmentFrame, err error) {
	raw, err := HTTP(false)
	if err != nil {
		return nil, nil, err
	}
	reader, err := pcapgo.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, nil, err
	}
	for {
		data, info, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		selected = append(selected, SegmentFrame{Raw: data, Info: info})
	}
	background := gopacket.NewPacket(selected[0].Raw, layers.LayerTypeEthernet, gopacket.Default)
	ether := background.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	ip := background.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcp := background.Layer(layers.LayerTypeTCP).(*layers.TCP)
	tcp.SYN, tcp.ACK, tcp.DstPort = false, true, 8080
	if err = tcp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, nil, err
	}
	random := rand.NewPCG(76, 16)
	for i, frame := range selected {
		all = append(all, frame)
		if i >= len(selected)-1 {
			continue
		}
		for port := range 2 {
			tcp.SrcPort = layers.TCPPort(46000 + port)
			for j := range 4 {
				payload := bytes.Repeat([]byte{0x38}, 60<<10)
				if port == 1 {
					for offset := range payload {
						payload[offset] = byte(random.Uint64())
					}
				}
				tcp.Seq = uint32((i*4 + j) * len(payload))
				buffer := gopacket.NewSerializeBuffer()
				if err = gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ether, ip, tcp, gopacket.Payload(payload)); err != nil {
					return nil, nil, err
				}
				data := buffer.Bytes()
				info := gopacket.CaptureInfo{Timestamp: frame.Info.Timestamp.Add(time.Duration(port*4+j+1) * time.Nanosecond), CaptureLength: len(data), Length: len(data)}
				all = append(all, SegmentFrame{Raw: data, Info: info})
			}
		}
	}
	return all, selected, nil
}
