package testpcap

import (
	"bytes"
	"errors"
	"io"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// HTTPQuality 保持完整握手、序号与校验和，只改变离线样本的端口、分段、分片和到达顺序。
func HTTPQuality(path string, port uint16, segmentBytes, fragmentBytes int, reverse bool) ([]byte, error) {
	if port == 0 || len(path) > 8192 || segmentBytes < 0 || segmentBytes > 8192 || fragmentBytes < 0 || fragmentBytes > 60000 || fragmentBytes != 0 && (fragmentBytes < 24 || fragmentBytes%8 != 0) {
		return nil, errors.New("离线质量样本参数无效")
	}
	base, err := HTTPPath(false, path)
	if err != nil {
		return nil, err
	}
	r, err := pcapgo.NewReader(bytes.NewReader(base))
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	w := pcapgo.NewWriter(&out)
	if err = w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		return nil, err
	}
	var number int
	for {
		data, _, readErr := r.ReadPacketData()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
		p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		eth := p.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
		ip := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		tcp := p.Layer(layers.LayerTypeTCP).(*layers.TCP)
		request := tcp.DstPort == 80 && len(tcp.Payload) > 0
		if tcp.DstPort == 80 {
			tcp.DstPort = layers.TCPPort(port)
		} else {
			tcp.SrcPort = layers.TCPPort(port)
		}
		chunks := [][]byte{tcp.Payload}
		if request && segmentBytes > 0 {
			chunks = nil
			for start := 0; start < len(tcp.Payload); start += segmentBytes {
				chunks = append(chunks, tcp.Payload[start:min(start+segmentBytes, len(tcp.Payload))])
			}
		}
		var generated [][]byte
		offset := 0
		for index, chunk := range chunks {
			partIP, partTCP := *ip, *tcp
			if request {
				partIP.Id = uint16(100 + index)
			}
			partTCP.Seq += uint32(offset)
			partTCP.PSH = tcp.PSH && index == len(chunks)-1
			offset += len(chunk)
			if err = partTCP.SetNetworkLayerForChecksum(&partIP); err != nil {
				return nil, err
			}
			buffer := gopacket.NewSerializeBuffer()
			options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
			if err = gopacket.SerializeLayers(buffer, options, eth, &partIP, &partTCP, gopacket.Payload(chunk)); err != nil {
				return nil, err
			}
			if !request || fragmentBytes == 0 {
				generated = append(generated, append([]byte(nil), buffer.Bytes()...))
				continue
			}
			payload := buffer.Bytes()[14+int(partIP.IHL)*4 : 14+int(partIP.Length)]
			for start := 0; start < len(payload); start += fragmentBytes {
				end := min(start+fragmentBytes, len(payload))
				fragment := partIP
				fragment.Flags, fragment.FragOffset = 0, uint16(start/8)
				if end < len(payload) {
					fragment.Flags = layers.IPv4MoreFragments
				}
				b := gopacket.NewSerializeBuffer()
				if err = gopacket.SerializeLayers(b, options, eth, &fragment, gopacket.Payload(payload[start:end])); err != nil {
					return nil, err
				}
				generated = append(generated, append([]byte(nil), b.Bytes()...))
			}
		}
		if request && reverse {
			for i, j := 0, len(generated)-1; i < j; i, j = i+1, j-1 {
				generated[i], generated[j] = generated[j], generated[i]
			}
		}
		for _, frame := range generated {
			number++
			if err = w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Date(2026, 10, 14, 0, 0, 0, number*1000000, time.UTC), CaptureLength: len(frame), Length: len(frame)}, frame); err != nil {
				return nil, err
			}
		}
	}
	return out.Bytes(), nil
}
