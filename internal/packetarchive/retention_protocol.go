package packetarchive

import (
	"bytes"
	"encoding/binary"

	"github.com/gopacket/gopacket/layers"
)

type streamPrefix struct {
	kind        string
	probe       [8]byte
	probed      int
	header      [6]byte
	headerBytes int
	read        int64
	left        int
	application int64
	content     byte
	changed     bool
	finished    bool
	banner      bool
	unknown     bool
}

func (p *streamPrefix) consume(raw []byte) {
	if p.unknown || p.application > 0 && p.kind == "ssh" {
		return
	}
	if p.kind == "" {
		n := copy(p.probe[p.probed:], raw)
		p.probed += n
		if p.probed != len(p.probe) {
			return
		}
		raw = raw[n:]
		switch {
		case bytes.HasPrefix(p.probe[:], []byte("SSH-")):
			p.kind = "ssh"
			p.ssh(p.probe[:])
		case p.probe[0] == 22 && p.probe[1] == 3 && p.probe[2] <= 3 && (p.probe[5] == 1 || p.probe[5] == 2):
			p.kind = "tls"
			p.tls(p.probe[:])
		default:
			// 只有识别出的明文传输才使用明文字节上限。
			for _, prefix := range []string{"HTTP/1.", "GET ", "POST ", "HEAD ", "PUT ", "PATCH ", "DELETE ", "OPTIONS "} {
				if bytes.HasPrefix(p.probe[:], []byte(prefix)) {
					p.kind = "http"
					return
				}
			}
			p.kind = "tcp"
			return
		}
	}
	switch p.kind {
	case "ssh":
		p.ssh(raw)
	case "tls":
		p.tls(raw)
	}
}

func (p *streamPrefix) tls(raw []byte) {
	for len(raw) > 0 && !p.unknown {
		if p.left == 0 {
			n := copy(p.header[p.headerBytes:5], raw)
			p.headerBytes += n
			p.read += int64(n)
			raw = raw[n:]
			if p.headerBytes < 5 {
				return
			}
			p.headerBytes = 0
			p.content = p.header[0]
			p.left = int(binary.BigEndian.Uint16(p.header[3:5]))
			if p.content < 20 || p.content > 24 || p.header[1] != 3 || p.header[2] > 3 || p.left == 0 || p.left > (1<<14)+2048 {
				p.unknown = true
				return
			}
			if p.finished && p.content == 23 && p.application == 0 {
				p.application = p.read - 5
			}
		}
		n := min(len(raw), p.left)
		p.left -= n
		p.read += int64(n)
		raw = raw[n:]
		if p.left == 0 {
			// TLS 1.3 的加密握手也使用外层类型 23，不能从它推断握手已结束。
			p.finished = p.finished || p.changed && p.content == 22
			p.changed = p.changed || p.content == 20
		}
	}
}

func (p *streamPrefix) ssh(raw []byte) {
	if !p.banner {
		end := bytes.IndexByte(raw, '\n')
		if end < 0 {
			p.read += int64(len(raw))
			p.unknown = p.read >= 255
			return
		}
		p.read += int64(end + 1)
		if p.read > 255 {
			p.unknown = true
			return
		}
		p.banner = true
		raw = raw[end+1:]
	}
	for len(raw) > 0 && !p.unknown && p.application == 0 {
		if p.left == 0 {
			n := copy(p.header[p.headerBytes:], raw)
			p.headerBytes += n
			p.read += int64(n)
			raw = raw[n:]
			if p.headerBytes < len(p.header) {
				return
			}
			p.headerBytes = 0
			length := binary.BigEndian.Uint32(p.header[:4])
			padding := uint32(p.header[4])
			if length < 6 || length > 256<<10 || padding < 4 || padding > length-2 {
				p.unknown = true
				return
			}
			p.content = p.header[5]
			p.left = int(length - 2)
		}
		n := min(p.left, len(raw))
		p.left -= n
		p.read += int64(n)
		raw = raw[n:]
		if p.left == 0 && p.content == 21 {
			p.application = p.read
		}
	}
}

type directionPrefix struct {
	streamPrefix
	next     uint32
	bytes    int64
	started  bool
	seenSYN  bool
	gap      bool
	quicLong bool
}

func (p *directionPrefix) tcp(tcp *layers.TCP) int64 {
	if tcp.SYN {
		p.seenSYN = true
	}
	if len(tcp.Payload) == 0 {
		return -1
	}
	seq := tcp.Seq
	if tcp.SYN {
		seq++
	}
	if !p.started {
		p.started, p.next = true, seq
	}
	delta := int64(int32(seq - p.next))
	offset := p.bytes + delta
	if delta > 0 {
		p.gap = true
		return -1
	}
	if fresh := tcp.Payload[min(-delta, int64(len(tcp.Payload))):]; len(fresh) != 0 {
		p.consume(fresh)
		p.next += uint32(len(fresh))
		p.bytes += int64(len(fresh))
	}
	return offset
}

func quicLong(raw []byte) bool {
	if len(raw) < 8 || raw[0]&0xc0 != 0xc0 {
		return false
	}
	version := binary.BigEndian.Uint32(raw[1:5])
	if version != 1 && version != 0x6b3343cf {
		return false
	}
	packetType := raw[0] & 0x30
	if version == 1 && packetType == 0x30 || version != 1 && packetType == 0 {
		return false
	}
	dcid := int(raw[5])
	return dcid <= 20 && 6+dcid < len(raw) && raw[6+dcid] <= 20 && 7+dcid+int(raw[6+dcid]) < len(raw)
}

func (p *directionPrefix) udp(raw []byte) int64 {
	if quicLong(raw) {
		p.quicLong = true
	}
	if !p.quicLong || len(raw) < 21 || raw[0]&0xc0 != 0x40 {
		return -1
	}
	offset := p.bytes
	p.bytes += int64(len(raw))
	return offset
}
