package replay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/kkx600/StarBeacon/internal/contract"
)

const MaxHTTPRawBytes = contract.MaxHTTPRawBytes
const HTTPEncoder = contract.HTTPEncoder

// Origin 说明测试材料来源。合成连接中的握手不代表真实网络曾经建立连接。
type Origin = contract.SampleOrigin

func SameOrigin(a, b *Origin) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

type exactWriter struct{ io.Writer }

func (w exactWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return n, err
}

// WriteHTTPPCAP 只序列化离线测试文件，不创建套接字。原始字节不经 HTTP 解析或换行转换。
// 地址、端口、初始序号、1460 字节分段与帧间隔均固定；时间由调用方冻结并记录。
func WriteHTTPPCAP(ctx context.Context, writer io.Writer, raw []byte, at time.Time) (origin Origin, err error) {
	if int64(len(raw)) < 1 || int64(len(raw)) > MaxHTTPRawBytes || at.Year() < 1970 || at.Year() > 2100 || writer == nil {
		return origin, errors.New("HTTP Raw 大小或合成时间无效")
	}
	if err := ctx.Err(); err != nil {
		return origin, err
	}
	w := pcapgo.NewWriter(exactWriter{writer})
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		return origin, err
	}
	frameID := 0
	write := func(server bool, seq, ack uint32, syn, ackFlag, psh, fin bool, payload []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		srcIP, dstIP := net.IPv4(192, 0, 2, 10), net.IPv4(198, 51, 100, 20)
		srcMAC, dstMAC := net.HardwareAddr{2, 0, 0, 0, 0, 1}, net.HardwareAddr{2, 0, 0, 0, 0, 2}
		srcPort, dstPort := layers.TCPPort(40000), layers.TCPPort(80)
		if server {
			srcIP, dstIP, srcMAC, dstMAC, srcPort, dstPort = dstIP, srcIP, dstMAC, srcMAC, dstPort, srcPort
		}
		eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, TTL: 64, Id: uint16(frameID), SrcIP: srcIP, DstIP: dstIP, Protocol: layers.IPProtocolTCP}
		tcp := &layers.TCP{SrcPort: srcPort, DstPort: dstPort, Seq: seq, Ack: ack, SYN: syn, ACK: ackFlag, PSH: psh, FIN: fin, Window: 65535}
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			return err
		}
		buffer := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
			return err
		}
		data := buffer.Bytes()
		info := gopacket.CaptureInfo{Timestamp: at.UTC().Add(time.Duration(frameID) * time.Millisecond), CaptureLength: len(data), Length: len(data)}
		frameID++
		return w.WritePacket(info, data)
	}
	c, s := uint32(1000), uint32(5000)
	for _, f := range []struct {
		server       bool
		seq, ack     uint32
		syn, ackFlag bool
	}{{false, c, 0, true, false}, {true, s, c + 1, true, true}, {false, c + 1, s + 1, false, true}} {
		if err := write(f.server, f.seq, f.ack, f.syn, f.ackFlag, false, false, nil); err != nil {
			return Origin{}, err
		}
	}
	c++
	s++
	for offset := 0; offset < len(raw); {
		end := min(offset+1460, len(raw))
		if err := write(false, c, s, false, true, true, false, raw[offset:end]); err != nil {
			return Origin{}, err
		}
		c += uint32(end - offset)
		offset = end
		if err := write(true, s, c, false, true, false, false, nil); err != nil {
			return Origin{}, err
		}
	}
	for _, f := range []struct {
		server   bool
		seq, ack uint32
		fin      bool
	}{{false, c, s, true}, {true, s, c + 1, true}, {false, c + 1, s + 1, false}} {
		if err := write(f.server, f.seq, f.ack, false, true, false, f.fin, nil); err != nil {
			return Origin{}, err
		}
	}
	sum := sha256.Sum256(raw)
	return Origin{Kind: "http_raw", Synthetic: true, RawSHA256: hex.EncodeToString(sum[:]), RawBytes: int64(len(raw)), Encoder: HTTPEncoder, SegmentBytes: 1460}, nil
}

// HTTPUpload 与 PCAP 上传采用相同的二进制协议；禁止字符串转码和 Content-Encoding 隐式解压。
func HTTPUpload(w http.ResponseWriter, r *http.Request, at time.Time) (io.Reader, int64, string, *Origin, error) {
	if r.ContentLength < 1 || r.ContentLength > MaxHTTPRawBytes || r.Header.Get("Content-Type") != "application/octet-stream" || r.Header.Get("Content-Encoding") != "" {
		return nil, 0, "", nil, errors.New("请提交 1 字节至 2 MiB 的原始 HTTP 二进制文件")
	}
	name, err := url.PathUnescape(r.Header.Get("X-Filename"))
	if err == nil {
		name, err = Filename(name)
	}
	if err != nil {
		return nil, 0, "", nil, errors.New("HTTP Raw 文件名无效")
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxHTTPRawBytes))
	if err != nil || int64(len(raw)) != r.ContentLength {
		return nil, 0, "", nil, errors.New("HTTP Raw 读取失败或长度不一致")
	}
	var output bytes.Buffer
	origin, err := WriteHTTPPCAP(r.Context(), &output, raw, at)
	if err != nil {
		return nil, 0, "", nil, err
	}
	return bytes.NewReader(output.Bytes()), int64(output.Len()), name, &origin, nil
}
