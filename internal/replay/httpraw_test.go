package replay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestHTTPPCAPPreservesRawBytesAndDeterministicOfflineConnection(t *testing.T) {
	at := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	for _, raw := range [][]byte{
		[]byte("GET /test HTTP/1.1\r\nHost: example.test\r\nHost: duplicate.test\r\n\r\n"),
		append([]byte("POST /binary HTTP/1.1\r\nContent-Length: 999\r\n\r\n"), 0, 255, 254, '\n'),
		bytes.Repeat([]byte{0, 255, '\r', '\n'}, int(MaxHTTPRawBytes)/4),
		[]byte("a"),
	} {
		var output, again bytes.Buffer
		origin, err := WriteHTTPPCAP(context.Background(), &output, raw, at)
		if err != nil {
			t.Fatal(err)
		}
		other, err := WriteHTTPPCAP(context.Background(), &again, raw, at.In(time.FixedZone("offset", 8*3600)))
		if err != nil || origin != other || !bytes.Equal(output.Bytes(), again.Bytes()) {
			t.Fatal("相同字节与时刻没有产生确定性文件", err)
		}
		sum := sha256.Sum256(raw)
		if !origin.Synthetic || origin.Kind != "http_raw" || origin.Encoder != HTTPEncoder || origin.RawBytes != int64(len(raw)) || origin.RawSHA256 != hex.EncodeToString(sum[:]) || origin.SegmentBytes != 1460 {
			t.Fatal("合成来源描述不准确")
		}
		reader, err := pcapgo.NewReader(bytes.NewReader(output.Bytes()))
		if err != nil || reader.LinkType() != layers.LinkTypeEthernet || reader.Snaplen() != 65535 {
			t.Fatal("PCAP 头无效", err)
		}
		var recovered []byte
		packets, seq := 0, uint32(1001)
		for {
			data, info, err := reader.ReadPacketData()
			if err == io.EOF {
				break
			}
			if err != nil || info.CaptureLength != info.Length || !info.Timestamp.Equal(at.Add(time.Duration(packets)*time.Millisecond)) {
				t.Fatal("帧长度或时间无效", err)
			}
			packet := gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Default)
			if packet.ErrorLayer() != nil {
				t.Fatal(packet.ErrorLayer().Error())
			}
			ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
			if len(tcp.Payload) > 1460 {
				t.Fatal("分段超过 MTU 预算")
			}
			if packets == 0 && (!tcp.SYN || tcp.ACK || tcp.Seq != 1000 || ip.SrcIP.String() != "192.0.2.10") {
				t.Fatal("缺少合成 SYN")
			}
			if packets == 1 && (!tcp.SYN || !tcp.ACK || tcp.Ack != 1001 || ip.SrcIP.String() != "198.51.100.20") {
				t.Fatal("缺少合成 SYN ACK")
			}
			if packets == 2 && (tcp.SYN || !tcp.ACK || tcp.Seq != 1001 || tcp.Ack != 5001) {
				t.Fatal("缺少合成 ACK")
			}
			if tcp.SrcPort == 80 && len(tcp.Payload) != 0 {
				t.Fatal("合成了实际不存在的 HTTP 响应")
			}
			if len(tcp.Payload) > 0 {
				if tcp.Seq != seq || tcp.SrcPort != 40000 || !tcp.PSH {
					t.Fatal("请求序号或方向不准确")
				}
				seq += uint32(len(tcp.Payload))
				recovered = append(recovered, tcp.Payload...)
			}
			// 库重新序列化后须逐字节相同，确认长度与网络、传输校验和均已计算。
			if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
				t.Fatal(err)
			}
			buf := gopacket.NewSerializeBuffer()
			if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet), ip, tcp, gopacket.Payload(tcp.Payload)); err != nil || !bytes.Equal(buf.Bytes(), data) {
				t.Fatal("帧校验和或长度不一致", err)
			}
			packets++
		}
		if !bytes.Equal(recovered, raw) || packets != 6+2*((len(raw)+1459)/1460) {
			t.Fatal("原始请求字节或关闭帧丢失")
		}
	}
}

type brokenHTTPWriter struct {
	remaining int
	short     bool
	cancel    context.CancelFunc
}

func (w *brokenHTTPWriter) Write(p []byte) (int, error) {
	if w.cancel != nil {
		w.cancel()
		w.cancel = nil
	}
	if len(p) <= w.remaining {
		w.remaining -= len(p)
		return len(p), nil
	}
	n := max(0, w.remaining)
	w.remaining = 0
	if w.short {
		return n, nil
	}
	return n, io.ErrClosedPipe
}

func TestHTTPPCAPRejectsBoundsCancellationAndPartialWrites(t *testing.T) {
	at := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	for _, raw := range [][]byte{nil, {}, make([]byte, MaxHTTPRawBytes+1)} {
		var out bytes.Buffer
		if _, err := WriteHTTPPCAP(context.Background(), &out, raw, at); err == nil || out.Len() != 0 {
			t.Fatal("越界材料被编码")
		}
	}
	for _, v := range []time.Time{{}, time.Date(2101, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if _, err := WriteHTTPPCAP(context.Background(), io.Discard, []byte("x"), v); err == nil {
			t.Fatal("越界时间被编码")
		}
	}
	if _, err := WriteHTTPPCAP(context.Background(), nil, []byte("x"), at); err == nil {
		t.Fatal("空输出被接受")
	}
	for _, budget := range []int{0, 24, 40, 114, 204, 294, 384, 474, 564, 654, 744} {
		for _, short := range []bool{false, true} {
			origin, err := WriteHTTPPCAP(context.Background(), &brokenHTTPWriter{remaining: budget, short: short}, bytes.Repeat([]byte("x"), 3000), at)
			if err == nil || origin != (Origin{}) {
				t.Fatal("部分文件被发布为有效合成材料", budget, short, err)
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := WriteHTTPPCAP(ctx, io.Discard, []byte("x"), at); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	if _, err := WriteHTTPPCAP(ctx, &brokenHTTPWriter{remaining: 10000, cancel: cancel}, []byte("x"), at); !errors.Is(err, context.Canceled) {
		t.Fatal("写入期间取消未停止", err)
	}
}

func TestHTTPUploadStrictBinaryLengthAndFilename(t *testing.T) {
	at := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	valid := func() (*httptest.ResponseRecorder, *http.Request) {
		r := httptest.NewRequest("POST", "/replay/samples/http", bytes.NewReader([]byte("GET / HTTP/1.1\r\n\r\n")))
		r.Header.Set("Content-Type", "application/octet-stream")
		r.Header.Set("X-Filename", url.PathEscape("请求.raw"))
		return httptest.NewRecorder(), r
	}
	w, r := valid()
	body, size, name, origin, err := HTTPUpload(w, r, at)
	if err != nil || origin == nil || size <= 24 || name != "请求.raw" {
		t.Fatal("有效原始材料未接受", err)
	}
	raw, err := io.ReadAll(body)
	if err != nil || int64(len(raw)) != size {
		t.Fatal(err)
	}
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.ContentLength = -1 }, func(r *http.Request) { r.ContentLength = 0 }, func(r *http.Request) { r.ContentLength = MaxHTTPRawBytes + 1 },
		func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") },
		func(r *http.Request) { r.Header.Set("X-Filename", "%zz") }, func(r *http.Request) { r.Header.Set("X-Filename", "../file") },
		func(r *http.Request) { r.ContentLength++ }, func(r *http.Request) { r.ContentLength-- },
		func(r *http.Request) { r.Body = io.NopCloser(bytes.NewReader(make([]byte, MaxHTTPRawBytes+1))) },
		func(r *http.Request) {
			ctx, cancel := context.WithCancel(r.Context())
			cancel()
			*r = *r.WithContext(ctx)
		},
	} {
		w, r := valid()
		mutate(r)
		if body, size, name, origin, err := HTTPUpload(w, r, at); err == nil || body != nil || size != 0 || name != "" || origin != nil {
			t.Fatal("无效上传产生了可用样本")
		}
	}
}
