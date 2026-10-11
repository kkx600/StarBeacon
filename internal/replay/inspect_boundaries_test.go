package replay

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func ngBoundaryBlock(order binary.ByteOrder, kind, size uint32) []byte {
	raw := make([]byte, size)
	order.PutUint32(raw, kind)
	order.PutUint32(raw[4:], size)
	order.PutUint32(raw[size-4:], size)
	if kind == 0x0a0d0d0a {
		order.PutUint32(raw[8:], 0x1a2b3c4d)
		if size >= 28 {
			order.PutUint16(raw[12:], 1)
			order.PutUint64(raw[16:], ^uint64(0))
		}
	}
	if kind == 1 && size >= 20 {
		order.PutUint16(raw[8:], uint16(layers.LinkTypeEthernet))
		order.PutUint32(raw[12:], 65535)
	}
	return raw
}

func TestPCAPNGBlockBoundariesRejectAllocationAndKeyMaterial(t *testing.T) {
	order := binary.LittleEndian
	section := ngBoundaryBlock(order, 0x0a0d0d0a, 28)
	for _, mode := range []string{"missing_section", "byte_order", "tail", "short_section", "short_interface", "interfaces", "snaplen", "short_data", "captured_size", "captured_original", "captured_block", "short_simple", "simple_size", "secrets", "header", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			raw := bytes.Clone(section)
			switch mode {
			case "missing_section":
				raw = ngBoundaryBlock(order, 1, 20)
			case "byte_order":
				order.PutUint32(raw[8:], 0)
			case "tail":
				order.PutUint32(raw[24:], 32)
			case "short_section":
				raw = ngBoundaryBlock(order, 0x0a0d0d0a, 16)
			case "short_interface":
				raw = append(raw, ngBoundaryBlock(order, 1, 16)...)
			case "interfaces":
				for range 257 {
					raw = append(raw, ngBoundaryBlock(order, 1, 20)...)
				}
			case "snaplen":
				b := ngBoundaryBlock(order, 1, 20)
				order.PutUint32(b[12:], MaxFrameBytes+1)
				raw = append(raw, b...)
			case "short_data":
				raw = append(raw, ngBoundaryBlock(order, 6, 28)...)
			case "captured_size", "captured_original", "captured_block":
				b := ngBoundaryBlock(order, 6, 36)
				caplen, original := uint32(8), uint32(8)
				if mode == "captured_size" {
					caplen, original = MaxFrameBytes+1, MaxFrameBytes+1
				}
				if mode == "captured_original" {
					caplen, original = 2, 1
				}
				order.PutUint32(b[20:], caplen)
				order.PutUint32(b[24:], original)
				raw = append(raw, b...)
			case "short_simple":
				raw = append(raw, ngBoundaryBlock(order, 3, 12)...)
			case "simple_size":
				b := ngBoundaryBlock(order, 3, 16)
				order.PutUint32(b[8:], MaxFrameBytes+1)
				raw = append(raw, b...)
			case "secrets":
				raw = append(raw, ngBoundaryBlock(order, 10, 12)...)
			case "header":
				raw = append(raw, []byte{0, 0, 0, 0}...)
			}
			path := filepath.Join(t.TempDir(), "boundary.pcapng")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			ctx := context.Background()
			if mode == "cancelled" {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			if checkNG(ctx, f, int64(len(raw))) == nil {
				t.Fatal("PCAPNG 边界无效仍被接受", mode)
			}
		})
	}
	for _, order := range []binary.ByteOrder{binary.BigEndian, binary.LittleEndian} {
		raw := append(ngBoundaryBlock(order, 0x0a0d0d0a, 28), ngBoundaryBlock(order, 1, 20)...)
		path := filepath.Join(t.TempDir(), "valid-headers.pcapng")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkNG(context.Background(), f, int64(len(raw))); err != nil {
			t.Fatal("合法字节序被拒绝", err)
		}
		_ = f.Close()
	}
}

func TestInspectionPreservesCaptureTruncationAndTimestampOrder(t *testing.T) {
	var capture bytes.Buffer
	writer := pcapgo.NewWriter(&capture)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "capture.pcap")
	if err := os.WriteFile(path, capture.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(context.Background(), path); err == nil {
		t.Fatal("空容器被计为有效样本")
	}
	stamp := time.Date(2026, 10, 3, 1, 0, 0, 0, time.UTC)
	_, data := handshakePacket(t, handshakeFrame{seq: 1000, syn: true})
	for i := range 3 {
		ci := gopacket.CaptureInfo{CaptureLength: len(data), Length: len(data) + 10, Timestamp: stamp.Add(-time.Duration(i) * time.Second)}
		if err := writer.WritePacket(ci, data); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, capture.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	meta, err := Inspect(context.Background(), path)
	if err != nil || meta.Packets != 3 || meta.TruncatedPackets != 3 || !meta.First.Equal(stamp.Add(-2*time.Second)) || !meta.Last.Equal(stamp) || meta.TCPHandshake.CompleteHandshakes != 0 {
		t.Fatal("截断或乱序捕获事实不正确", meta, err)
	}
	for _, raw := range [][]byte{nil, bytes.Repeat([]byte{0}, 24)} {
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Inspect(context.Background(), path); err == nil {
			t.Fatal("无效容器被接受")
		}
	}
	if _, err := Inspect(context.Background(), filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("缺失样本被接受")
	}
}
