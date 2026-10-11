package packetarchive

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcapgo"
)

type captureFixture struct {
	read   func() ([]byte, gopacket.CaptureInfo, *uint16, error)
	stats  func() (*uint64, error)
	closed bool
}

func (f *captureFixture) Read() ([]byte, gopacket.CaptureInfo, *uint16, error) { return f.read() }
func (f *captureFixture) Drops() (*uint64, error) {
	if f.stats != nil {
		return f.stats()
	}
	return nil, os.ErrNotExist
}
func (f *captureFixture) Close() { f.closed = true }

func TestCaptureRotationPreservesFrameAcrossBoundaries(t *testing.T) {
	s, _ := testSpool(t)
	h := captureHeader()
	clock := h.StartedAt
	ctx, cancel := context.WithCancelCause(context.Background())
	payload := bytes.Repeat([]byte{0x29}, 200000)
	calls := 0
	stats := uint64(3)
	source := &captureFixture{stats: func() (*uint64, error) { v := stats; return &v, nil }}
	source.read = func() ([]byte, gopacket.CaptureInfo, *uint16, error) {
		calls++
		if calls == 10 {
			cancel(ErrConfiguration)
			return nil, gopacket.CaptureInfo{}, nil, ErrPollTimeout
		}
		clock = clock.Add(100 * time.Millisecond)
		stats++
		return payload, gopacket.CaptureInfo{Timestamp: clock, CaptureLength: len(payload), Length: len(payload)}, nil, nil
	}
	if err := CapturePackets(ctx, s, h, 30*time.Second, source, func() time.Time { return clock }, nil); err != nil {
		t.Fatal(err)
	}
	if !source.closed {
		t.Fatal("捕获句柄未关闭")
	}
	rows, err := s.List()
	if err != nil || len(rows) != 2 {
		t.Fatal(len(rows), err)
	}
	packets := 0
	for _, row := range rows {
		if row.State != "sealed" || row.Capture.KernelDrops == nil {
			t.Fatal("实际计数被遗漏", row.State)
		}
		path, _ := s.path(row.ID, ".raw")
		f, e := os.Open(path)
		if e != nil {
			t.Fatal(e)
		}
		reader, e := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
		if e != nil {
			t.Fatal(e)
		}
		for {
			raw, ci, e := reader.ReadPacketData()
			if e == io.EOF {
				break
			}
			if e != nil || !bytes.Equal(raw, payload) || ci.Length != len(payload) {
				t.Fatal("轮转边界原包丢失或被修改", e)
			}
			packets++
		}
		f.Close()
	}
	if packets != 9 || rows[0].Capture.Termination != "configuration" {
		t.Fatal("轮转遗漏当前读取帧或关闭原因不真实", packets)
	}
}

func TestCaptureTimeoutsRotationAndUnknownCounterRemainExplicit(t *testing.T) {
	s, _ := testSpool(t)
	h := captureHeader()
	clock := h.StartedAt
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	source := &captureFixture{read: func() ([]byte, gopacket.CaptureInfo, *uint16, error) {
		calls++
		clock = clock.Add(time.Second)
		if calls == 4 {
			cancel()
		}
		return nil, gopacket.CaptureInfo{}, nil, ErrPollTimeout
	}}
	if err := CapturePackets(ctx, s, h, 2*time.Second, source, func() time.Time { return clock }, nil); err != nil {
		t.Fatal(err)
	}
	rows, err := s.List()
	if err != nil || len(rows) != 3 {
		t.Fatal(len(rows), err)
	}
	for _, row := range rows {
		if row.Capture.KernelDrops != nil || row.Capture.CounterState != "unavailable" || row.Capture.Packets != 0 {
			t.Fatal("未观测被填成零")
		}
	}
}

func TestCaptureSourceErrorAndInvalidFramesRetainPartialEvidence(t *testing.T) {
	for _, code := range []string{"source", "frame", "vlan", "oversize"} {
		t.Run(code, func(t *testing.T) {
			s, _ := testSpool(t)
			h := captureHeader()
			calls := 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			source := &captureFixture{read: func() ([]byte, gopacket.CaptureInfo, *uint16, error) {
				calls++
				raw := []byte{1, 2, 3}
				ci := gopacket.CaptureInfo{Timestamp: h.StartedAt, CaptureLength: 3, Length: 3}
				if calls == 1 {
					return raw, ci, nil, nil
				}
				switch code {
				case "source":
					return nil, ci, nil, io.ErrUnexpectedEOF
				case "frame":
					ci.CaptureLength = 2
				case "vlan":
					v := uint16(5000)
					return raw, ci, &v, nil
				case "oversize":
					raw = make([]byte, SnapLength+1)
					ci.CaptureLength = len(raw)
					ci.Length = len(raw)
					cancel()
				}
				return raw, ci, nil, nil
			}}
			err := CapturePackets(ctx, s, h, 30*time.Second, source, func() time.Time { return h.StartedAt }, nil)
			rows, e := s.List()
			if e != nil || len(rows) != 1 || !source.closed {
				t.Fatal(e)
			}
			if code == "oversize" {
				if err != nil || rows[0].Capture.TruncatedPackets != 1 || rows[0].State != "sealed" {
					t.Fatal("大帧截断未标注", err)
				}
			} else if err == nil || rows[0].State != "quarantined" {
				t.Fatal("中断现场被当成完整证据", err)
			}
		})
	}
}

func TestCaptureRejectsInvalidBudgetAndMissingSource(t *testing.T) {
	s, _ := testSpool(t)
	h := captureHeader()
	if err := CapturePackets(context.Background(), s, h, time.Second, nil, time.Now, nil); !errors.Is(err, ErrIntegrity) {
		t.Fatal(err)
	}
	source := &captureFixture{}
	if err := CapturePackets(context.Background(), s, h, 0, source, time.Now, nil); !errors.Is(err, ErrIntegrity) {
		t.Fatal(err)
	}
}
