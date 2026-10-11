package packetarchive

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket/pcapgo"
	"github.com/kkx600/StarBeacon/internal/testpcap"
)

func recordedFile(t *testing.T, empty bool) (*os.File, Capture) {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), "original.pcapng"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	c := captureHeader()
	c.StartedAt = c.StartedAt.Add(123456789 * time.Nanosecond)
	c.BPFFilter = "tcp port 80"
	r, err := NewRecorder(f, c, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if !empty {
		raw, err := testpcap.HTTP(false)
		if err != nil {
			t.Fatal(err)
		}
		reader, err := pcapgo.NewReader(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		for {
			data, ci, err := reader.ReadPacketData()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			ci.Timestamp = ci.Timestamp.Add(123 * time.Nanosecond)
			if err = r.Write(ci, data, nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	drops := uint64(3)
	c, err = r.Seal(c.StartedAt.Add(time.Second), "rotation", &drops)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Sync(); err != nil {
		t.Fatal(err)
	}
	return f, c
}

func TestValidateRawFileMatchesActualPacketsAndNanosecondStatistics(t *testing.T) {
	for _, empty := range []bool{false, true} {
		f, capture := recordedFile(t, empty)
		if err := ValidateRawFile(context.Background(), f, capture); err != nil {
			t.Fatal("原始目录与实际容器不一致", err)
		}
		position, err := f.Seek(0, io.SeekCurrent)
		if err != nil || position != 0 {
			t.Fatal("验证完成后没有回到文件起点", position, err)
		}
	}
}

func TestValidateRawFileRejectsMetadataDriftAndContainerCorruption(t *testing.T) {
	f, capture := recordedFile(t, false)
	for name, mutate := range map[string]func(*Capture){
		"接口":   func(v *Capture) { v.Interface = "eth1" },
		"MAC":  func(v *Capture) { v.InterfaceMAC = "02:00:00:00:00:02" },
		"BPF":  func(v *Capture) { v.BPFFilter = "udp" },
		"包数":   func(v *Capture) { v.Packets++ },
		"字节数":  func(v *Capture) { v.PacketBytes++ },
		"截断":   func(v *Capture) { v.TruncatedPackets = 1 },
		"VLAN": func(v *Capture) { v.VLANOffloadPackets = 1 },
		"时间":   func(v *Capture) { stamp := v.FirstPacketAt.Add(time.Nanosecond); v.FirstPacketAt = &stamp },
		"结束时间": func(v *Capture) { v.EndedAt = v.EndedAt.Add(time.Nanosecond) },
		"丢包":   func(v *Capture) { drops := uint64(4); v.KernelDrops = &drops },
		"丢包未知": func(v *Capture) { v.CounterState = "unavailable"; v.KernelDrops = nil },
		"身份":   func(v *Capture) { v.SensorID = "../other" },
	} {
		t.Run(name, func(t *testing.T) {
			v := capture
			mutate(&v)
			if ValidateRawFile(context.Background(), f, v) == nil {
				t.Fatal("不一致目录被接受")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ValidateRawFile(ctx, f, capture); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	for _, corrupt := range [][]byte{raw[:len(raw)-1], append(bytes.Clone(raw), raw...), []byte("not pcapng")} {
		path := filepath.Join(t.TempDir(), "corrupt.pcapng")
		if err = os.WriteFile(path, corrupt, 0600); err != nil {
			t.Fatal(err)
		}
		input, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		verifyErr := ValidateRawFile(context.Background(), input, capture)
		input.Close()
		if verifyErr == nil {
			t.Fatal("受损或多节容器被接受")
		}
	}
	f.Close()
	if ValidateRawFile(context.Background(), f, capture) == nil {
		t.Fatal("关闭文件被接受")
	}
}
