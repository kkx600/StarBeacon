package packetarchive

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/kkx600/StarBeacon/internal/testpcap"
)

func byteRanges(raw []byte) RangeSource {
	return func(_ context.Context, offset, size int64) (io.ReadCloser, error) {
		if offset < 0 || size < 0 || offset > int64(len(raw)) || size > int64(len(raw))-offset {
			return nil, io.ErrUnexpectedEOF
		}
		return io.NopCloser(bytes.NewReader(raw[offset : offset+size])), nil
	}
}

func TestCodecPreservesOriginalCapturesAndIndependentRanges(t *testing.T) {
	for _, ng := range []bool{false, true} {
		pcap, err := testpcap.HTTP(ng)
		if err != nil {
			t.Fatal(err)
		}
		// 多帧输入含完整握手、业务正文及跨帧字节，不能只验证单帧文本压缩。
		raw := bytes.Repeat(pcap, MinFrameBytes/len(pcap)+3)
		for _, codec := range []string{"none", "zstd"} {
			var stored bytes.Buffer
			index, err := EncodeFrames(context.Background(), &stored, bytes.NewReader(raw), codec, MinFrameBytes)
			if err != nil || index.Validate() != nil || len(index.Frames) < 2 {
				t.Fatalf("编码失败：%+v %v", index, err)
			}
			var output bytes.Buffer
			if err = ReadRange(context.Background(), &output, byteRanges(stored.Bytes()), index, 0, int64(len(raw))); err != nil || !bytes.Equal(raw, output.Bytes()) {
				t.Fatalf("原字节往返不一致：%v", err)
			}
			output.Reset()
			offset, length := int64(MinFrameBytes-17), int64(65)
			calls := 0
			ranges := byteRanges(stored.Bytes())
			selective := func(ctx context.Context, off, size int64) (io.ReadCloser, error) {
				calls++
				return ranges(ctx, off, size)
			}
			if err = ReadRange(context.Background(), &output, selective, index, offset, length); err != nil || !bytes.Equal(raw[offset:offset+length], output.Bytes()) || calls != 2 {
				t.Fatalf("跨帧范围读取不一致：%d %v", calls, err)
			}
		}
	}
}

func TestCodecRejectsCorruptionAndFalseRanges(t *testing.T) {
	raw := bytes.Repeat([]byte("\x00HTTP/1.1\r\nTLS\xff"), 16000)
	var stored bytes.Buffer
	index, err := EncodeFrames(context.Background(), &stored, bytes.NewReader(raw), "zstd", MinFrameBytes)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Encoding){
		"偏移空洞":   func(v *Encoding) { v.Frames[1].StoredOffset++ },
		"原始帧过大":  func(v *Encoding) { v.Frames[0].RawLength = MaxFrameBytes + 1 },
		"多余原始长度": func(v *Encoding) { v.RawBytes++ },
		"大写摘要":   func(v *Encoding) { v.RawSHA256 = "A" + v.RawSHA256[1:] },
		"未知编解码器": func(v *Encoding) { v.Codec = "gzip" },
		"实现漂移":   func(v *Encoding) { v.Implementation = "unqualified" },
		"非法帧尺寸":  func(v *Encoding) { v.FrameBytes = MinFrameBytes + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			v := index
			v.Frames = append([]Frame(nil), index.Frames...)
			mutate(&v)
			if ReadRange(context.Background(), io.Discard, byteRanges(stored.Bytes()), v, 0, v.RawBytes) == nil {
				t.Fatal("错误目录被接受")
			}
		})
	}
	t.Run("压缩内容损坏", func(t *testing.T) {
		data := bytes.Clone(stored.Bytes())
		data[len(data)/2] ^= 0x40
		if ReadRange(context.Background(), io.Discard, byteRanges(data), index, 0, index.RawBytes) == nil {
			t.Fatal("损坏内容被接受")
		}
	})
	t.Run("存储端忽略范围", func(t *testing.T) {
		source := func(context.Context, int64, int64) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(stored.Bytes())), nil
		}
		if ReadRange(context.Background(), io.Discard, source, index, 0, 1) == nil {
			t.Fatal("额外内容被接受")
		}
	})
	t.Run("总摘要冲突", func(t *testing.T) {
		v := index
		v.RawSHA256 = Digest([]byte("different"))
		if ReadRange(context.Background(), io.Discard, byteRanges(stored.Bytes()), v, 0, v.RawBytes) == nil {
			t.Fatal("总摘要冲突被接受")
		}
	})
	t.Run("长度伪造", func(t *testing.T) {
		v := index
		v.Frames = append([]Frame(nil), index.Frames...)
		v.Frames[len(v.Frames)-1].RawLength--
		v.RawBytes--
		if ReadRange(context.Background(), io.Discard, byteRanges(stored.Bytes()), v, 0, v.RawBytes) == nil {
			t.Fatal("解压实际长度未受控")
		}
	})
}

type failedReader struct{}

func (failedReader) Read([]byte) (int, error) { return 0, io.ErrClosedPipe }

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestCodecCancellationBudgetsAndIOFailures(t *testing.T) {
	raw := bytes.Repeat([]byte{0x2a}, MinFrameBytes+7)
	for _, p := range []struct {
		codec  string
		frame  int
		source io.Reader
		writer io.Writer
	}{
		{"zip", MinFrameBytes, bytes.NewReader(raw), io.Discard},
		{"zstd", MinFrameBytes - 1, bytes.NewReader(raw), io.Discard},
		{"none", MinFrameBytes, bytes.NewReader(raw[:23]), io.Discard},
		{"none", MinFrameBytes, nil, io.Discard},
		{"zstd", MinFrameBytes, failedReader{}, io.Discard},
		{"none", MinFrameBytes, bytes.NewReader(raw), failedWriter{}},
		{"none", MinFrameBytes, bytes.NewReader(raw), shortWriter{}},
	} {
		if _, err := EncodeFrames(context.Background(), p.writer, p.source, p.codec, p.frame); err == nil {
			t.Fatal("非法参数或 IO 失败被忽略")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := EncodeFrames(ctx, io.Discard, bytes.NewReader(raw), "zstd", MinFrameBytes); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	// 有界零流生成器避免测试为了检查上限而自身分配整个大文件。
	if _, err := EncodeFrames(context.Background(), io.Discard, io.LimitReader(zeros{}, MaxSegmentBytes+1), "none", MaxFrameBytes); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	var stored bytes.Buffer
	index, err := EncodeFrames(context.Background(), &stored, bytes.NewReader(raw), "zstd", MinFrameBytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range [][2]int64{{-1, 1}, {0, 0}, {index.RawBytes, 1}, {index.RawBytes - 1, 2}, {0, 1 << 62}} {
		if ReadRange(context.Background(), io.Discard, byteRanges(stored.Bytes()), index, request[0], request[1]) == nil {
			t.Fatal("非法读取范围被接受")
		}
	}
	if err := ReadRange(ctx, io.Discard, byteRanges(stored.Bytes()), index, 0, index.RawBytes); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := ReadRange(context.Background(), failedWriter{}, byteRanges(stored.Bytes()), index, 0, index.RawBytes); err == nil {
		t.Fatal("输出失败被忽略")
	}
	if err := ReadRange(context.Background(), io.Discard, func(context.Context, int64, int64) (io.ReadCloser, error) { return nil, io.ErrClosedPipe }, index, 0, index.RawBytes); err == nil {
		t.Fatal("范围请求失败被忽略")
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }
