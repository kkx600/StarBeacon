package packetarchive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket/pcapgo"
)

func TestSegmentFlowScopeAndFrozenEvidence(t *testing.T) {
	ctx := context.Background()
	for _, indexed := range []bool{true, false} {
		t.Run(map[bool]string{true: "定稿索引", false: "普通归档"}[indexed], func(t *testing.T) {
			var s *Spool
			var row LocalRecord
			if indexed {
				s, row, _ = indexedFixture(t)
			} else {
				s, _ = testSpool(t)
				frames := sessionFrames(t)
				pending := hotRetention(t, s, "plain_flow", frames[0].info.Timestamp.Add(-time.Second), frames)
				sealRetention(t, pending, frames[len(frames)-1].info.Timestamp.Add(time.Second))
				row, _ = retainedRecord(t, s, pending.ID)
			}
			m := *row.Manifest
			key, _ := orderedFlow(netip.MustParseAddrPort("192.0.2.10:40000"), netip.MustParseAddrPort("198.51.100.20:80"), "tcp", "")
			request := SegmentFlowRequest{flowKey: key, ManifestSHA256: row.ManifestSHA256, RawSHA256: m.Encoding.RawSHA256}
			raw, err := json.Marshal(request)
			if err != nil || json.Unmarshal(raw, &request) != nil {
				t.Fatal("会话分段请求往返失败", err, string(raw))
			}
			if json.Unmarshal([]byte(strings.Replace(string(raw), `"transport":"tcp"`, `"transport":"tcp","transport":"udp"`, 1)), &request) == nil {
				t.Fatal("重复字段被接受")
			}
			if json.Unmarshal([]byte(strings.Replace(string(raw), `"transport":"tcp"`, `"transport":1`, 1)), &request) == nil {
				t.Fatal("非字符串协议被接受")
			}
			stored, _, err := s.OpenStored(row.ID)
			if err != nil {
				t.Fatal(err)
			}
			defer stored.Close()
			var offsets []int64
			source := func(ctx context.Context, offset, size int64) (io.ReadCloser, error) {
				offsets = append(offsets, offset)
				return RangeFile(stored)(ctx, offset, size)
			}
			input := SessionInput{Manifest: m, ObjectVersion: "cached_object", Range: source}
			if indexed {
				index, err := row.Index.Decode(m)
				if err != nil {
					t.Fatal(err)
				}
				input.Index = &index
			} else {
				input.File, err = StageSessionSource(ctx, t.TempDir(), m, source)
				if err != nil {
					t.Fatal(err)
				}
				defer input.File.Close()
			}
			wrong := request
			wrong.RawSHA256 = strings.Repeat("f", 64)
			if _, err := ReadSegmentFlow(ctx, wrong, input); !errors.Is(err, ErrIntegrity) {
				t.Fatal("摘要错误的请求被接受", err)
			}
			flow, err := ReadSegmentFlow(ctx, request, input)
			if err != nil || len(flow.packets) == 0 || flow.Retention != retainAll {
				t.Fatal("所选流没有提取到冻结报文", err)
			}
			if indexed && !slices.Equal(offsets, []int64{m.Encoding.Frames[1].StoredOffset}) {
				t.Fatal("不应取回无关帧", offsets)
			}
			missing := input
			missing.Index, missing.File = nil, nil
			if _, err := ReadSegmentFlow(ctx, request, missing); !errors.Is(err, ErrIntegrity) {
				t.Fatal("缺少读取证据时仍接受会话分段", err)
			}
			if indexed {
				gone := errors.New("选中帧不可读取")
				broken := input
				broken.Range = func(context.Context, int64, int64) (io.ReadCloser, error) { return nil, gone }
				if _, err := ReadSegmentFlow(ctx, request, broken); !errors.Is(err, gone) {
					t.Fatal("所选帧读取失败后仍尝试还原", err)
				}
			}
			if _, err := flow.Inspect(len(flow.packets) + 1); !errors.Is(err, ErrPacketNotFound) {
				t.Fatal("包序号越过会话范围", err)
			}
			packet, err := flow.Inspect(1)
			if err != nil || packet.RawSHA256 != m.Encoding.RawSHA256 || packet.PacketSHA256 != Digest(flow.packets[0].raw) {
				t.Fatal("逐包回执未绑定实际捕获", err)
			}
			var output bytes.Buffer
			if err := flow.WriteSnapshot(ctx, &output); err != nil {
				t.Fatal(err)
			}
			reader, err := pcapgo.NewNgReader(&output, pcapgo.DefaultNgReaderOptions)
			if err != nil || !strings.Contains(reader.SectionInfo().Comment, `"completeness":"snapshot"`) {
				t.Fatal("文件误标为完整会话", err)
			}
			canceled, stop := context.WithCancel(ctx)
			stop()
			if err := flow.WriteSnapshot(canceled, io.Discard); !errors.Is(err, context.Canceled) {
				t.Fatal("取消导出后仍继续写入快照", err)
			}
			if err := (SegmentFlow{}).WriteSnapshot(ctx, io.Discard); !errors.Is(err, ErrPacketNotFound) {
				t.Fatal("空分段仍生成快照", err)
			}
			wrong = request
			wrong.B = netip.MustParseAddrPort("203.0.113.45:65535")
			if _, err := ReadSegmentFlow(ctx, wrong, input); !errors.Is(err, ErrPacketNotFound) {
				t.Fatal("未命中的五元组读取到了无关包", err)
			}
			if !indexed {
				if err := os.Truncate(input.File.Name(), 24); err != nil {
					t.Fatal(err)
				}
				if _, err := ReadSegmentFlow(ctx, request, input); err == nil {
					t.Fatal("本机暂存截断后仍被接受")
				}
			}
		})
	}
}
