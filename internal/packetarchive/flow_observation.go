package packetarchive

import (
	"context"
	"io"
	"os"
	"slices"

	"github.com/gopacket/gopacket/pcapgo"
)

// ObserveSegmentFlows 用已校验的原包提取当前轮转窗口的流计数。定稿索引包含裁剪前后的字节数，
// 因而试行采集器可直接复用同一索引，常规归档则以实际保存的帧计量。
func ObserveSegmentFlows(ctx context.Context, file *os.File, m Manifest, record IndexRecord) ([]IndexedFlow, bool, error) {
	if m.Encoding.Schema == PackedSchema {
		index, err := record.Decode(m)
		return index.Flows, false, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, false, err
	}
	reader, err := pcapgo.NewNgReader(file, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		return nil, false, err
	}
	positions := make(map[flowKey]int)
	var observed []IndexedFlow
	limited := false
	for {
		if err = ctx.Err(); err != nil {
			return nil, false, err
		}
		raw, info, options, err := reader.ZeroCopyReadPacketDataWithOptions()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false, err
		}
		key := retentionFlow(raw, captureVLAN(options)).key
		if !key.A.IsValid() {
			continue
		}
		stamp := info.Timestamp.UTC()
		pos, found := positions[key]
		if !found {
			if len(observed) == maxSessionRecords {
				limited = true
				continue
			}
			pos = len(observed)
			positions[key] = pos
			observed = append(observed, IndexedFlow{flowKey: key, StartedAt: stamp, EndedAt: stamp, State: retainAll})
		}
		flow := &observed[pos]
		if stamp.Before(flow.StartedAt) {
			flow.StartedAt = stamp
		}
		if stamp.After(flow.EndedAt) {
			flow.EndedAt = stamp
		}
		flow.Packets++
		flow.OriginalBytes += uint64(len(raw))
		flow.RetainedBytes += uint64(len(raw))
	}
	slices.SortFunc(observed, func(a, b IndexedFlow) int { return flowOrder(a.flowKey, b.flowKey) })
	return observed, limited, nil
}
