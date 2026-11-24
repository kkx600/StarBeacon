package packetarchive

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/gopacket/gopacket/layers"
)

func TestSegmentFlowObservationKeepsActualCountersAtFlowBudget(t *testing.T) {
	ctx := context.Background()
	frames := sessionFrames(t)
	first := frames[0]
	later := first
	later.info.Timestamp = first.info.Timestamp.Add(time.Millisecond)
	unclassified := first
	unclassified.raw = []byte{1, 2, 3}
	unclassified.info.Length, unclassified.info.CaptureLength = len(unclassified.raw), len(unclassified.raw)
	packets := []sessionFrame{later, first, unclassified}
	for i := 1; i <= maxSessionRecords; i++ {
		packets = append(packets, mutateSessionTCP(t, first, func(tcp *layers.TCP) {
			tcp.SrcPort = layers.TCPPort(40000 + i)
		}))
	}
	last := first
	last.info.Timestamp = first.info.Timestamp.Add(2 * time.Millisecond)
	packets = append(packets, last)
	input := sessionArchive(t, "bounded_observation", packets, nil)
	flows, limited, err := ObserveSegmentFlows(ctx, input.File, input.Manifest, IndexRecord{})
	if err != nil || !limited || len(flows) != maxSessionRecords {
		t.Fatal("窗口流观察未受预算限制", len(flows), limited, err)
	}
	capture := flows[0]
	if capture.A.Port() != 40000 || capture.Packets != 3 || capture.OriginalBytes != uint64(3*len(first.raw)) ||
		capture.RetainedBytes != capture.OriginalBytes || !capture.StartedAt.Equal(first.info.Timestamp) || !capture.EndedAt.Equal(last.info.Timestamp) {
		t.Fatalf("达到预算后已有流的实际计数或时间漂移：%+v", capture)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err = ObserveSegmentFlows(canceled, input.File, input.Manifest, IndexRecord{}); !errors.Is(err, context.Canceled) {
		t.Fatal("取消后仍观察流", err)
	}
	if err = input.File.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err = ObserveSegmentFlows(ctx, input.File, input.Manifest, IndexRecord{}); !errors.Is(err, os.ErrClosed) {
		t.Fatal("已关闭原包仍被当成可用观察", err)
	}
}
