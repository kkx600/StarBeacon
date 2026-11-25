package packetarchive

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gopacket/gopacket/pcapgo"
)

type retentionFlowState struct {
	RetentionSession
	directions [2]directionPrefix
	synDir     int
	synSeq     uint32
	synSeen    bool
	protected  bool
	alert      bool
}

func (f *retentionFlowState) protocol() string {
	if f.directions[0].quicLong || f.directions[1].quicLong {
		return "quic"
	}
	for _, proto := range []string{"tls", "ssh", "http"} {
		if f.directions[0].kind == proto || f.directions[1].kind == proto {
			return proto
		}
	}
	return f.Transport
}

type retentionMark struct {
	flow      int
	size      uint64
	offset    int64
	direction int
	stamp     int64
	digest    [32]byte
	mirror    bool
	uncertain bool
	keep      bool
}

func captureVLAN(options pcapgo.NgPacketOptions) *uint16 {
	for _, comment := range options.Comments {
		value, ok := strings.CutPrefix(comment, "StarBeacon: vlan_offload_id=")
		if !ok {
			continue
		}
		raw, _, _ := strings.Cut(value, ";")
		if parsed, err := strconv.ParseUint(raw, 10, 12); err == nil {
			tag := uint16(parsed)
			return &tag
		}
	}
	return nil
}

func scanRetention(ctx context.Context, source *os.File, c Capture, policy RetentionPolicy) ([]retentionMark, []retentionFlowState, error) {
	reader, err := pcapgo.NewNgReader(source, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		return nil, nil, err
	}
	marks := make([]retentionMark, 0, c.Packets)
	flows := make([]retentionFlowState, 0, min(c.Packets, maxSessionRecords))
	active := make(map[flowKey]int)
	mirrorEnabled := policy.Mode == RetentionSmart && *policy.DedupMillis > 0
	for order := uint64(1); order <= c.Packets; order++ {
		if err = ctx.Err(); err != nil {
			return nil, nil, err
		}
		data, info, options, e := reader.ZeroCopyReadPacketDataWithOptions()
		if e != nil {
			return nil, nil, e
		}
		frame := retentionFlow(data, captureVLAN(options))
		stamp := info.Timestamp.UTC()
		mark := retentionMark{flow: -1, size: uint64(len(data)), stamp: stamp.UnixNano(), uncertain: frame.uncertain}
		if !frame.key.A.IsValid() {
			marks = append(marks, mark)
			continue
		}
		index, exists := active[frame.key]
		syn := frame.tcp != nil && frame.tcp.SYN && !frame.tcp.ACK
		newSession := !exists
		if exists {
			previous := &flows[index]
			newSession = syn && (!previous.synSeen || previous.synSeq != frame.tcp.Seq || previous.synDir != frame.direction) ||
				frame.key.Transport == "udp" && stamp.Sub(previous.EndedAt) > 30*time.Second
		}
		if newSession {
			if len(flows) == maxSessionRecords {
				return nil, nil, ErrLimit
			}
			index = len(flows)
			active[frame.key] = index
			flows = append(flows, retentionFlowState{
				RetentionSession: RetentionSession{flowKey: frame.key, FirstPacket: order, StartedAt: stamp, EndedAt: stamp, PolicyRevision: policy.Revision},
				protected:        retentionProtects(policy, frame.key),
			})
		}
		flow := &flows[index]
		if syn {
			flow.synSeen, flow.synSeq, flow.synDir = true, frame.tcp.Seq, frame.direction
		}
		if stamp.Before(flow.StartedAt) {
			flow.StartedAt = stamp
		}
		if stamp.After(flow.EndedAt) {
			flow.EndedAt = stamp
		}
		flow.OriginalBytes += mark.size
		mark.flow, mark.direction = index, frame.direction
		prefix := &flow.directions[frame.direction]
		if frame.tcp != nil {
			mark.offset = prefix.tcp(frame.tcp)
		} else {
			mark.offset = prefix.udp(frame.payload)
		}
		if frame.uncertain || info.Length > info.CaptureLength {
			prefix.gap = true
		}
		if mirrorEnabled && !mark.uncertain && info.Length == info.CaptureLength {
			mark.mirror = true
			mark.digest = frame.mirrorDigest()
		}
		marks = append(marks, mark)
	}
	return marks, flows, nil
}

func bindRetentionAlerts(flows []retentionFlowState, alerts []retentionAlert) {
	byTuple := make(map[flowKey][]int)
	for i, flow := range flows {
		key := flow.flowKey
		key.VLAN = ""
		byTuple[key] = append(byTuple[key], i)
	}
	for _, alert := range alerts {
		tuple := *alert.Key
		tuple.VLAN = ""
		for _, i := range byTuple[tuple] {
			flow := &flows[i]
			if alert.Key.VLAN != "" && alert.Key.VLAN != flow.VLAN {
				continue
			}
			if !alert.At.Before(flow.StartedAt.Add(-alertClockMargin)) && !alert.At.After(flow.EndedAt.Add(alertClockMargin)) {
				flow.alert = true
			}
		}
	}
}

func retainSmart(mark retentionMark, flow *retentionFlowState, policy RetentionPolicy) bool {
	prefix := flow.directions[mark.direction]
	if mark.offset < 0 || prefix.gap || prefix.unknown {
		return true
	}
	switch flow.Protocol {
	case "http":
		return !prefix.seenSYN || prefix.kind != "http" || mark.offset < int64(policy.PlainBytes)
	case "ssh", "tls":
		return prefix.kind != flow.Protocol || prefix.application == 0 || mark.offset < prefix.application+int64(*policy.EncryptedBytes)
	case "quic":
		return !prefix.quicLong || mark.offset < int64(*policy.EncryptedBytes)
	default:
		return true
	}
}

// 用较早保留的副本去重。新副本不会延长第一个副本的去重窗口。
type mirrorWindow struct {
	entries map[[32]byte]int
	ring    [8192]int
	next    int
}

func (w *mirrorWindow) duplicate(marks []retentionMark, n int, maxAge int64, preserve bool) bool {
	mark := &marks[n]
	if !mark.mirror {
		return false
	}
	if found, ok := w.entries[mark.digest]; ok {
		gap := mark.stamp - marks[found].stamp
		if gap >= 0 && gap <= maxAge {
			return !preserve
		}
	}
	if id := w.ring[w.next]; id != 0 {
		key := marks[id-1].digest
		if registered, ok := w.entries[key]; ok && registered == id-1 {
			delete(w.entries, key)
		}
	}
	w.ring[w.next] = n + 1
	w.next = (w.next + 1) % len(w.ring)
	w.entries[mark.digest] = n
	return false
}

func chooseRetained(marks []retentionMark, flows []retentionFlowState, alerts []retentionAlert, policy RetentionPolicy, summary *RetentionSummary) []RetentionSession {
	bindRetentionAlerts(flows, alerts)
	for i := range flows {
		flows[i].Protocol = flows[i].protocol()
	}
	var retained uint64
	mirrors := mirrorWindow{entries: make(map[[32]byte]int)}
	dedupWindow := int64(time.Duration(*policy.DedupMillis) * time.Millisecond)
	for i := range marks {
		mark := &marks[i]
		if mark.flow < 0 {
			summary.UnclassifiedBytes += mark.size
			if policy.Mode != RetentionAlertOnly || mark.uncertain && len(alerts) > 0 {
				mark.keep = true
				retained += mark.size
				summary.UnclassifiedRetainedBytes += mark.size
			}
			continue
		}
		flow := &flows[mark.flow]
		switch policy.Mode {
		case RetentionFull:
			mark.keep = true
		case RetentionAlertOnly:
			mark.keep = flow.alert
		case RetentionSmart:
			preserve := flow.alert || flow.protected
			mark.keep = preserve || retainSmart(*mark, flow, policy)
			if mark.keep && mirrors.duplicate(marks, i, dedupWindow, preserve) {
				mark.keep = false
				summary.DuplicateBytes += mark.size
			}
		}
		if mark.keep {
			retained += mark.size
			flow.RetainedBytes += mark.size
		}
	}
	summary.RetainedBytes = retained
	sessions := make([]RetentionSession, 0, len(flows))
	for _, flow := range flows {
		flow.State = retentionState(flow.OriginalBytes, flow.RetainedBytes)
		sessions = append(sessions, flow.RetentionSession)
	}
	return sessions
}

func rewriteRetained(ctx context.Context, in *os.File, out *os.File, c Capture, marks []retentionMark, limit int64) (Capture, error) {
	if _, err := in.Seek(0, io.SeekStart); err != nil {
		return c, err
	}
	reader, err := pcapgo.NewNgReader(in, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		return c, err
	}
	header := c
	header.Packets, header.PacketBytes, header.FirstPacketAt, header.LastPacketAt = 0, 0, nil, nil
	header.TruncatedPackets, header.VLANOffloadPackets = 0, 0
	header.Retention = nil
	metadata, err := json.Marshal(c.Retention)
	if err != nil {
		return c, err
	}
	recorder, err := newRecorder(out, header, limit, "StarBeacon 留存策略 "+string(metadata))
	if err != nil {
		return c, err
	}
	for _, mark := range marks {
		if err := ctx.Err(); err != nil {
			return c, err
		}
		data, info, options, err := reader.ZeroCopyReadPacketDataWithOptions()
		if err != nil {
			return c, err
		}
		if mark.keep {
			if err = recorder.write(info, data, options, captureVLAN(options) != nil); err != nil {
				return c, err
			}
		}
	}
	result, err := recorder.Seal(c.EndedAt, c.Termination, c.KernelDrops)
	if err != nil {
		return c, err
	}
	result.Retention = c.Retention
	if err = ValidateRawFile(ctx, out, result); err != nil {
		return c, err
	}
	return result, nil
}

func (s *Spool) finalizeRetention(ctx context.Context, row LocalRecord, raw *os.File) (Capture, []RetentionSession, *os.File, error) {
	capture := row.Capture
	plan := row.Seal
	if plan == nil {
		return capture, nil, raw, nil
	}
	if err := ValidateRawFile(ctx, raw, capture); err != nil {
		return capture, nil, nil, err
	}
	summary := plan.summary(capture)
	capture.Retention = &summary
	fallback := func(reason string) (Capture, []RetentionSession, *os.File, error) {
		summary.Mode, summary.Degradation = RetentionFull, reason
		summary.UnclassifiedBytes, summary.UnclassifiedRetainedBytes = capture.PacketBytes, capture.PacketBytes
		_, err := raw.Seek(0, io.SeekStart)
		return capture, nil, raw, err
	}
	if plan.rawFallback() {
		return fallback(plan.Degradation)
	}
	if !plan.Policy.Valid() || plan.AlertCutoff == 0 {
		return capture, nil, nil, ErrIntegrity
	}
	var alerts []retentionAlert
	if plan.Policy.Mode != RetentionFull {
		var err error
		alerts, err = s.retentionAlerts(capture, plan.AlertCutoff)
		if errors.Is(err, errAlertGap) {
			return fallback(alertGap)
		}
		if err != nil {
			return capture, nil, nil, err
		}
	}
	marks, flows, err := scanRetention(ctx, raw, capture, plan.Policy)
	if errors.Is(err, ErrLimit) {
		return fallback(sessionBudget)
	}
	if err != nil {
		return capture, nil, nil, err
	}
	sessions := chooseRetained(marks, flows, alerts, plan.Policy, &summary)
	if summary.RetainedBytes == summary.OriginalBytes {
		_, err = raw.Seek(0, io.SeekStart)
		return capture, sessions, raw, err
	}
	staged, err := os.CreateTemp(s.Dir, row.ID+".retained-")
	if err != nil {
		return capture, nil, nil, err
	}
	compacted, err := rewriteRetained(ctx, raw, staged, capture, marks, (row.ReservedBytes-MaxManifestBytes)/3)
	if err != nil {
		_ = staged.Close()
		_ = os.Remove(staged.Name())
		return capture, nil, nil, err
	}
	return compacted, sessions, staged, nil
}
