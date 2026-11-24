package traffic

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/model"
)

func TestPacketSessionSegmentValidatesItsArchiveEvidenceAndRetention(t *testing.T) {
	begin := time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)
	raw := PacketSessionSegment{Schema: PacketSessionSchema, ArchiveID: "archive_owned", RunID: "run_owned", Interface: "eth0",
		ManifestSHA256: strings.Repeat("1", 64), ArchiveRawSHA: strings.Repeat("2", 64),
		WindowStart: begin, WindowEnd: begin.Add(time.Minute), FirstObserved: begin.Add(time.Second), LastObserved: begin.Add(time.Minute - time.Second),
		OriginalBytes: 1024, RetainedBytes: 1024, RetainedPackets: 4, Retention: "retained", PolicyRevision: 1, NetworkDomain: "lab"}
	newDoc := func(segment PacketSessionSegment) model.Alert {
		doc := model.Alert{SourceGenerationID: "archive_owned", Timestamp: raw.LastObserved, ObservedAt: raw.WindowEnd}
		encoded, err := json.Marshal(segment)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(encoded)
		doc.RawSHA256 = hex.EncodeToString(digest[:])
		doc.Event.Kind, doc.Event.Dataset, doc.Event.Original = PacketSessionKind, PacketSessionDataset, string(encoded)
		return doc
	}
	truncated, metadata := raw, raw
	truncated.Retention, truncated.RetainedBytes = "policy_truncated", 512
	metadata.Retention, metadata.RetainedBytes, metadata.RetainedPackets = "metadata_only", 0, 0
	for _, state := range []PacketSessionSegment{raw, truncated, metadata} {
		actual, err := ParsePacketSession(newDoc(state))
		if err != nil || actual.Retention != state.Retention || actual.RetainedBytes != state.RetainedBytes || !actual.LastObserved.Equal(state.LastObserved) {
			t.Fatal("有效留存语义被拒绝", actual, err)
		}
	}
	for name, change := range map[string]func(*PacketSessionSegment){
		"其他归档":   func(v *PacketSessionSegment) { v.ArchiveID = "foreign_archive" },
		"摘要错误":   func(v *PacketSessionSegment) { v.ArchiveRawSHA = "damaged" },
		"失配时间":   func(v *PacketSessionSegment) { v.LastObserved = begin },
		"过长窗口":   func(v *PacketSessionSegment) { v.WindowEnd = begin.Add(2 * time.Hour) },
		"缺失网络域":  func(v *PacketSessionSegment) { v.NetworkDomain = "" },
		"计数过量":   func(v *PacketSessionSegment) { v.RetainedBytes++ },
		"错误留存标记": func(v *PacketSessionSegment) { v.Retention = "metadata_only" },
	} {
		t.Run(name, func(t *testing.T) {
			item := raw
			change(&item)
			if _, err := ParsePacketSession(newDoc(item)); err == nil {
				t.Fatal("来源或留存漂移被接纳")
			}
		})
	}
	doc := newDoc(raw)
	doc.Event.Dataset = "suricata.eve"
	if _, err := ParsePacketSession(doc); err == nil {
		t.Fatal("EVE 被当作服务端归档观察")
	}
	doc = newDoc(raw)
	doc.Event.Original += " "
	if _, err := ParsePacketSession(doc); err == nil {
		t.Fatal("原文修改通过冻结摘要校验")
	}
}
