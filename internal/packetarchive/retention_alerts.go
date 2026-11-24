package packetarchive

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/kkx600/StarBeacon/internal/normalize"
	bolt "go.etcd.io/bbolt"
)

const (
	retentionAlertHistory = 2 * time.Hour
	maxRetentionAlerts    = 32768
	alertClockMargin      = time.Millisecond
)

var (
	retentionAlerts = []byte("packet_retention_alerts")
	alertCount      = []byte("count")
	alertEvicted    = []byte("evicted_through")
)

type retentionAlert struct {
	At        time.Time
	Interface string   `json:"interface,omitempty"`
	Key       *flowKey `json:"key,omitempty"`
}

// RecordRetentionAlert 与事件、来源检查点共用一笔 WAL 事务。
func RecordRetentionAlert(tx *bolt.Tx, payload []byte, eventID string, observed time.Time) error {
	var event struct {
		Timestamp string   `json:"timestamp"`
		Interface string   `json:"in_iface"`
		Source    string   `json:"src_ip"`
		Target    string   `json:"dest_ip"`
		SrcPort   uint16   `json:"src_port"`
		DstPort   uint16   `json:"dest_port"`
		Proto     string   `json:"proto"`
		VLAN      []uint16 `json:"vlan"`
	}
	decoded := json.Unmarshal(payload, &event) == nil
	at, err := normalize.ParseTimestamp(event.Timestamp)
	if err != nil || at.After(observed.Add(time.Minute)) || at.UnixNano() <= 0 {
		at, decoded = observed, false
	}
	start := observed.Add(-retentionAlertHistory)
	if at.Before(start) {
		return nil
	}
	record := retentionAlert{At: at.UTC(), Interface: event.Interface}
	if len(event.Interface) > 15 || strings.ContainsAny(event.Interface, "/\\\x00\r\n ") {
		record.Interface, decoded = "", false
	}
	if decoded {
		a, aErr := netip.ParseAddr(event.Source)
		b, bErr := netip.ParseAddr(event.Target)
		if aErr == nil && bErr == nil {
			key, _ := orderedFlow(netip.AddrPortFrom(a.Unmap(), event.SrcPort), netip.AddrPortFrom(b.Unmap(), event.DstPort), strings.ToLower(event.Proto), vlanScope(event.VLAN))
			if key.valid() && event.SrcPort != 0 && event.DstPort != 0 {
				record.Key = &key
			}
		}
	}
	bucket, err := tx.CreateBucketIfNotExists(retentionAlerts)
	if err != nil {
		return err
	}
	pos := make([]byte, 17, 17+len(eventID))
	pos[0] = 1
	binary.BigEndian.PutUint64(pos[1:9], uint64(at.UnixNano()))
	binary.BigEndian.PutUint64(pos[9:], uint64(tx.ID()))
	pos = append(pos, eventID...)
	count := alertValue(bucket.Get(alertCount))
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if bucket.Get(pos) == nil {
		count++
	}
	if err = bucket.Put(pos, encoded); err != nil {
		return err
	}
	cursor := bucket.Cursor()
	evicted := alertValue(bucket.Get(alertEvicted))
	for i := 0; i < 16; i++ {
		first, _ := cursor.Seek([]byte{1})
		if len(first) < 17 || first[0] != 1 {
			break
		}
		nanos := binary.BigEndian.Uint64(first[1:9])
		if count <= maxRetentionAlerts && nanos >= uint64(start.UnixNano()) {
			break
		}
		evicted = max(evicted, nanos)
		if err = cursor.Delete(); err != nil {
			return err
		}
		count--
	}
	if err = bucket.Put(alertEvicted, sequenceKey(evicted)); err != nil {
		return err
	}
	return bucket.Put(alertCount, sequenceKey(count))
}

func alertValue(raw []byte) uint64 {
	if len(raw) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(raw)
}

var errAlertGap = errors.New("封段窗口内的告警范围无法核对")

func (s *Spool) retentionAlerts(c Capture, cutoff uint64) (out []retentionAlert, err error) {
	start, end := c.StartedAt, c.EndedAt
	if c.FirstPacketAt != nil && c.FirstPacketAt.Before(start) {
		start = *c.FirstPacketAt
	}
	if c.LastPacketAt != nil && c.LastPacketAt.After(end) {
		end = *c.LastPacketAt
	}
	floor, ceiling := uint64(start.Add(-alertClockMargin).UnixNano()), uint64(end.Add(alertClockMargin).UnixNano())
	err = s.DB.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(retentionAlerts)
		if bucket == nil {
			return nil
		}
		if alertValue(bucket.Get(alertEvicted)) >= floor {
			return errAlertGap
		}
		cursor := bucket.Cursor()
		seek := append([]byte{1}, sequenceKey(floor)...)
		for key, value := cursor.Seek(seek); bytes.HasPrefix(key, seek[:1]); key, value = cursor.Next() {
			if len(key) < 17 {
				return ErrIntegrity
			}
			nanos, archived := binary.BigEndian.Uint64(key[1:9]), binary.BigEndian.Uint64(key[9:17])
			if nanos > ceiling {
				break
			}
			if archived >= cutoff {
				continue
			}
			var event retentionAlert
			if json.Unmarshal(value, &event) != nil || uint64(event.At.UnixNano()) != nanos || event.Key != nil && !event.Key.valid() {
				return ErrIntegrity
			}
			if event.Interface != "" && event.Interface != c.Interface {
				continue
			}
			if event.Key == nil {
				return errAlertGap
			}
			out = append(out, event)
		}
		return nil
	})
	return out, err
}
