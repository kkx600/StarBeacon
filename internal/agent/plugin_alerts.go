package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/contract"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const maxDeviceAlertIDs = 1_000_000

var deviceAlertSources = []byte("device_alert_sources")
var deviceAlertCursorKey = []byte("cursor")

func (w *WAL) deviceAlertCursor(plugin, device string) (string, error) {
	if !contract.ValidID(plugin) || !contract.ValidID(device) {
		return "", contract.ErrDeviceAlert
	}
	var cursor string
	err := w.DB.View(func(tx *bolt.Tx) error {
		root := tx.Bucket(deviceAlertSources)
		if root == nil {
			return contract.ErrDeviceAlert
		}
		if source := root.Bucket([]byte(plugin + "/" + device)); source != nil {
			cursor = string(source.Get(deviceAlertCursorKey))
		}
		if !contract.ValidDeviceCursor(cursor) {
			return contract.ErrDeviceAlert
		}
		return nil
	})
	return cursor, err
}

// 同一事务写入设备事件、去重标识和新游标，队列满或校验失败时保留原位置。
func (w *WAL) appendDeviceAlerts(plugin, name, device, expected, route string, page contract.DeviceAlertPage) error {
	if !contract.ValidID(plugin) || !contract.ValidID(device) || !contract.DeviceAlertText(name, 512) ||
		!contract.ValidDeviceCursor(expected) || !contract.ValidDeviceCursor(page.Cursor) || page.Items == nil ||
		len(page.Items) > contract.MaxDeviceAlertPage || len(page.Items) != 0 && route == "" {
		return contract.ErrDeviceAlert
	}
	observed := timestamppb.New(time.Now().UTC())
	return w.DB.Update(func(tx *bolt.Tx) error {
		root := tx.Bucket(deviceAlertSources)
		if root == nil {
			return contract.ErrDeviceAlert
		}
		source, err := root.CreateBucketIfNotExists([]byte(plugin + "/" + device))
		if err != nil {
			return err
		}
		if string(source.Get(deviceAlertCursorKey)) != expected {
			return contract.ErrDeviceAlert
		}
		meta, pending := tx.Bucket([]byte("meta")), tx.Bucket([]byte("alerts"))
		seqKey, sizeKey, countKey, idsKey := []byte("alerts_sequence"), []byte("pending_bytes"), []byte("pending_count"), []byte("device_alert_ids")
		sequence, size, count, ids := uintValue(meta.Get(seqKey)), uintValue(meta.Get(sizeKey)), uintValue(meta.Get(countKey)), uintValue(meta.Get(idsKey))
		for _, alert := range page.Items {
			if alert.Validate() != nil {
				return contract.ErrDeviceAlert
			}
			eventID := contract.DeviceAlertID(w.TenantID, w.RegistrationID, plugin, device, alert.ID)
			dedup, _ := hex.DecodeString(eventID)
			if source.Get(dedup) != nil {
				continue
			}
			if ids >= maxDeviceAlertIDs || sequence == ^uint64(0) || count == ^uint64(0) {
				return ErrWALFull
			}
			sequence++
			record := contract.DeviceAlertRecord{PluginID: plugin, PluginName: name, DeviceID: device, Alert: alert}
			var data bytes.Buffer
			encoder := json.NewEncoder(&data)
			encoder.SetEscapeHTML(false)
			if err := encoder.Encode(record); err != nil {
				return err
			}
			raw := data.Bytes()
			saved, err := contract.ReadDeviceAlertRecord(raw)
			if err != nil {
				return err
			}
			payloadHash, originalHash := sha256.Sum256(raw), sha256.Sum256(saved.Alert.Raw)
			entry := &sensorv1.EventRecord{EventId: eventID, Sequence: sequence, SourceGenerationId: plugin,
				EventTime: timestamppb.New(alert.Time), ObservedAt: observed, EventType: "device_alert", PayloadSchema: contract.DeviceAlertSchema,
				ContentType: "application/json", Payload: raw, PayloadSha256: payloadHash[:], RawSha256: originalHash[:]}
			wire, err := proto.Marshal(entry)
			if err != nil {
				return err
			}
			body, err := json.Marshal(Pending{Route: route, Record: wire})
			if err != nil {
				return err
			}
			if size > w.MaxBytes || uint64(len(body)) > w.MaxBytes-size {
				return ErrWALFull
			}
			if err = pending.Put(key(sequence), body); err != nil {
				return err
			}
			if err = source.Put(dedup, []byte{1}); err != nil {
				return err
			}
			ids++
			count++
			size += uint64(len(body))
		}
		for _, value := range []struct {
			key   []byte
			count uint64
		}{{seqKey, sequence}, {sizeKey, size}, {countKey, count}, {idsKey, ids}} {
			if err := meta.Put(value.key, key(value.count)); err != nil {
				return err
			}
		}
		return source.Put(deviceAlertCursorKey, []byte(page.Cursor))
	})
}
