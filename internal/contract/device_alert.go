package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kkx600/StarBeacon/internal/strictjson"
)

const DeviceAlertSchema = "response.device-alert.v1"
const MaxDeviceAlertPage = 200
const MaxDeviceAlertBytes = 16 * 1024
const maxDeviceAlertProjectedBytes = MaxDeviceAlertBytes + 2048
const maxDeviceAlertRecordBytes = maxDeviceAlertProjectedBytes + 1024

var earliestDeviceAlertTime = time.Unix(0, 0)
var latestDeviceAlertTime = time.Unix(0, math.MaxInt64)

var ErrDeviceAlert = errors.New("设备告警、标识或拉取位置无效")

type DeviceAlert struct {
	ID            string          `json:"id"`
	Time          time.Time       `json:"time"`
	Severity      string          `json:"severity"`
	Name          string          `json:"name"`
	SourceIP      string          `json:"source_ip,omitempty"`
	DestinationIP string          `json:"destination_ip,omitempty"`
	Host          string          `json:"host,omitempty"`
	Raw           json.RawMessage `json:"raw"`
}

type DeviceAlertPage struct {
	Cursor string        `json:"cursor"`
	Items  []DeviceAlert `json:"items"`
}

type DeviceAlertRecord struct {
	PluginID   string      `json:"plugin_id"`
	PluginName string      `json:"plugin_name"`
	DeviceID   string      `json:"device_id"`
	Alert      DeviceAlert `json:"alert"`
}

func DeviceAlertText(s string, max int) bool {
	return s != "" && len(s) <= max && utf8.ValidString(s) && strings.TrimSpace(s) == s && !strings.ContainsFunc(s, unicode.IsControl)
}

func ValidDeviceCursor(s string) bool { return s == "" || DeviceAlertText(s, 512) }

func (v *DeviceAlert) UnmarshalJSON(raw []byte) error {
	fields := []string{"id", "time", "severity", "name", "source_ip", "destination_ip", "host", "raw"}
	type alert DeviceAlert
	var next alert
	if strictjson.TopFields(string(raw), fields, maxDeviceAlertProjectedBytes) != nil || json.Unmarshal(raw, &next) != nil {
		return ErrDeviceAlert
	}
	s, err := deviceSeverity(next.Severity)
	if err != nil {
		return err
	}
	next.Severity, next.Time = s, next.Time.UTC()
	if DeviceAlert(next).Validate() != nil {
		return ErrDeviceAlert
	}
	*v = DeviceAlert(next)
	return nil
}

func deviceSeverity(s string) (string, error) {
	switch s {
	case "critical", "严重":
		return "critical", nil
	case "high", "高危":
		return "high", nil
	case "medium", "中危":
		return "medium", nil
	case "low", "低危":
		return "low", nil
	default:
		return "", ErrDeviceAlert
	}
}

func (v DeviceAlert) Validate() error {
	if !DeviceAlertText(v.ID, 192) || !DeviceAlertText(v.Name, 512) || v.Time.Before(earliestDeviceAlertTime) || v.Time.After(latestDeviceAlertTime) ||
		v.Host != "" && !DeviceAlertText(v.Host, 256) || len(v.Raw) > MaxDeviceAlertBytes || !json.Valid(v.Raw) {
		return ErrDeviceAlert
	}
	for _, ip := range []string{v.SourceIP, v.DestinationIP} {
		if ip == "" {
			continue
		}
		address, err := netip.ParseAddr(ip)
		if err != nil || address.Zone() != "" || address.Is4In6() || address.String() != ip {
			return ErrDeviceAlert
		}
	}
	if severity, err := deviceSeverity(v.Severity); err != nil || severity != v.Severity {
		return ErrDeviceAlert
	}
	return nil
}

func ReadDeviceAlertPage(raw []byte) (DeviceAlertPage, error) {
	var v DeviceAlertPage
	if strictjson.TopFields(string(raw), []string{"cursor", "items"}, MaxDeviceAlertBytes) != nil {
		return v, ErrDeviceAlert
	}
	var cursor struct {
		Value *string `json:"cursor"`
	}
	if json.Unmarshal(raw, &cursor) != nil || cursor.Value == nil || json.Unmarshal(raw, &v) != nil || !ValidDeviceCursor(v.Cursor) || v.Items == nil || len(v.Items) > MaxDeviceAlertPage {
		return v, ErrDeviceAlert
	}
	return v, nil
}

func ReadDeviceAlertRecord(raw []byte) (DeviceAlertRecord, error) {
	var v DeviceAlertRecord
	if strictjson.TopFields(string(raw), []string{"plugin_id", "plugin_name", "device_id", "alert"}, maxDeviceAlertRecordBytes) != nil ||
		json.Unmarshal(raw, &v) != nil || !ValidID(v.PluginID) || !DeviceAlertText(v.PluginName, 512) || !ValidID(v.DeviceID) || v.Alert.Validate() != nil {
		return v, ErrDeviceAlert
	}
	return v, nil
}

func DeviceAlertID(tenant, registration, plugin, device, upstream string) string {
	var b bytes.Buffer
	for _, value := range []string{"StarBeacon/device-alert/v1", tenant, registration, plugin, device, upstream} {
		text(&b, value)
	}
	sum := sha256.Sum256(b.Bytes())
	return hex.EncodeToString(sum[:])
}
