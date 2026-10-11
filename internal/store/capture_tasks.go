package store

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/model"
)

var ErrCaptureState = errors.New("采集配置观测不匹配或设备尚未就绪")

// 调用者已锁定设备；心跳、注册代次与在途任务在同一事务中核对。
func qualifyCaptureTask(ctx context.Context, tx pgx.Tx, tenant, sensor, registration string, raw json.RawMessage, signer ed25519.PrivateKey) error {
	p, err := control.ReadCaptureConfiguration(raw)
	if err != nil {
		return err
	}
	var encoded json.RawMessage
	err = tx.QueryRow(ctx, `SELECT health FROM sensors WHERE tenant_id=$1 AND id=$2 AND registration_id=$3 AND active AND last_seen>now()-interval '35 seconds'`, tenant, sensor, registration).Scan(&encoded)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrCaptureState
	}
	if err != nil {
		return err
	}
	var h model.HostHealth
	var observed struct {
		control.CaptureSettings
		Managed      bool   `json:"managed"`
		Revision     uint64 `json:"revision"`
		ConfigSHA256 string `json:"config_sha256"`
		Status       string `json:"status"`
	}
	now := time.Now().UTC()
	if json.Unmarshal(encoded, &h) != nil || json.Unmarshal(h.Capture, &observed) != nil || !observed.Managed || observed.Status == "pending" || observed.Status == "starting" || h.ObservedAt.IsZero() || now.Sub(h.ObservedAt) > 35*time.Second || h.ObservedAt.After(now.Add(time.Minute)) || h.CommandSignerSHA256 != control.Digest(signer.Public().(ed25519.PublicKey)) || observed.Revision != *p.ExpectedRevision || observed.ConfigSHA256 != p.ExpectedConfigSHA256 || control.CaptureSettingsDigest(observed.CaptureSettings) != p.ExpectedSettingsSHA256 {
		return ErrCaptureState
	}
	available := false
	for _, capability := range h.TaskCapabilities {
		available = available || capability == "capture.configure"
	}
	if !available {
		return ErrCaptureState
	}
	for _, name := range p.Settings.Interfaces {
		valid := false
		for _, nic := range h.NetworkInterfaces {
			mac, err := net.ParseMAC(nic.MAC)
			if nic.Name == name && nic.Up && !nic.Loopback && err == nil && len(mac) == 6 {
				valid = true
			}
		}
		if !valid {
			return ErrCaptureState
		}
	}
	return nil
}
