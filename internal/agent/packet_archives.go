package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/packetarchive"
	"github.com/kkx600/StarBeacon/internal/store"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type PacketArchiveState struct {
	Enabled         bool                            `json:"enabled"`
	State           string                          `json:"state"`
	Code            string                          `json:"code,omitempty"`
	Codec           string                          `json:"codec"`
	ReservedBytes   string                          `json:"reserved_bytes"`
	QuotaBytes      string                          `json:"quota_bytes"`
	Interfaces      []packetarchive.CaptureProgress `json:"interfaces"`
	LastConfirmedID string                          `json:"last_confirmed_id,omitempty"`
	LastConfirmedAt *time.Time                      `json:"last_confirmed_at,omitempty"`
	ObservedAt      time.Time                       `json:"observed_at"`
}
type PacketArchiveController struct {
	Config   config.Config
	Spool    *packetarchive.Spool
	Capture  *CaptureSupervisor
	WAL      *WAL
	mu       sync.Mutex
	state    PacketArchiveState
	progress map[string]packetarchive.CaptureProgress
	cancel   context.CancelFunc
	done     chan struct{}
}

func NewPacketArchiveController(c config.Config, w *WAL, capture *CaptureSupervisor) (*PacketArchiveController, error) {
	if !c.PacketCapture || capture == nil {
		return nil, packetarchive.ErrIntegrity
	}
	spool, err := packetarchive.NewSpool(w.DB, c.PacketDir, w.TenantID, w.SensorID, w.RegistrationID, c.PacketSpoolBytes, c.PacketSegmentBytes)
	if err != nil {
		return nil, err
	}
	return &PacketArchiveController{Config: c, Spool: spool, Capture: capture, WAL: w, progress: map[string]packetarchive.CaptureProgress{}, state: PacketArchiveState{Enabled: true, State: "waiting", Codec: c.PacketCodec, QuotaBytes: strconv.FormatInt(c.PacketSpoolBytes, 10), Interfaces: []packetarchive.CaptureProgress{}}}, nil
}
func (p *PacketArchiveController) Snapshot() PacketArchiveState {
	p.mu.Lock()
	v := p.state
	if p.state.LastConfirmedAt != nil {
		at := *p.state.LastConfirmedAt
		v.LastConfirmedAt = &at
	}
	v.Interfaces = []packetarchive.CaptureProgress{}
	for _, row := range p.progress {
		v.Interfaces = append(v.Interfaces, row)
	}
	p.mu.Unlock()
	used, err := p.Spool.Reserved()
	if err == nil {
		v.ReservedBytes = strconv.FormatInt(used, 10)
	} else {
		v.Code = "packet_spool_unavailable"
	}
	v.ObservedAt = time.Now().UTC()
	return v
}
func (p *PacketArchiveController) setState(state, code string) {
	p.mu.Lock()
	p.state.State, p.state.Code = state, code
	p.mu.Unlock()
	p.WAL.setFailure("packet_capture_unavailable", code != "")
}
func (p *PacketArchiveController) Start(ctx context.Context) {
	run, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	p.done = make(chan struct{})
	go func() { defer close(p.done); p.captureLoop(run) }()
}
func (p *PacketArchiveController) Close() {
	if p.cancel != nil {
		p.cancel()
		<-p.done
	}
}
func (p *PacketArchiveController) captureLoop(ctx context.Context) {
	var current string
	var stop context.CancelCauseFunc
	var complete chan error
	defer func() {
		if stop != nil {
			stop(context.Canceled)
			<-complete
		}
		p.setState("stopped", "")
	}()
	for ctx.Err() == nil {
		state := p.Capture.Snapshot()
		settings := state.CaptureSettings
		digest := control.CaptureSettingsDigest(control.CaptureSettings(settings))
		if settings.Promiscuous == nil {
			if !pause(ctx, 200*time.Millisecond) {
				return
			}
			continue
		}
		if complete != nil {
			select {
			case err := <-complete:
				stop = nil
				complete = nil
				current = ""
				code := "packet_source_unavailable"
				if errors.Is(err, packetarchive.ErrQuota) {
					code = "packet_spool_full"
				}
				p.setState("failed", code)
				if !pause(ctx, 5*time.Second) {
					return
				}
			default:
			}
		}
		if digest != current {
			if stop != nil {
				stop(packetarchive.ErrConfiguration)
				<-complete
				stop = nil
				complete = nil
			}
			p.mu.Lock()
			p.progress = map[string]packetarchive.CaptureProgress{}
			p.mu.Unlock()
			if len(settings.Interfaces) == 0 {
				p.setState("stopped", "")
				current = digest
			} else {
				run, cancel := context.WithCancelCause(ctx)
				stop = cancel
				complete = make(chan error, 1)
				current = digest
				result := complete
				go func() { result <- p.captureInterfaces(run, settings, digest) }()
			}
		}
		if !pause(ctx, 200*time.Millisecond) {
			return
		}
	}
}
func (p *PacketArchiveController) captureInterfaces(ctx context.Context, settings CaptureSettings, digest string) error {
	call, cancel := context.WithTimeout(ctx, 15*time.Second)
	instructions, err := compileCaptureFilter(call, p.Config, settings.BPFFilter, packetarchive.SnapLength)
	cancel()
	if err != nil {
		return err
	}
	group, run := errgroup.WithContext(ctx)
	runID := store.RandomID("packet_run_")
	for _, name := range settings.Interfaces {
		group.Go(func() error {
			if _, err := net.InterfaceByName(name); err != nil {
				return err
			}
			source, mac, err := packetarchive.OpenSource(name, *settings.Promiscuous, instructions)
			if err != nil {
				return err
			}
			p.setState("capturing", "")
			header := packetarchive.Capture{TenantID: p.WAL.TenantID, SensorID: p.WAL.SensorID, RegistrationID: p.WAL.RegistrationID, RunID: runID, Interface: name, InterfaceMAC: mac, SettingsSHA256: digest, BPFFilter: settings.BPFFilter, Promiscuous: *settings.Promiscuous}
			return packetarchive.CapturePackets(run, p.Spool, header, p.Config.PacketRotateInterval, source, time.Now, func(v packetarchive.CaptureProgress) { p.mu.Lock(); p.progress[name] = v; p.mu.Unlock() })
		})
	}
	return group.Wait()
}

func (p *PacketArchiveController) Upload(ctx context.Context, client sensorv1.SensorServiceClient) error {
	backoff := time.Second
	for ctx.Err() == nil {
		row, err := p.Spool.NextPending()
		if errors.Is(err, os.ErrNotExist) {
			if !pause(ctx, 200*time.Millisecond) {
				return nil
			}
			continue
		}
		if err == nil && row.State == "acknowledged" && row.Acknowledgement != nil {
			err = p.Spool.Confirm(*row.Acknowledgement)
		} else if err == nil {
			row, err = p.Spool.Prepare(ctx, row.ID, p.Config.PacketCodec)
			if err == nil {
				call, cancel := context.WithTimeout(ctx, 90*time.Second)
				err = p.uploadOne(call, client, row)
				cancel()
			}
		}
		p.WAL.setFailure("packet_upload_unavailable", err != nil)
		if err != nil {
			if errors.Is(err, packetarchive.ErrIntegrity) || status.Code(err) == codes.DataLoss {
				_ = p.Spool.Quarantine(row.ID, "packet_validation_failed")
			}
			if !pause(ctx, backoff) {
				return nil
			}
			backoff = min(backoff*2, 30*time.Second)
		} else {
			p.mu.Lock()
			at := time.Now().UTC()
			p.state.LastConfirmedID, p.state.LastConfirmedAt = row.ID, &at
			p.mu.Unlock()
			backoff = time.Second
		}
	}
	return nil
}
func (p *PacketArchiveController) uploadOne(ctx context.Context, client sensorv1.SensorServiceClient, row packetarchive.LocalRecord) error {
	file, row, err := p.Spool.OpenStored(row.ID)
	if err != nil {
		return err
	}
	defer file.Close()
	manifest, _, err := row.Manifest.JSON()
	if err != nil {
		return err
	}
	stream, err := client.UploadPacketArchive(ctx)
	if err != nil {
		return err
	}
	defer stream.CloseSend()
	if err = stream.Send(&sensorv1.PacketArchiveChunk{ManifestJson: manifest}); err != nil {
		return err
	}
	buffer := make([]byte, 128*1024)
	var offset uint64
	for {
		n, e := file.Read(buffer)
		if n > 0 {
			if err = stream.Send(&sensorv1.PacketArchiveChunk{Offset: offset, Data: buffer[:n]}); err != nil {
				return err
			}
			offset += uint64(n)
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
	}
	ack, err := stream.CloseAndRecv()
	if err != nil {
		return err
	}
	if ack == nil || ack.Id != row.ID || ack.ExpiresAt == nil || ack.ExpiresAt.CheckValid() != nil || ack.StoredBytes > uint64(packetarchive.MaxStoredBytes) {
		return packetarchive.ErrIntegrity
	}
	return p.Spool.Confirm(packetarchive.Acknowledgement{ID: ack.Id, ManifestSHA256: ack.ManifestSha256, RawSHA256: ack.RawSha256, StoredSHA256: ack.StoredSha256, StoredBytes: int64(ack.StoredBytes), ObjectVersion: ack.ObjectVersion, ExpiresAt: ack.ExpiresAt.AsTime()})
}
func (p *PacketArchiveController) JSON() json.RawMessage {
	v, _ := json.Marshal(p.Snapshot())
	return v
}
