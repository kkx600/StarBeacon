package syslogdata

import "time"

type Health struct {
	ReceiverBinding
	State           string     `json:"state"`
	Reason          string     `json:"reason"`
	ObservedAt      time.Time  `json:"observed_at"`
	StartedAt       time.Time  `json:"started_at"`
	Received        string     `json:"received"`
	Persisted       string     `json:"persisted"`
	Dropped         string     `json:"dropped"`
	Rejected        string     `json:"rejected"`
	FramingErrors   string     `json:"framing_errors"`
	LastPersistedAt *time.Time `json:"last_persisted_at"`
	MaxMessageBytes int        `json:"max_message_bytes"`
	IdentityQuality string     `json:"identity_quality"`
	UpstreamLoss    string     `json:"upstream_loss"`
}

func (h Health) Valid() bool {
	if !h.ReceiverBinding.Valid() || h.StartedAt.IsZero() || h.ObservedAt.IsZero() || h.StartedAt.After(h.ObservedAt) || h.MaxMessageBytes < 256 || h.MaxMessageBytes > MaxMessageBytes {
		return false
	}
	for _, v := range []string{h.Received, h.Persisted, h.Dropped, h.Rejected, h.FramingErrors} {
		if !canonicalCounter(v) {
			return false
		}
	}
	if h.LastPersistedAt != nil && (h.LastPersistedAt.Before(h.StartedAt) || h.LastPersistedAt.After(h.ObservedAt)) {
		return false
	}
	switch h.State {
	case "starting":
		if h.Reason != "listener_not_ready" {
			return false
		}
	case "listening":
		if h.Reason != "" {
			return false
		}
	case "unavailable":
		if h.Reason != "listener_unavailable" {
			return false
		}
	case "degraded":
		if h.Reason != "durable_queue_unavailable" {
			return false
		}
	case "stopped":
		if h.Reason != "listener_stopped" {
			return false
		}
	default:
		return false
	}
	if h.Transport == "tls" {
		return h.IdentityQuality == "certificate" && h.UpstreamLoss == "unknown"
	}
	if h.IdentityQuality != "network_allowlist" {
		return false
	}
	if h.Transport == "udp" {
		return h.UpstreamLoss == "unmeasurable"
	}
	return h.UpstreamLoss == "unknown"
}
