//go:build !linux

package gatewayblock

import (
	"context"
	"time"
)

func observeEgress(_ context.Context, name string, _ Flow, verified, _ time.Time) Observation {
	return Observation{State: FlowUnknown, Code: "observer_unavailable", Interface: name, StartedAt: verified, FinishedAt: verified}
}
