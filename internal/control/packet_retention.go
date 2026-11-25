package control

import (
	"encoding/json"
	"time"

	"github.com/kkx600/StarBeacon/internal/packetpolicy"
)

const PacketRetentionConfigure = "packet.retention.configure"

func validatePacketRetention(raw json.RawMessage) error {
	var change packetpolicy.Change
	return json.Unmarshal(raw, &change)
}

func ValidatePacketRetentionReceipt(c Command, receipt Receipt) error {
	var change packetpolicy.Change
	var observed packetpolicy.Observation
	if c.Kind != PacketRetentionConfigure || c.ID != receipt.CommandID || receipt.Code != "" || receipt.FinishedAt == nil ||
		json.Unmarshal(c.Payload, &change) != nil || json.Unmarshal(receipt.Result, &observed) != nil ||
		!change.Confirms(observed, c.ID) || observed.AppliedAt.Before(c.IssuedAt.Add(-time.Minute)) || observed.AppliedAt.After(*receipt.FinishedAt) {
		return packetpolicy.ErrInput
	}
	return nil
}
