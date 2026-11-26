package decision

import (
	"encoding/base64"
	"strconv"
	"strings"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
)

type PlanActivity struct {
	ID     string    `json:"id"`
	At     time.Time `json:"at"`
	Kind   string    `json:"kind"`
	State  string    `json:"state"`
	Object string    `json:"object"`
	Code   string    `json:"code"`
	TaskID string    `json:"task_id"`
}

type ActivityPage struct {
	Items      []PlanActivity `json:"items"`
	NextCursor string         `json:"next_cursor"`
}

func (a PlanActivity) Cursor() string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(a.At.UnixMicro(), 10) + "/" + a.ID))
}

func ActivityCursor(value string) (*time.Time, string, error) {
	if value == "" {
		return nil, "", nil
	}
	if len(value) > 112 {
		return nil, "", ErrInput
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	stamp, id, split := strings.Cut(string(raw), "/")
	micros, parse := strconv.ParseInt(stamp, 10, 64)
	at := time.UnixMicro(micros).UTC()
	if err != nil || !split || parse != nil || at.Year() < 1 || at.Year() > 9999 || !contract.ValidID(id) ||
		(PlanActivity{At: at, ID: id}).Cursor() != value {
		return nil, "", ErrInput
	}
	return &at, id, nil
}
