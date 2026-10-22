package correlation

import (
	"encoding/base64"
	"encoding/json"

	"github.com/kkx600/StarBeacon/internal/contract"
)

type cursor struct {
	After string `json:"after"`
	Scope string `json:"scope"`
}

func (q Query) fingerprint(tenant string) string {
	q.Cursor = ""
	return Digest(struct {
		Tenant string `json:"tenant"`
		Query  Query  `json:"query"`
	}{tenant, q})
}

func (q Query) Position(tenant string) (string, error) {
	if q.Validate() != nil || !contract.ValidID(tenant) {
		return "", ErrInput
	}
	if q.Cursor == "" {
		return "", nil
	}
	encoded := base64.RawURLEncoding.Strict()
	raw, err := encoded.DecodeString(q.Cursor)
	var position cursor
	if err != nil || encoded.EncodeToString(raw) != q.Cursor || contract.JSONFields(string(raw), []string{"after", "scope"}, 1024) != nil || json.Unmarshal(raw, &position) != nil || !contract.ValidID(position.After) || position.Scope != q.fingerprint(tenant) {
		return "", ErrInput
	}
	return position.After, nil
}

func (q Query) Next(tenant, after string) string {
	raw, _ := json.Marshal(cursor{After: after, Scope: q.fingerprint(tenant)})
	return base64.RawURLEncoding.EncodeToString(raw)
}
