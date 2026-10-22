package correlation

import (
	"cmp"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
)

type Evidence struct {
	EventID   string    `json:"event_id"`
	RawSHA256 string    `json:"raw_sha256"`
	Timestamp time.Time `json:"timestamp"`
}

type Window struct {
	DetectionID       string     `json:"detection_id"`
	SensorID          string     `json:"sensor_id"`
	RegistrationID    string     `json:"sensor_registration_id"`
	GroupValue        string     `json:"group_value"`
	Start             time.Time  `json:"start"`
	End               time.Time  `json:"end"`
	Count             int        `json:"count"`
	MetricValue       int        `json:"metric_value"`
	MissingMetric     int        `json:"missing_metric"`
	Status            string     `json:"status"`
	EvidenceSHA256    string     `json:"evidence_sha256"`
	Evidence          []Evidence `json:"evidence"`
	EvidenceTruncated bool       `json:"evidence_truncated"`
}

type Result struct {
	SchemaVersion       string    `json:"schema_version"`
	TenantID            string    `json:"tenant_id"`
	RuleID              string    `json:"rule_id"`
	RuleRevision        int64     `json:"rule_revision"`
	DefinitionSHA256    string    `json:"definition_sha256"`
	Query               Request   `json:"query"`
	ObservedAt          time.Time `json:"observed_at"`
	SnapshotSHA256      string    `json:"snapshot_sha256"`
	UniqueEvents        int       `json:"unique_events"`
	DuplicateEvents     int       `json:"duplicate_events"`
	MissingGroup        int       `json:"missing_group"`
	ThresholdWindows    int       `json:"threshold_windows"`
	PartialWindows      int       `json:"partial_windows"`
	SourceCoverage      string    `json:"source_coverage"`
	ExecutionAuthorized bool      `json:"execution_authorized"`
	Windows             []Window  `json:"windows"`
}

type fact struct {
	Evidence
	SensorID        string `json:"sensor_id"`
	RegistrationID  string `json:"sensor_registration_id"`
	SourceIP        string `json:"source_ip"`
	DestinationIP   string `json:"destination_ip"`
	SourcePort      uint16 `json:"source_port"`
	DestinationPort uint16 `json:"destination_port"`
	RuleID          string `json:"rule_id"`
}

func canonicalIP(value string) bool {
	if value == "" {
		return true
	}
	address, err := netip.ParseAddr(value)
	return err == nil && address.Zone() == "" && address.Unmap().String() == value
}

func factFrom(tenant string, input model.Alert, query Request) (fact, error) {
	f := fact{Evidence: Evidence{EventID: input.EventID, RawSHA256: input.RawSHA256, Timestamp: input.Timestamp.UTC()}, SensorID: input.SensorID, RegistrationID: input.RegistrationID, SourceIP: input.Source.IP, DestinationIP: input.Destination.IP, SourcePort: input.Source.Port, DestinationPort: input.Destination.Port, RuleID: input.Rule.ID}
	if input.TenantID != tenant || input.Event.Kind != "alert" || input.Event.Original != "" || !contract.ValidID(f.EventID) || !contract.ValidID(f.SensorID) || !contract.ValidID(f.RegistrationID) || len(f.RawSHA256) != 64 || f.Timestamp.Before(query.Start) || !f.Timestamp.Before(query.End) || !canonicalIP(f.SourceIP) || !canonicalIP(f.DestinationIP) || f.RuleID != "" && !Text(f.RuleID, 128, true) {
		return fact{}, ErrSource
	}
	for _, c := range f.RawSHA256 {
		if c < '0' || c > '9' && c < 'a' || c > 'f' {
			return fact{}, ErrSource
		}
	}
	return f, nil
}

func (f fact) value(field string) string {
	switch field {
	case "source.ip":
		return f.SourceIP
	case "destination.ip":
		return f.DestinationIP
	case "source.port":
		if f.SourcePort != 0 {
			return strconv.FormatUint(uint64(f.SourcePort), 10)
		}
	case "destination.port":
		if f.DestinationPort != 0 {
			return strconv.FormatUint(uint64(f.DestinationPort), 10)
		}
	case "rule.id":
		return f.RuleID
	}
	return ""
}

// Evaluate 只处理完整返回的既有告警快照。缺失字段、边界窗口和来源覆盖分别记录。
// 分组始终包含探针与注册代次，不能将不同站点相同私网地址自动视为同一实体。
func Evaluate(rule Record, query Request, input []model.Alert, now time.Time) (Result, error) {
	query.Start, query.End = query.Start.UTC(), query.End.UTC()
	out := Result{SchemaVersion: ResultSchema, TenantID: rule.TenantID, RuleID: rule.ID, RuleRevision: rule.Revision, DefinitionSHA256: rule.DefinitionSHA256, Query: query, ObservedAt: now.UTC(), SourceCoverage: "not_attested", Windows: []Window{}}
	if rule.Validate() != nil || !rule.Active || rule.CreatedAt.After(now) || query.Validate(now) != nil || query.ExpectedRevision != rule.Revision || input == nil {
		return Result{}, ErrInput
	}
	if len(input) > MaxFacts {
		return Result{}, ErrLimit
	}
	seen := make(map[string]fact, len(input))
	for _, item := range input {
		f, err := factFrom(rule.TenantID, item, query)
		if err != nil {
			return Result{}, err
		}
		if previous, ok := seen[f.EventID]; ok {
			if previous != f {
				return Result{}, ErrSource
			}
			out.DuplicateEvents++
			continue
		}
		seen[f.EventID] = f
	}
	facts := make([]fact, 0, len(seen))
	for _, f := range seen {
		facts = append(facts, f)
	}
	slices.SortFunc(facts, func(a, b fact) int { return cmp.Compare(a.EventID, b.EventID) })
	out.UniqueEvents = len(facts)
	out.SnapshotSHA256 = Digest(struct {
		Scope []string
		Query Request
		Facts []fact
	}{[]string{rule.TenantID, rule.ID, strconv.FormatInt(rule.Revision, 10), rule.DefinitionSHA256}, query, facts})
	type state struct {
		window Window
		facts  []fact
		values map[string]bool
	}
	groups := map[string]*state{}
	seconds := int64(rule.Definition.WindowSeconds)
	for _, f := range facts {
		value := f.value(rule.Definition.GroupBy)
		if value == "" {
			out.MissingGroup++
			continue
		}
		start := time.Unix(f.Timestamp.Unix()/seconds*seconds, 0).UTC()
		key := Digest([]string{rule.TenantID, rule.ID, strconv.FormatInt(rule.Revision, 10), rule.DefinitionSHA256, f.SensorID, f.RegistrationID, rule.Definition.GroupBy, value, start.Format(time.RFC3339), "threshold"})
		current := groups[key]
		if current == nil {
			if len(groups) >= MaxGroups {
				return Result{}, ErrLimit
			}
			current = &state{window: Window{DetectionID: key, SensorID: f.SensorID, RegistrationID: f.RegistrationID, GroupValue: value, Start: start, End: start.Add(time.Duration(seconds) * time.Second), Evidence: []Evidence{}}, values: map[string]bool{}}
			groups[key] = current
		}
		current.window.Count++
		current.facts = append(current.facts, f)
		if rule.Definition.Metric == "distinct" {
			metric := f.value(rule.Definition.DistinctField)
			if metric == "" {
				current.window.MissingMetric++
			} else {
				current.values[metric] = true
			}
		}
		if len(current.window.Evidence) < MaxEvidence {
			current.window.Evidence = append(current.window.Evidence, f.Evidence)
		}
	}
	for _, current := range groups {
		w := &current.window
		w.EvidenceSHA256 = Digest(current.facts)
		w.EvidenceTruncated = w.Count > len(w.Evidence)
		w.MetricValue = w.Count
		if rule.Definition.Metric == "distinct" {
			w.MetricValue = len(current.values)
		}
		w.Status = "threshold_not_observed"
		if w.Start.Before(query.Start) || w.End.After(query.End) {
			w.Status = "partial_window"
			out.PartialWindows++
		} else if w.MetricValue >= rule.Definition.Threshold {
			w.Status = "threshold_observed"
			out.ThresholdWindows++
		}
		out.Windows = append(out.Windows, *w)
	}
	slices.SortFunc(out.Windows, func(a, b Window) int {
		if order := a.Start.Compare(b.Start); order != 0 {
			return order
		}
		return cmp.Compare(a.DetectionID, b.DetectionID)
	})
	return out, nil
}
