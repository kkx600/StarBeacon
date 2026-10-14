package application

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
)

type Attribution struct {
	SchemaVersion string `json:"schema_version"`
	DeploymentID  string `json:"deployment_id"`
	StateSHA256   string `json:"state_sha256"`
	RawSHA256     string `json:"raw_sha256"`
	ProductID     string `json:"product_id"`
	ProductName   string `json:"product_name"`
	CategoryID    string `json:"category_id"`
	Result        Result `json:"result"`
}

var errTransactionUnbound = errors.New("告警协议事务为引擎估计，不能用于产品归因")

// 仅解析实际协议事务字段；不使用 DNS 回答地址、通用指纹或其他流的名称填补缺测。
func EVEObservation(raw []byte) (Observation, bool, error) {
	o := Observation{SchemaVersion: ObservationSchema, TLSALPN: []string{}, DNSNames: []string{}}
	var event struct {
		EventType string `json:"event_type"`
		AppProto  string `json:"app_proto"`
		TxGuessed bool   `json:"tx_guessed"`
		HTTP      *struct {
			Host      string `json:"hostname"`
			Method    string `json:"http_method"`
			Path      string `json:"url"`
			UserAgent string `json:"http_user_agent"`
		} `json:"http"`
		TLS *struct {
			SNI        string   `json:"sni"`
			ClientALPN []string `json:"client_alpns"`
			ServerALPN []string `json:"server_alpns"`
		} `json:"tls"`
		QUIC *struct {
			SNI        string `json:"sni"`
			Extensions []struct {
				Type   int      `json:"type"`
				Values []string `json:"values"`
			} `json:"extensions"`
		} `json:"quic"`
		DNS *struct {
			Version json.Number `json:"version"`
			Type    string      `json:"type"`
			Name    string      `json:"rrname"`
			Queries []struct {
				Name string `json:"rrname"`
			} `json:"queries"`
		} `json:"dns"`
	}
	if len(raw) > contract.MaxPayloadBytes || json.Unmarshal(raw, &event) != nil {
		return o, false, ErrInput
	}
	o.Protocol = strings.ToLower(event.EventType)
	if event.EventType == "alert" {
		o.Protocol = strings.ToLower(event.AppProto)
	}
	if !slices.Contains([]string{"http", "tls", "quic", "dns"}, o.Protocol) {
		return o, false, nil
	}
	if event.EventType == "alert" && event.TxGuessed {
		return o, true, errTransactionUnbound
	}
	switch o.Protocol {
	case "http":
		if event.HTTP != nil {
			o.HTTPHost, o.HTTPMethod, o.HTTPPath, o.HTTPUserAgent = event.HTTP.Host, event.HTTP.Method, event.HTTP.Path, event.HTTP.UserAgent
		}
	case "tls":
		if event.TLS != nil {
			o.TLSSNI = event.TLS.SNI
			for _, value := range append(event.TLS.ClientALPN, event.TLS.ServerALPN...) {
				if !slices.Contains(o.TLSALPN, value) {
					o.TLSALPN = append(o.TLSALPN, value)
				}
			}
		}
	case "quic":
		if event.QUIC != nil {
			o.TLSSNI = event.QUIC.SNI
			for _, extension := range event.QUIC.Extensions {
				if extension.Type == 16 {
					for _, value := range extension.Values {
						if !slices.Contains(o.TLSALPN, value) {
							o.TLSALPN = append(o.TLSALPN, value)
						}
					}
				}
			}
		}
	case "dns":
		if event.DNS != nil {
			v := event.DNS
			if v.Version == "3" {
				for _, q := range v.Queries {
					o.DNSNames = append(o.DNSNames, q.Name)
				}
			} else if v.Version == "2" && v.Type == "query" && v.Name != "" {
				o.DNSNames = append(o.DNSNames, v.Name)
			}
		}
	}
	return o, true, o.Validate()
}

func (m *Matcher) Attribute(raw []byte, deploymentID string, now time.Time) (Attribution, bool, error) {
	if !contract.ValidID(deploymentID) || now.IsZero() {
		return Attribution{}, false, ErrInput
	}
	o, supported, err := EVEObservation(raw)
	if !supported {
		return Attribution{}, false, err
	}
	var result Result
	if err != nil {
		// 畸形可见属性不应阻塞原始告警或被静默忽略；明确记录无法匹配的原因。
		result = Result{SchemaVersion: ResultSchema, Origin: "suricata_visible_metadata", Protocol: o.Protocol, Status: "unknown", Reason: "metadata_invalid", EvaluatedAt: now.UTC(), ObservationSHA256: Digest(o), RulesSHA256: m.sha256, RuleCount: len(m.versions), Matches: []Match{}}
		if errors.Is(err, errTransactionUnbound) {
			result.Reason = "transaction_unbound"
		}
	} else {
		result, err = m.Evaluate(o, now)
		if err != nil {
			return Attribution{}, false, err
		}
	}
	// 条件原文可能含多字节路径或 JSON 转义。展示预算只省略后续依据，不能阻塞原始告警。
	// 每条命中仍至少保留一个域名正向依据，全部产品继续参与冲突判断。
	for i := range result.Matches {
		match := &result.Matches[i]
		for len(match.Evidence) > 1 {
			encoded, _ := json.Marshal(match)
			if len(encoded) <= 1536 {
				break
			}
			match.Evidence = match.Evidence[:len(match.Evidence)-1]
			match.EvidenceLimited = true
		}
	}
	h := sha256.Sum256(raw)
	a := Attribution{SchemaVersion: AttributionSchema, DeploymentID: deploymentID, StateSHA256: StateDigest(deploymentID, m.sha256), RawSHA256: hex.EncodeToString(h[:]), Result: result}
	if result.Status == "candidate" {
		a.ProductID, a.ProductName, a.CategoryID = result.Matches[0].ProductID, result.Matches[0].ProductName, result.Matches[0].CategoryID
	}
	return a, true, nil
}

func ReadAttribution(raw []byte) (Attribution, error) {
	var a Attribution
	fields := []string{"schema_version", "deployment_id", "state_sha256", "raw_sha256", "product_id", "product_name", "category_id", "result", "origin", "protocol", "status", "reason", "evaluated_at", "observation_sha256", "rules_sha256", "rule_count", "matched_rule_count", "matches", "limited", "rule_id", "revision", "evidence", "evidence_limited", "field", "op", "pattern"}
	if contract.JSONFields(string(raw), fields, MaxAttributionBytes) != nil {
		return a, ErrInput
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&a) != nil || d.Decode(new(any)) != io.EOF || a.SchemaVersion != AttributionSchema || !contract.ValidID(a.DeploymentID) || !ValidSHA256(a.RawSHA256) || a.StateSHA256 != StateDigest(a.DeploymentID, a.Result.RulesSHA256) || a.Result.Origin != "suricata_visible_metadata" || a.Result.SchemaVersion != ResultSchema || !ValidSHA256(a.Result.RulesSHA256) || !ValidSHA256(a.Result.ObservationSHA256) || a.Result.RuleCount < 0 || a.Result.RuleCount > MaxRules || a.Result.MatchedRuleCount < 0 || a.Result.MatchedRuleCount > a.Result.RuleCount || a.Result.Matches == nil || len(a.Result.Matches) > 16 || a.Result.Limited != (a.Result.MatchedRuleCount > len(a.Result.Matches)) || len(a.Result.Matches) != min(a.Result.MatchedRuleCount, 16) || a.Result.EvaluatedAt.IsZero() {
		return Attribution{}, ErrInput
	}
	if !slices.Contains([]string{"http", "tls", "quic", "dns"}, a.Result.Protocol) || !slices.Contains([]string{"candidate", "conflict", "unknown"}, a.Result.Status) {
		return Attribution{}, ErrInput
	}
	return a, nil
}

func (m *Matcher) Verify(a Attribution, raw []byte, deploymentID string, observed time.Time) error {
	expected, supported, err := m.Attribute(raw, deploymentID, observed)
	if err != nil || !supported || Digest(expected) != Digest(a) {
		return ErrInput
	}
	return nil
}
