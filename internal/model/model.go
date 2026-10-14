// Package model 定义跨进程使用的领域数据，SDK 类型不进入 HTTP 数据契约。
package model

import (
	"encoding/json"
	"time"

	"github.com/kkx600/StarBeacon/internal/application"
	"github.com/kkx600/StarBeacon/internal/response"
)

type Principal struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	CSRF     string `json:"csrf_token"`
	// 登录验证绑定账号修订，权限或密码变化后不能凭旧验证结果创建会话。
	CredentialRevision int64 `json:"-"`
}
type Sensor struct {
	ID                string          `json:"id"`
	Name              string          `json:"name"`
	RegistrationID    string          `json:"registration_id"`
	Active            bool            `json:"active"`
	CreatedAt         time.Time       `json:"created_at"`
	LastSeen          *time.Time      `json:"last_seen"`
	Health            json.RawMessage `json:"health"`
	Status            string          `json:"status"`
	MetadataRevision  int64           `json:"metadata_revision"`
	GroupID           string          `json:"group_id"`
	GroupName         string          `json:"group_name"`
	Site              string          `json:"site"`
	Description       string          `json:"description"`
	MetadataUpdatedAt time.Time       `json:"metadata_updated_at"`
}
type HostHealth struct {
	ApplicationRules         json.RawMessage    `json:"application_rules,omitempty"`
	ResponseConnectors       []response.Health  `json:"response_connectors,omitempty"`
	RegisteredRulesAvailable bool               `json:"registered_rules_available"`
	RegisteredRulesSHA256    string             `json:"registered_rules_sha256,omitempty"`
	TaskCapabilities         []string           `json:"task_capabilities,omitempty"`
	CommandSignerSHA256      string             `json:"command_signer_sha256,omitempty"`
	Version                  string             `json:"version"`
	Hostname                 string             `json:"hostname"`
	ObservedAt               time.Time          `json:"observed_at"`
	CPUPercent               *float64           `json:"cpu_percent"`
	MemoryPercent            *float64           `json:"memory_percent"`
	DiskPercent              *float64           `json:"disk_percent"`
	RXBytes                  string             `json:"rx_bytes"`
	TXBytes                  string             `json:"tx_bytes"`
	WALPending               uint64             `json:"wal_pending"`
	WALBytes                 int64              `json:"wal_bytes"`
	Errors                   []string           `json:"errors"`
	CaptureStatus            string             `json:"capture_status"`
	Capture                  json.RawMessage    `json:"capture,omitempty"`
	PacketArchive            json.RawMessage    `json:"packet_archive,omitempty"`
	NetworkInterfaces        []NetworkInterface `json:"network_interfaces,omitempty"`
}
type NetworkInterface struct {
	Name      string   `json:"name"`
	Index     int      `json:"index"`
	MAC       string   `json:"mac"`
	MTU       int      `json:"mtu"`
	Up        bool     `json:"up"`
	Loopback  bool     `json:"loopback"`
	Addresses []string `json:"addresses"`
}
type Endpoint struct {
	IP   string `json:"ip,omitempty"`
	Port uint16 `json:"port,omitempty"`
	MAC  string `json:"mac,omitempty"`
}
type Alert struct {
	Application        *application.Attribution `json:"application,omitempty"`
	SchemaVersion      string                   `json:"schema_version"`
	EventID            string                   `json:"event_id"`
	TenantID           string                   `json:"tenant_id"`
	SensorID           string                   `json:"sensor_id"`
	RegistrationID     string                   `json:"sensor_registration_id"`
	SourceGenerationID string                   `json:"source_generation_id"`
	SourceOffset       string                   `json:"source_offset"`
	Sequence           string                   `json:"sequence"`
	RawSHA256          string                   `json:"raw_sha256"`
	Timestamp          time.Time                `json:"@timestamp"`
	ObservedAt         time.Time                `json:"observed_at"`
	ReceivedAt         time.Time                `json:"received_at"`
	Event              struct {
		Kind     string `json:"kind"`
		Dataset  string `json:"dataset"`
		Original string `json:"original"`
	} `json:"event"`
	Source      Endpoint `json:"source"`
	Destination Endpoint `json:"destination"`
	Network     struct {
		Transport string `json:"transport,omitempty"`
		Protocol  string `json:"protocol,omitempty"`
	} `json:"network"`
	Rule struct {
		ID       string `json:"id,omitempty"`
		Name     string `json:"name,omitempty"`
		Revision string `json:"revision,omitempty"`
	} `json:"rule"`
	HTTP struct {
		Method   string `json:"method,omitempty"`
		Hostname string `json:"hostname,omitempty"`
		Path     string `json:"path,omitempty"`
	} `json:"http"`
	Suricata struct {
		FlowID string `json:"flow_id,omitempty"`
		Action string `json:"action,omitempty"`
	} `json:"suricata"`
	Severity       string `json:"severity"`
	EvidenceStatus string `json:"evidence_status"`
}
type SearchRequest struct {
	Start         time.Time `json:"start"`
	End           time.Time `json:"end"`
	Page          int       `json:"page"`
	PageSize      int       `json:"page_size"`
	Keyword       string    `json:"keyword"`
	SourceIP      string    `json:"source_ip"`
	DestinationIP string    `json:"destination_ip"`
	Protocol      string    `json:"protocol"`
	Method        string    `json:"method"`
	Path          string    `json:"path"`
	Severity      string    `json:"severity"`
	Filter        string    `json:"filter"`
}
type SearchResult struct {
	Items    []Alert `json:"items"`
	Total    int64   `json:"total"`
	Page     int     `json:"page"`
	PageSize int     `json:"page_size"`
}

type TrafficSearchRequest struct {
	SearchRequest
	EventKind      string `json:"event_kind"`
	SensorID       string `json:"sensor_id"`
	RegistrationID string `json:"sensor_registration_id"`
	GenerationID   string `json:"source_generation_id"`
	FlowID         string `json:"flow_id"`
}
