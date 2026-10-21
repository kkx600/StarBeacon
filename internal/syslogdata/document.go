package syslogdata

import "time"

// Document 原始事实与解析结果分别保存；来源时间不替代接收时间作为留存依据。
type Document struct {
	MessageTruncated bool      `json:"message_truncated,omitempty"`
	SchemaVersion    string    `json:"schema_version"`
	EventID          string    `json:"event_id"`
	TenantID         string    `json:"tenant_id"`
	SensorID         string    `json:"sensor_id"`
	RegistrationID   string    `json:"sensor_registration_id"`
	Sequence         string    `json:"sequence"`
	PayloadSHA256    string    `json:"payload_sha256"`
	Partition        string    `json:"partition"`
	ReceivedAt       time.Time `json:"received_at"`
	Record           Record    `json:"record"`
	Parsed           Parsed    `json:"parsed"`
}
