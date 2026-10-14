// Package protocolcap 按原生目录与实际配置分别描述协议能力，不把配置或版本视为检测效果证明。
package protocolcap

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

const SchemaVersion = 1

type Binding struct {
	Transport string `json:"transport"`
	Mode      string `json:"mode"`
}

type Entry struct {
	Protocol        string    `json:"protocol"`
	Name            string    `json:"name"`
	Bindings        []Binding `json:"bindings"`
	NativeListed    bool      `json:"native_listed"`
	Recognition     string    `json:"recognition"`
	Transactions    string    `json:"transactions"`
	OnlineRules     string    `json:"online_rules"`
	FileExtraction  string    `json:"file_extraction"`
	PacketForensics string    `json:"packet_forensics"`
	ExternalLogs    string    `json:"external_logs"`
	Qualification   string    `json:"qualification"`
}

type Limit struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type Report struct {
	SchemaVersion int       `json:"schema_version"`
	State         string    `json:"state"`
	ObservedAt    time.Time `json:"observed_at"`
	Source        string    `json:"source"`
	CaptureActive bool      `json:"capture_active"`
	EngineVersion string    `json:"engine_version,omitempty"`
	EngineSHA256  string    `json:"engine_sha256,omitempty"`
	ConfigSHA256  string    `json:"config_sha256,omitempty"`
	ErrorCode     string    `json:"error_code,omitempty"`
	Protocols     []Entry   `json:"protocols"`
	Limits        []Limit   `json:"limits"`
}

type definition struct {
	id, name, transports, logger string
	headers                      bool
}

// 名称只用于展示；原生目录未列出、配置未显式启用的能力不得由本表补为支持。
var definitions = []definition{
	{"ethernet", "Ethernet", "l2", "", true}, {"vlan", "VLAN", "l2", "", true},
	{"arp", "ARP", "l2", "", true}, {"ipv4", "IPv4", "ip", "", true}, {"ipv6", "IPv6", "ip", "", true},
	{"tcp", "TCP", "tcp", "", true}, {"udp", "UDP", "udp", "", true},
	{"icmp", "ICMP", "ip", "", true}, {"icmpv6", "ICMPv6", "ip", "", true},
	{"http", "HTTP/1", "tcp", "http", false}, {"http2", "HTTP/2", "tcp", "http2", false},
	{"websocket", "WebSocket", "tcp", "websocket", false}, {"doh2", "DoH over HTTP/2", "tcp", "doh2", false},
	{"tls", "TLS", "tcp", "tls", false}, {"quic", "QUIC", "udp", "quic", false},
	{"dns", "DNS", "tcp,udp", "dns", false}, {"mdns", "mDNS", "udp", "mdns", false},
	{"ftp", "FTP", "tcp", "ftp", false}, {"ftp-data", "FTP 数据通道", "tcp", "ftp_data", false},
	{"smtp", "SMTP", "tcp", "smtp", false}, {"imap", "IMAP", "tcp", "imap", false}, {"pop3", "POP3", "tcp", "pop3", false},
	{"ssh", "SSH", "tcp", "ssh", false}, {"smb", "SMB", "tcp", "smb", false},
	{"dcerpc", "DCE/RPC", "tcp,udp", "dcerpc", false}, {"nfs", "NFS", "tcp,udp", "nfs", false},
	{"rdp", "RDP", "tcp", "rdp", false}, {"rfb", "RFB", "tcp", "rfb", false}, {"telnet", "Telnet", "tcp", "telnet", false},
	{"dhcp", "DHCP", "udp", "dhcp", false}, {"ntp", "NTP", "udp", "ntp", false}, {"snmp", "SNMP", "udp", "snmp", false},
	{"sip", "SIP", "tcp,udp", "sip", false}, {"mqtt", "MQTT", "tcp", "mqtt", false},
	{"ldap", "LDAP", "tcp", "ldap", false}, {"krb5", "Kerberos", "tcp,udp", "krb5", false},
	{"ike", "IKE", "udp", "ike", false}, {"tftp", "TFTP", "udp", "tftp", false},
	{"bittorrent-dht", "BitTorrent DHT", "udp", "bittorrent_dht", false},
	{"pgsql", "PostgreSQL", "tcp", "pgsql", false}, {"modbus", "Modbus", "tcp", "modbus", false},
	{"dnp3", "DNP3", "tcp,udp", "dnp3", false}, {"enip", "EtherNet/IP", "tcp,udp", "enip", false},
}

var protocolName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,47}$`)
var sizeValue = regexp.MustCompile(`(?i)^[0-9]{1,16}(?:\.[0-9]{1,3})?\s*(?:[kmgt]i?b|b)?$`)

// ListProtocols 只接受原生命令的完整目录段；未列出不等于该引擎未编译该协议。
func ListProtocols(raw []byte) ([]string, error) {
	if len(raw) > 32*1024 || bytes.ContainsRune(raw, 0) {
		return nil, errors.New("原生协议目录超过边界")
	}
	const header = "=========Supported App Layer Protocols========="
	lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
	found, names := false, map[string]bool{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == header {
			if found {
				return nil, errors.New("原生协议目录重复")
			}
			found = true
			continue
		}
		if !found || line == "" {
			continue
		}
		if !protocolName.MatchString(line) || names[line] || len(names) >= 128 {
			return nil, errors.New("原生协议目录格式无效")
		}
		names[line] = true
	}
	if !found || len(names) == 0 {
		return nil, errors.New("未取得原生协议目录")
	}
	out := make([]string, 0, len(names))
	for name := range names {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

func Configuration(raw []byte) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > 1024*1024 {
		return nil, errors.New("协议配置大小无效")
	}
	var value map[string]any
	d := yaml.NewDecoder(bytes.NewReader(raw))
	if d.Decode(&value) != nil || len(value) == 0 || d.Decode(new(any)) != io.EOF {
		return nil, errors.New("协议配置无效")
	}
	// 未展开的引用会改变有效配置；不以单文件内容推断被引用文件的启用状态。
	for _, key := range []string{"include", "includes", "plugins"} {
		if v, ok := value[key]; ok && v != nil {
			list, empty := v.([]any)
			if !empty || len(list) != 0 {
				return nil, errors.New("协议配置含未核验引用或插件")
			}
		}
	}
	return value, nil
}

func at(value map[string]any, path ...string) any {
	var current any = value
	for _, key := range path {
		next, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = next[key]
	}
	return current
}

func mode(value any) string {
	switch v := value.(type) {
	case bool:
		if v {
			return "yes"
		}
		return "no"
	case string:
		switch strings.ToLower(v) {
		case "yes", "true":
			return "yes"
		case "no", "false":
			return "no"
		case "detection-only":
			return "detection-only"
		}
	}
	return "unknown"
}

func loggers(config map[string]any) map[string]bool {
	out := map[string]bool{}
	outputs, _ := config["outputs"].([]any)
	for _, output := range outputs {
		item, _ := output.(map[string]any)
		eve, _ := item["eve-log"].(map[string]any)
		if mode(eve["enabled"]) != "yes" {
			continue
		}
		types, _ := eve["types"].([]any)
		for _, entry := range types {
			switch v := entry.(type) {
			case string:
				out[v] = true
			case map[string]any:
				for name, options := range v {
					fields, _ := options.(map[string]any)
					if mode(fields["enabled"]) != "no" {
						out[name] = true
					}
				}
			}
		}
	}
	return out
}

// Build 保留配置未知、仅识别与实际日志启用的区别；规则和效果始终要求独立样本验收。
func Build(base Report, names []string, config map[string]any, packetCapture bool) Report {
	base.SchemaVersion, base.State = SchemaVersion, "observed"
	base.Protocols, base.Limits = []Entry{}, []Limit{}
	listed, known := map[string]bool{}, map[string]bool{}
	for _, name := range names {
		listed[name] = true
	}
	defs := append([]definition(nil), definitions...)
	for _, def := range defs {
		known[def.id] = true
	}
	for _, name := range names {
		if !known[name] && protocolName.MatchString(name) {
			defs = append(defs, definition{id: name, name: name, transports: "unknown"})
			known[name] = true
		}
	}
	logs := loggers(config)
	for _, def := range defs {
		row := Entry{Protocol: def.id, Name: def.name, NativeListed: listed[def.id], Recognition: "unknown", Transactions: "unknown", OnlineRules: "requires_validation", FileExtraction: "not_implemented", PacketForensics: "not_implemented", ExternalLogs: "not_implemented", Qualification: "not_qualified", Bindings: []Binding{}}
		if def.headers {
			if packetCapture {
				row.PacketForensics = "packet_headers_only"
			}
			row.OnlineRules = "requires_validation"
		} else {
			for _, transport := range strings.Split(def.transports, ",") {
				value := at(config, "app-layer", "protocols", def.id, transport, "enabled")
				if value == nil {
					value = at(config, "app-layer", "protocols", def.id, "enabled")
				}
				row.Bindings = append(row.Bindings, Binding{Transport: transport, Mode: mode(value)})
			}
			modes := map[string]bool{}
			for _, binding := range row.Bindings {
				modes[binding.Mode] = true
			}
			switch {
			case len(modes) > 1:
				row.Recognition, row.Transactions = "partial", "partial"
			case modes["no"]:
				row.Recognition, row.Transactions, row.OnlineRules = "disabled", "disabled", "disabled"
			case !row.NativeListed:
				row.Recognition = "unlisted"
			case modes["detection-only"]:
				row.Recognition, row.Transactions, row.OnlineRules = "detection_only", "disabled", "disabled"
			case modes["yes"]:
				row.Recognition = "configured"
				if logs[def.logger] {
					row.Transactions = "configured"
				} else {
					row.Transactions = "not_configured"
				}
			default:
				row.Recognition = "native_listed"
			}
		}
		base.Protocols = append(base.Protocols, row)
	}
	for _, path := range [][]string{{"flow", "memcap"}, {"stream", "memcap"}, {"stream", "reassembly", "memcap"}, {"stream", "reassembly", "depth"}, {"defrag", "memcap"}, {"app-layer", "protocols", "http", "libhtp", "default-config", "request-body-limit"}, {"app-layer", "protocols", "http", "libhtp", "default-config", "response-body-limit"}} {
		value := at(config, path...)
		text := ""
		if data, err := json.Marshal(value); err == nil {
			text = strings.Trim(string(data), `"`)
		}
		if !sizeValue.MatchString(text) {
			text = ""
		}
		base.Limits = append(base.Limits, Limit{Key: strings.Join(path, "."), Value: text})
	}
	return base
}
