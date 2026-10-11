// Package inventory 定义人工确认的资产、资产组与网络范围；不会把 IP 归属推断为攻击成功。
package inventory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type Group struct {
	Name        string `json:"name"`
	Owner       string `json:"owner"`
	Description string `json:"description"`
	Active      bool   `json:"active"`
}
type Interface struct {
	Name string   `json:"name"`
	MAC  string   `json:"mac"`
	IPs  []string `json:"ips"`
}
type Asset struct {
	Name          string      `json:"name"`
	Owner         string      `json:"owner"`
	GroupID       string      `json:"group_id"`
	NetworkDomain string      `json:"network_domain"`
	Criticality   string      `json:"criticality"`
	Description   string      `json:"description"`
	Interfaces    []Interface `json:"interfaces"`
	Active        bool        `json:"active"`
}
type Network struct {
	Name          string `json:"name"`
	Prefix        string `json:"prefix"`
	GroupID       string `json:"group_id"`
	NetworkDomain string `json:"network_domain"`
	Purpose       string `json:"purpose"`
	Description   string `json:"description"`
	Active        bool   `json:"active"`
}
type Record struct {
	ID        string          `json:"id"`
	Kind      string          `json:"kind"`
	Revision  int64           `json:"revision"`
	Data      json.RawMessage `json:"data"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}
type Page struct {
	Items      []Record `json:"items"`
	NextCursor string   `json:"next_cursor"`
}
type Normalized struct {
	Name, GroupID string
	Active        bool
	Data          json.RawMessage
}

func ValidKind(kind string) bool { return kind == "assets" || kind == "groups" || kind == "networks" }

func decode(raw []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return fmt.Errorf("对象字段或类型无效")
	}
	if d.Decode(new(any)) != io.EOF {
		return fmt.Errorf("对象必须为单个 JSON 文档")
	}
	return nil
}
func text(value string, max int) bool {
	return len([]rune(value)) <= max && strings.IndexFunc(value, unicode.IsControl) < 0
}
func name(value string) bool {
	return strings.TrimSpace(value) == value && len([]rune(value)) >= 1 && text(value, 128)
}
func Validate(kind string, raw json.RawMessage) (Normalized, error) {
	var normalized Normalized
	if len(raw) == 0 || len(raw) > 32768 || !utf8.Valid(raw) || !json.Valid(raw) || string(raw) == "null" {
		return normalized, fmt.Errorf("对象数据必须为不超过 32 KiB 的 JSON")
	}
	var value any
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || (string(bytes.TrimSpace(fields["active"])) != "true" && string(bytes.TrimSpace(fields["active"])) != "false") {
		return normalized, fmt.Errorf("使用状态必须为明确的布尔值")
	}
	switch kind {
	case "groups":
		var group Group
		if err := decode(raw, &group); err != nil {
			return normalized, err
		}
		if !name(group.Name) || !text(group.Owner, 128) || !text(group.Description, 1024) {
			return normalized, fmt.Errorf("资产组名称、责任人或说明格式无效")
		}
		normalized.Name = group.Name
		normalized.Active = group.Active
		value = group
	case "assets":
		var asset Asset
		if err := decode(raw, &asset); err != nil {
			return normalized, err
		}
		if !name(asset.Name) || !text(asset.Owner, 128) || !text(asset.Description, 1024) || !name(asset.NetworkDomain) {
			return normalized, fmt.Errorf("资产名称、责任人、网络域或说明格式无效")
		}
		if asset.Criticality != "critical" && asset.Criticality != "high" && asset.Criticality != "normal" && asset.Criticality != "low" {
			return normalized, fmt.Errorf("资产重要性无效")
		}
		if len(asset.Interfaces) > 32 {
			return normalized, fmt.Errorf("单资产最多配置 32 个网络接口")
		}
		names := map[string]bool{}
		if asset.Interfaces == nil {
			asset.Interfaces = []Interface{}
		}
		for i := range asset.Interfaces {
			iface := &asset.Interfaces[i]
			if iface.IPs == nil {
				iface.IPs = []string{}
			}
			if !name(iface.Name) || names[iface.Name] || len(iface.IPs) > 32 {
				return normalized, fmt.Errorf("接口名称重复、格式无效或地址数量超限")
			}
			names[iface.Name] = true
			if iface.MAC != "" {
				mac, err := net.ParseMAC(iface.MAC)
				if err != nil || len(mac) != 6 {
					return normalized, fmt.Errorf("MAC 地址必须为 6 字节")
				}
				iface.MAC = mac.String()
			}
			ips := map[string]bool{}
			for j, raw := range iface.IPs {
				ip, err := netip.ParseAddr(raw)
				if err != nil || ip.Zone() != "" {
					return normalized, fmt.Errorf("资产 IP 地址无效")
				}
				value := ip.Unmap().String()
				if ips[value] {
					return normalized, fmt.Errorf("同一接口存在重复 IP 地址")
				}
				ips[value] = true
				iface.IPs[j] = value
			}
		}
		normalized.Name = asset.Name
		normalized.GroupID = asset.GroupID
		normalized.Active = asset.Active
		value = asset
	case "networks":
		var network Network
		if err := decode(raw, &network); err != nil {
			return normalized, err
		}
		if !name(network.Name) || !name(network.NetworkDomain) || !text(network.Description, 1024) {
			return normalized, fmt.Errorf("网段名称、网络域或说明格式无效")
		}
		if network.Purpose != "internal" && network.Purpose != "external" && network.Purpose != "excluded" {
			return normalized, fmt.Errorf("网段用途无效")
		}
		prefix, err := netip.ParsePrefix(network.Prefix)
		if err != nil || prefix.Addr().Is4In6() {
			return normalized, fmt.Errorf("网段必须采用标准 IPv4 或 IPv6 CIDR")
		}
		network.Prefix = prefix.Masked().String()
		normalized.Name = network.Name
		normalized.GroupID = network.GroupID
		normalized.Active = network.Active
		value = network
	default:
		return normalized, fmt.Errorf("对象类型不受支持")
	}
	data, err := json.Marshal(value)
	normalized.Data = data
	return normalized, err
}
