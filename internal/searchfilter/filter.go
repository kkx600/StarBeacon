// Package searchfilter 将显示过滤表达式转换为受限、类型化的 ES 查询。
// 字段和运算符来自固定目录，表达式不能指定索引、脚本或租户作用域。
package searchfilter

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer"
)

const Version = "1.0"

type Field struct {
	Name      string   `json:"name"`
	Label     string   `json:"label"`
	Type      string   `json:"type"`
	Aliases   []string `json:"aliases"`
	Operators []string `json:"operators"`
	Paths     []string `json:"-"`
	Protocol  string   `json:"-"`
}

var fields = []Field{
	{Name: "source.ip", Label: "源 IP", Type: "ip", Aliases: []string{"ip.src", "ipv6.src"}, Paths: []string{"source.ip"}},
	{Name: "destination.ip", Label: "目的 IP", Type: "ip", Aliases: []string{"ip.dst", "ipv6.dst"}, Paths: []string{"destination.ip"}},
	{Name: "ip.addr", Label: "通信 IP", Type: "ip", Aliases: []string{"ipv6.addr"}, Paths: []string{"source.ip", "destination.ip"}},
	{Name: "source.mac", Label: "源 MAC", Type: "mac", Aliases: []string{"eth.src"}, Paths: []string{"source.mac"}},
	{Name: "destination.mac", Label: "目的 MAC", Type: "mac", Aliases: []string{"eth.dst"}, Paths: []string{"destination.mac"}},
	{Name: "eth.addr", Label: "通信 MAC", Type: "mac", Paths: []string{"source.mac", "destination.mac"}},
	{Name: "source.port", Label: "源端口", Type: "port", Paths: []string{"source.port"}},
	{Name: "destination.port", Label: "目的端口", Type: "port", Paths: []string{"destination.port"}},
	{Name: "tcp.srcport", Label: "TCP 源端口", Type: "port", Paths: []string{"source.port"}, Protocol: "tcp"},
	{Name: "tcp.dstport", Label: "TCP 目的端口", Type: "port", Paths: []string{"destination.port"}, Protocol: "tcp"},
	{Name: "tcp.port", Label: "TCP 通信端口", Type: "port", Paths: []string{"source.port", "destination.port"}, Protocol: "tcp"},
	{Name: "udp.srcport", Label: "UDP 源端口", Type: "port", Paths: []string{"source.port"}, Protocol: "udp"},
	{Name: "udp.dstport", Label: "UDP 目的端口", Type: "port", Paths: []string{"destination.port"}, Protocol: "udp"},
	{Name: "udp.port", Label: "UDP 通信端口", Type: "port", Paths: []string{"source.port", "destination.port"}, Protocol: "udp"},
	{Name: "network.transport", Label: "传输协议", Type: "keyword", Paths: []string{"network.transport"}},
	{Name: "network.protocol", Label: "应用协议", Type: "keyword", Paths: []string{"network.protocol"}},
	{Name: "http.method", Label: "HTTP 请求方法", Type: "keyword", Aliases: []string{"http.request.method"}, Paths: []string{"http.method"}, Protocol: "http"},
	{Name: "http.path", Label: "HTTP 请求路径", Type: "string", Aliases: []string{"http.request.uri"}, Paths: []string{"http.path"}, Protocol: "http"},
	{Name: "http.hostname", Label: "HTTP 主机", Type: "keyword", Aliases: []string{"http.host"}, Paths: []string{"http.hostname"}, Protocol: "http"},
	{Name: "rule.id", Label: "规则 SID", Type: "identifier", Aliases: []string{"suricata.sid"}, Paths: []string{"rule.id"}},
	{Name: "rule.revision", Label: "规则修订", Type: "identifier", Paths: []string{"rule.revision"}},
	{Name: "rule.name", Label: "规则名称", Type: "text", Paths: []string{"rule.name.keyword"}},
	{Name: "suricata.flow_id", Label: "流标识", Type: "identifier", Paths: []string{"suricata.flow_id"}},
	{Name: "suricata.action", Label: "检测动作", Type: "keyword", Paths: []string{"suricata.action"}},
	{Name: "severity", Label: "严重级别", Type: "keyword", Paths: []string{"severity"}},
	{Name: "sensor_id", Label: "探针标识", Type: "keyword", Paths: []string{"sensor_id"}},
	{Name: "event_id", Label: "事件标识", Type: "keyword", Paths: []string{"event_id"}},
	{Name: "event.kind", Label: "事件类型", Type: "keyword", Paths: []string{"event.kind"}},
	{Name: "evidence_status", Label: "证据状态", Type: "keyword", Paths: []string{"evidence_status"}},
	{Name: "@timestamp", Label: "事件发生时间", Type: "time", Aliases: []string{"frame.time"}, Paths: []string{"@timestamp"}},
	{Name: "observed_at", Label: "采集器观察时间", Type: "time", Paths: []string{"observed_at"}},
	{Name: "received_at", Label: "平台接收时间", Type: "time", Paths: []string{"received_at"}},
	{Name: "application.product_id", Label: "应用产品标识", Type: "keyword", Aliases: []string{"app.product"}, Paths: []string{"application.product_id"}},
	{Name: "application.category_id", Label: "应用类别", Type: "keyword", Aliases: []string{"app.category"}, Paths: []string{"application.category_id"}},
	{Name: "application.result.status", Label: "应用识别状态", Type: "keyword", Aliases: []string{"app.status"}, Paths: []string{"application.result.status"}},
	{Name: "application.deployment_id", Label: "应用部署任务", Type: "keyword", Paths: []string{"application.deployment_id"}},
	{Name: "application.result.rules_sha256", Label: "应用规则快照", Type: "keyword", Paths: []string{"application.result.rules_sha256"}},
}

var protocols = map[string]string{
	"tcp": "network.transport", "udp": "network.transport", "icmp": "network.transport", "icmpv6": "network.transport",
	"http": "network.protocol", "http2": "network.protocol", "tls": "network.protocol", "dns": "network.protocol", "quic": "network.protocol",
	"ssh": "network.protocol", "ftp": "network.protocol", "smtp": "network.protocol", "imap": "network.protocol", "pop3": "network.protocol",
	"smb": "network.protocol", "rdp": "network.protocol", "dhcp": "network.protocol", "ntp": "network.protocol", "sip": "network.protocol",
	"mqtt": "network.protocol", "modbus": "network.protocol", "dnp3": "network.protocol", "nfs": "network.protocol", "snmp": "network.protocol",
}

type expression struct {
	Terms []*conjunction `parser:"@@ ( (\"or\" | \"||\") @@ )*"`
}
type conjunction struct {
	Terms []*unary `parser:"@@ ( (\"and\" | \"&&\") @@ )*"`
}
type unary struct {
	Not       []string    `parser:"@(\"not\" | \"!\")*"`
	Group     *expression `parser:"( \"(\" @@ \")\""`
	Predicate *predicate  `parser:"| @@ )"`
}
type predicate struct {
	Pos        lexer.Position
	Name       string      `parser:"@Word"`
	Comparison *comparison `parser:"@@?"`
}
type comparison struct {
	Operator string    `parser:"@(\"==\" | \"!=\" | \">=\" | \"<=\" | \">\" | \"<\" | \"eq\" | \"ne\" | \"ge\" | \"le\" | \"gt\" | \"lt\" | \"contains\" | \"in\")"`
	Set      *valueSet `parser:"( @@"`
	Scalar   *value    `parser:"| @@ )"`
}
type valueSet struct {
	Values []*value `parser:"\"{\" ( @@ ( \",\"? @@ )* )? \"}\""`
}
type value struct {
	Raw    *string `parser:"@RawString"`
	Quoted *string `parser:"| @String"`
	Atom   *string `parser:"| @Word"`
}

var grammar = participle.MustBuild[expression](participle.Lexer(lexer.MustSimple([]lexer.SimpleRule{
	{Name: "whitespace", Pattern: `\s+`},
	{Name: "RawString", Pattern: `r"(?:[^"\\]|\\.)*"`},
	{Name: "String", Pattern: `"(?:[^"\\]|\\.)*"`},
	{Name: "Operator", Pattern: `==|!=|>=|<=|&&|\|\||[(){}!,<>]`},
	{Name: "Word", Pattern: `[@A-Za-z0-9_][A-Za-z0-9_@.:/+-]*`},
})), participle.Unquote("String"), participle.UseLookahead(2))

type Error struct {
	Message string `json:"message"`
	Line    int    `json:"line"`
	Column  int    `json:"column"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("第 %d 行，第 %d 列：%s", e.Line, e.Column, e.Message)
}
func fail(p lexer.Position, message string) error {
	return &Error{Message: message, Line: p.Line, Column: p.Column}
}

func Catalog() []Field {
	out := make([]Field, 0, len(fields)+len(protocols))
	for _, f := range fields {
		f.Aliases = append([]string{}, f.Aliases...)
		f.Paths = append([]string{}, f.Paths...)
		f.Operators = operators(f.Type)
		out = append(out, f)
	}
	// 固定排序避免字段目录在页面和版本摘要中随机变化。
	for _, name := range []string{"tcp", "udp", "icmp", "icmpv6", "http", "http2", "tls", "dns", "quic", "ssh", "ftp", "smtp", "imap", "pop3", "smb", "rdp", "dhcp", "ntp", "sip", "mqtt", "modbus", "dnp3", "nfs", "snmp"} {
		out = append(out, Field{Name: name, Label: name + " 协议", Type: "protocol", Aliases: []string{}, Operators: []string{"exists"}})
	}
	for _, name := range []string{"ip", "ipv6", "eth"} {
		out = append(out, Field{Name: name, Label: name + " 协议", Type: "protocol", Aliases: []string{}, Operators: []string{"exists"}})
	}
	return out
}

// CatalogForDataset 与检索实际允许的字段保持一致；协议目录不授予其他数据集权限。
func CatalogForDataset(dataset string) ([]Field, error) {
	if dataset != "alerts" && dataset != "context" {
		return nil, fmt.Errorf("检索数据集无效")
	}
	out := Catalog()
	if dataset == "alerts" {
		return out, nil
	}
	filtered := make([]Field, 0, len(out))
	for _, field := range out {
		if field.Name == "severity" || field.Name == "evidence_status" || field.Name == "suricata.action" || strings.HasPrefix(field.Name, "rule.") {
			continue
		}
		filtered = append(filtered, field)
	}
	return filtered, nil
}
func operators(kind string) []string {
	out := []string{"exists", "==", "!=", "in"}
	if kind == "port" || kind == "time" || kind == "ip" {
		out = append(out, ">", ">=", "<", "<=")
	}
	if kind == "string" || kind == "keyword" || kind == "text" {
		out = append(out, "contains")
	}
	return out
}

// Compile 有界解析及编译；租户与时间范围由调用者另外强制加入 filter。
func Compile(source string) (any, error) {
	return compile(source, fields)
}

// CompileForDataset 使用同一语法与预算，只允许目标数据集已发布的字段及别名。
func CompileForDataset(source, dataset string) (any, error) {
	catalog, err := CatalogForDataset(dataset)
	if err != nil {
		return nil, err
	}
	return compile(source, catalog)
}

func compile(source string, catalog []Field) (any, error) {
	if !utf8.ValidString(source) || len(source) > 4096 {
		return nil, &Error{Message: "表达式必须为有效 UTF-8，长度不能超过 4096 字节", Line: 1, Column: 1}
	}
	if strings.TrimSpace(source) == "" {
		return nil, nil
	}
	// 在递归解析前限制结构深度，避免恶意括号消耗调用栈。
	depth, quote, escape := 0, false, false
	for _, c := range source {
		if quote {
			if escape {
				escape = false
			} else if c == '\\' {
				escape = true
			} else if c == '"' {
				quote = false
			}
			continue
		}
		if c == '"' {
			quote = true
		} else if c == '(' {
			depth++
			if depth > 16 {
				return nil, &Error{Message: "括号嵌套不能超过 16 层", Line: 1, Column: 1}
			}
		} else if c == ')' {
			depth--
		}
	}
	ast, err := grammar.ParseString("", source)
	if err != nil {
		if e, ok := err.(participle.Error); ok {
			p := e.Position()
			return nil, &Error{Message: "过滤表达式语法不完整或包含不支持的运算", Line: p.Line, Column: p.Column}
		}
		return nil, err
	}
	budget := 128
	return compileExpression(ast, &budget, catalog)
}
func boolQuery(key string, nodes []any) any {
	if len(nodes) == 1 && key != "must_not" {
		return nodes[0]
	}
	v := map[string]any{key: nodes}
	if key == "should" {
		v["minimum_should_match"] = 1
	}
	return map[string]any{"bool": v}
}
func term(path string, v any) any { return map[string]any{"term": map[string]any{path: v}} }
func exists(path string) any      { return map[string]any{"exists": map[string]string{"field": path}} }
func addressFamily(path string, ipv6 bool) any {
	if !ipv6 {
		return term(path, "0.0.0.0/0")
	}
	// ES 的 IPv4 使用 IPv6 映射编码；::/0 不能区分地址族。
	// 存在性同时排除缺失地址，避免把无地址记录归为 IPv6。
	return boolQuery("filter", []any{exists(path), boolQuery("must_not", []any{term(path, "0.0.0.0/0")})})
}
func compileExpression(e *expression, budget *int, catalog []Field) (any, error) {
	or := make([]any, 0, len(e.Terms))
	for _, c := range e.Terms {
		and := make([]any, 0, len(c.Terms))
		for _, u := range c.Terms {
			var node any
			var err error
			if u.Group != nil {
				node, err = compileExpression(u.Group, budget, catalog)
			} else {
				*budget--
				if *budget < 0 {
					return nil, fail(u.Predicate.Pos, "过滤条件不能超过 128 项")
				}
				node, err = compilePredicate(u.Predicate, catalog)
			}
			if err != nil {
				return nil, err
			}
			if len(u.Not)%2 == 1 {
				node = boolQuery("must_not", []any{node})
			}
			and = append(and, node)
		}
		or = append(or, boolQuery("filter", and))
	}
	return boolQuery("should", or), nil
}
func compilePredicate(p *predicate, catalog []Field) (any, error) {
	if p.Name == "ip" || p.Name == "ipv6" || p.Name == "eth" {
		if p.Comparison != nil {
			return nil, fail(p.Pos, "协议存在性请直接使用协议名称")
		}
		// 判断实际索引地址，不将传输层标签或缺失 MAC 推定为链路层观测。
		if p.Name == "eth" {
			return boolQuery("should", []any{exists("source.mac"), exists("destination.mac")}), nil
		}
		return boolQuery("should", []any{addressFamily("source.ip", p.Name == "ipv6"), addressFamily("destination.ip", p.Name == "ipv6")}), nil
	}
	if path, ok := protocols[p.Name]; ok {
		if p.Comparison != nil {
			return nil, fail(p.Pos, "协议存在性请直接使用协议名称")
		}
		return term(path, p.Name), nil
	}
	var f *Field
	for i := range catalog {
		candidate := &catalog[i]
		if candidate.Name == p.Name {
			f = candidate
			break
		}
		for _, alias := range candidate.Aliases {
			if alias == p.Name {
				f = candidate
				break
			}
		}
		if f != nil {
			break
		}
	}
	if f == nil {
		return nil, fail(p.Pos, "字段未纳入当前数据集索引，不能转换："+p.Name)
	}
	var matches, present []any
	negative := p.Comparison != nil && (p.Comparison.Operator == "!=" || p.Comparison.Operator == "ne")
	comparisonPredicate := *p
	if negative {
		comparisonCopy := *p.Comparison
		comparisonCopy.Operator = "=="
		comparisonPredicate.Comparison = &comparisonCopy
	}
	for _, path := range f.Paths {
		node, err := compileComparison(path, *f, &comparisonPredicate)
		if err != nil {
			return nil, err
		}
		presence := exists(path)
		if strings.HasPrefix(p.Name, "ip.") {
			node = boolQuery("filter", []any{term(path, "0.0.0.0/0"), node})
			presence = boolQuery("filter", []any{term(path, "0.0.0.0/0"), presence})
		}
		if strings.HasPrefix(p.Name, "ipv6.") {
			node = boolQuery("filter", []any{addressFamily(path, true), node})
			presence = boolQuery("filter", []any{addressFamily(path, true), presence})
		}
		present = append(present, presence)
		matches = append(matches, node)
	}
	result := boolQuery("should", matches)
	// Wireshark 3.6 起 != 表示所有已出现的值都不相等；缺失字段不能命中。
	if negative {
		result = boolQuery("filter", []any{boolQuery("should", present), boolQuery("must_not", []any{result})})
	}
	if f.Protocol != "" {
		result = boolQuery("filter", []any{term(protocols[f.Protocol], f.Protocol), result})
	}
	return result, nil
}
func compileComparison(path string, f Field, p *predicate) (any, error) {
	c := p.Comparison
	if c == nil {
		return exists(path), nil
	}
	op := c.Operator
	if alias := map[string]string{"eq": "==", "ne": "!=", "gt": ">", "ge": ">=", "lt": "<", "le": "<="}[op]; alias != "" {
		op = alias
	}
	allowed := false
	for _, candidate := range operators(f.Type) {
		allowed = allowed || candidate == op
	}
	if !allowed {
		return nil, fail(p.Pos, "字段不支持该运算符："+op)
	}
	values := []*value{c.Scalar}
	if c.Set != nil {
		values = c.Set.Values
	}
	if (op == "in") != (c.Set != nil) || len(values) == 0 || len(values) > 64 {
		return nil, fail(p.Pos, "in 需要 1–64 个值的集合，其他比较需要一个值")
	}
	var nodes []any
	for _, v := range values {
		raw := ""
		if v.Raw != nil {
			raw = (*v.Raw)[2 : len(*v.Raw)-1]
		} else if v.Quoted != nil {
			raw = *v.Quoted
		} else {
			raw = *v.Atom
		}
		if op == "in" && f.Type == "port" && strings.Contains(raw, "..") {
			bounds := strings.Split(raw, "..")
			if len(bounds) != 2 {
				return nil, fail(p.Pos, "端口范围格式无效")
			}
			lo, e1 := strconv.ParseUint(bounds[0], 0, 16)
			hi, e2 := strconv.ParseUint(bounds[1], 0, 16)
			if e1 != nil || e2 != nil || hi < lo {
				return nil, fail(p.Pos, "端口范围必须在 0–65535 内且起点不大于终点")
			}
			nodes = append(nodes, map[string]any{"range": map[string]any{path: map[string]any{"gte": lo, "lte": hi}}})
			continue
		}
		value, err := typedValue(raw, f)
		if err != nil {
			return nil, fail(p.Pos, err.Error())
		}
		if f.Type == "ip" && (op == ">" || op == ">=" || op == "<" || op == "<=") && strings.Contains(raw, "/") {
			return nil, fail(p.Pos, "IP 大小比较需要单个地址，网段请使用相等或集合条件")
		}
		node := term(path, value)
		switch op {
		case "!=":
			node = boolQuery("filter", []any{exists(path), boolQuery("must_not", []any{node})})
		case ">", ">=", "<", "<=":
			key := map[string]string{">": "gt", ">=": "gte", "<": "lt", "<=": "lte"}[op]
			node = map[string]any{"range": map[string]any{path: map[string]any{key: value}}}
		case "contains":
			if raw == "" {
				return nil, fail(p.Pos, "包含匹配不能为空")
			}
			pattern := strings.NewReplacer("\\", "\\\\", "*", "\\*", "?", "\\?").Replace(fmt.Sprint(value))
			node = map[string]any{"wildcard": map[string]any{path: map[string]any{"value": "*" + pattern + "*"}}}
		}
		nodes = append(nodes, node)
	}
	return boolQuery("should", nodes), nil
}
func typedValue(raw string, f Field) (any, error) {
	if len(raw) > 1024 || !utf8.ValidString(raw) || strings.ContainsAny(raw, "\x00\r\n") {
		return nil, fmt.Errorf("过滤值格式或长度无效")
	}
	switch f.Type {
	case "port":
		v, err := strconv.ParseUint(raw, 0, 16)
		if err != nil {
			return nil, fmt.Errorf("端口必须为 0–65535 的整数")
		}
		return v, nil
	case "ip":
		if strings.Contains(raw, "/") {
			ip, err := netip.ParsePrefix(raw)
			if err != nil {
				return nil, fmt.Errorf("IP 网段无效")
			}
			return ip.Masked().String(), nil
		}
		ip, err := netip.ParseAddr(raw)
		if err != nil || ip.Zone() != "" {
			return nil, fmt.Errorf("IP 地址无效")
		}
		return ip.Unmap().String(), nil
	case "mac":
		v, err := net.ParseMAC(raw)
		if err != nil || len(v) != 6 {
			return nil, fmt.Errorf("MAC 地址必须为 6 字节")
		}
		return v.String(), nil
	case "identifier":
		if _, err := strconv.ParseUint(raw, 10, 64); err != nil {
			return nil, fmt.Errorf("标识必须为无符号 64 位十进制整数")
		}
		return raw, nil
	case "time":
		v, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return nil, fmt.Errorf("时间必须采用 RFC3339 格式并包含时区")
		}
		return v.UTC(), nil
	}
	if f.Name == "http.method" {
		raw = strings.ToUpper(raw)
	}
	if f.Name == "network.transport" || f.Name == "network.protocol" {
		raw = strings.ToLower(raw)
	}
	return raw, nil
}
