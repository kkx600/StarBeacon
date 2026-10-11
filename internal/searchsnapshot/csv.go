// Package searchsnapshot 定义有界检索元数据导出，不包含原始载荷或生成报文。
package searchsnapshot

import (
	"bytes"
	"encoding/csv"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kkx600/StarBeacon/internal/model"
)

const MaxRows = 10000
const MaxBytes = 8 * 1024 * 1024

var ErrLimit = errors.New("导出超过 10,000 条或 8 MiB，请缩小时间范围或增加条件")

type CSV struct {
	buffer bytes.Buffer
	rows   int
}

func NewCSV() *CSV {
	c := &CSV{}
	c.buffer.WriteString("\xef\xbb\xbf")
	w := csv.NewWriter(&c.buffer)
	w.UseCRLF = true
	_ = w.Write([]string{"事件标识", "事件时间 UTC", "采集时间 UTC", "接收时间 UTC", "探针标识", "注册代次", "来源代次", "来源偏移", "序列", "源 IP", "源端口", "源 MAC", "目的 IP", "目的端口", "目的 MAC", "传输协议", "应用协议", "事件类型", "级别", "规则 SID", "规则修订", "告警名称", "HTTP 方法", "HTTP 主机", "HTTP 路径", "流标识", "原文 SHA-256", "证据状态"})
	w.Flush()
	return c
}

func (c *CSV) Append(v model.Alert) error {
	if c.rows >= MaxRows {
		return ErrLimit
	}
	timestamp := func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format(time.RFC3339Nano)
	}
	port := func(v uint16) string { return strconv.FormatUint(uint64(v), 10) }
	row := []string{v.EventID, timestamp(v.Timestamp), timestamp(v.ObservedAt), timestamp(v.ReceivedAt), v.SensorID, v.RegistrationID, v.SourceGenerationID, v.SourceOffset, v.Sequence, v.Source.IP, port(v.Source.Port), v.Source.MAC, v.Destination.IP, port(v.Destination.Port), v.Destination.MAC, v.Network.Transport, v.Network.Protocol, v.Event.Kind, v.Severity, v.Rule.ID, v.Rule.Revision, v.Rule.Name, v.HTTP.Method, v.HTTP.Hostname, v.HTTP.Path, v.Suricata.FlowID, v.RawSHA256, v.EvidenceStatus}
	for i, value := range row {
		if !utf8.ValidString(value) {
			return errors.New("导出字段包含无效 UTF-8")
		}
		row[i] = safeCell(value)
	}
	// 单行先编码并核验预算，避免在错误前留下可误用的部分记录。
	var encoded bytes.Buffer
	w := csv.NewWriter(&encoded)
	w.UseCRLF = true
	if err := w.Write(row); err != nil {
		return err
	}
	w.Flush()
	if c.buffer.Len()+encoded.Len() > MaxBytes {
		return ErrLimit
	}
	c.buffer.Write(encoded.Bytes())
	c.rows++
	return nil
}

func safeCell(value string) string {
	visible := strings.TrimLeftFunc(value, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) || r == '\ufeff' })
	if visible != "" && strings.ContainsRune("=+-@", rune(visible[0])) {
		return "'" + value
	}
	// 表格软件的数值精度有限；长整数字符串保留文本身份。
	if len(value) > 15 && strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) == -1 {
		return "'" + value
	}
	return value
}

func (c *CSV) Bytes() []byte { return c.buffer.Bytes() }
func (c *CSV) Rows() int     { return c.rows }
