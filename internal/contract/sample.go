package contract

import (
	"crypto/sha256"
	"encoding/hex"
)

const MaxHTTPRawBytes int64 = 2 * 1024 * 1024
const HTTPEncoder = "http-raw-tcp/1"

// SampleOrigin 说明测试材料来源。合成握手不代表真实网络曾经建立连接。
type SampleOrigin struct {
	Kind         string `json:"kind"`
	Synthetic    bool   `json:"synthetic"`
	RawSHA256    string `json:"raw_sha256"`
	RawBytes     int64  `json:"raw_bytes"`
	Encoder      string `json:"encoder"`
	SegmentBytes int    `json:"segment_bytes"`
}

func (o SampleOrigin) Valid() bool {
	raw, err := hex.DecodeString(o.RawSHA256)
	return err == nil && len(raw) == sha256.Size && hex.EncodeToString(raw) == o.RawSHA256 && o.Kind == "http_raw" && o.Synthetic && o.RawBytes >= 1 && o.RawBytes <= MaxHTTPRawBytes && o.Encoder == HTTPEncoder && o.SegmentBytes == 1460
}
