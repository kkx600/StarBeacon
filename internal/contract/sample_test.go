package contract

import (
	"strings"
	"testing"
)

func TestSampleOriginRequiresExactSyntheticHTTPProvenance(t *testing.T) {
	valid := SampleOrigin{Kind: "http_raw", Synthetic: true, RawSHA256: strings.Repeat("a", 64), RawBytes: 1, Encoder: HTTPEncoder, SegmentBytes: 1460}
	if !valid.Valid() {
		t.Fatal("合法 HTTP Raw 来源未通过")
	}
	for name, change := range map[string]func(*SampleOrigin){
		"kind":           func(v *SampleOrigin) { v.Kind = "pcap" },
		"synthetic":      func(v *SampleOrigin) { v.Synthetic = false },
		"empty_hash":     func(v *SampleOrigin) { v.RawSHA256 = "" },
		"invalid_hash":   func(v *SampleOrigin) { v.RawSHA256 = strings.Repeat("g", 64) },
		"uppercase_hash": func(v *SampleOrigin) { v.RawSHA256 = strings.Repeat("A", 64) },
		"short_hash":     func(v *SampleOrigin) { v.RawSHA256 = strings.Repeat("a", 62) },
		"empty_raw":      func(v *SampleOrigin) { v.RawBytes = 0 },
		"negative_raw":   func(v *SampleOrigin) { v.RawBytes = -1 },
		"oversized_raw":  func(v *SampleOrigin) { v.RawBytes = MaxHTTPRawBytes + 1 },
		"encoder":        func(v *SampleOrigin) { v.Encoder = "http-raw-tcp/2" },
		"segment":        func(v *SampleOrigin) { v.SegmentBytes = 1500 },
	} {
		t.Run(name, func(t *testing.T) {
			v := valid
			change(&v)
			if v.Valid() {
				t.Fatal("非真实约定来源被接受")
			}
		})
	}
	valid.RawBytes = MaxHTTPRawBytes
	if !valid.Valid() {
		t.Fatal("允许的最大原始样本未通过")
	}
}
