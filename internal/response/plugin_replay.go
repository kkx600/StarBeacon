package response

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
)

// PluginReplay 在采集器父进程逐条匹配合成样例，不持有真实设备连接。
type PluginReplay struct {
	mu       sync.Mutex
	examples []PluginExample
	next     int
	failed   bool
}

func NewPluginReplay(examples []PluginExample, values map[string]string) *PluginReplay {
	pairs := make([]string, 0, len(values)*2)
	for key, value := range values {
		encoded, _ := json.Marshal(value)
		pairs = append(pairs, `"{{`+key+`}}"`, string(encoded))
	}
	replace := strings.NewReplacer(pairs...)
	replay := &PluginReplay{examples: make([]PluginExample, len(examples))}
	for i, sample := range examples {
		sample.Request, sample.Response = replace.Replace(sample.Request), replace.Replace(sample.Response)
		replay.examples[i] = sample
	}
	return replay
}

func (r *PluginReplay) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failed || req.Context().Err() != nil || r.next == len(r.examples) {
		r.failed = true
		return nil, ErrInput
	}
	sample := r.examples[r.next]
	var input []byte
	var err error
	if req.Body != nil {
		defer req.Body.Close()
		input, err = io.ReadAll(io.LimitReader(req.Body, 16*1024+1))
	}
	if err != nil || len(input) > 16*1024 || req.Method != sample.Method || req.URL.Path != sample.Path || req.URL.RawQuery != sample.Query ||
		sample.Request != "" && !equivalentJSON(input, []byte(sample.Request)) {
		r.failed = true
		return nil, ErrInput
	}
	r.next++
	return &http.Response{StatusCode: sample.Status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(sample.Response)), Request: req}, nil
}

func (r *PluginReplay) Complete() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return !r.failed && r.next == len(r.examples)
}

func equivalentJSON(a, b []byte) bool {
	canonical := func(raw []byte) []byte {
		var v any
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		if !json.Valid(raw) || d.Decode(&v) != nil {
			return nil
		}
		normalized, _ := json.Marshal(v)
		return normalized
	}
	x, y := canonical(a), canonical(b)
	return len(x) != 0 && bytes.Equal(x, y)
}
