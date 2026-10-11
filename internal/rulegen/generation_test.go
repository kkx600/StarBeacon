package rulegen

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/replay"
	"github.com/kkx600/StarBeacon/internal/testpcap"
)

func requestFixture() Request {
	return Request{Description: "检测指定 HTTP 路径，同时说明误报边界", Source: "natural_language", ProviderID: "provider_owned", ProviderRevision: 1, CandidateCount: 1, AllowContext: true}
}
func evidenceFixture(t *testing.T) Evidence {
	t.Helper()
	e, err := Seal(Evidence{Packets: []replay.PacketSnippet{}})
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func candidateFixture(sid uint32) Candidate {
	return Candidate{SID: sid, EngineVersion: EngineVersion, Title: "请求路径检测", Rule: fmt.Sprintf(`alert http any any -> any any (msg:"路径检测"; http.uri; content:"/starbeacon/validation"; sid:%d; rev:1;)`, sid), Explanation: "匹配请求路径；仍需装载检查和正反样本验证。", Risks: []string{"合法业务可能使用相同路径"}, References: []int64{}}
}
func outputText(candidates []Candidate) string {
	raw, _ := json.Marshal(output{Candidates: candidates})
	return string(raw)
}

func TestRequestAndFrozenPromptConstraints(t *testing.T) {
	request, e := requestFixture(), evidenceFixture(t)
	prompt, err := Prompt(request, e, []uint32{MinSID})
	if err != nil || !strings.Contains(prompt, request.Description) || !strings.Contains(prompt, e.SHA256) {
		t.Fatal("有效说明或冻结摘要未进入模型上下文", err)
	}
	if InputHash(request) != InputHash(request) || !ValidSHA(InputHash(request)) {
		t.Fatal("输入摘要不稳定")
	}
	changed := request
	changed.Description += "变化"
	if InputHash(request) == InputHash(changed) {
		t.Fatal("不同请求使用同一摘要")
	}
	for _, mutate := range []func(*Request){
		func(r *Request) { r.Description = " " }, func(r *Request) { r.Description = "\x00" }, func(r *Request) { r.Description = string([]byte{255}) }, func(r *Request) { r.Description = strings.Repeat("字", 4001) },
		func(r *Request) { r.ProviderID = "../provider" }, func(r *Request) { r.ProviderRevision = 0 }, func(r *Request) { r.ProviderRevision = 1 << 53 }, func(r *Request) { r.CandidateCount = 0 }, func(r *Request) { r.CandidateCount = 4 }, func(r *Request) { r.AllowContext = false },
		func(r *Request) { r.Source = "unknown" }, func(r *Request) { r.SampleID = "sample_extra" }, func(r *Request) { r.SampleSHA256 = strings.Repeat("a", 64) }, func(r *Request) { r.Source = "pcap"; r.SampleID = "sample_owned"; r.SampleSHA256 = "bad" },
		func(r *Request) {
			r.Source = "pcap"
			r.SampleID = "invalid/path"
			r.SampleSHA256 = strings.Repeat("a", 64)
		},
	} {
		bad := request
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("无效输入被接受", bad)
		}
		if _, err := Prompt(bad, e, []uint32{MinSID}); !errors.Is(err, ErrInput) {
			t.Fatal(err)
		}
	}
	for _, sids := range [][]uint32{nil, {MinSID - 1}, {MaxSID + 1}, {MinSID, MinSID}} {
		if _, err := Prompt(request, e, sids); err == nil {
			t.Fatal("无效分配被接受")
		}
	}
	request.CandidateCount = 2
	if _, err := Prompt(request, e, []uint32{MinSID, MinSID}); err == nil {
		t.Fatal("重复分配被接受")
	}
	request = requestFixture()
	bad := e
	bad.SHA256 = "incorrect"
	if _, err := Prompt(request, bad, []uint32{MinSID}); err == nil {
		t.Fatal("修改后的证据被接受")
	}
	bad = e
	bad.Packets = []replay.PacketSnippet{{Packet: 1}}
	bad, _ = Seal(bad)
	if _, err := Prompt(request, bad, []uint32{MinSID}); err == nil {
		t.Fatal("自然语言请求带入未授权包材料")
	}
	if _, err := Seal(Evidence{Packets: []replay.PacketSnippet{{PayloadHex: strings.Repeat("a", 14001)}}}); err == nil {
		t.Fatal("超限材料被保存")
	}
	stamp := time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := Seal(Evidence{Metadata: &replay.Metadata{First: &stamp}}); err == nil {
		t.Fatal("不可编码时间被保存")
	}
	request.Source = "pcap"
	request.SampleID = "sample_owned"
	request.SampleSHA256 = strings.Repeat("a", 64)
	if request.Validate() != nil {
		t.Fatal("合法 PCAP 请求被拒绝")
	}
	material := Evidence{Sample: &replay.Sample{ID: request.SampleID, SHA256: request.SampleSHA256}, Metadata: &replay.Metadata{}, Packets: []replay.PacketSnippet{}}
	material, _ = Seal(material)
	if _, err := Prompt(request, material, []uint32{MinSID}); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Evidence){func(e *Evidence) { e.Sample = nil }, func(e *Evidence) { e.Metadata = nil }, func(e *Evidence) { s := *e.Sample; s.ID = "sample_other"; e.Sample = &s }, func(e *Evidence) { s := *e.Sample; s.SHA256 = strings.Repeat("b", 64); e.Sample = &s }} {
		bad := material
		mutate(&bad)
		bad, _ = Seal(bad)
		if _, err := Prompt(request, bad, []uint32{MinSID}); err == nil {
			t.Fatal("材料身份偏差未拒绝")
		}
	}
	request.Source = "http_raw"
	if _, err := Prompt(request, material, []uint32{MinSID}); err == nil {
		t.Fatal("PCAP 被错误声明为合成 HTTP")
	}
	s := *material.Sample
	s.Origin = &replay.Origin{Kind: "http_raw", Synthetic: true, RawSHA256: strings.Repeat("a", 64), RawBytes: 1, Encoder: replay.HTTPEncoder, SegmentBytes: 1460}
	material.Sample = &s
	material, _ = Seal(material)
	if _, err := Prompt(request, material, []uint32{MinSID}); err != nil {
		t.Fatal("合成来源未进入冻结上下文", err)
	}
}

func TestCandidateContractBindsSIDAndOnlyCurrentPacketReferences(t *testing.T) {
	e := evidenceFixture(t)
	sids := []uint32{MinSID, MinSID + 1, MaxSID}
	candidates := []Candidate{}
	for _, sid := range sids {
		candidates = append(candidates, candidateFixture(sid))
	}
	decoded, err := DecodeOutput(outputText(candidates), e, sids)
	if err != nil || len(decoded) != 3 {
		t.Fatal(err)
	}
	bound := BindCandidates("gen_0123456789abcdef0123456789abcdef", decoded)
	if ValidateCandidates(bound, e, sids) != nil {
		t.Fatal("服务器候选绑定失败")
	}
	for _, c := range bound {
		if !ValidSHA(c.SHA256) || !contract.ValidID(c.PackageID) || c.PackageID != PackageID("gen_0123456789abcdef0123456789abcdef", c.SID) {
			t.Fatal("候选包身份或摘要无效")
		}
	}
	bound[0].SHA256 = strings.Repeat("a", 64)
	if ValidateCandidates(bound, e, sids) == nil {
		t.Fatal("修改后的候选摘要未拒绝")
	}
	c := candidateFixture(MinSID)
	e.Packets = []replay.PacketSnippet{{Packet: 4}}
	c.References = []int64{4}
	if _, err := DecodeOutput(outputText([]Candidate{c}), e, []uint32{MinSID}); err != nil {
		t.Fatal("实际包序号引用未接受", err)
	}
	for i, mutate := range []func(*Candidate){
		func(c *Candidate) { c.SID = MinSID - 1 }, func(c *Candidate) { c.EngineVersion = "7.0" }, func(c *Candidate) { c.Title = "" }, func(c *Candidate) { c.Title = "x\x00" }, func(c *Candidate) { c.Explanation = "" }, func(c *Candidate) { c.Explanation = strings.Repeat("字", 1001) },
		func(c *Candidate) { c.Rule = strings.Replace(c.Rule, "alert ", "drop ", 1) }, func(c *Candidate) { c.Rule += "\n" }, func(c *Candidate) { c.Rule = strings.Repeat("a", 16385) }, func(c *Candidate) { c.Rule = string([]byte{255}) }, func(c *Candidate) { c.Rule = strings.Replace(c.Rule, "sid:1000000;", "sid:1000001;", 1) },
		func(c *Candidate) { c.Rule = strings.Replace(c.Rule, "rev:1;", "rev:2;", 1) }, func(c *Candidate) { c.Rule = strings.Replace(c.Rule, "rev:1;", "rev:1;rev:1;", 1) }, func(c *Candidate) { c.Rule = strings.Replace(c.Rule, `msg:"路径检测";`, "", 1) },
		func(c *Candidate) { c.Rule = strings.Replace(c.Rule, "rev:1;", "rev:1; lua:script;", 1) }, func(c *Candidate) { c.Rule = strings.Replace(c.Rule, "rev:1;", "rev:1; dataset:example;", 1) }, func(c *Candidate) { c.Rule = strings.Replace(c.Rule, "rev:1;", "rev:1; bypass;", 1) }, func(c *Candidate) { c.Rule = strings.Replace(c.Rule, "rev:1;", "rev:1; filestore;", 1) },
		func(c *Candidate) { c.Risks = nil }, func(c *Candidate) { c.Risks = make([]string, 9) }, func(c *Candidate) { c.Risks = []string{""} }, func(c *Candidate) { c.Risks = []string{strings.Repeat("字", 301)} }, func(c *Candidate) { c.References = nil }, func(c *Candidate) { c.References = []int64{5} }, func(c *Candidate) { c.References = []int64{4, 4} }, func(c *Candidate) { c.References = make([]int64, 9) }, func(c *Candidate) { c.PackageID = "forged" }, func(c *Candidate) { c.SHA256 = strings.Repeat("a", 64) },
	} {
		bad := c
		mutate(&bad)
		if _, err := DecodeOutput(outputText([]Candidate{bad}), e, []uint32{MinSID}); err == nil {
			t.Fatal("非法候选被接受", i)
		}
		if ValidateCandidates([]Candidate{bad}, e, []uint32{MinSID}) == nil {
			t.Fatal("非法候选保存校验被接受", i)
		}
	}
	if _, err := DecodeOutput(outputText([]Candidate{candidateFixture(MinSID), candidateFixture(MinSID)}), e, []uint32{MinSID, MinSID + 1}); err == nil {
		t.Fatal("重复 SID 候选被接受")
	}
	for _, text := range []string{"", "{}", `{"candidates":null}`, `{"candidates":[]}`, `{"Candidates":[]}`, `{"candidates":[],"candidates":[]}`, outputText(candidates) + "{}", strings.Repeat("a", 60001), `{"candidates":[{"sid":1000000,"sid":1000000}]}`, `{"candidates":[[[[[[[[[[[]]]]]]]]]]]}`, `{"candidates":`, string([]byte{255}), `{"candidates":[],"untrusted":true}`, `{"candidates":[],"title":{"sid":1}}`} {
		if _, err := DecodeOutput(text, e, sids); err == nil {
			t.Fatal("非严格输出被接受", text)
		}
	}
	if _, err := DecodeOutput(outputText(candidates), e, nil); err == nil {
		t.Fatal("无分配候选被接受")
	}
}

func TestSIDAdmissionDoesNotReadIdentifiersInsideQuotedContent(t *testing.T) {
	text := `# 说明
alert tcp any any -> any any (msg:"sid:1000001;"; content:"escaped\"; sid:1000002;"; sid:1000000; rev:1;)
alert udp any any -> any any (msg:"第二条"; sid:1999999; rev:1;)`
	sids, err := RuleSIDs(text)
	if err != nil || len(sids) != 2 || sids[0] != MinSID || sids[1] != MaxSID {
		t.Fatal("引号内 SID 被识别成真实选项", sids, err)
	}
	for _, text := range []string{`alert tcp any any -> any any`, `alert tcp any any -> any any (sid:1;`, `alert tcp any any -> any any (sid:1)`, `alert tcp any any -> any any (sid:1;sid:2;)`, `alert tcp any any -> any any (msg:"x";)`, `alert tcp any any -> any any (sid:01;)`, `alert tcp any any -> any any (sid:0;)`, `alert tcp any any -> any any (sid:4294967296;)`, `alert tcp any any -> any any (sid:-1;)`, `alert tcp any any -> any any (msg:"unfinished; sid:1;)`} {
		if _, err := RuleSIDs(text); err == nil {
			t.Fatal("缺失或歧义 SID 被接受", text)
		}
	}
}

type materialStorage struct {
	data    []byte
	err     error
	readErr bool
	closed  bool
}

func (s *materialStorage) Put(context.Context, string, io.Reader, int64) (string, string, error) {
	return "", "", errors.New("只读")
}
func (s *materialStorage) Remove(context.Context, string) error { return errors.New("只读") }
func (s *materialStorage) Open(context.Context, string) (io.ReadCloser, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &materialBody{s: s, Reader: bytes.NewReader(s.data)}, nil
}

type materialBody struct {
	*bytes.Reader
	s *materialStorage
}

func (b *materialBody) Close() error { b.s.closed = true; return nil }
func (b *materialBody) Read(p []byte) (int, error) {
	if b.s.readErr {
		return 0, io.ErrUnexpectedEOF
	}
	return b.Reader.Read(p)
}

func TestMaterialReadsOwnedObjectWithoutChangingOriginal(t *testing.T) {
	raw, err := testpcap.HTTP(false)
	if err != nil {
		t.Fatal(err)
	}
	hash := func(raw []byte) string { return contractHash(raw) }
	sample := replay.Sample{ID: "sample_owned", Size: int64(len(raw)), SHA256: hash(raw), Format: "pcap"}
	storage := &materialStorage{data: raw}
	e, err := Material(context.Background(), storage, "tenant_owned", sample)
	if err != nil || !storage.closed || e.Metadata == nil || e.Metadata.Packets != 9 || len(e.Packets) != 2 || e.Packets[0].Packet != 4 || e.Packets[0].SourceIP != "192.0.2.10" || !ValidSHA(e.SHA256) || !bytes.Equal(storage.data, raw) {
		t.Fatal("冻结材料丢失真实包索引或改变了原始字节", e, err)
	}
	for _, mutate := range []func(*replay.Sample){func(s *replay.Sample) { s.ID = "invalid/path" }, func(s *replay.Sample) { s.Size = 23 }, func(s *replay.Sample) { s.Size = replay.MaxSampleBytes + 1 }, func(s *replay.Sample) { s.Size++ }, func(s *replay.Sample) { s.SHA256 = strings.Repeat("b", 64) }, func(s *replay.Sample) { s.Origin = &replay.Origin{} }} {
		bad := sample
		mutate(&bad)
		if _, err := Material(context.Background(), storage, "tenant_owned", bad); err == nil {
			t.Fatal("材料完整性错误未拒绝")
		}
	}
	if _, err := Material(context.Background(), nil, "tenant_owned", sample); err == nil {
		t.Fatal("空存储被接受")
	}
	if _, err := Material(context.Background(), storage, "../tenant", sample); err == nil {
		t.Fatal("跨域路径被接受")
	}
	for _, objects := range []*materialStorage{{data: append(append([]byte{}, raw...), 1)}, {data: raw[:len(raw)-1]}, {err: io.ErrClosedPipe}, {data: raw, readErr: true}, {data: make([]byte, 24)}} {
		bad := sample
		if len(objects.data) == 24 {
			bad.Size = 24
			bad.SHA256 = hash(objects.data)
		}
		if _, err := Material(context.Background(), objects, "tenant_owned", bad); err == nil {
			t.Fatal("无效对象产生了可用材料")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Material(ctx, storage, "tenant_owned", sample); !errors.Is(err, context.Canceled) {
		t.Fatal("取消后仍读取材料", err)
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "regular")
	if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", file)
	if _, err := Material(context.Background(), storage, "tenant_owned", sample); err == nil {
		t.Fatal("临时目录故障仍返回材料")
	}
}

func contractHash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
