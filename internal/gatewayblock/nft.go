package gatewayblock

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
)

const table = "starbeacon_gateway"
const configLimit = 8192

type Service struct {
	path string
	nft  func(context.Context, ...string) ([]byte, error)
}

func NewService(path string) *Service {
	if path == "" || runtime.GOOS != "linux" {
		return nil
	}
	return &Service{path: path, nft: runNFT}
}

func runNFT(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "/usr/sbin/nft", args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin", "LC_ALL=C"}
	var output boundedBuffer
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	err := cmd.Run()
	return output.bytes.Bytes(), err
}

type boundedBuffer struct{ bytes bytes.Buffer }

func (b *boundedBuffer) Write(value []byte) (int, error) {
	if len(value) > 64*1024-b.bytes.Len() {
		return 0, ErrUnavailable
	}
	return b.bytes.Write(value)
}

func (s *Service) local() (LocalConfig, error) {
	var config LocalConfig
	info, err := os.Lstat(s.path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&022 != 0 || info.Size() > configLimit {
		return config, ErrUnavailable
	}
	file, err := os.Open(s.path)
	if err != nil {
		return config, ErrUnavailable
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return config, ErrUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(file, configLimit+1))
	if err != nil || contract.JSONFields(string(raw), []string{"enabled", "scope", "sources", "destinations"}, configLimit) != nil ||
		json.Unmarshal(raw, &config) != nil || !config.Enabled || !config.Scope.Valid() {
		return LocalConfig{}, ErrUnavailable
	}
	return config, nil
}

type nftMatch struct {
	Op    string
	Right string
	Left  struct {
		Concat []struct {
			Payload struct {
				Protocol string
				Field    string
			}
		}
	}
}

// 正反方向各自核对五元组集合的引用以及后续的丢弃动作。
func (m nftMatch) direction(f Flow) int {
	if m.Op != "==" || m.Right != "@"+f.setName() || len(m.Left.Concat) != 4 {
		return 0
	}
	ip := "ip"
	if f.SourceIP.Is6() {
		ip = "ip6"
	}
	fields := [4]string{}
	for i, part := range m.Left.Concat {
		want := ip
		if i%2 == 1 {
			want = f.Transport
		}
		if part.Payload.Protocol != want {
			return 0
		}
		fields[i] = part.Payload.Field
	}
	switch fields {
	case [4]string{"saddr", "sport", "daddr", "dport"}:
		return 1
	case [4]string{"daddr", "dport", "saddr", "sport"}:
		return 2
	default:
		return 0
	}
}

func (s *Service) ready(ctx context.Context, flow *Flow) bool {
	raw, err := s.nft(ctx, "-j", "-n", "list", "chain", "inet", table, "forwarding")
	var root struct {
		Nftables []struct {
			Chain *struct {
				Family string
				Table  string
				Name   string
				Type   string
				Hook   string
			}
			Rule *struct {
				Family string
				Table  string
				Chain  string
				Expr   []struct {
					Match *nftMatch
					Drop  json.RawMessage
				}
			}
		}
	}
	if err != nil || json.Unmarshal(raw, &root) != nil {
		return false
	}
	present, directions := false, 0
	for _, entry := range root.Nftables {
		if c := entry.Chain; c != nil && c.Family == "inet" && c.Table == table && c.Name == "forwarding" && c.Type == "filter" && c.Hook == "forward" {
			present = true
		}
		r := entry.Rule
		if flow != nil && r != nil && r.Family == "inet" && r.Table == table && r.Chain == "forwarding" &&
			len(r.Expr) == 3 && r.Expr[0].Match != nil && bytes.Equal(r.Expr[2].Drop, []byte("null")) {
			directions |= r.Expr[0].Match.direction(*flow)
		}
	}
	return present && (flow == nil || directions == 3)
}

func (s *Service) Health(ctx context.Context) *Health {
	if s == nil {
		return nil
	}
	config, err := s.local()
	if err != nil {
		return nil
	}
	call, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if !s.ready(call, nil) {
		return nil
	}
	health := config.Binding()
	return &health
}

func (f Flow) setName() string {
	if f.SourceIP.Is4() {
		return f.Transport + "4"
	}
	return f.Transport + "6"
}

func (f Flow) tuple() string {
	return fmt.Sprintf("%s . %d . %s . %d", f.SourceIP, f.SourcePort, f.DestinationIP, f.DestinationPort)
}

// Apply 只写入预置集合的一条限时记录。写入结果未知时仅读回原条目。
func (s *Service) Apply(ctx context.Context, commandID string, a Action, expires time.Time) (Result, string, error) {
	if s == nil {
		return Result{}, "gateway_unavailable", ErrUnavailable
	}
	config, err := s.local()
	if err != nil {
		return Result{}, "gateway_unavailable", err
	}
	if !contract.ValidID(commandID) || !a.Flow.Valid() || !config.Scope.Allows(a.Flow) || config.Binding().ConfigSHA256 != a.ConfigSHA256 {
		return Result{}, "gateway_scope_changed", ErrIneligible
	}
	call, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	if !s.ready(call, &a.Flow) {
		return Result{}, "gateway_unavailable", ErrUnavailable
	}
	writeUntil := time.Now().Add(750 * time.Millisecond)
	if expires.Before(writeUntil) {
		writeUntil = expires
	}
	seconds := int(a.LeaseUntil.Sub(writeUntil) / time.Second)
	if !time.Now().Before(writeUntil) || seconds < 1 || seconds > 60 {
		return Result{}, "gateway_authorization_expired", ErrIneligible
	}
	write, done := context.WithDeadline(call, writeUntil)
	// create 保留已有租约的超时和归属。所有命令参数都来自固定值及已验证的地址、端口和身份。
	_, _ = s.nft(write, "create", "element", "inet", table, a.Flow.setName(), "{", a.Flow.tuple(),
		"timeout", strconv.Itoa(seconds)+"s", "comment", strconv.Quote(commandID), "}")
	done()
	raw, err := s.nft(call, "-j", "-n", "list", "set", "inet", table, a.Flow.setName())
	now := time.Now().UTC()
	if err != nil || !verifyElement(raw, a.Flow, commandID, int(a.LeaseUntil.Sub(now)/time.Second)+1) {
		return Result{}, "result_unknown", ErrUnknown
	}
	return Result{RequestID: a.RequestID, ConfigSHA256: a.ConfigSHA256, Flow: a.Flow, LeaseUntil: a.LeaseUntil, VerifiedAt: now}, "", nil
}

func verifyElement(raw []byte, flow Flow, owner string, maxSeconds int) bool {
	type record struct {
		Family string
		Table  string
		Name   string
		Flags  []string
		Elem   []struct {
			Element struct {
				Val struct {
					Concat []json.RawMessage
				}
				Comment string
				Timeout int
				Expires int
			} `json:"elem"`
		}
	}
	var root struct {
		Nftables []struct {
			Set *record
		}
	}
	if json.Unmarshal(raw, &root) != nil || maxSeconds < 1 {
		return false
	}
	for _, row := range root.Nftables {
		r := row.Set
		if r == nil || r.Family != "inet" || r.Table != table || r.Name != flow.setName() || !slices.Contains(r.Flags, "timeout") {
			continue
		}
		for _, element := range r.Elem {
			item := element.Element
			if item.Comment != owner {
				continue
			}
			concat := item.Val.Concat
			if item.Timeout < 1 || item.Timeout > 60 || item.Expires < 1 || item.Expires > maxSeconds || len(concat) != 4 {
				return false
			}
			want := []any{flow.SourceIP, flow.SourcePort, flow.DestinationIP, flow.DestinationPort}
			for i, field := range want {
				encoded, _ := json.Marshal(field)
				if !bytes.Equal(encoded, bytes.TrimSpace(concat[i])) {
					return false
				}
			}
			return true
		}
	}
	return false
}
