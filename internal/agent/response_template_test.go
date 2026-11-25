package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/response"
	bolt "go.etcd.io/bbolt"
)

type templateACLFixture struct {
	mu           sync.Mutex
	token        string
	logins       int
	writes       int
	removes      int
	corruptID    bool
	loseReply    bool
	conflictRule bool
	leases       map[string]response.Lease
}

func (d *templateACLFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	write := func(status int, value any) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(value)
	}
	if r.Method == http.MethodPost && r.URL.Path == "/session/new" {
		var login map[string]string
		if json.NewDecoder(r.Body).Decode(&login) != nil || login["user"] != "fixture-user" || login["pass"] != "fixture-password" || r.Header.Get("Authorization") != "" {
			write(403, map[string]int{"code": 3})
			return
		}
		d.logins++
		d.token = fmt.Sprintf("controlled-template-token-%d", d.logins)
		write(200, map[string]string{"access_token": d.token})
		return
	}
	if d.token == "" || r.Header.Get("Authorization") != "Bearer "+d.token {
		write(401, map[string]int{"code": 401})
		return
	}
	now := time.Now().UTC()
	switch {
	case r.Method == "GET" && r.URL.Path == "/v1/status":
		write(200, map[string]any{"ok": true, "unit": "device_fixture", "firmware": "fixture/1", "expires_locally": true, "isolated_rules": true, "checks_owner": true, "maximum_age": 600, "checked_at": now})
	case r.Method == "POST" && r.URL.Path == "/v1/acl":
		var input struct {
			Lease   string    `json:"comment"`
			Target  string    `json:"address"`
			Owner   string    `json:"owner"`
			Expires time.Time `json:"end"`
			TTL     int       `json:"ttl"`
			Policy  string    `json:"policy"`
		}
		if json.NewDecoder(r.Body).Decode(&input) != nil || input.TTL < 1 || input.TTL > 60 || input.Policy != "temporary" || input.Owner == "" || input.Lease == "" || input.Target != "198.51.100.10" || !input.Expires.After(now) {
			write(400, map[string]int{"code": 1})
			return
		}
		d.writes++
		if _, exists := d.leases[input.Lease]; exists {
			write(409, map[string]int{"code": 2})
			return
		}
		reference := fmt.Sprintf("rule_%d", d.writes)
		d.leases[input.Lease] = response.Lease{DeviceID: "device_fixture", LeaseID: input.Lease, OwnerSHA256: input.Owner, TargetIP: input.Target, ExpiresAt: input.Expires, State: "active", DeviceRuleID: reference}
		if d.loseReply {
			write(503, map[string]int{"code": 9})
			return
		}
		if d.conflictRule {
			reference = "different_reply"
		}
		write(201, map[string]any{"code": 0, "key": reference})
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/acl/by-task/"):
		lease, ok := d.leases[strings.TrimPrefix(r.URL.Path, "/v1/acl/by-task/")]
		if !ok {
			write(404, map[string]string{"code": "unassigned"})
			return
		}
		if !lease.ExpiresAt.After(now) && lease.State == "active" {
			lease.State = "expired"
		}
		if d.corruptID {
			lease.DeviceRuleID = "different_rule"
		}
		write(200, map[string]any{"comment": lease.LeaseID, "unit": lease.DeviceID, "owner": lease.OwnerSHA256, "address": lease.TargetIP, "end": lease.ExpiresAt, "checked_at": now, "rule_state": lease.State, "key": lease.DeviceRuleID})
	case r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/v1/acl/rules/"):
		id := strings.TrimPrefix(r.URL.Path, "/v1/acl/rules/")
		for task, lease := range d.leases {
			if lease.DeviceRuleID == id && r.Header.Get("If-Match") == `"`+lease.OwnerSHA256+`"` {
				d.removes++
				lease.State = "revoked"
				d.leases[task] = lease
				w.WriteHeader(204)
				return
			}
		}
		write(412, map[string]int{"code": 4})
	default:
		write(404, map[string]int{"code": 10})
	}
}

func TestResponseTemplateACLThroughCollectorLeaseLifecycle(t *testing.T) {
	ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
	defer stop()
	service, _, _, _ := responseServiceFixture(t)
	definitionRaw, err := os.ReadFile("../response/testdata/owned_acl_template.json")
	if err != nil {
		t.Fatal(err)
	}
	var definition response.Template
	if err := json.Unmarshal(definitionRaw, &definition); err != nil {
		t.Fatal(err)
	}
	device := &templateACLFixture{leases: map[string]response.Lease{}}
	server := httptest.NewTLSServer(device)
	defer server.Close()
	old := service.clients["connector_fixture"]
	cfg := old.Config
	cfg.Origin = server.URL
	if err := os.WriteFile(cfg.CAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.TokenFile, []byte(`{"username":"fixture-user","password":"fixture-password"}`), 0600); err != nil {
		t.Fatal(err)
	}
	client, err := response.NewTemplateClient(cfg, definition)
	if err != nil {
		t.Fatal(err)
	}
	old.Close()
	service.clients[cfg.ID] = client
	service.check(ctx, cfg.ID)
	if ready := service.Health(); len(ready) != 1 || ready[0].Status != "ready" || ready[0].MaxTTLSeconds != 600 {
		t.Fatal("模板设备的身份与限时能力未核实", ready)
	}
	command := responseCommand(service, "task_template_owned")
	a, err := response.ReadAction(command.Payload)
	if err != nil || a.ConfigSHA256 == cfg.SHA256() {
		t.Fatal("授权摘要未绑定模板版本", err)
	}
	expectState := func(kind, state string) {
		t.Helper()
		command.Kind = kind
		raw, code, err := service.Execute(ctx, command)
		result, validate := response.ReadResult(raw, a, kind, time.Now().UTC())
		if err != nil || code != "" || validate != nil || result.Observation.State != state ||
			bytes.Contains(raw, []byte("controlled-template-token")) || bytes.Contains(raw, []byte("rule_1")) {
			t.Fatalf("设备证据或凭据边界异常，动作 %s，状态 %s，代码 %s，错误 %v／%v", kind, result.Observation.State, code, err, validate)
		}
	}
	expectState("response.block", "active")
	expectState("response.block", "active")
	var stored responseRecord
	if err := service.WAL.DB.View(func(tx *bolt.Tx) error {
		return json.Unmarshal(tx.Bucket([]byte("response_leases")).Get([]byte(a.LeaseID)), &stored)
	}); err != nil || stored.DeviceRuleID != "rule_1" {
		t.Fatal("独立回读的设备规则标识没有随私有租约落盘", err)
	}
	device.mu.Lock()
	device.token = ""
	device.corruptID = true
	device.mu.Unlock()
	command.Kind = "response.revoke"
	if _, code, err := service.Execute(ctx, command); code != "result_unknown" || !errors.Is(err, response.ErrUnknown) {
		t.Fatal("设备返回不同规则时仍尝试解除", code, err)
	}
	device.mu.Lock()
	device.corruptID = false
	device.mu.Unlock()
	expectState("response.read", "active")
	expectState("response.revoke", "revoked")
	expectState("response.read", "revoked")
	device.mu.Lock()
	if device.logins != 2 || device.writes != 1 || device.removes != 1 {
		logins, writes, removes := device.logins, device.writes, device.removes
		device.mu.Unlock()
		t.Fatal("重登录、未知结果或重复请求引起多余动作", logins, writes, removes)
	}
	device.loseReply = true
	device.mu.Unlock()
	command = responseCommand(service, "task_template_lost_reply")
	a, err = response.ReadAction(command.Payload)
	if err != nil {
		t.Fatal(err)
	}
	expectState("response.block", "active")
	expectState("response.revoke", "revoked")
	device.mu.Lock()
	device.loseReply, device.conflictRule = false, true
	device.mu.Unlock()
	command = responseCommand(service, "task_template_conflict_reply")
	if _, code, err := service.Execute(ctx, command); code != "result_unknown" || !errors.Is(err, response.ErrUnknown) {
		t.Fatal("提交与回读指向不同标识时仍声称成功", code, err)
	}
	a, err = response.ReadAction(command.Payload)
	if err != nil {
		t.Fatal(err)
	}
	expectState("response.read", "active")
	expectState("response.revoke", "revoked")
	device.mu.Lock()
	defer device.mu.Unlock()
	if device.writes != 3 || device.removes != 3 {
		t.Fatal("状态未知后的回读产生了重复设备写入")
	}
}
