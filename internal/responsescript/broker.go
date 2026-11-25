package responsescript

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

func headerName(name string) bool {
	if name == "" || name != http.CanonicalHeaderKey(name) || !identifier(name) || strings.ContainsAny(name, "_.") {
		return false
	}
	switch name {
	case "Host", "Connection", "Content-Length", "Transfer-Encoding", "Trailer", "Upgrade",
		"Te", "Keep-Alive", "Expect", "Content-Type", "Accept", "Accept-Encoding", "Cookie",
		"Set-Cookie", "Forwarded", "X-Http-Method", "X-Http-Method-Override", "X-Method-Override",
		"X-Original-Url", "X-Rewrite-Url":
		return false
	}
	return !strings.HasPrefix(name, "Proxy-") && !strings.HasPrefix(name, "X-Forwarded-")
}

func validNames(names []string) bool {
	if len(names) > 32 {
		return false
	}
	for _, name := range names {
		if !identifier(name) {
			return false
		}
	}
	return true
}

func (r *Runtime) freezeRoutes() error {
	routes := slices.Clone(r.cfg.Routes)
	seen := make(map[[3]string]bool, len(routes))
	for i, route := range routes {
		key := [3]string{route.Entry, route.Method, route.Path}
		sample := route.Path
		if strings.HasSuffix(sample, "/{rule_id}") {
			sample = strings.TrimSuffix(sample, "{rule_id}") + "sample"
		}
		if seen[key] || !entryKnown(route.Entry) || !verbKnown(route.Method) || route.Method != http.MethodGet && !mutation(route.Entry) || !routePath(sample) || !validNames(route.Query) || !validNames(route.Fields) || len(route.Headers) > 8 {
			return Scope
		}
		if route.Method != http.MethodGet && (len(route.Query) > 0 || r.cfg.Login != nil && route.Path == r.cfg.Login.Path) {
			return Scope
		}
		for name, ref := range route.Headers {
			if !headerName(name) || name == "Authorization" && ref == "" {
				return Scope
			}
			if ref == "token" && r.cfg.Login == nil {
				return Credential
			}
			if ref != "" && ref != "token" && (r.secrets[ref].data == "" || r.secrets[ref].hmac) {
				return Credential
			}
		}
		seen[key] = true
		routes[i].Query, routes[i].Fields, routes[i].Headers = slices.Clone(route.Query), slices.Clone(route.Fields), maps.Clone(route.Headers)
	}
	r.cfg.Routes = routes
	if r.cfg.Login == nil {
		return nil
	}
	login := *r.cfg.Login
	if !routePath(login.Path) || !identifier(login.TokenField) || len(login.Secrets) == 0 || len(login.Secrets) > 8 {
		return Scope
	}
	for field, ref := range login.Secrets {
		if !identifier(field) || r.secrets[ref].data == "" || r.secrets[ref].hmac {
			return Credential
		}
	}
	login.Secrets = maps.Clone(login.Secrets)
	r.cfg.Login = &login
	return nil
}

type broker struct {
	r        *Runtime
	in       Invocation
	state    map[string]stateItem
	events   []Event
	requests int
	wrote    bool
}

func (r *Runtime) containsSecret(value string) bool {
	if r.token != "" && strings.Contains(value, r.token) {
		return true
	}
	for _, secret := range r.secrets {
		if strings.Contains(value, secret.data) {
			return true
		}
	}
	return false
}

func (r *Runtime) inspect(value any, depth int) Code {
	if depth > 32 {
		return Size
	}
	switch value := value.(type) {
	case map[string]any:
		for key, item := range value {
			if r.containsSecret(key) {
				return Credential
			}
			if code := r.inspect(item, depth+1); code != OK {
				return code
			}
		}
	case []any:
		for _, item := range value {
			if code := r.inspect(item, depth+1); code != OK {
				return code
			}
		}
	case string:
		if r.containsSecret(value) {
			return Credential
		}
	case json.Number:
		if r.containsSecret(value.String()) {
			return Credential
		}
	}
	return OK
}

func (r *Runtime) decode(raw json.RawMessage) (any, Code) {
	if len(raw) > maxData {
		return nil, Size
	}
	if !json.Valid(raw) {
		return nil, Input
	}
	var value any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&value); err != nil {
		return nil, Input
	}
	return value, r.inspect(value, 0)
}

func (r *Runtime) tokenRef() string {
	return "token:" + strconv.FormatUint(r.tokenID, 10)
}

func (r *Runtime) hasRef(ref string) bool {
	if ref == r.tokenRef() {
		return r.token != "" && r.now().Before(r.tokenEnds)
	}
	_, ok := r.secrets[ref]
	return ok
}

func (b *broker) record(event Event) {
	if len(b.events) < maxEvents {
		b.events = append(b.events, event)
	}
}

func (b *broker) dispatch(ctx context.Context, request frame) frame {
	r := b.r
	reply := frame{Code: OK}
	switch request.Kind {
	case "http":
		return b.device(ctx, request)
	case "secret":
		if r.secrets[request.Name].data == "" {
			reply.Code = Credential
		} else {
			reply.Value.Ref = request.Name
		}
	case "get", "set":
		return b.storage(request)
	case "hmac":
		key := r.secrets[request.Value.Ref]
		if !key.hmac {
			reply.Code = Credential
		} else if len(request.Bytes) > maxData {
			reply.Code = Size
		} else {
			mac := hmac.New(sha256.New, []byte(key.data))
			mac.Write(request.Bytes)
			reply.Text = hex.EncodeToString(mac.Sum(nil))
		}
	case "log":
		if request.Level != "info" && request.Level != "warn" && request.Level != "error" || !printable(request.Text) {
			reply.Code = Input
		} else if r.containsSecret(request.Text) {
			reply.Code = Credential
		} else {
			b.record(Event{Code: OK, Level: request.Level, Message: request.Text})
		}
	default:
		reply.Code = Isolation
	}
	return reply
}

func (b *broker) storage(request frame) frame {
	r := b.r
	now := r.now()
	reply := frame{Code: OK}
	if !identifier(request.Name) {
		return frame{Code: Input}
	}
	if request.Kind == "get" {
		item := b.state[request.Name]
		if now.Before(item.until) && (item.value.Ref == "" || r.hasRef(item.value.Ref)) {
			reply.Value = item.value
		}
		return reply
	}
	if request.TTL < 1 || request.TTL > 86400 {
		return frame{Code: Input}
	}
	if _, exists := b.state[request.Name]; !exists && len(b.state) >= maxStateKeys {
		return frame{Code: Size}
	}
	if request.Value.Ref != "" {
		if !r.hasRef(request.Value.Ref) || len(request.Value.JSON) > 0 {
			return frame{Code: Credential}
		}
	} else if _, code := r.decode(request.Value.JSON); code != OK {
		return frame{Code: code}
	}
	b.state[request.Name] = stateItem{request.Value, now.Add(time.Duration(request.TTL) * time.Second)}
	return reply
}

func (b *broker) route(method, p string) (Route, bool) {
	for _, route := range b.r.cfg.Routes {
		if route.Entry == b.in.Entry && route.Method == method && route.Path == p {
			return route, true
		}
	}
	for _, route := range b.r.cfg.Routes {
		if base, variable := strings.CutSuffix(route.Path, "/{rule_id}"); variable && route.Entry == b.in.Entry && route.Method == method && b.in.RuleID != "" && base+"/"+b.in.RuleID == p {
			return route, true
		}
	}
	return Route{}, false
}

func (b *broker) device(ctx context.Context, request frame) (reply frame) {
	r := b.r
	p := strings.TrimPrefix(request.URL, r.cfg.Origin)
	event := Event{}
	defer func() {
		event.Code = reply.Code
		b.record(event)
	}()
	if !routePath(p) {
		return frame{Code: Scope}
	}
	route, ok := b.route(request.Method, p)
	login := r.cfg.Login
	isLogin := login != nil && request.Method == http.MethodPost && p == login.Path
	if !ok && !isLogin {
		return frame{Code: Scope}
	}
	event.Method, event.Route = request.Method, route.Path
	if isLogin {
		event.Route = login.Path
	}
	// 请求路径只允许登记的字面路径和任务端提供的设备规则标识。
	if r.containsSecret(p) {
		return frame{Code: Credential}
	}
	headers := make(http.Header)
	body := request.Value.JSON
	if isLogin {
		if len(request.Query) != 0 || len(request.Fields) != len(login.Secrets) || len(body) != 0 || len(request.Headers) != 0 {
			return frame{Code: Scope}
		}
		fields := make(map[string]string, len(login.Secrets))
		for field, ref := range login.Secrets {
			if actual := request.Fields[field]; actual.Ref != ref || len(actual.JSON) != 0 {
				return frame{Code: Credential}
			}
			fields[field] = r.secrets[ref].data
		}
		body, _ = json.Marshal(fields)
	} else {
		if len(request.Fields) != 0 {
			return frame{Code: Credential}
		}
		for key, value := range request.Query {
			if !slices.Contains(route.Query, key) || len(value) > maxLogBytes {
				return frame{Code: Scope}
			}
			if r.containsSecret(value) {
				return frame{Code: Credential}
			}
		}
		if code := b.headers(route, headers, request.Headers); code != OK {
			return frame{Code: code}
		}
		if request.Method == http.MethodGet {
			if len(body) != 0 {
				return frame{Code: Scope}
			}
		} else {
			grant := b.in.Write
			if b.wrote || grant == nil || request.Method != grant.Method || p != grant.Path {
				return frame{Code: Scope}
			}
			if len(body) > 0 {
				value, code := r.decode(body)
				if code != OK {
					return frame{Code: code}
				}
				body, _ = json.Marshal(value)
			}
			if !bytes.Equal(body, grant.Body) {
				return frame{Code: Scope}
			}
		}
	}
	now := r.now()
	for len(r.requests) > 0 && !now.Before(r.requests[0].Add(time.Minute)) {
		r.requests = r.requests[1:]
	}
	if b.requests >= maxRequests || len(r.requests) >= requestsInMin {
		return frame{Code: Rate}
	}
	b.requests++
	r.requests = append(r.requests, now)
	if !isLogin && request.Method != http.MethodGet {
		b.wrote = true
	}
	req, err := http.NewRequestWithContext(ctx, request.Method, r.deviceURL(p, request.Query), bytes.NewReader(body))
	if err != nil {
		return frame{Code: Input}
	}
	req.Header = headers
	req.Header.Set("Accept", "application/json")
	if len(body) != 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := r.client.Do(req)
	if err != nil {
		return frame{Code: deviceCode(ctx, err)}
	}
	defer res.Body.Close()
	event.Status = res.StatusCode
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		return frame{Code: Scope}
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxData+1))
	if err != nil {
		return frame{Code: deviceCode(ctx, err)}
	}
	if len(raw) > maxData {
		return frame{Code: Size}
	}
	return b.response(event.Status, route, isLogin, raw)
}

func (b *broker) headers(route Route, headers http.Header, requested map[string]wireValue) Code {
	r := b.r
	for name, value := range requested {
		ref, ok := route.Headers[name]
		if !ok {
			return Scope
		}
		var text string
		if ref != "" {
			expected := ref
			if ref == "token" {
				expected = r.tokenRef()
			}
			if value.Ref != expected || !r.hasRef(expected) || len(value.JSON) > 0 {
				return Credential
			}
			if ref == "token" {
				text = r.token
				if name == "Authorization" {
					text = "Bearer " + text
				}
			} else {
				text = r.secrets[ref].data
			}
		} else {
			if value.Ref != "" || json.Unmarshal(value.JSON, &text) != nil || r.containsSecret(text) {
				return Credential
			}
		}
		if !printable(text) {
			return Input
		}
		headers.Set(name, text)
	}
	for name, ref := range route.Headers {
		if ref != "" && headers.Get(name) == "" {
			return Credential
		}
	}
	return OK
}

func (b *broker) response(status int, route Route, login bool, raw []byte) frame {
	r := b.r
	reply := frame{Code: OK, Status: status}
	if login && (status < 200 || status >= 300) {
		return reply
	}
	var value map[string]json.RawMessage
	if (!login && len(route.Fields) == 0) || len(bytes.TrimSpace(raw)) == 0 && !login {
		return reply
	}
	if json.Unmarshal(raw, &value) != nil || value == nil {
		return frame{Code: DeviceError}
	}
	if login {
		field := r.cfg.Login.TokenField
		var token string
		if json.Unmarshal(value[field], &token) != nil || !printable(token) || r.containsSecret(token) && token != r.token {
			return frame{Code: Credential}
		}
		r.tokenID++
		r.token, r.tokenEnds = token, r.now().Add(tokenTTL)
		reply.Fields = map[string]wireValue{field: {Ref: r.tokenRef()}}
		return reply
	}
	reply.Fields = make(map[string]wireValue, len(route.Fields))
	for _, key := range route.Fields {
		if raw, exists := value[key]; exists {
			if r.containsSecret(key) {
				return frame{Code: Credential}
			}
			if _, code := r.decode(raw); code != OK {
				return frame{Code: code}
			}
			reply.Fields[key] = wireValue{JSON: raw}
		}
	}
	return reply
}
