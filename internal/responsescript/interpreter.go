package responsescript

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"

	starjson "go.starlark.net/lib/json"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
	"go.starlark.net/syntax"
)

type interpreter struct {
	link   channel
	thread *starlark.Thread
	code   Code
	calls  bool
}

type opaque struct {
	name string
	vm   *interpreter
}

func (v opaque) String() string {
	v.vm.reject(Credential)
	return "<凭据>"
}
func (v opaque) Type() string                 { return "credential" }
func (v opaque) Truth() starlark.Bool         { return true }
func (v opaque) Freeze()                      {}
func (v opaque) Hash() (uint32, error)        { return 0, v.vm.reject(Credential) }
func (v opaque) MarshalJSON() ([]byte, error) { return nil, v.vm.reject(Credential) }

func (v *interpreter) reject(code Code) error {
	if v.code == "" {
		v.code = code
	}
	v.thread.Cancel(string(code))
	return code
}

func (v *interpreter) run(p program) (json.RawMessage, Code) {
	v.thread = &starlark.Thread{
		Name:       "response-plugin",
		Load:       func(*starlark.Thread, string) (starlark.StringDict, error) { return nil, v.reject(Scope) },
		Print:      func(*starlark.Thread, string) { v.reject(ScriptError) },
		OnMaxSteps: func(*starlark.Thread) { v.reject(Steps) },
	}
	v.thread.SetMaxExecutionSteps(maxSteps)
	if !entryKnown(p.Entry) || len(p.Source) > maxSource || len(p.Args) > 4 {
		return nil, Input
	}
	globals, err := starlark.ExecFileOptions(&syntax.FileOptions{}, v.thread, "plugin.star", p.Source, v.functions(p.Now))
	if err != nil {
		return nil, v.codeOr(ScriptError)
	}
	entry, ok := globals[p.Entry].(*starlark.Function)
	if !ok {
		return nil, ScriptError
	}
	input := make(starlark.Tuple, 1, len(p.Args)+1)
	input[0] = starlarkstruct.FromStringDict(starlark.String("context"), starlark.StringDict{
		"base_url": starlark.String(p.Origin), "task_id": starlark.String(p.TaskID),
		"owner_sha256": starlark.String(p.OwnerSHA256), "expires_at": starlark.String(p.ExpiresAt),
		"duration_seconds": starlark.MakeInt(p.DurationSeconds),
	})
	for _, arg := range p.Args {
		data, err := v.value(wireValue{JSON: arg})
		if err != nil {
			return nil, v.codeOr(Input)
		}
		input = append(input, data)
	}
	v.calls = true
	result, err := starlark.Call(v.thread, entry, input, nil)
	if err != nil || v.code != "" {
		return nil, v.codeOr(ScriptError)
	}
	output, err := v.encode(result)
	if err != nil {
		return nil, v.codeOr(ScriptError)
	}
	return output, OK
}

func (v *interpreter) codeOr(fallback Code) Code {
	if v.code != "" {
		return v.code
	}
	return fallback
}

func (v *interpreter) exchange(request frame) (frame, error) {
	if !v.calls {
		return frame{}, v.reject(Scope)
	}
	if err := v.link.send(request); err != nil {
		return frame{}, v.reject(ScriptError)
	}
	reply, err := v.link.receive()
	if err != nil || reply.Code != OK {
		return frame{}, v.reject(ScriptError)
	}
	return reply, nil
}

func (v *interpreter) encode(value starlark.Value) (json.RawMessage, error) {
	result, err := starlark.Call(v.thread, starjson.Module.Members["encode"], starlark.Tuple{value}, nil)
	if err != nil {
		return nil, err
	}
	raw, _ := starlark.AsString(result)
	if len(raw) > maxData {
		return nil, v.reject(Size)
	}
	return json.RawMessage(raw), nil
}

func (v *interpreter) value(value wireValue) (starlark.Value, error) {
	if value.Ref != "" {
		return opaque{value.Ref, v}, nil
	}
	if len(value.JSON) == 0 {
		return starlark.None, nil
	}
	if len(value.JSON) > maxData {
		return nil, v.reject(Size)
	}
	return starlark.Call(v.thread, starjson.Module.Members["decode"], starlark.Tuple{starlark.String(value.JSON)}, nil)
}

func (v *interpreter) wire(value starlark.Value) (wireValue, error) {
	if ref, ok := value.(opaque); ok {
		return wireValue{Ref: ref.name}, nil
	}
	raw, err := v.encode(value)
	return wireValue{JSON: raw}, err
}

type builtin func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error)

func module(name string, methods map[string]builtin) *starlarkstruct.Module {
	values := make(starlark.StringDict, len(methods))
	for name, fn := range methods {
		values[name] = starlark.NewBuiltin(name, fn)
	}
	return &starlarkstruct.Module{Name: name, Members: values}
}

func (v *interpreter) functions(now string) starlark.StringDict {
	fail := v.log("error")
	return starlark.StringDict{
		"http": module("http", map[string]builtin{
			"get": v.http("GET"), "post": v.http("POST"), "put": v.http("PUT"), "delete": v.http("DELETE"),
		}),
		"secret": module("secret", map[string]builtin{"get": v.named("secret")}),
		"state":  module("state", map[string]builtin{"get": v.named("get"), "set": v.set}),
		"json":   module("json", map[string]builtin{"encode": v.jsonEncode, "decode": v.jsonDecode}),
		"base64": module("base64", map[string]builtin{"encode": v.bytes("encode"), "decode": v.bytes("decode")}),
		"hash":   module("hash", map[string]builtin{"sha256": v.bytes("sha256"), "hmac_sha256": v.hmac}),
		"time": module("time", map[string]builtin{"now": func(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kw []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs(fn.Name(), args, kw); err != nil {
				return nil, err
			}
			return starlark.String(now), nil
		}}),
		"log":  module("log", map[string]builtin{"info": v.log("info"), "warn": v.log("warn"), "fail": fail}),
		"fail": starlark.NewBuiltin("fail", fail),
	}
}

func (v *interpreter) named(kind string) builtin {
	return func(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kw []starlark.Tuple) (starlark.Value, error) {
		var name string
		if err := starlark.UnpackArgs(fn.Name(), args, kw, "name", &name); err != nil {
			return nil, err
		}
		reply, err := v.exchange(frame{Kind: kind, Name: name})
		if err != nil {
			return nil, err
		}
		return v.value(reply.Value)
	}
}

func (v *interpreter) set(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kw []starlark.Tuple) (starlark.Value, error) {
	var name string
	var data starlark.Value
	ttl := 3600
	if err := starlark.UnpackArgs(fn.Name(), args, kw, "name", &name, "value", &data, "ttl?", &ttl); err != nil {
		return nil, err
	}
	value, err := v.wire(data)
	if err != nil {
		return nil, err
	}
	_, err = v.exchange(frame{Kind: "set", Name: name, TTL: ttl, Value: value})
	return starlark.None, err
}

func (v *interpreter) log(level string) builtin {
	return func(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kw []starlark.Tuple) (starlark.Value, error) {
		var message starlark.Value
		if err := starlark.UnpackArgs(fn.Name(), args, kw, "message", &message); err != nil {
			return nil, err
		}
		if _, ok := message.(opaque); ok {
			return nil, v.reject(Credential)
		}
		text, ok := starlark.AsString(message)
		if !ok {
			return nil, v.reject(Input)
		}
		if _, err := v.exchange(frame{Kind: "log", Level: level, Text: text}); err != nil {
			return nil, err
		}
		if level == "error" {
			return nil, v.reject(ScriptError)
		}
		return starlark.None, nil
	}
}

func (v *interpreter) jsonEncode(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kw []starlark.Tuple) (starlark.Value, error) {
	var data starlark.Value
	if err := starlark.UnpackArgs(fn.Name(), args, kw, "value", &data); err != nil {
		return nil, err
	}
	raw, err := v.encode(data)
	return starlark.String(raw), err
}

func (v *interpreter) jsonDecode(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kw []starlark.Tuple) (starlark.Value, error) {
	var data starlark.Value
	if err := starlark.UnpackArgs(fn.Name(), args, kw, "value", &data); err != nil {
		return nil, err
	}
	text, err := v.data(data)
	if err != nil {
		return nil, err
	}
	return v.value(wireValue{JSON: json.RawMessage(text)})
}

func (v *interpreter) data(value starlark.Value) (string, error) {
	var data string
	switch typed := value.(type) {
	case opaque:
		return "", v.reject(Credential)
	case starlark.String:
		data = string(typed)
	case starlark.Bytes:
		data = string(typed)
	default:
		return "", v.reject(Input)
	}
	if len(data) > maxData {
		return "", v.reject(Size)
	}
	return data, nil
}

func (v *interpreter) bytes(kind string) builtin {
	return func(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kw []starlark.Tuple) (starlark.Value, error) {
		var value starlark.Value
		if err := starlark.UnpackArgs(fn.Name(), args, kw, "value", &value); err != nil {
			return nil, err
		}
		data, err := v.data(value)
		if err != nil {
			return nil, err
		}
		switch kind {
		case "encode":
			return starlark.String(base64.StdEncoding.EncodeToString([]byte(data))), nil
		case "decode":
			decoded, err := base64.StdEncoding.Strict().DecodeString(data)
			if err != nil {
				return nil, v.reject(Input)
			}
			return starlark.Bytes(decoded), nil
		default:
			digest := sha256.Sum256([]byte(data))
			return starlark.String(hex.EncodeToString(digest[:])), nil
		}
	}
}

func (v *interpreter) hmac(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kw []starlark.Tuple) (starlark.Value, error) {
	var key, value starlark.Value
	if err := starlark.UnpackArgs(fn.Name(), args, kw, "key", &key, "value", &value); err != nil {
		return nil, err
	}
	ref, ok := key.(opaque)
	if !ok {
		return nil, v.reject(Credential)
	}
	data, err := v.data(value)
	if err != nil {
		return nil, err
	}
	reply, err := v.exchange(frame{Kind: "hmac", Value: wireValue{Ref: ref.name}, Bytes: []byte(data)})
	return starlark.String(reply.Text), err
}

func (v *interpreter) http(method string) builtin {
	return func(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kw []starlark.Tuple) (starlark.Value, error) {
		var address string
		var params, headers *starlark.Dict
		var body starlark.Value
		if err := starlark.UnpackArgs(fn.Name(), args, kw, "url", &address, "params?", &params, "headers?", &headers, "json?", &body); err != nil {
			return nil, err
		}
		if len(address) > 1024 {
			return nil, v.reject(Scope)
		}
		request := frame{Kind: "http", Method: method, URL: address}
		if params != nil {
			request.Query = make(map[string]string, params.Len())
			for _, item := range params.Items() {
				key, ok := starlark.AsString(item[0])
				if !ok || !identifier(key) {
					return nil, v.reject(Scope)
				}
				switch item[1].(type) {
				case starlark.String, starlark.Int, starlark.Bool:
					text, err := v.data(starlark.String(queryValue(item[1])))
					if err != nil {
						return nil, err
					}
					request.Query[key] = text
				case opaque:
					return nil, v.reject(Credential)
				default:
					return nil, v.reject(Input)
				}
			}
		}
		if headers != nil {
			var err error
			request.Headers, err = v.fields(headers)
			if err != nil {
				return nil, err
			}
		}
		if body != nil {
			var err error
			request.Value, request.Fields, err = v.httpBody(body)
			if err != nil {
				return nil, err
			}
		}
		reply, err := v.exchange(request)
		if err != nil {
			return nil, err
		}
		return v.httpResult(reply)
	}
}

func queryValue(value starlark.Value) string {
	if text, ok := starlark.AsString(value); ok {
		return text
	}
	return strings.ToLower(value.String())
}

func (v *interpreter) fields(dict *starlark.Dict) (map[string]wireValue, error) {
	if dict.Len() > 8 {
		return nil, v.reject(Size)
	}
	fields := make(map[string]wireValue, dict.Len())
	for _, item := range dict.Items() {
		key, ok := starlark.AsString(item[0])
		if !ok || !identifier(key) {
			return nil, v.reject(Input)
		}
		value, err := v.wire(item[1])
		if err != nil {
			return nil, err
		}
		fields[key] = value
	}
	return fields, nil
}

func (v *interpreter) httpBody(body starlark.Value) (wireValue, map[string]wireValue, error) {
	if dict, ok := body.(*starlark.Dict); ok {
		for _, item := range dict.Items() {
			if _, hasRef := item[1].(opaque); hasRef {
				fields, err := v.fields(dict)
				return wireValue{}, fields, err
			}
		}
	}
	value, err := v.wire(body)
	if value.Ref != "" {
		err = v.reject(Credential)
	}
	return value, nil, err
}

func (v *interpreter) httpResult(reply frame) (starlark.Value, error) {
	fields := starlark.NewDict(len(reply.Fields))
	for key, value := range reply.Fields {
		item, err := v.value(value)
		if err != nil {
			return nil, err
		}
		if err := fields.SetKey(starlark.String(key), item); err != nil {
			return nil, err
		}
	}
	return starlarkstruct.FromStringDict(starlark.String("response"), starlark.StringDict{
		"status": starlark.MakeInt(reply.Status),
		"json": starlark.NewBuiltin("json", func(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kw []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs(fn.Name(), args, kw); err != nil {
				return nil, err
			}
			return fields, nil
		}),
	}), nil
}
