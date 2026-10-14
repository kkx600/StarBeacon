// Package control 定义平台与采集器之间的受限任务，不接受任意系统命令。
package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/kkx600/StarBeacon/internal/application"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/response"
)

const Schema = "sensor.command.v1"
const ReceiptSchema = "sensor.receipt.v1"
const MaxPayload = 1024 * 1024

var ErrExpired = errors.New("任务过期或时间不可信")

type Command struct {
	ID             string          `json:"id"`
	TenantID       string          `json:"tenant_id"`
	SensorID       string          `json:"sensor_id"`
	RegistrationID string          `json:"registration_id"`
	Kind           string          `json:"kind"`
	IssuedAt       time.Time       `json:"issued_at"`
	ExpiresAt      time.Time       `json:"expires_at"`
	Payload        json.RawMessage `json:"payload"`
}

type Receipt struct {
	CommandID     string          `json:"command_id"`
	CommandSHA256 string          `json:"command_sha256"`
	State         string          `json:"state"`
	Code          string          `json:"code,omitempty"`
	Result        json.RawMessage `json:"result"`
	StartedAt     time.Time       `json:"started_at"`
	FinishedAt    *time.Time      `json:"finished_at,omitempty"`
}

type RulePackage struct {
	PackageID     string             `json:"package_id"`
	Revision      int64              `json:"revision"`
	EngineVersion string             `json:"engine_version"`
	Text          string             `json:"text"`
	SHA256        string             `json:"sha256"`
	Authorization *RuleAuthorization `json:"authorization,omitempty"`
}

// 发布授权绑定不可变回执、检测配置和写入前的规则状态；装载检查本身不能授权部署。
type RuleAuthorization struct {
	ValidationTaskID        string `json:"validation_task_id"`
	PositiveReplayTaskID    string `json:"positive_replay_task_id"`
	NegativeReplayTaskID    string `json:"negative_replay_task_id"`
	ExpectedRulesSHA256     string `json:"expected_rules_sha256"`
	ConfigSHA256            string `json:"config_sha256"`
	ProfileSHA256           string `json:"profile_sha256"`
	ValidationReceiptSHA256 string `json:"validation_receipt_sha256"`
	PositiveReceiptSHA256   string `json:"positive_receipt_sha256"`
	NegativeReceiptSHA256   string `json:"negative_receipt_sha256"`
}

func (a *RuleAuthorization) Validate() error {
	if a == nil || !contract.ValidID(a.ValidationTaskID) || !contract.ValidID(a.PositiveReplayTaskID) || !contract.ValidID(a.NegativeReplayTaskID) || a.ValidationTaskID == a.PositiveReplayTaskID || a.ValidationTaskID == a.NegativeReplayTaskID || a.PositiveReplayTaskID == a.NegativeReplayTaskID {
		return errors.New("规则发布缺少独立装载检查、命中与未命中回执")
	}
	for _, value := range []string{a.ExpectedRulesSHA256, a.ConfigSHA256, a.ProfileSHA256, a.ValidationReceiptSHA256, a.PositiveReceiptSHA256, a.NegativeReceiptSHA256} {
		raw, err := hex.DecodeString(value)
		if err != nil || len(raw) != sha256.Size || hex.EncodeToString(raw) != value {
			return errors.New("规则发布证据或配置摘要无效")
		}
	}
	return nil
}

type Replay struct {
	SampleID     string                 `json:"sample_id"`
	SampleSHA256 string                 `json:"sample_sha256"`
	SampleSize   int64                  `json:"sample_size"`
	RuleMode     string                 `json:"rule_mode"`
	Package      *RulePackage           `json:"package,omitempty"`
	Origin       *contract.SampleOrigin `json:"origin,omitempty"`
}

// 核实任务只允许重新装载中断事务的当前文件，不允许下发新规则或任意路径。
type RuleReconcile struct {
	UnknownTaskID        string `json:"unknown_task_id"`
	UnknownCommandSHA256 string `json:"unknown_command_sha256"`
	ExpectedSHA256       string `json:"expected_sha256"`
	TargetSHA256         string `json:"target_sha256"`
	PreviousSHA256       string `json:"previous_sha256"`
	ConfigSHA256         string `json:"config_sha256"`
	ProfileSHA256        string `json:"profile_sha256"`
}

func (p RuleReconcile) Validate() error {
	if !contract.ValidID(p.UnknownTaskID) {
		return errors.New("待核实任务身份无效")
	}
	for _, value := range []string{p.UnknownCommandSHA256, p.ExpectedSHA256, p.TargetSHA256, p.PreviousSHA256, p.ConfigSHA256, p.ProfileSHA256} {
		raw, err := hex.DecodeString(value)
		if err != nil || len(raw) != sha256.Size || hex.EncodeToString(raw) != value {
			return errors.New("规则核实摘要无效")
		}
	}
	if p.ExpectedSHA256 != p.TargetSHA256 && p.ExpectedSHA256 != p.PreviousSHA256 {
		return errors.New("当前文件不属于待核实规则事务")
	}
	return nil
}

type RuleReconcileResult struct {
	Verified             bool            `json:"verified"`
	UnknownTaskID        string          `json:"unknown_task_id"`
	UnknownCommandSHA256 string          `json:"unknown_command_sha256"`
	ActiveSHA256         string          `json:"active_sha256"`
	ConfigSHA256         string          `json:"config_sha256"`
	ProfileSHA256        string          `json:"profile_sha256"`
	Stats                json.RawMessage `json:"ruleset_stats"`
}

func (r RuleReconcileResult) Validate(p RuleReconcile) error {
	if p.Validate() != nil || !r.Verified || r.UnknownTaskID != p.UnknownTaskID || r.UnknownCommandSHA256 != p.UnknownCommandSHA256 || r.ActiveSHA256 != p.ExpectedSHA256 || r.ConfigSHA256 != p.ConfigSHA256 || r.ProfileSHA256 != p.ProfileSHA256 {
		return errors.New("规则核实回执与原事务不一致")
	}
	var stats []struct {
		Loaded *int `json:"rules_loaded"`
		Failed *int `json:"rules_failed"`
	}
	if json.Unmarshal(r.Stats, &stats) != nil || len(stats) != 1 || stats[0].Loaded == nil || stats[0].Failed == nil || *stats[0].Loaded < 1 || *stats[0].Failed != 0 {
		return errors.New("规则核实缺少完整原生装载回读")
	}
	return nil
}

func ReplayPayload(p Replay) (json.RawMessage, error) {
	raw, e := encodeJSON(p)
	if e != nil {
		return nil, e
	}
	if len(raw) > MaxPayload {
		return nil, errors.New("重放参数超过设备任务上限")
	}
	return raw, nil
}

func Digest(raw []byte) string    { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func HashBytes(raw []byte) []byte { h := sha256.Sum256(raw); return h[:] }
func SignedBytes(raw []byte) []byte {
	return append([]byte("StarBeacon/sensor.command.v1\x00"), raw...)
}
func Encode(c Command, key ed25519.PrivateKey) ([]byte, []byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, nil, errors.New("任务签名密钥未配置")
	}
	if e := Validate(c); e != nil {
		return nil, nil, e
	}
	raw, e := encodeJSON(c)
	if e != nil {
		return nil, nil, e
	}
	return raw, ed25519.Sign(key, SignedBytes(raw)), nil
}

func encodeJSON(v any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if e := encoder.Encode(v); e != nil {
		return nil, e
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'}), nil
}
func RulePayload(p RulePackage) (json.RawMessage, error) {
	raw, e := encodeJSON(p)
	if e != nil {
		return nil, e
	}
	if len(raw) > MaxPayload {
		return nil, errors.New("规则包编码超过 1 MiB 设备任务上限，请拆分规则包")
	}
	return raw, nil
}
func Decode(raw, signature []byte, key ed25519.PublicKey, tenant, sensor, registration string, now time.Time) (Command, error) {
	var c Command
	if len(raw) > MaxPayload+8192 || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, SignedBytes(raw), signature) {
		return c, errors.New("任务签名无效")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(&c); e != nil {
		return c, e
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return c, errors.New("任务包含多余内容")
	}
	if e := Validate(c); e != nil {
		return c, e
	}
	if c.TenantID != tenant || c.SensorID != sensor || c.RegistrationID != registration {
		return c, errors.New("任务不属于当前设备身份")
	}
	if c.IssuedAt.After(now.Add(time.Minute)) || !c.ExpiresAt.After(now) {
		return c, ErrExpired
	}
	return c, nil
}
func Validate(c Command) error {
	for _, id := range []string{c.ID, c.TenantID, c.SensorID, c.RegistrationID} {
		if !contract.ValidID(id) {
			return errors.New("任务身份无效")
		}
	}
	if c.IssuedAt.IsZero() || !c.ExpiresAt.After(c.IssuedAt) || c.ExpiresAt.Sub(c.IssuedAt) > 24*time.Hour {
		return errors.New("任务期限无效")
	}
	if len(c.Payload) == 0 || len(c.Payload) > MaxPayload || !json.Valid(c.Payload) {
		return errors.New("任务参数无效")
	}
	switch c.Kind {
	case "applications.apply":
		p, err := application.ReadPackage(c.Payload)
		if err == nil && p.ExpectedRegistrationID != c.RegistrationID {
			return application.ErrInput
		}
		return err
	case "response.block", "response.read", "response.revoke":
		a, err := response.ReadAction(c.Payload)
		if err != nil || a.OwnerSHA256 != response.Owner(c.TenantID, c.SensorID, c.RegistrationID, a.LeaseID) || c.Kind == "response.block" && a.LeaseID != c.ID {
			return response.ErrInput
		}
		if c.Kind == "response.block" && (!a.RequestedAt.Equal(c.IssuedAt) || !c.ExpiresAt.Before(a.ExpiresAt)) {
			return response.ErrInput
		}
		return nil
	case "capture.configure":
		_, err := ReadCaptureConfiguration(c.Payload)
		return err
	case "rules.reconcile":
		var p RuleReconcile
		d := json.NewDecoder(bytes.NewReader(c.Payload))
		d.DisallowUnknownFields()
		if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF {
			return errors.New("规则核实参数无效")
		}
		return p.Validate()
	case "rules.replay":
		var p Replay
		d := json.NewDecoder(bytes.NewReader(c.Payload))
		d.DisallowUnknownFields()
		if e := d.Decode(&p); e != nil {
			return e
		}
		sha, e := hex.DecodeString(p.SampleSHA256)
		if !contract.ValidID(p.SampleID) || e != nil || len(sha) != 32 || p.SampleSize < 24 || p.SampleSize > 100*1024*1024 || p.Origin != nil && !p.Origin.Valid() {
			return errors.New("重放样本身份、摘要或大小无效")
		}
		if p.RuleMode == "registered" && p.Package == nil {
			return nil
		}
		if p.RuleMode != "package" || p.Package == nil {
			return errors.New("重放规则来源无效")
		}
		payload, e := RulePayload(*p.Package)
		if e != nil {
			return e
		}
		copy := c
		copy.Kind = "rules.validate"
		copy.Payload = payload
		return Validate(copy)
	case "diagnostics":
		if string(bytes.TrimSpace(c.Payload)) != "{}" {
			return errors.New("诊断任务不接受额外参数")
		}
	case "rules.validate", "rules.apply":
		var p RulePackage
		d := json.NewDecoder(bytes.NewReader(c.Payload))
		d.DisallowUnknownFields()
		if e := d.Decode(&p); e != nil {
			return e
		}
		if !contract.ValidID(p.PackageID) || p.Revision < 1 || p.EngineVersion != "8.0.7" || len(p.Text) == 0 || len(p.Text) > 900*1024 || p.SHA256 != Digest([]byte(p.Text)) {
			return errors.New("规则包身份、版本或摘要无效")
		}
		if c.Kind == "rules.apply" {
			return p.Authorization.Validate()
		}
		if p.Authorization != nil {
			return errors.New("装载检查不接受发布授权")
		}
	default:
		return errors.New("设备不接受该任务类型")
	}
	return nil
}
func GenerateKeys(privatePath, publicPath string) error {
	if privatePath == publicPath {
		return errors.New("任务密钥输出路径必须不同")
	}
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	der, e := x509.MarshalPKCS8PrivateKey(priv)
	if e != nil {
		return e
	}
	pubDER, e := x509.MarshalPKIXPublicKey(pub)
	if e != nil {
		return e
	}
	created := []string{}
	complete := false
	defer func() {
		if !complete {
			for _, path := range created {
				_ = os.Remove(path)
			}
		}
	}()
	for _, v := range []struct {
		path, kind string
		data       []byte
	}{{privatePath, "PRIVATE KEY", der}, {publicPath, "PUBLIC KEY", pubDER}} {
		f, e := os.OpenFile(v.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		created = append(created, v.path)
		e = pem.Encode(f, &pem.Block{Type: v.kind, Bytes: v.data})
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
	}
	complete = true
	return nil
}
func PrivateKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, nil
	}
	info, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("任务签名私钥必须是仅所有者可访问的普通文件")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	b, _ := pem.Decode(raw)
	if b == nil {
		return nil, errors.New("任务签名私钥格式无效")
	}
	v, e := x509.ParsePKCS8PrivateKey(b.Bytes)
	if e != nil {
		return nil, e
	}
	k, ok := v.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("任务签名只接受 Ed25519")
	}
	return k, nil
}
func PublicKey(path string) (ed25519.PublicKey, error) {
	if path == "" {
		return nil, nil
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	b, _ := pem.Decode(raw)
	if b == nil {
		return nil, errors.New("任务签名公钥格式无效")
	}
	v, e := x509.ParsePKIXPublicKey(b.Bytes)
	if e != nil {
		return nil, e
	}
	k, ok := v.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("任务签名只接受 Ed25519")
	}
	return k, nil
}
func JSONDigest(raw []byte) (string, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if e := d.Decode(&v); e != nil {
		return "", e
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return "", errors.New("JSON 包含多余内容")
	}
	encoded, e := json.Marshal(v)
	if e != nil {
		return "", e
	}
	return Digest(encoded), nil
}
