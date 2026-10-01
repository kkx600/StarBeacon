package store

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/model"
)

type RulePackage struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Revision      int64     `json:"revision"`
	EngineVersion string    `json:"engine_version"`
	Text          string    `json:"text"`
	SHA256        string    `json:"sha256"`
	CreatedAt     time.Time `json:"created_at"`
}

func ValidateRules(text string) error {
	if len(text) == 0 || len(text) > 900*1024 || !utf8.ValidString(text) || strings.ContainsRune(text, 0) {
		return errors.New("规则文本必须是有效 UTF-8，最大 900 KiB")
	}
	count := 0
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "alert ") && !strings.HasPrefix(line, "alert\t") {
			return errors.New("旁路规则包只接受单行 alert 规则，其他动作需独立授权")
		}
		if forbiddenRuleOptions.MatchString(line) {
			return errors.New("规则包含需要独立能力授权的关键词")
		}
		count++
	}
	if count == 0 {
		return errors.New("规则包没有检测规则")
	}
	return nil
}

var forbiddenRuleOptions = regexp.MustCompile(`(?i)\b(?:lua|luajit|dataset|bypass|filestore)\s*[:;]`)

func (p *Postgres) SaveRulePackage(ctx context.Context, u model.Principal, id, name, text string, expected int64, requestID string) (RulePackage, error) {
	v := RulePackage{ID: id, Name: name, Text: text, EngineVersion: "8.0.7", SHA256: control.Digest([]byte(text))}
	e := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/rules/"+id); e != nil {
			return e
		}
		var latest int64
		if e := tx.QueryRow(ctx, `SELECT COALESCE(max(revision),0) FROM rule_packages WHERE tenant_id=$1 AND id=$2`, u.TenantID, id).Scan(&latest); e != nil {
			return e
		}
		if latest != expected {
			return ErrConflict
		}
		v.Revision = latest + 1
		if e := tx.QueryRow(ctx, `INSERT INTO rule_packages(tenant_id,id,name,revision,engine_version,rules_text,sha256,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING created_at`, u.TenantID, id, name, v.Revision, v.EngineVersion, text, v.SHA256, u.ID).Scan(&v.CreatedAt); e != nil {
			return e
		}
		return insertOperationAudit(ctx, tx, u, "rule.package.save", id, requestID)
	})
	return v, e
}
func (p *Postgres) RulePackages(ctx context.Context, tenant string) ([]RulePackage, error) {
	out := []RulePackage{}
	e := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT DISTINCT ON(id) id,name,revision,engine_version,sha256,created_at FROM rule_packages WHERE tenant_id=$1 ORDER BY id,revision DESC LIMIT 200`, tenant)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var v RulePackage
			if e = rows.Scan(&v.ID, &v.Name, &v.Revision, &v.EngineVersion, &v.SHA256, &v.CreatedAt); e != nil {
				return e
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	return out, e
}
func (p *Postgres) RulePackage(ctx context.Context, tenant, id string, revision int64) (RulePackage, error) {
	var v RulePackage
	e := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id,name,revision,engine_version,rules_text,sha256,created_at FROM rule_packages WHERE tenant_id=$1 AND id=$2 AND revision=$3`, tenant, id, revision).Scan(&v.ID, &v.Name, &v.Revision, &v.EngineVersion, &v.Text, &v.SHA256, &v.CreatedAt)
	})
	return v, e
}
