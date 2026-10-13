package admin

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/store"
	"golang.org/x/crypto/bcrypt"
)

func Bootstrap(ctx context.Context, p *store.Postgres, tenant, name, username, password, role string) error {
	if !contract.ValidID(tenant) || len(username) < 3 || len(username) > 64 || len(password) < 12 || len(password) > 72 || (role != "admin" && role != "viewer") {
		return fmt.Errorf("租户、账号或密码格式不合法")
	}
	hash, e := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if e != nil {
		return e
	}
	return p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, "INSERT INTO tenants(id,name) VALUES($1,$2) ON CONFLICT(id) DO NOTHING", tenant, name); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, "INSERT INTO users(id,tenant_id,username,password_hash,role) VALUES($1,$2,$3,$4,$5)", store.RandomID("user_"), tenant, username, string(hash), role); e != nil {
			return e
		}
		for _, category := range []string{"alerts", "pcap", "network", "operations", "logins", "notifications", "reports", "files", "asset_history", "models", "incidents"} {
			if _, e := tx.Exec(ctx, "INSERT INTO retention_policies(tenant_id,category,days) VALUES($1,$2,180) ON CONFLICT DO NOTHING", tenant, category); e != nil {
				return e
			}
		}
		return nil
	})
}
func BootstrapIfMissing(ctx context.Context, p *store.Postgres, tenant, name, username, password, role string) error {
	u, hash, e := p.Password(ctx, username)
	if e == nil {
		if u.TenantID != tenant || u.Role != role || bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
			return fmt.Errorf("账号已经存在且配置不匹配；不会重置密码")
		}
		return nil
	}
	if !errors.Is(e, model.ErrUnauthenticated) {
		return e
	}
	return Bootstrap(ctx, p, tenant, name, username, password, role)
}
func CreateRuntimeRole(ctx context.Context, p *store.Postgres, password string) error {
	if len(password) < 24 {
		return fmt.Errorf("运行账号密码长度不足")
	}
	tx, e := p.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var exists bool
	if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='starbeacon_app')").Scan(&exists); e != nil {
		return e
	}
	if !exists {
		// 由 PostgreSQL format 的 %L 转义密码，避免将输入拼入角色 DDL。
		var ddl string
		if e = tx.QueryRow(ctx, "SELECT format('CREATE ROLE starbeacon_app LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD %L', $1::text)", password).Scan(&ddl); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, ddl); e != nil {
			return e
		}
	}
	var database string
	if e = tx.QueryRow(ctx, "SELECT current_database()").Scan(&database); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "GRANT CONNECT ON DATABASE "+pgx.Identifier{database}.Sanitize()+" TO starbeacon_app"); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `GRANT USAGE ON SCHEMA public TO starbeacon_app;
		GRANT SELECT ON tenants,users,retention_policies TO starbeacon_app;
		GRANT SELECT,INSERT,DELETE ON sessions TO starbeacon_app;
		GRANT SELECT,UPDATE ON sensors TO starbeacon_app;
		GRANT SELECT,INSERT,UPDATE ON routes TO starbeacon_app;
		GRANT SELECT,INSERT ON operation_audits TO starbeacon_app;
		GRANT SELECT,INSERT ON login_audits TO starbeacon_app;
		GRANT USAGE ON SEQUENCE operation_audits_id_seq,login_audits_id_seq TO starbeacon_app`); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `GRANT SELECT,INSERT,UPDATE ON sensor_tasks TO starbeacon_app; GRANT SELECT,INSERT ON rule_packages TO starbeacon_app; GRANT SELECT,INSERT,UPDATE,DELETE ON replay_samples TO starbeacon_app`); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `GRANT SELECT,INSERT,UPDATE ON sensor_groups TO starbeacon_app; GRANT SELECT,INSERT,DELETE ON sensor_management_requests TO starbeacon_app`); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `GRANT SELECT,INSERT,UPDATE,DELETE ON saved_searches TO starbeacon_app; GRANT SELECT,INSERT,DELETE ON saved_search_changes TO starbeacon_app`); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `GRANT SELECT,INSERT,UPDATE ON application_rules TO starbeacon_app; GRANT SELECT,INSERT,DELETE ON application_rule_revisions TO starbeacon_app`); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `GRANT SELECT,INSERT,UPDATE ON decision_policies TO starbeacon_app; GRANT SELECT,INSERT,DELETE ON decision_policy_revisions TO starbeacon_app`); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `GRANT SELECT,INSERT,DELETE ON decision_evaluations TO starbeacon_app`); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `GRANT SELECT,INSERT,DELETE ON decision_responses TO starbeacon_app`); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `GRANT SELECT,INSERT,DELETE ON decision_continuous_runs TO starbeacon_app`); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `GRANT SELECT,INSERT,UPDATE,DELETE ON decision_triage_triggers TO starbeacon_app`); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `GRANT SELECT,INSERT,UPDATE ON inventory_objects TO starbeacon_app; GRANT SELECT,INSERT ON inventory_history TO starbeacon_app`); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `GRANT SELECT,INSERT,UPDATE ON notification_channels TO starbeacon_app; GRANT SELECT,INSERT ON notification_channel_versions,notification_batches TO starbeacon_app; GRANT SELECT,INSERT,UPDATE ON notification_deliveries TO starbeacon_app`); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `GRANT SELECT,INSERT,UPDATE ON model_providers,model_capability_checks TO starbeacon_app; GRANT SELECT,INSERT ON model_provider_versions TO starbeacon_app`); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `GRANT SELECT,INSERT,UPDATE ON analysis_threads,analysis_jobs TO starbeacon_app;
	 GRANT USAGE ON SCHEMA starbeacon_jobs TO starbeacon_app;
	 GRANT SELECT,INSERT,UPDATE,DELETE ON starbeacon_jobs.river_job,starbeacon_jobs.river_queue,starbeacon_jobs.river_leader TO starbeacon_app;
	 REVOKE INSERT,UPDATE,DELETE ON starbeacon_jobs.river_migration FROM starbeacon_app;
	 GRANT SELECT ON starbeacon_jobs.river_migration TO starbeacon_app;
	 GRANT USAGE,SELECT ON SEQUENCE starbeacon_jobs.river_job_id_seq TO starbeacon_app`); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `GRANT SELECT,INSERT,UPDATE ON report_plans,report_plan_runs TO starbeacon_app; GRANT DELETE ON report_plan_runs TO starbeacon_app; GRANT EXECUTE ON FUNCTION public.lock_report_plan_owner(text) TO starbeacon_app`); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `GRANT SELECT,INSERT,UPDATE,DELETE ON alert_assessments TO starbeacon_app; GRANT SELECT,INSERT,DELETE ON alert_assessment_changes TO starbeacon_app`); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `GRANT SELECT,INSERT,UPDATE,DELETE ON rule_generation_jobs,alert_triage_jobs TO starbeacon_app; GRANT SELECT,INSERT ON rule_sid_registry TO starbeacon_app; GRANT SELECT,INSERT,UPDATE ON rule_sid_state TO starbeacon_app`); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `GRANT SELECT,INSERT,UPDATE,DELETE ON packet_archives TO starbeacon_app; GRANT SELECT,INSERT,UPDATE ON packet_archive_capacity TO starbeacon_app; GRANT EXECUTE ON FUNCTION public.lock_packet_sensor(text,text) TO starbeacon_app`); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `GRANT SELECT,INSERT,UPDATE,DELETE ON incidents TO starbeacon_app; GRANT SELECT,INSERT,DELETE ON incident_changes TO starbeacon_app; GRANT SELECT,INSERT ON incident_alert_links TO starbeacon_app`); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `GRANT SELECT,INSERT,DELETE ON user_management_requests TO starbeacon_app; GRANT EXECUTE ON FUNCTION public.save_tenant_user(text,text,text,text,text,boolean,bigint,text,jsonb) TO starbeacon_app`); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `GRANT SELECT,INSERT,UPDATE ON password_attempts TO starbeacon_app; GRANT EXECUTE ON FUNCTION public.create_tenant_session(text,text,bigint,text,text),public.change_tenant_password(text,bigint,text,text,bigint,text,text,jsonb) TO starbeacon_app`); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `GRANT UPDATE ON retention_policies TO starbeacon_app; GRANT SELECT,INSERT,DELETE ON retention_previews TO starbeacon_app; GRANT SELECT,INSERT ON retention_changes TO starbeacon_app`); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `GRANT SELECT,INSERT,UPDATE,DELETE ON mcp_bindings TO starbeacon_app; GRANT SELECT,INSERT ON mcp_auth_routes TO starbeacon_app`); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `GRANT DELETE ON operation_audits,login_audits,sensor_tasks,inventory_history,retention_changes,notification_deliveries,notification_batches,notification_channel_versions,model_capability_checks,model_provider_versions,analysis_jobs,analysis_threads,routes TO starbeacon_app; GRANT SELECT,INSERT,UPDATE ON retention_maintenance TO starbeacon_app`); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
