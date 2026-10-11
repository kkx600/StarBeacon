//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/store"
)

func TestRuntimeRoleRejectsOwnershipPrivilegeChainsAndConcealedIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	fixture := newIsolatedDatabase(t, ctx)
	ownerConfig, err := pgx.ParseConfig(fixture.OwnerDSN)
	require(t, err)
	rolePassword := store.Token()
	createRole := func(attributes string) string {
		t.Helper()
		role := store.RandomID("it_role_")
		var ddl string
		require(t, fixture.Owner.Pool.QueryRow(ctx, "SELECT format('CREATE ROLE %I LOGIN %s PASSWORD %L',$1::text,$2::text,$3::text)", role, attributes, rolePassword).Scan(&ddl))
		_, err := fixture.Owner.Pool.Exec(ctx, ddl)
		require(t, err)
		fixture.roles = append(fixture.roles, role)
		return role
	}
	roleStore := func(t *testing.T, role, command string) *store.Postgres {
		t.Helper()
		var callback func(context.Context, *pgx.Conn) error
		if command != "" {
			callback = func(ctx context.Context, conn *pgx.Conn) error {
				_, err := conn.Exec(ctx, command)
				return err
			}
		}
		return oneConnectionStore(t, ctx, testDatabaseURL(t, fixture.OwnerDSN, "", role, rolePassword), callback)
	}
	exec := func(sql string) {
		t.Helper()
		_, err := fixture.Owner.Pool.Exec(ctx, sql)
		require(t, err)
	}
	assertDenied := func(t *testing.T, p *store.Postgres) {
		t.Helper()
		if err := p.VerifyRuntimeRole(ctx); err == nil || !strings.Contains(err.Error(), "运行账号不能") {
			t.Fatalf("特权运行账号未被拒绝或权限检查发生 SQL 错误：%v", err)
		}
	}
	safe := createRole("NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION")
	t.Run("ordinary_runtime", func(t *testing.T) {
		require(t, roleStore(t, safe, "").VerifyRuntimeRole(ctx))
		require(t, fixture.Runtime.VerifyRuntimeRole(ctx))
	})
	t.Run("replay_table_owner", func(t *testing.T) {
		exec("ALTER TABLE replay_samples OWNER TO " + pgx.Identifier{safe}.Sanitize())
		defer exec("ALTER TABLE replay_samples OWNER TO " + pgx.Identifier{ownerConfig.User}.Sanitize())
		assertDenied(t, roleStore(t, safe, ""))
	})
	t.Run("future_business_table_owner", func(t *testing.T) {
		exec("CREATE TABLE public.it_future_business(id integer)")
		defer exec("DROP TABLE public.it_future_business")
		exec("ALTER TABLE public.it_future_business OWNER TO " + pgx.Identifier{safe}.Sanitize())
		assertDenied(t, roleStore(t, safe, ""))
	})
	group := createRole("NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION")
	actor := createRole("NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION")
	exec("CREATE TABLE public.it_membership_business(id integer)")
	exec("ALTER TABLE public.it_membership_business OWNER TO " + pgx.Identifier{group}.Sanitize())
	for _, test := range []struct {
		name, options string
		denied        bool
	}{
		{"inherited_owner", "INHERIT TRUE, SET FALSE", true},
		{"switchable_owner", "INHERIT FALSE, SET TRUE", true},
		{"inert_membership", "INHERIT FALSE, SET FALSE", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			exec("GRANT " + pgx.Identifier{group}.Sanitize() + " TO " + pgx.Identifier{actor}.Sanitize() + " WITH " + test.options)
			defer exec("REVOKE " + pgx.Identifier{group}.Sanitize() + " FROM " + pgx.Identifier{actor}.Sanitize())
			p := roleStore(t, actor, "")
			if test.denied {
				assertDenied(t, p)
			} else {
				require(t, p.VerifyRuntimeRole(ctx))
			}
		})
	}
	t.Run("inherited_owner_hidden_by_set_role", func(t *testing.T) {
		exec("GRANT " + pgx.Identifier{group}.Sanitize() + " TO " + pgx.Identifier{actor}.Sanitize() + " WITH INHERIT TRUE, SET FALSE")
		exec("GRANT " + pgx.Identifier{safe}.Sanitize() + " TO " + pgx.Identifier{actor}.Sanitize() + " WITH INHERIT FALSE, SET TRUE")
		defer exec("REVOKE " + pgx.Identifier{group}.Sanitize() + "," + pgx.Identifier{safe}.Sanitize() + " FROM " + pgx.Identifier{actor}.Sanitize())
		assertDenied(t, roleStore(t, actor, "SET ROLE "+pgx.Identifier{safe}.Sanitize()))
	})
	for _, attribute := range []string{"BYPASSRLS", "CREATEROLE", "CREATEDB", "REPLICATION"} {
		privileged := createRole("NOSUPERUSER " + attribute)
		t.Run("direct_"+strings.ToLower(attribute), func(t *testing.T) {
			assertDenied(t, roleStore(t, privileged, ""))
		})
		t.Run("switchable_"+strings.ToLower(attribute), func(t *testing.T) {
			exec("GRANT " + pgx.Identifier{privileged}.Sanitize() + " TO " + pgx.Identifier{safe}.Sanitize() + " WITH INHERIT FALSE, SET TRUE")
			defer exec("REVOKE " + pgx.Identifier{privileged}.Sanitize() + " FROM " + pgx.Identifier{safe}.Sanitize())
			assertDenied(t, roleStore(t, safe, ""))
		})
		t.Run("hidden_"+strings.ToLower(attribute), func(t *testing.T) {
			exec("GRANT " + pgx.Identifier{safe}.Sanitize() + " TO " + pgx.Identifier{privileged}.Sanitize() + " WITH INHERIT FALSE, SET TRUE")
			defer exec("REVOKE " + pgx.Identifier{safe}.Sanitize() + " FROM " + pgx.Identifier{privileged}.Sanitize())
			assertDenied(t, roleStore(t, privileged, "SET ROLE "+pgx.Identifier{safe}.Sanitize()))
		})
	}
	t.Run("superuser_hidden_by_session_authorization", func(t *testing.T) {
		p := oneConnectionStore(t, ctx, fixture.OwnerDSN, func(ctx context.Context, conn *pgx.Conn) error {
			_, err := conn.Exec(ctx, "SET SESSION AUTHORIZATION "+pgx.Identifier{safe}.Sanitize())
			return err
		})
		assertDenied(t, p)
	})
}
