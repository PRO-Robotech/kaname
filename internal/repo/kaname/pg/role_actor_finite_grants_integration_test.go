// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	bindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/multitracer"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// Только ephemeral LOGIN внутри изолированной protocol fixture. Ни обычный
// grant_runtime, ни SET ROLE поверх owner для этого соединения не используются.
func roleActorFiniteLogin(t *testing.T, r protocolRig) (*pgxpool.Pool, string, *roleMutationDiagnostic) {
	t.Helper()
	name := fmt.Sprintf("role_actor_%s", strings.ReplaceAll(ids.NewID("rol"), "-", "_"))
	quoted := pgx.Identifier{name}.Sanitize()
	password := ids.NewID("pwd")
	_, err := r.admin.Exec(r.ctx, "CREATE ROLE "+quoted+" LOGIN PASSWORD '"+strings.ReplaceAll(password, "'", "''")+"' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT")
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = r.admin.Exec(ctx, "DROP OWNED BY "+quoted)
		_, _ = r.admin.Exec(ctx, "DROP ROLE "+quoted)
	})
	_, err = r.admin.Exec(r.ctx, `SELECT kaname.authority_role_actor_login_configure_v1($1::regrole,$2::regrole)`, r.role, name)
	require.NoError(t, err)
	cfg := r.admin.Config()
	cfg.ConnConfig.User = name
	cfg.ConnConfig.Password = password
	cfg.AfterConnect = nil
	diagnostic := &roleMutationDiagnostic{}
	if cfg.ConnConfig.Tracer == nil {
		cfg.ConnConfig.Tracer = diagnostic
	} else {
		cfg.ConnConfig.Tracer = multitracer.New(cfg.ConnConfig.Tracer, diagnostic)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("role writer PostgreSQL diagnostics: %s", diagnostic.snapshot())
		}
	})
	pool, err := pgxpool.NewWithConfig(r.ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	var effective, session string
	require.NoError(t, pool.QueryRow(r.ctx, `SELECT current_user,session_user`).Scan(&effective, &session))
	require.Equal(t, name, effective)
	require.Equal(t, name, session)
	return pool, name, diagnostic
}

// Один штатный rig и реальные Create/Update use cases. Обычный runtime обслуживает
// очередь операций и внешние чтения; сам RoleMutationWriter использует новый pool.
func TestRoleActorLoginFiniteGrantsAndRoleRoutes(t *testing.T) {
	w := delegationUCFixture(t)
	existing := roleFinalCreate(t, w, nil, "finite_role_before")
	holder := roleFinalCarrier(t, w, existing, domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(w.member)})
	pool, name, diagnostic := roleActorFiniteLogin(t, w.r)
	shared, _ := fullContractActivate(t, w.r)
	repo := kanamepg.New(pool, nil)
	contract, err := kanamepg.NewFullWriterContract(w.r.ctx, repo, w.r.bundle)
	require.NoError(t, err)
	full, err := repo.WithFullWriterContract(contract)
	require.NoError(t, err)
	roleWriters, err := kanamepg.NewRolePolicyWriters(w.r.ctx, shared, full, w.r.bundle)
	require.NoError(t, err)
	writers := &finiteRoleWriterDiagnostic{RolePolicyWriters: roleWriters, diagnostic: diagnostic}

	separation := func(t *testing.T) {
		var ready bool
		require.NoError(t, pool.QueryRow(w.r.ctx, `SELECT kaname.authority_role_actor_login_ready_v1()`).Scan(&ready))
		require.True(t, ready)
		for _, sig := range []string{
			"authority_role_access_label_content_approved_v1()",
			"authority_role_actor_login_ready_v1()",
		} {
			var enrolled, ordinary bool
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT has_function_privilege($1,$3,'EXECUTE'),has_function_privilege($2,$3,'EXECUTE')`, name, w.r.role, "kaname."+sig).Scan(&enrolled, &ordinary))
			require.True(t, enrolled, sig)
			require.False(t, ordinary, sig)
		}
		for _, sig := range []string{
			"authority_role_actor_login_configure_v1(regrole,regrole)",
			"authority_role_actor_grant_v1(regrole)",
			"_authority_access_label_role_source_store_v1()",
			"authority_access_label_role_projection_apply_v1(jsonb,text,text)",
			"authority_role_access_label_source_check_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer)",
			"authority_binding_sequence_prepare_v3(text,jsonb)",
			"authority_group_add_prepare_v3(jsonb,integer,integer)",
			"authority_forward_prepare_v4(jsonb[])",
			"authority_native_delete_prepare_v4(jsonb[])",
		} {
			var allowed bool
			require.NoError(t, pool.QueryRow(w.r.ctx, `SELECT has_function_privilege(current_user,$1,'EXECUTE')`, "kaname."+sig).Scan(&allowed))
			require.False(t, allowed, sig)
		}
		for _, table := range []string{"authority_role_actor_login", "authority_role_access_label_rule", "authority_access_label_definition"} {
			_, err := pool.Exec(w.r.ctx, `SELECT * FROM kaname.`+pgx.Identifier{table}.Sanitize()+` LIMIT 0`)
			requireAccessDefinitionSQLState(t, err, "42501")
		}
		for _, q := range []string{
			`DELETE FROM kaname.roles WHERE false`,
			`UPDATE kaname.users SET email_verified_at=email_verified_at WHERE false`,
			`UPDATE kaname.service_accounts SET enabled=enabled WHERE false`,
			`UPDATE kaname.access_bindings SET role_id=role_id WHERE false`,
			`INSERT INTO kaname.groups(id,account_id,name) SELECT 'none',NULL,'none' WHERE false`,
		} {
			_, err := pool.Exec(w.r.ctx, q)
			requireAccessDefinitionSQLState(t, err, "42501")
		}
		_, err := w.r.runtime.Exec(w.r.ctx, `SELECT * FROM kaname.authority_role_actor_login LIMIT 0`)
		requireAccessDefinitionSQLState(t, err, "42501")
		// Без signed prepared writer producer закрыт даже для enrolled LOGIN.
		_, err = pool.Exec(w.r.ctx, `SELECT kaname.authority_role_access_label_content_approved_v1()`)
		requireAccessDefinitionSQLState(t, err, "42501")
		_, err = w.r.runtime.Exec(w.r.ctx, `SELECT kaname.authority_role_access_label_content_approved_v1()`)
		requireAccessDefinitionSQLState(t, err, "42501")
		// Membership отсутствует: обычный runtime не получает новый seat через SET ROLE.
		_, err = w.r.runtime.Exec(w.r.ctx, "SET ROLE "+pgx.Identifier{name}.Sanitize())
		requireAccessDefinitionSQLState(t, err, "42501")
	}
	t.Run("separation", separation)
	t.Run("create", func(t *testing.T) {
		created := roleFinalCreate(t, w, writers, "finite_role_created")
		require.NotEmpty(t, created.ID)
	})
	t.Run("update", func(t *testing.T) {
		uc := roleapp.NewUpdateRoleUseCase(w.r.repo, w.ops, w.source).
			WithRoleAuthorityWriter(writers).WithTupleReconciler(bindingapp.NewRoleTupleReconciler())
		op, err := uc.Execute(declarerCtx(w.r.ctx, w.owner), roleapp.UpdateRoleInput{
			ID: existing.ID, Rules: domain.Rules{{Module: "iam", Resources: []string{"role"}, Verbs: []string{"list", "update"}}},
			UpdateMask: []string{"rules"},
		})
		require.NoError(t, err)
		require.Nil(t, roleFinalAwaitOperation(t, w, op.ID).Error)
		var version int
		require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT grant_capability_version FROM kaname.access_bindings WHERE id=$1`, holder).Scan(&version))
		require.Equal(t, 1, version, "реальная promotion существующего carrier")
		var rules []byte
		require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT rules FROM kaname.roles WHERE id=$1`, existing.ID).Scan(&rules))
		require.Contains(t, string(rules), "update")
	})
	t.Run("regrant", func(t *testing.T) {
		// Перевыдача обычного runtime не должна получать новый approval seat.
		_, err := w.r.admin.Exec(w.r.ctx, `SELECT kaname.authority_protocol_grant_runtime($1::regrole)`, w.r.role)
		require.NoError(t, err)
		_, err = w.r.admin.Exec(w.r.ctx, `SELECT kaname.authority_role_actor_login_configure_v1($1::regrole,$2::regrole)`, w.r.role, name)
		require.NoError(t, err)
		_, err = w.r.admin.Exec(w.r.ctx, `SELECT kaname.authority_protocol_grant_runtime($1::regrole)`, name)
		requireAccessDefinitionSQLState(t, err, "42501")
		separation(t)
		roleFinalCreate(t, w, writers, "finite_role_regrant")
	})
	t.Run("unenroll", func(t *testing.T) {
		_, err := w.r.admin.Exec(w.r.ctx, `SELECT kaname.authority_role_actor_login_configure_v1(NULL,NULL)`)
		require.NoError(t, err)
		var allowed bool
		require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT has_table_privilege($1,'kaname.roles','INSERT,UPDATE') OR has_function_privilege($1,'kaname.authority_role_access_label_content_approved_v1()','EXECUTE')`, name).Scan(&allowed))
		require.False(t, allowed)
	})
}

// Диагностика сохраняет ошибку подготовки до её преобразования в RPC-статус.
// После подготовки use case получает исходный writer со всеми его портами.
type finiteRoleWriterDiagnostic struct {
	*kanamepg.RolePolicyWriters
	diagnostic *roleMutationDiagnostic
}

func (d *finiteRoleWriterDiagnostic) RoleMutationWriter(ctx context.Context, request kaname.RoleMutationRequest, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	writer, err := d.RolePolicyWriters.RoleMutationWriter(ctx, request, actor)
	if err != nil {
		d.diagnostic.record("role-writer-prepare", "", err)
	}
	return writer, err
}
