// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func rolePrelockRig(t *testing.T) (protocolRig, domain.RoleID) {
	t.Helper()
	r, _ := writerProtocolRigBeforePreparation(t)
	binding := groupLifecycleBinding(t, r, r.a, bindingPublicOwner(t, r), "prelock_role", domain.Rule{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}})
	var role domain.RoleID
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT role_id FROM kaname.access_bindings WHERE id=$1`, string(binding)).Scan(&role))
	return r, role
}

// Все три вызова идут через настоящие Role repo ports; SQL helper не подменяет
// проверяемый вход. ReplaceRuleSelectors сохраняет непустой catalog prelock.
func rolePrelockCall(ctx context.Context, w kaname.Writer, method string, id domain.RoleID) error {
	switch method {
	case "module":
		return w.RolesW().LockOwnerModule(ctx, "iam")
	case "selectors":
		return w.RolesW().ReplaceRuleSelectors(ctx, id, []domain.RuleSelector{{RuleFP: "prelock", Arm: domain.ArmAnchor, ObjectTypes: []string{"iam.account"}, Grants: map[string][]string{}}})
	default:
		_, _, _, err := w.RolesW().RulesForRegrain(ctx, id)
		return err
	}
}

func TestRolePrelockCompatibilityAdmissionPrecedesEveryLockingRead(t *testing.T) {
	for _, method := range []string{"module", "selectors", "regrain"} {
		t.Run(method, func(t *testing.T) {
			r, role := rolePrelockRig(t)
			holder, err := r.admin.Begin(r.ctx)
			require.NoError(t, err)
			lifecycleRollback(t, holder)
			_, err = holder.Exec(r.ctx, `SELECT pg_advisory_xact_lock(1262569292,0)`)
			require.NoError(t, err)
			done := lifecycleAsync(t, r.ctx, func(ctx context.Context) error {
				w, err := r.repo.Writer(ctx)
				if err != nil {
					return err
				}
				defer func() { _ = w.Rollback(context.WithoutCancel(ctx)) }()
				return rolePrelockCall(ctx, w, method, role)
			})
			pid := receiptWaitForBlocker(t, r.ctx, r.admin, int(holder.Conn().PgConn().PID()))
			var consumerWait, rowRead bool
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
    EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND classid=1262569292::oid AND objid=0::oid AND objsubid=2 AND mode='ExclusiveLock' AND NOT granted),
    EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='relation' AND relation IN ('kaname.catalog_module'::regclass,'kaname.catalog_resource'::regclass,'kaname.roles'::regclass) AND mode='RowShareLock')`, pid).Scan(&consumerWait, &rowRead))
			require.True(t, consumerWait, "вход ждёт настоящий consumer barrier")
			require.False(t, rowRead, "до admission нельзя даже начать SELECT с row lock")
			require.NoError(t, holder.Rollback(r.ctx))
			require.NoError(t, lifecycleResult(t, r.ctx, done), "после admission настоящий метод должен работать")
		})
	}
}

func TestRolePrelockStrictUnsignedRefusesBeforeConflictingRows(t *testing.T) {
	r, role := rolePrelockRig(t)
	require.NoError(t, lifecycleOwner(r).PrepareAuthorityBundle(r.ctx, r.bundle))
	fullContractActivate(t, r)
	holder, err := r.admin.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, holder)
	_, err = holder.Exec(r.ctx, `SELECT 1 FROM kaname.catalog_module WHERE module='iam' FOR UPDATE;
 SELECT 1 FROM kaname.catalog_resource WHERE dotted='iam.account' FOR UPDATE`)
	require.NoError(t, err)
	_, err = holder.Exec(r.ctx, `SELECT 1 FROM kaname.roles WHERE id=$1 FOR UPDATE`, string(role))
	require.NoError(t, err)
	var before string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY rule_fp),'[]'::jsonb)::text FROM kaname.role_rule_selectors s WHERE role_id=$1`, string(role)).Scan(&before))
	for _, method := range []string{"module", "selectors", "regrain"} {
		t.Run(method, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(r.ctx, 5*time.Second)
			defer cancel()
			w, err := r.repo.Writer(ctx)
			require.NoError(t, err)
			defer func() { _ = w.Rollback(context.WithoutCancel(r.ctx)) }()
			err = rolePrelockCall(ctx, w, method, role)
			require.ErrorContains(t, err, "sqlstate 42501", "отказ attestation должен прийти до ожидания удерживаемой строки")
			require.NoError(t, ctx.Err(), "timeout не считается правильным отказом")
			require.NoError(t, w.Rollback(r.ctx))
		})
	}
	var after string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY rule_fp),'[]'::jsonb)::text FROM kaname.role_rule_selectors s WHERE role_id=$1`, string(role)).Scan(&after))
	require.Equal(t, before, after)
	require.NoError(t, holder.Rollback(r.ctx))
}

func TestRolePrelockSignedStagedAndFullKeepTheirAccountAdmission(t *testing.T) {
	for _, generation := range []string{"staged", "full"} {
		t.Run(generation, func(t *testing.T) {
			r, role := rolePrelockRig(t)
			require.NoError(t, lifecycleOwner(r).PrepareAuthorityBundle(r.ctx, r.bundle))
			repo := r.repo
			if generation == "full" {
				repo, _ = fullContractActivate(t, r)
			}
			for _, method := range []string{"module", "selectors", "regrain"} {
				t.Run(method, func(t *testing.T) {
					intent := r.intent(r.a)
					intent.Kind = kaname.AuthorityRole
					intent.Owners = []kaname.AuthorityOwnerRef{{Kind: "role", ID: string(role)}}
					w, err := repo.ParticipantAuthorityWriter(r.ctx, intent)
					require.NoError(t, err)
					lifecycleWriterCleanup(t, w)
					decision := w.AuthorityFence().DecisionAt()
					require.NoError(t, rolePrelockCall(r.ctx, w, method, role))
					require.Equal(t, decision, w.AuthorityFence().DecisionAt())
					var shared, exclusive int
					require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FILTER(WHERE l.mode='ShareLock' AND l.granted),count(*) FILTER(WHERE l.mode='ExclusiveLock')
      FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid
      WHERE a.usename=$1 AND l.locktype='advisory' AND l.classid=1262569292::oid AND l.objid=0::oid AND l.objsubid=2`, r.role).Scan(&shared, &exclusive))
					require.Equal(t, 1, shared, "подписанный account writer сохраняет shared consumer admission")
					require.Zero(t, exclusive, "helper не повышает consumer mode и не запрашивает GLOBAL")
					require.NoError(t, w.Rollback(r.ctx))
				})
			}
		})
	}
}

func TestRolePrelockVoidEntryKeepsVerifierPrivateAndReadinessPinned(t *testing.T) {
	r, _ := rolePrelockRig(t)
	require.NoError(t, lifecycleOwner(r).PrepareAuthorityBundle(r.ctx, r.bundle))
	full, _ := fullContractActivate(t, r)
	var publicEntry, privateVerifier bool
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(current_user,'kaname.authority_role_prelock_admit_v3()','EXECUTE'),has_function_privilege(current_user,'kaname.authority_protocol_attestation()','EXECUTE')`).Scan(&publicEntry, &privateVerifier))
	require.True(t, publicEntry)
	require.False(t, privateVerifier)
	var resultType string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT prorettype::regtype::text FROM pg_proc WHERE oid='kaname.authority_role_prelock_admit_v3()'::regprocedure`).Scan(&resultType))
	require.Equal(t, "void", resultType)
	// Даже доступный void helper не создаёт подпись для unsigned strict TX.
	tx, err := r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	_, err = tx.Exec(r.ctx, `SELECT kaname.authority_role_prelock_admit_v3()`)
	var pe *pgconn.PgError
	require.ErrorAs(t, err, &pe)
	require.Equal(t, "42501", pe.Code)
	require.NoError(t, tx.Rollback(r.ctx))
	require.NoError(t, full.ValidateFullAuthorityBundle(r.ctx, r.bundle))
	var original string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT pg_get_functiondef('kaname.authority_role_prelock_admit_v3()'::regprocedure)`).Scan(&original))
	defer func() {
		_, restoreErr := r.admin.Exec(r.ctx, original)
		require.NoError(t, restoreErr)
		_, restoreErr = r.admin.Exec(r.ctx, `REVOKE ALL ON FUNCTION kaname.authority_role_prelock_admit_v3() FROM PUBLIC`)
		require.NoError(t, restoreErr)
	}()
	_, err = r.admin.Exec(r.ctx, `CREATE OR REPLACE FUNCTION kaname.authority_role_prelock_admit_v3() RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$ BEGIN RETURN; END $$`)
	require.NoError(t, err)
	require.Error(t, full.ValidateFullAuthorityBundle(r.ctx, r.bundle), "пустой helper не является готовым ABI")
	_, err = r.admin.Exec(r.ctx, original)
	require.NoError(t, err)
	require.NoError(t, full.ValidateFullAuthorityBundle(r.ctx, r.bundle))
	_, err = r.admin.Exec(r.ctx, `GRANT EXECUTE ON FUNCTION kaname.authority_role_prelock_admit_v3() TO PUBLIC`)
	require.NoError(t, err)
	require.Error(t, full.ValidateFullAuthorityBundle(r.ctx, r.bundle), "PUBLIC EXECUTE не является approved runtime profile")
	_, err = r.admin.Exec(r.ctx, `REVOKE ALL ON FUNCTION kaname.authority_role_prelock_admit_v3() FROM PUBLIC`)
	require.NoError(t, err)
	require.NoError(t, full.ValidateFullAuthorityBundle(r.ctx, r.bundle))
}
