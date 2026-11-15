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

func parentPrelockRig(t *testing.T) (protocolRig, domain.UserID) {
	t.Helper()
	r, _ := writerProtocolRigBeforePreparation(t)
	return r, domain.UserID(bindingPublicOwner(t, r))
}

// Три настоящих repo ports сохраняют свои OLD row/membership reads.
// Вход выдаёт только admission; это не доказательство native права удаления.
func parentPrelockCall(ctx context.Context, w kaname.Writer, method string, r protocolRig, owner domain.UserID) error {
	switch method {
	case "account-owner":
		return w.AccountsW().LockOwner(ctx, owner)
	case "user-removal":
		_, err := w.UsersW().LockForRemoval(ctx, owner)
		return err
	default:
		_, err := w.AccountsW().LockForRemoval(ctx, domain.AccountID(r.a))
		return err
	}
}

func TestParentPrelockCompatibilityAdmissionPrecedesEveryLockingRead(t *testing.T) {
	for _, method := range []string{"account-removal", "account-owner", "user-removal"} {
		t.Run(method, func(t *testing.T) {
			r, owner := parentPrelockRig(t)
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
				return parentPrelockCall(ctx, w, method, r, owner)
			})
			pid := receiptWaitForBlocker(t, r.ctx, r.admin, int(holder.Conn().PgConn().PID()))
			var consumerWait, rowRead bool
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
    EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND classid=1262569292::oid AND objid=0::oid AND objsubid=2 AND mode='ExclusiveLock' AND NOT granted),
    EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='relation' AND relation IN ('kaname.accounts'::regclass,'kaname.users'::regclass) AND mode='RowShareLock')`, pid).Scan(&consumerWait, &rowRead))
			require.True(t, consumerWait, "вход ждёт настоящий consumer barrier")
			require.False(t, rowRead, "до admission нельзя даже начать SELECT с row lock")
			require.NoError(t, holder.Rollback(r.ctx))
			require.NoError(t, lifecycleResult(t, r.ctx, done), "после admission настоящий метод должен работать")
		})
	}
}

func TestParentPrelockStrictUnsignedRefusesBeforeConflictingRows(t *testing.T) {
	r, owner := parentPrelockRig(t)
	require.NoError(t, lifecycleOwner(r).PrepareAuthorityBundle(r.ctx, r.bundle))
	fullContractActivate(t, r)
	holder, err := r.admin.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, holder)
	_, err = holder.Exec(r.ctx, `SELECT 1 FROM kaname.accounts WHERE id=$1 FOR UPDATE`, r.a)
	require.NoError(t, err)
	_, err = holder.Exec(r.ctx, `SELECT 1 FROM kaname.users WHERE id=$1 FOR UPDATE`, string(owner))
	require.NoError(t, err)
	var before string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_build_object(
 'account',(SELECT to_jsonb(a) FROM kaname.accounts a WHERE id=$1),
 'owner',(SELECT to_jsonb(u) FROM kaname.users u WHERE id=$2))::text`, r.a, string(owner)).Scan(&before))
	for _, method := range []string{"account-removal", "account-owner", "user-removal"} {
		t.Run(method, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(r.ctx, 5*time.Second)
			defer cancel()
			w, err := r.repo.Writer(ctx)
			require.NoError(t, err)
			defer func() { _ = w.Rollback(context.WithoutCancel(r.ctx)) }()
			err = parentPrelockCall(ctx, w, method, r, owner)
			require.ErrorContains(t, err, "sqlstate 42501", "отказ attestation должен прийти до ожидания удерживаемой строки")
			require.NoError(t, ctx.Err(), "timeout не считается правильным отказом")
			require.NoError(t, w.Rollback(r.ctx))
		})
	}
	var after string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_build_object(
 'account',(SELECT to_jsonb(a) FROM kaname.accounts a WHERE id=$1),
 'owner',(SELECT to_jsonb(u) FROM kaname.users u WHERE id=$2))::text`, r.a, string(owner)).Scan(&after))
	require.Equal(t, before, after)
	require.NoError(t, holder.Rollback(r.ctx))
}

func TestParentPrelockSignedStagedAndFullKeepTheirAccountAdmission(t *testing.T) {
	for _, generation := range []string{"staged", "full"} {
		t.Run(generation, func(t *testing.T) {
			r, owner := parentPrelockRig(t)
			require.NoError(t, lifecycleOwner(r).PrepareAuthorityBundle(r.ctx, r.bundle))
			repo := r.repo
			if generation == "full" {
				repo, _ = fullContractActivate(t, r)
			}
			for _, method := range []string{"account-removal", "account-owner", "user-removal"} {
				t.Run(method, func(t *testing.T) {
					intent := r.intent(r.a)
					w, err := repo.ParticipantAuthorityWriter(r.ctx, intent)
					require.NoError(t, err)
					lifecycleWriterCleanup(t, w)
					decision := w.AuthorityFence().DecisionAt()
					require.NoError(t, parentPrelockCall(r.ctx, w, method, r, owner))
					require.Equal(t, decision, w.AuthorityFence().DecisionAt())
					// В этой фикстуре ровно одна открытая LOGIN TX; далее проверяем её PID.
					var pids []int32
					require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT array_agg(pid) FROM pg_stat_activity WHERE usename=$1 AND xact_start IS NOT NULL`, r.role).Scan(&pids))
					require.Len(t, pids, 1)
					var shared, exclusive int
					require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FILTER(WHERE mode='ShareLock' AND granted),count(*) FILTER(WHERE mode='ExclusiveLock')
      FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND classid=1262569292::oid AND objid=0::oid AND objsubid=2`, pids[0]).Scan(&shared, &exclusive))
					require.Equal(t, 1, shared, "подписанный account writer сохраняет shared consumer admission")
					require.Zero(t, exclusive, "helper не повышает consumer mode и не запрашивает GLOBAL")
					require.NoError(t, w.Rollback(r.ctx))
				})
			}
		})
	}
}

func TestParentPrelockVoidEntryKeepsVerifierPrivateAndReadinessPinned(t *testing.T) {
	r, _ := parentPrelockRig(t)
	require.NoError(t, lifecycleOwner(r).PrepareAuthorityBundle(r.ctx, r.bundle))
	full, _ := fullContractActivate(t, r)
	var publicEntry, privateVerifier bool
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(current_user,'kaname.authority_parent_prelock_admit_v3()','EXECUTE'),has_function_privilege(current_user,'kaname.authority_protocol_attestation()','EXECUTE')`).Scan(&publicEntry, &privateVerifier))
	require.True(t, publicEntry)
	require.False(t, privateVerifier)
	var resultType string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT prorettype::regtype::text FROM pg_proc WHERE oid='kaname.authority_parent_prelock_admit_v3()'::regprocedure`).Scan(&resultType))
	require.Equal(t, "void", resultType)
	// Даже доступный void helper не создаёт подпись для unsigned strict TX.
	tx, err := r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	_, err = tx.Exec(r.ctx, `SELECT kaname.authority_parent_prelock_admit_v3()`)
	var pe *pgconn.PgError
	require.ErrorAs(t, err, &pe)
	require.Equal(t, "42501", pe.Code)
	require.NoError(t, tx.Rollback(r.ctx))
	require.NoError(t, full.ValidateFullAuthorityBundle(r.ctx, r.bundle))
	var original string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT pg_get_functiondef('kaname.authority_parent_prelock_admit_v3()'::regprocedure)`).Scan(&original))
	defer func() {
		_, restoreErr := r.admin.Exec(r.ctx, original)
		require.NoError(t, restoreErr)
		_, restoreErr = r.admin.Exec(r.ctx, `REVOKE ALL ON FUNCTION kaname.authority_parent_prelock_admit_v3() FROM PUBLIC`)
		require.NoError(t, restoreErr)
	}()
	_, err = r.admin.Exec(r.ctx, `CREATE OR REPLACE FUNCTION kaname.authority_parent_prelock_admit_v3() RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$ BEGIN RETURN; END $$`)
	require.NoError(t, err)
	require.Error(t, full.ValidateFullAuthorityBundle(r.ctx, r.bundle), "пустой helper не является готовым ABI")
	_, err = r.admin.Exec(r.ctx, original)
	require.NoError(t, err)
	require.NoError(t, full.ValidateFullAuthorityBundle(r.ctx, r.bundle))
	_, err = r.admin.Exec(r.ctx, `GRANT EXECUTE ON FUNCTION kaname.authority_parent_prelock_admit_v3() TO PUBLIC`)
	require.NoError(t, err)
	require.Error(t, full.ValidateFullAuthorityBundle(r.ctx, r.bundle), "PUBLIC EXECUTE не является approved runtime profile")
	_, err = r.admin.Exec(r.ctx, `REVOKE ALL ON FUNCTION kaname.authority_parent_prelock_admit_v3() FROM PUBLIC`)
	require.NoError(t, err)
	require.NoError(t, full.ValidateFullAuthorityBundle(r.ctx, r.bundle))
}

func TestParentPrelockOwnerAndRemovalShareOneAdmissionOrder(t *testing.T) {
	for _, first := range []string{"account-owner", "user-removal"} {
		t.Run(first, func(t *testing.T) {
			r, owner := parentPrelockRig(t)
			second := "user-removal"
			if first == second {
				second = "account-owner"
			}
			w, err := r.repo.Writer(r.ctx)
			require.NoError(t, err)
			defer func() { _ = w.Rollback(context.WithoutCancel(r.ctx)) }()
			require.NoError(t, parentPrelockCall(r.ctx, w, first, r, owner))
			var pids []int32
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT array_agg(pid) FROM pg_stat_activity WHERE usename=$1 AND xact_start IS NOT NULL`, r.role).Scan(&pids))
			require.Len(t, pids, 1)
			done := lifecycleAsync(t, r.ctx, func(ctx context.Context) error {
				next, err := r.repo.Writer(ctx)
				if err != nil {
					return err
				}
				defer func() { _ = next.Rollback(context.WithoutCancel(ctx)) }()
				return parentPrelockCall(ctx, next, second, r, owner)
			})
			pid := receiptWaitForBlocker(t, r.ctx, r.admin, int(pids[0]))
			var consumerWait, rowRead bool
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
 EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND classid=1262569292::oid AND objid=0::oid AND objsubid=2 AND mode='ExclusiveLock' AND NOT granted),
 EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='relation' AND relation='kaname.users'::regclass AND mode='RowShareLock')`, pid).Scan(&consumerWait, &rowRead))
			require.True(t, consumerWait)
			require.False(t, rowRead, "вторая сторона не держит users row против consumer первой")
			require.NoError(t, w.Rollback(r.ctx))
			require.NoError(t, lifecycleResult(t, r.ctx, done))
		})
	}
}
