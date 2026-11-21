// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func lifecycleOwner(r protocolRig) *kanamepg.Repository { return kanamepg.New(r.admin, nil) }
func lifecycleState(t *testing.T, r protocolRig, phase, mode string) {
	t.Helper()
	var gotPhase, gotMode, model, catalog, projector string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT a.phase,p.enforcement,a.model_id,a.catalog_id,a.projector_version FROM kaname.authority_semantic_identity a CROSS JOIN kaname.authority_writer_protocol p`).Scan(&gotPhase, &gotMode, &model, &catalog, &projector))
	require.Equal(t, phase, gotPhase)
	require.Equal(t, mode, gotMode)
	id := r.bundle.Identity()
	require.Equal(t, id.ModelID, model)
	require.Equal(t, id.CatalogID, catalog)
	require.Equal(t, id.ProjectorVersion, projector)
}
func lifecycleResult(t *testing.T, ctx context.Context, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		t.Fatal("lifecycle не завершился до context deadline")
		return ctx.Err()
	}
}
func lifecycleRollback(t *testing.T, tx pgx.Tx) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(ctx)
	})
}

// Любой ранний Fatal освобождает TX до pool.Close; проверки rollback остаются ниже.
func lifecycleWriterCleanup(t *testing.T, w kaname.AuthorityWriter) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = w.Rollback(ctx)
	})
}
func lifecycleAsync(t *testing.T, ctx context.Context, fn func(context.Context) error) <-chan error {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- fn(ctx); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("lifecycle worker не освободился после отмены")
		}
	})
	return done
}

func TestAuthorityLifecycleRealHandoffAndOrdinaryParticipant(t *testing.T) {
	r := writerProtocolRig(t)
	handed, err := r.repo.LoadAuthorityBundle(r.ctx, r.bundle.ModelSource())
	require.NoError(t, err)
	require.NotSame(t, r.bundle, handed)
	require.Equal(t, r.bundle.Identity(), handed.Identity())
	bad, err := r.repo.LoadAuthorityBundle(r.ctx, r.bundle.ModelSource()+"\n")
	require.Error(t, err)
	require.Nil(t, bad)
	in := r.intent(r.a)
	in.Bundle = handed
	for _, phase := range []string{"prepared", "active"} {
		t.Run(phase, func(t *testing.T) {
			if phase == "active" {
				require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, handed))
				lifecycleState(t, r, "active", "strict")
			}
			writer, err := r.repo.ParticipantAuthorityWriter(r.ctx, in)
			require.NoError(t, err)
			lifecycleWriterCleanup(t, writer)
			_, semantic := writer.(kaname.SemanticAuthorityWriter)
			require.False(t, semantic, "ordinary participant не является semantic decision writer")
			_, err = writer.GroupsW().Insert(r.ctx, domain.Group{ID: domain.GroupID("grp-lifecycle-" + phase), AccountID: domain.AccountID(r.a), Name: domain.GroupName("lifecycle-" + phase)})
			require.NoError(t, err)
			require.NoError(t, writer.Commit(r.ctx))
			if phase == "prepared" {
				decision, err := r.repo.CoordinatedEntryWriter(r.ctx, in)
				require.Error(t, err)
				require.Nil(t, decision)
			}
		})
	}
	old, err := r.repo.TransitionalAuthorityWriter(r.ctx, in)
	require.Error(t, err)
	require.Nil(t, old)
	// Разные account fences остаются независимыми после настоящего cutover.
	first, err := r.repo.ParticipantAuthorityWriter(r.ctx, r.intent(r.a))
	require.NoError(t, err)
	lifecycleWriterCleanup(t, first)
	second, err := r.repo.ParticipantAuthorityWriter(r.ctx, r.intent(r.b))
	require.NoError(t, err)
	lifecycleWriterCleanup(t, second)
	require.NoError(t, second.Rollback(r.ctx))
	require.NoError(t, first.Rollback(r.ctx))
	require.NoError(t, lifecycleOwner(r).CloseAuthorityBundle(r.ctx))
	lifecycleState(t, r, "transition", "strict")
	denied, err := r.repo.ParticipantAuthorityWriter(r.ctx, in)
	require.Error(t, err)
	require.Nil(t, denied)
	bad, err = r.repo.LoadAuthorityBundle(r.ctx, r.bundle.ModelSource())
	require.Error(t, err)
	require.Nil(t, bad)
	require.NoError(t, lifecycleOwner(r).StageAuthorityBundle(r.ctx, r.bundle))
	lifecycleState(t, r, "prepared", "strict")
	denied, err = r.repo.ParticipantAuthorityWriter(r.ctx, in)
	require.Error(t, err)
	require.Nil(t, denied, "prepared после strict не открывает compatibility")
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	authorityWaitReleased(t, r.runtime)
}

func TestAuthorityLifecycleOwnerAndWholeIdentityAreRequired(t *testing.T) {
	r := writerProtocolRig(t)
	for _, call := range []func() error{
		func() error { return r.repo.StageAuthorityBundle(r.ctx, r.bundle) },
		func() error { return r.repo.ActivateAuthorityBundle(r.ctx, r.bundle) },
		func() error { return r.repo.CloseAuthorityBundle(r.ctx) },
	} {
		var pgerr *pgconn.PgError
		require.ErrorAs(t, call(), &pgerr)
		require.Equal(t, "42501", pgerr.Code)
	}
	_, err := r.runtime.Exec(r.ctx, `UPDATE kaname.authority_bundle_handoff SET projector_version='forged'`)
	require.Error(t, err)
	// Неподходящий bundle — валидная admission, но другая полная identity.
	rows, err := kanamepg.NewCatalogRepo(r.admin).ReadCatalogHalves(r.ctx)
	require.NoError(t, err)
	require.Greater(t, len(rows.Live.Verbs), 1)
	rows.Live.Verbs = rows.Live.Verbs[1:]
	other, err := granteffect.NewBundle(r.ctx, r.bundle.ModelSource(), rows, granteffect.ProjectorVersion)
	require.NoError(t, err)
	require.Error(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, other))
	lifecycleState(t, r, "prepared", "compatibility")
	tx, err := r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	in := r.intent(r.a)
	in.Bundle = other
	_, err = protocolEnter(r.ctx, tx, in, "participant")
	require.Error(t, err)
	require.NoError(t, tx.Rollback(r.ctx))
	// SQL entry не принимает неизвестную версию протокола или проектора.
	for _, tc := range []struct {
		version   int
		projector string
	}{{2, granteffect.ProjectorVersion}, {1, "granteffect/unsupported"}} {
		fresh, err := r.runtime.Begin(r.ctx)
		require.NoError(t, err)
		lifecycleRollback(t, fresh)
		id := r.bundle.Identity()
		if tc.version == 1 {
			_, err = fresh.Exec(r.ctx, `SELECT kaname.authority_protocol_enter_typed_v2('accounts',ARRAY[$1::text],jsonb_build_array(jsonb_build_object('kind','account','id',$1::text)),'group',$2,$3,$4,'participant')`, r.a, id.ModelID, id.CatalogID, tc.projector)
		} else {
			// ABI2 фиксирует stored protocol=1; старая форма с caller version
			// отвергается целиком, включая неизвестную версию прежнего клиента.
			_, err = fresh.Exec(r.ctx, `SELECT kaname.authority_protocol_enter('accounts',ARRAY[$1::text],jsonb_build_array(jsonb_build_object('kind','account','id',$1::text)),'group',$2,$3,$4,$5,'participant')`, r.a, id.ModelID, id.CatalogID, tc.projector, tc.version)
		}
		require.Error(t, err)
		require.NoError(t, fresh.Rollback(r.ctx))
	}
	// Обычный LOGIN не становится owner через временные каталоги.
	conn, err := r.runtime.Acquire(r.ctx)
	require.NoError(t, err)
	defer conn.Release()
	_, err = conn.Exec(r.ctx, `CREATE TEMP TABLE pg_class(oid oid,relowner oid); CREATE TEMP TABLE pg_locks(pid integer)`)
	require.NoError(t, err)
	_, err = conn.Exec(r.ctx, `SELECT kaname.authority_protocol_drain()`)
	var pgerr *pgconn.PgError
	require.ErrorAs(t, err, &pgerr)
	require.Equal(t, "42501", pgerr.Code)
	_, err = conn.Exec(r.ctx, `DROP TABLE pg_temp.pg_class,pg_temp.pg_locks`)
	require.NoError(t, err)
}

func TestAuthorityLifecycleDrainsOldUnfencedDMLBeforeControlRows(t *testing.T) {
	for _, finish := range []string{"commit", "rollback"} {
		t.Run(finish, func(t *testing.T) {
			r := writerProtocolRig(t)
			old, err := r.runtime.Begin(r.ctx)
			require.NoError(t, err)
			lifecycleRollback(t, old)
			_, err = old.Exec(r.ctx, `UPDATE kaname.accounts SET description='old unfenced' WHERE id=$1`, r.a)
			require.NoError(t, err)
			done := lifecycleAsync(t, r.ctx, func(ctx context.Context) error { return lifecycleOwner(r).ActivateAuthorityBundle(ctx, r.bundle) })
			waiter := receiptWaitForBlocker(t, r.ctx, r.admin, int(old.Conn().PgConn().PID()))
			var tableWait bool
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='relation' AND NOT granted)`, waiter).Scan(&tableWait))
			require.True(t, tableWait)
			// Если activation взял protocol FOR UPDATE перед drain, этот второй DML
			// старой TX зависнет: детерминированная проверка исходной инверсии.
			_, err = old.Exec(r.ctx, `UPDATE kaname.accounts SET description='old still progresses' WHERE id=$1`, r.a)
			require.NoError(t, err)
			if finish == "commit" {
				require.NoError(t, old.Commit(r.ctx))
			} else {
				require.NoError(t, old.Rollback(r.ctx))
			}
			require.NoError(t, lifecycleResult(t, r.ctx, done))
			lifecycleState(t, r, "active", "strict")
			_, err = r.runtime.Exec(r.ctx, `UPDATE kaname.accounts SET description='raw after cutover' WHERE id=$1`, r.a)
			require.Error(t, err)
		})
	}
}

func TestAuthorityLifecycleCancellationReleasesDrain(t *testing.T) {
	r := writerProtocolRig(t)
	old, err := r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, old)
	_, err = old.Exec(r.ctx, `UPDATE kaname.accounts SET description='held legacy write' WHERE id=$1`, r.a)
	require.NoError(t, err)
	oldPID := int(old.Conn().PgConn().PID())
	ctx, cancel := context.WithCancel(r.ctx)
	defer cancel()
	done := lifecycleAsync(t, ctx, func(ctx context.Context) error { return lifecycleOwner(r).ActivateAuthorityBundle(ctx, r.bundle) })
	activationPID := receiptWaitForBlocker(t, r.ctx, r.admin, oldPID)
	var drainWaiting bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT EXISTS(
 SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='relation'
 AND mode='AccessExclusiveLock' AND NOT granted)`, activationPID).Scan(&drainWaiting))
	require.True(t, drainWaiting, "отмена проверяется во время реального ожидания drain")
	cancel()
	require.ErrorIs(t, lifecycleResult(t, r.ctx, done), context.Canceled)
	lifecycleState(t, r, "prepared", "compatibility")
	// Проверяем освобождение именно activation, а не законных locks old TX.
	// Пул может уже использовать тот же PID для observer SELECT (AccessShare).
	// Синхронное bounded ожидание подтверждения server cleanup: без фонового
	// condition, который мог бы пережить таймер и изменить прочитанные флаги.
	releaseErr := waitAuthorityPIDRelease(r.ctx, r.admin, activationPID)
	var activationReleased, legacyAdmissionHeld bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT NOT EXISTS(
 SELECT 1 FROM pg_locks WHERE pid=$1 AND (locktype='advisory'
 OR (locktype='relation' AND mode<>'AccessShareLock'))), EXISTS(
 SELECT 1 FROM pg_locks WHERE pid=$2 AND database=(SELECT oid FROM pg_database WHERE datname=current_database())
 AND locktype='advisory' AND classid=1262569292::oid AND objid=0::oid
 AND objsubid=2 AND mode='ExclusiveLock' AND granted)`, activationPID, oldPID).Scan(&activationReleased, &legacyAdmissionHeld))
	if !activationReleased {
		// Снимок не меняет вычисленный verdict и не повторяет ожидание release.
		// PID мог быть переиспользован пулом: сохраняем observer PID и времена
		// backend/TX/query, но не текст SQL и не бизнес-параметры.
		diagnosticCtx, stopDiagnostic := context.WithTimeout(context.Background(), 500*time.Millisecond)
		var snapshot string
		diagnosticErr := r.admin.QueryRow(diagnosticCtx, `WITH p AS (
 SELECT pid,backend_start,xact_start,query_start,state_change,state,
        wait_event_type,wait_event,pg_blocking_pids(pid) AS blockers,md5(query) AS query_hash
 FROM pg_stat_activity WHERE datname=current_database() AND pid IN ($1,$2)
 ORDER BY pid LIMIT 2
), l AS (
 SELECT pid,locktype,mode,granted,database,relation::regclass::text AS relation,
        classid,objid,objsubid,transactionid::text AS transaction_id,virtualxid,virtualtransaction
 FROM pg_locks WHERE pid IN ($1,$2)
 ORDER BY granted,pid,locktype,relation,classid,objid LIMIT 64
)
SELECT jsonb_build_object('observer_pid',pg_backend_pid(),
 'activity',coalesce((SELECT jsonb_agg(to_jsonb(p) ORDER BY pid) FROM p),'[]'::jsonb),
 'locks',coalesce((SELECT jsonb_agg(to_jsonb(l)) FROM l),'[]'::jsonb))::text`, activationPID, oldPID).Scan(&snapshot)
		stopDiagnostic()
		if diagnosticErr != nil {
			t.Logf("cancel lock diagnostic: activation_pid=%d old_pid=%d snapshot_unavailable=true", activationPID, oldPID)
		} else {
			t.Logf("cancel lock diagnostic: activation_pid=%d old_pid=%d state=%s", activationPID, oldPID, snapshot)
		}
	}
	require.NoError(t, releaseErr)
	require.True(t, activationReleased, "cancel освободил все advisory/table drain locks своего PID")
	require.True(t, legacyAdmissionHeld, "ещё открытая raw TX законно удерживает compatibility admission")
	var enteredAccounts []domain.AccountID
	current := lifecycleAsync(t, r.ctx, func(ctx context.Context) error {
		writer, openErr := r.repo.ParticipantAuthorityWriter(ctx, r.intent(r.b))
		if openErr != nil {
			return openErr
		}
		enteredAccounts = writer.AuthorityFence().Accounts()
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		return writer.Rollback(cleanup)
	})
	participantPID := receiptWaitForBlocker(t, r.ctx, r.admin, oldPID)
	require.NotEqual(t, activationPID, participantPID, "runtime participant использует отдельный LOGIN pool")
	var participantWaiting bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT EXISTS(
 SELECT 1 FROM pg_locks WHERE pid=$1 AND database=(SELECT oid FROM pg_database WHERE datname=current_database())
 AND locktype='advisory' AND classid=1262569292::oid AND objid=0::oid
 AND objsubid=2 AND mode='ShareLock' AND NOT granted)
 AND $2=ANY(pg_blocking_pids($1))`, participantPID, oldPID).Scan(&participantWaiting))
	require.True(t, participantWaiting, "participant ждёт old TX, а не отменённый activation")
	require.NoError(t, old.Rollback(r.ctx))
	require.NoError(t, lifecycleResult(t, r.ctx, current))
	require.Equal(t, []domain.AccountID{domain.AccountID(r.b)}, enteredAccounts)
	authorityWaitReleased(t, r.admin)
	authorityWaitReleased(t, r.runtime)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	lifecycleState(t, r, "active", "strict")
}

func TestAuthorityLifecycleRejectsOldSnapshotsAndQueuedRawWriter(t *testing.T) {
	for _, isolation := range []pgx.TxIsoLevel{pgx.ReadCommitted, pgx.RepeatableRead, pgx.Serializable} {
		t.Run(string(isolation), func(t *testing.T) {
			r := writerProtocolRig(t)
			old, err := r.runtime.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: isolation})
			require.NoError(t, err)
			lifecycleRollback(t, old)
			var phase string
			require.NoError(t, old.QueryRow(r.ctx, `SELECT phase FROM kaname.authority_semantic_identity`).Scan(&phase))
			require.Equal(t, "prepared", phase)
			require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
			_, err = old.Exec(r.ctx, `UPDATE kaname.accounts SET description='old snapshot' WHERE id=$1`, r.a)
			var pgerr *pgconn.PgError
			require.ErrorAs(t, err, &pgerr)
			if isolation == pgx.ReadCommitted {
				require.Equal(t, "42501", pgerr.Code)
			} else {
				require.Equal(t, "40001", pgerr.Code)
			}
			require.NoError(t, old.Rollback(r.ctx))
			current, err := r.repo.ParticipantAuthorityWriter(r.ctx, r.intent(r.a))
			require.NoError(t, err)
			lifecycleWriterCleanup(t, current)
			require.NoError(t, current.Rollback(r.ctx))
		})
	}
	t.Run("queued-before-commit", func(t *testing.T) {
		r := writerProtocolRig(t)
		gate, err := r.admin.Begin(r.ctx)
		require.NoError(t, err)
		lifecycleRollback(t, gate)
		_, err = gate.Exec(r.ctx, `SELECT 1 FROM kaname.authority_semantic_identity FOR UPDATE`)
		require.NoError(t, err)
		activation := lifecycleAsync(t, r.ctx, func(ctx context.Context) error { return lifecycleOwner(r).ActivateAuthorityBundle(ctx, r.bundle) })
		activatingPID := receiptWaitForBlocker(t, r.ctx, r.admin, int(gate.Conn().PgConn().PID()))
		queued := lifecycleAsync(t, r.ctx, func(ctx context.Context) error {
			_, err := r.runtime.Exec(ctx, `UPDATE kaname.accounts SET description='queued raw' WHERE id=$1`, r.a)
			return err
		})
		receiptWaitForBlocker(t, r.ctx, r.admin, activatingPID)
		require.NoError(t, gate.Rollback(r.ctx))
		require.NoError(t, lifecycleResult(t, r.ctx, activation))
		var pgerr *pgconn.PgError
		require.ErrorAs(t, lifecycleResult(t, r.ctx, queued), &pgerr)
		require.Equal(t, "42501", pgerr.Code)
	})
}

func TestAuthorityLifecycleCatalogChangeClosesHandoffAndChecksEdition(t *testing.T) {
	r := writerProtocolRig(t)
	// Изменение applied edition не обязано менять canonical rows, но закрывает
	// прежнюю согласованность source/model; старая delivery не может её восстановить.
	require.NoError(t, lifecycleOwner(r).StageAuthorityBundle(r.ctx, r.bundle, kaname.AuthorityModuleEdition{Module: "iam"}))
	digest := "sha256:" + strings.Repeat("a", 64)
	_, err := r.admin.Exec(r.ctx, `UPDATE kaname.catalog_module SET applied_revision=1,applied_digest=$1 WHERE module='iam'`, digest)
	require.NoError(t, err)
	lifecycleState(t, r, "transition", "compatibility")
	bad, err := r.repo.LoadAuthorityBundle(r.ctx, r.bundle.ModelSource())
	require.Error(t, err)
	require.Nil(t, bad)
	require.Error(t, lifecycleOwner(r).StageAuthorityBundle(r.ctx, r.bundle, kaname.AuthorityModuleEdition{Module: "iam"}))
	require.Error(t, lifecycleOwner(r).StageAuthorityBundle(r.ctx, r.bundle, kaname.AuthorityModuleEdition{Module: "iam", Revision: 1, Digest: "sha256:" + strings.Repeat("b", 64)}))
	require.NoError(t, lifecycleOwner(r).StageAuthorityBundle(r.ctx, r.bundle, kaname.AuthorityModuleEdition{Module: "iam", Revision: 1, Digest: digest}))
	lifecycleState(t, r, "prepared", "compatibility")
	require.Error(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle, kaname.AuthorityModuleEdition{Module: "iam", Revision: 2, Digest: digest}))
	lifecycleState(t, r, "prepared", "compatibility")
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle, kaname.AuthorityModuleEdition{Module: "iam", Revision: 1, Digest: digest}))
}

func TestAuthorityLifecycleRejectsIncompleteActualGuardFootprint(t *testing.T) {
	r := writerProtocolRig(t)
	var trigger string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT tgname FROM pg_trigger WHERE tgrelid='kaname.accounts'::regclass AND tgfoid='kaname.authority_protocol_row_guard()'::regprocedure`).Scan(&trigger))
	_, err := r.admin.Exec(r.ctx, "ALTER TABLE kaname.accounts DISABLE TRIGGER "+pgx.Identifier{trigger}.Sanitize())
	require.NoError(t, err)
	require.Error(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	lifecycleState(t, r, "prepared", "compatibility")
	_, err = r.admin.Exec(r.ctx, "ALTER TABLE kaname.accounts ENABLE TRIGGER "+pgx.Identifier{trigger}.Sanitize())
	require.NoError(t, err)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
}

// kaname#1034: nil pool доказывает отказ до открытия TX, а не ошибку подключения.
func TestAuthorityLifecycleRejectsInputBeforeConnection(t *testing.T) {
	repository := kanamepg.New(nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	writer, err := repository.ParticipantAuthorityWriter(ctx, kaname.AuthorityWriteIntent{})
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, writer)
	writer, err = repository.ParticipantAuthorityWriter(context.Background(), kaname.AuthorityWriteIntent{})
	require.Error(t, err)
	require.Nil(t, writer, "typed nil не должен превращаться в пригодный interface")
	require.Error(t, repository.StageAuthorityBundle(context.Background(), nil))
	require.Error(t, repository.ActivateAuthorityBundle(context.Background(), nil))
	require.ErrorIs(t, repository.CloseAuthorityBundle(ctx), context.Canceled)
	bundle, err := repository.LoadAuthorityBundle(context.Background(), "")
	require.Error(t, err)
	require.Nil(t, bundle)
}

// Даже точный active bundle не разрешает old-binary entry после ABI2 cutover.
func TestAuthorityConsumerV2RejectsOldEntryWithValidBundle(t *testing.T) {
	r := writerProtocolRig(t)
	r.strict(t)
	tx, err := r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	identity := r.bundle.Identity()
	_, err = tx.Exec(r.ctx, `SELECT kaname.authority_protocol_enter('accounts',ARRAY[$1::text],jsonb_build_array(jsonb_build_object('kind','account','id',$1::text)),'group',$2,$3,$4,1,'participant')`, r.a, identity.ModelID, identity.CatalogID, identity.ProjectorVersion)
	var pgerr *pgconn.PgError
	require.ErrorAs(t, err, &pgerr)
	require.Equal(t, "42501", pgerr.Code)
	require.NoError(t, tx.Rollback(r.ctx))
	fresh, err := r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, fresh)
	_, err = protocolEnter(r.ctx, fresh, r.intent(r.a), "participant")
	require.NoError(t, err, "тот же ordinary LOGIN и bundle проходят явный ABI2 entry")
	require.NoError(t, fresh.Rollback(r.ctx))
}
