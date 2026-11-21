// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"database/sql"
	"io/fs"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	saapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/service_account"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
)

type saStateWorld struct {
	r               protocolRig
	full            *kanamepg.Repository
	factory         *kanamepg.ServiceAccountStateWriters
	sa              domain.ServiceAccount
	actor, outsider string
	binding         domain.AccessBindingID
	selfBinding     domain.AccessBindingID
	ops             operations.Repo
}

func saStateFixture(t *testing.T, expiry bool) saStateWorld {
	t.Helper()
	r := writerProtocolRig(t)
	actor := seedMemberUser(t, r.ctx, r.admin, r.a, "state-editor")
	outsider := seedMemberUser(t, r.ctx, r.admin, r.b, "state-outsider")
	_, err := r.admin.Exec(r.ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=ANY($1::text[])`, []string{actor, outsider})
	require.NoError(t, err)
	sa := seedSA(t, r.ctx, lifecycleOwner(r), domain.AccountID(r.a), "state-service-account")
	binding := groupLifecycleBinding(t, r, r.a, actor, "state_editor_role", domain.Rule{Module: "iam", Resources: []string{"serviceAccount"}, Verbs: []string{"update"}})
	var role domain.RoleID
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT role_id FROM kaname.access_bindings WHERE id=$1`, string(binding)).Scan(&role))
	seed, err := lifecycleOwner(r).Writer(r.ctx)
	require.NoError(t, err)
	defer func() { _ = seed.Rollback(context.WithoutCancel(r.ctx)) }()
	self, err := bindingset.Insert(r.ctx, seed.AccessBindingsW(), domain.AccessBinding{ID: domain.AccessBindingID(ids.NewID("acb")), RoleID: role, SubjectType: domain.SubjectTypeServiceAccount, SubjectID: domain.SubjectID(sa.ID), ResourceType: "account", ResourceID: r.a, Scope: domain.ScopeAccount, Status: domain.AccessBindingStatusActive})
	require.NoError(t, err)
	require.NoError(t, seed.Commit(r.ctx))
	source := rolePolicyCatalog(t, r)
	engine := reconcile.New(kanamepg.NewReconcileAdapter(r.admin, source), slog.Default(), source)
	require.NoError(t, engine.ReconcileBinding(r.ctx, binding))
	require.NoError(t, engine.ReconcileBinding(r.ctx, self.ID))
	if expiry {
		_, err = r.admin.Exec(r.ctx, `UPDATE kaname.access_bindings SET expires_at=clock_timestamp()+interval '5 seconds' WHERE id=$1`, string(binding))
		require.NoError(t, err)
	}
	full, _ := fullContractActivate(t, r)
	factory, err := kanamepg.NewServiceAccountStateWriters(r.ctx, full, r.bundle)
	require.NoError(t, err)
	return saStateWorld{r, full, factory, sa, actor, outsider, binding, self.ID, operations.NewRepo(r.runtime, "kaname")}
}
func (w saStateWorld) actorSubject() domain.Subject {
	return domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(w.actor)}
}
func (w saStateWorld) execute(ctx context.Context, enabled bool) (*operations.Operation, error) {
	if enabled {
		return saapp.NewEnableServiceAccountUseCase(w.full, w.ops).WithServiceAccountStateWriter(w.factory).Execute(ctx, w.sa.ID)
	}
	return saapp.NewDisableServiceAccountUseCase(w.full, w.ops).WithServiceAccountStateWriter(w.factory).Execute(ctx, w.sa.ID)
}
func saStateSnapshot(t *testing.T, w saStateWorld) string {
	t.Helper()
	var state string
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT jsonb_build_array(
 (SELECT to_jsonb(s) FROM kaname.service_accounts s WHERE id=$1),
 (SELECT to_jsonb(c) FROM kaname.minted_token_revocations c WHERE subject=$1),
 (SELECT count(*) FROM kaname.audit_outbox),(SELECT count(*) FROM kaname.resource_journal),
 (SELECT count(*) FROM kaname.resource_reconcile_outbox))::text`, string(w.sa.ID)).Scan(&state))
	return state
}
func saStateEnabled(t *testing.T, w saStateWorld) bool {
	t.Helper()
	var enabled bool
	require.NoError(t, w.r.runtime.QueryRow(w.r.ctx, `SELECT enabled FROM kaname.service_accounts WHERE id=$1`, string(w.sa.ID)).Scan(&enabled))
	return enabled
}

func TestFullServiceAccountStateActualEnableDisableNoopAuditAndDenied(t *testing.T) {
	w := saStateFixture(t, false)
	for _, enabled := range []bool{false, false, true, true} {
		op, err := w.execute(declarerCtx(w.r.ctx, w.actor), enabled)
		require.NoError(t, err)
		require.Nil(t, awaitOperation(t, w.r.ctx, w.ops, op.ID).Error)
		require.Equal(t, enabled, saStateEnabled(t, w))
	}
	var audits, cutoffs int
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT
 (SELECT count(*) FROM kaname.audit_outbox WHERE event_payload->>'resource_id'=$1 AND event_payload->>'actor'=$2 AND event_type IN ('iam.service_account.disabled','iam.service_account.enabled')),
 (SELECT count(*) FROM kaname.minted_token_revocations WHERE subject=$1 AND reason='owner is no longer active' AND revoked_by='kaname:owner-deactivated')`, string(w.sa.ID), w.actor).Scan(&audits, &cutoffs))
	require.Equal(t, 4, audits, "оба принятых no-op тоже оставляют атомарный audit")
	require.Equal(t, 1, cutoffs, "Enable не отменяет отсечку уже выпущенных токенов")
	before := saStateSnapshot(t, w)
	for _, enabled := range []bool{false, true} {
		op, err := w.execute(declarerCtx(w.r.ctx, w.outsider), enabled)
		require.NoError(t, err)
		done := awaitOperation(t, w.r.ctx, w.ops, op.ID)
		require.NotNil(t, done.Error)
		require.EqualValues(t, 7, done.Error.Code)
		require.Equal(t, before, saStateSnapshot(t, w))
	}
	denied, deniedErr := w.factory.ServiceAccountStateWriter(w.r.ctx, w.sa.ID, false, domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(w.outsider)})
	require.Nil(t, denied)
	require.ErrorIs(t, deniedErr, iamerr.ErrPermissionDenied)
	op, err := saapp.NewDisableServiceAccountUseCase(w.full, w.ops).WithServiceAccountStateWriter(nil).Execute(declarerCtx(w.r.ctx, w.actor), w.sa.ID)
	require.NoError(t, err)
	done := awaitOperation(t, w.r.ctx, w.ops, op.ID)
	require.NotNil(t, done.Error)
	require.EqualValues(t, 14, done.Error.Code)
	raw, err := w.full.Writer(w.r.ctx)
	require.NoError(t, err)
	_, err = raw.ServiceAccountsW().SetEnabled(w.r.ctx, w.sa.ID, false)
	require.Error(t, err)
	require.NoError(t, raw.Rollback(w.r.ctx))
	require.Equal(t, before, saStateSnapshot(t, w))
}

func TestFullServiceAccountStateExpiryAfterRealRowAndCutoffWaits(t *testing.T) {
	for _, kind := range []string{"sa-row", "missing-cutoff", "existing-cutoff"} {
		for _, enabled := range []bool{false, true} {
			t.Run(kind+map[bool]string{false: "/disable", true: "/enable"}[enabled], func(t *testing.T) {
				w := saStateFixture(t, true)
				if kind == "existing-cutoff" {
					require.NoError(t, kanamepg.NewMintedTokenRevocationRepo(w.r.runtime).Revoke(w.r.ctx, string(w.sa.ID), time.Now().Add(-time.Hour), "existing", "test"))
				}
				before := saStateSnapshot(t, w)
				holder, err := w.r.runtime.Begin(w.r.ctx)
				require.NoError(t, err)
				lifecycleRollback(t, holder)
				if kind == "sa-row" {
					// Только блокирующее чтение; ordinary LOGIN не получает unsigned UPDATE.
					_, err = holder.Exec(w.r.ctx, `SELECT id FROM kaname.service_accounts WHERE id=$1 FOR UPDATE`, string(w.sa.ID))
				} else {
					_, err = holder.Exec(w.r.ctx, `INSERT INTO kaname.minted_token_revocations(subject,revoke_before,reason,revoked_by) VALUES($1,clock_timestamp(),'uncommitted','test') ON CONFLICT(subject) DO UPDATE SET reason=EXCLUDED.reason`, string(w.sa.ID))
				}
				require.NoError(t, err)
				op, err := w.execute(declarerCtx(w.r.ctx, w.actor), enabled)
				require.NoError(t, err)
				pid := receiptWaitForBlocker(t, w.r.ctx, w.r.admin, int(holder.Conn().PgConn().PID()))
				var keyWait, keyHeld, mintedRX bool
				require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT
     EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND classid=1262569302::oid AND NOT granted),
     EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND classid=1262569302::oid AND granted),
     EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='relation' AND relation='kaname.minted_token_revocations'::regclass AND mode='RowExclusiveLock' AND granted)`, pid).Scan(&keyWait, &keyHeld, &mintedRX))
				if kind == "sa-row" {
					require.False(t, keyHeld)
					require.False(t, mintedRX, "SA row предшествует minted RX")
				} else {
					require.True(t, keyWait)
					require.True(t, mintedRX, "INSERT и preflight соблюдают RX→key")
				}
				// Given проверяется ПОСЛЕ observed blocker по часам сервера: grant ещё
				// действует, а та же транзакция действительно удерживает writer в wait.
				// Медленный setup должен явно провалить Given, а не дать ложный expiry PASS.
				var liveAtWait, stillBlocked bool
				require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT expires_at>clock_timestamp(),
     $3::integer=ANY(pg_blocking_pids($2::integer))
     FROM kaname.access_bindings WHERE id=$1`, string(w.binding), pid, int(holder.Conn().PgConn().PID())).Scan(&liveAtWait, &stillBlocked))
				require.True(t, liveAtWait, "grant должен быть live после наблюдаемого blocker")
				require.True(t, stillBlocked, "тот же holder удерживает writer до expiry")
				require.Eventually(t, func() bool {
					var expired bool
					e := w.r.admin.QueryRow(w.r.ctx, `SELECT expires_at<clock_timestamp() FROM kaname.access_bindings WHERE id=$1`, string(w.binding)).Scan(&expired)
					return e == nil && expired
				}, 10*time.Second, 10*time.Millisecond)
				// Expiry уже подтверждён сервером; holder ещё не отпущен.
				require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT $2::integer=ANY(pg_blocking_pids($1::integer))`, pid, int(holder.Conn().PgConn().PID())).Scan(&stillBlocked))
				require.True(t, stillBlocked, "grant истёк во время реального ожидания")
				require.NoError(t, holder.Rollback(w.r.ctx))
				done := awaitOperation(t, w.r.ctx, w.ops, op.ID)
				require.NotNil(t, done.Error)
				require.EqualValues(t, 7, done.Error.Code)
				require.Equal(t, before, saStateSnapshot(t, w), "поздний отказ не пишет enabled/cutoff/audit/journal")
			})
		}
	}
}

func TestFullServiceAccountStateActorIsTargetAndRevokedSource(t *testing.T) {
	w := saStateFixture(t, false)
	// Прямой UC тест подставляет typed principal и не проходит authentication.
	// Здесь проверяются native v_update и отзыв источника; запрет аутентификации
	// отключённого SA проверяет отдельная authentication полоса, не этот тест.
	self := operations.WithPrincipal(w.r.ctx, operations.Principal{Type: "service_account", ID: string(w.sa.ID)})
	op, err := w.execute(self, true)
	require.NoError(t, err)
	require.Nil(t, awaitOperation(t, w.r.ctx, w.ops, op.ID).Error)
	op, err = w.execute(self, false)
	require.NoError(t, err)
	require.Nil(t, awaitOperation(t, w.r.ctx, w.ops, op.ID).Error)
	require.False(t, saStateEnabled(t, w), "OLD разрешает субъекту отключить самого себя")
	// Отзываем точно self binding настоящим full participant и коммитим до
	// отрицательного вопроса; enabled сам по себе не удаляет выдачу v_update.
	selfIntent := w.r.intent(w.r.a)
	selfIntent.Kind = kaname.AuthorityBinding
	selfRevoke, err := w.full.ParticipantAuthorityWriter(w.r.ctx, selfIntent)
	require.NoError(t, err)
	lifecycleWriterCleanup(t, selfRevoke)
	_, err = selfRevoke.AccessBindingsW().RevokeGuarded(w.r.ctx, w.selfBinding, domain.UserID(w.actor))
	require.NoError(t, err)
	require.NoError(t, selfRevoke.Commit(w.r.ctx))
	before := saStateSnapshot(t, w)
	op, err = w.execute(self, true)
	require.NoError(t, err)
	done := awaitOperation(t, w.r.ctx, w.ops, op.ID)
	require.NotNil(t, done.Error)
	require.EqualValues(t, 7, done.Error.Code)
	require.Equal(t, before, saStateSnapshot(t, w), "отозванный self binding не разрешает Enable и не оставляет эффектов")
	op, err = w.execute(declarerCtx(w.r.ctx, w.actor), true)
	require.NoError(t, err)
	require.Nil(t, awaitOperation(t, w.r.ctx, w.ops, op.ID).Error)
	var selfAudits int
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.audit_outbox WHERE event_payload->>'actor'=$1 AND event_payload->>'resource_id'=$1`, string(w.sa.ID)).Scan(&selfAudits))
	require.Equal(t, 2, selfAudits, "typed principal проходит через operations.Run и audit")
	// Реальная committed смена источника, не подмена checker отрицательным stub.
	intent := w.r.intent(w.r.a)
	intent.Kind = kaname.AuthorityBinding
	revoke, err := w.full.ParticipantAuthorityWriter(w.r.ctx, intent)
	require.NoError(t, err)
	lifecycleWriterCleanup(t, revoke)
	_, err = revoke.AccessBindingsW().RevokeGuarded(w.r.ctx, w.binding, domain.UserID(w.actor))
	require.NoError(t, err)
	require.NoError(t, revoke.Commit(w.r.ctx))
	before = saStateSnapshot(t, w)
	op, err = w.execute(declarerCtx(w.r.ctx, w.actor), false)
	require.NoError(t, err)
	done = awaitOperation(t, w.r.ctx, w.ops, op.ID)
	require.NotNil(t, done.Error)
	require.EqualValues(t, 7, done.Error.Code)
	require.Equal(t, before, saStateSnapshot(t, w))
}

func TestFullServiceAccountStateRollbackCancelAndNoLateCutoffWait(t *testing.T) {
	w := saStateFixture(t, false)
	before := saStateSnapshot(t, w)
	opened, err := w.factory.ServiceAccountStateWriter(w.r.ctx, w.sa.ID, false, w.actorSubject())
	require.NoError(t, err)
	lifecycleWriterCleanup(t, opened)
	_, err = opened.ServiceAccountsW().SetEnabled(w.r.ctx, w.sa.ID, false)
	require.NoError(t, err)
	require.NoError(t, opened.EmitAuditEvent(w.r.ctx, service.AuditEvent{EventType: "iam.service_account.disabled", TenantAccountID: w.r.a, Payload: map[string]any{"actor": w.actor, "resource_id": string(w.sa.ID)}}))
	cancelled, cancel := context.WithCancel(w.r.ctx)
	cancel()
	require.NoError(t, opened.Rollback(cancelled))
	require.Equal(t, before, saStateSnapshot(t, w))
	// После preflight конкурирующий настоящий UPSERT ждёт key, а не наш body.
	require.NoError(t, kanamepg.NewMintedTokenRevocationRepo(w.r.runtime).Revoke(w.r.ctx, string(w.sa.ID), time.Now().Add(-time.Hour), "existing", "test"))
	opened, err = w.factory.ServiceAccountStateWriter(w.r.ctx, w.sa.ID, false, w.actorSubject())
	require.NoError(t, err)
	lifecycleWriterCleanup(t, opened)
	done := lifecycleAsync(t, w.r.ctx, func(ctx context.Context) error {
		return kanamepg.NewMintedTokenRevocationRepo(w.r.runtime).Revoke(ctx, string(w.sa.ID), time.Now(), "concurrent", "test")
	})
	var ownerPID int
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT pid FROM pg_locks WHERE locktype='advisory' AND classid=1262569302::oid AND objid=(hashtext($1)::bigint & 4294967295)::oid AND granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())`, string(w.sa.ID)).Scan(&ownerPID))
	receiptWaitForBlocker(t, w.r.ctx, w.r.admin, ownerPID)
	bodyCtx, bodyCancel := context.WithTimeout(w.r.ctx, 3*time.Second)
	defer bodyCancel()
	_, err = opened.ServiceAccountsW().SetEnabled(bodyCtx, w.sa.ID, false)
	require.NoError(t, err)
	require.NoError(t, opened.Commit(bodyCtx))
	require.NoError(t, lifecycleResult(t, w.r.ctx, done))
	require.False(t, saStateEnabled(t, w))
	// Отмена во время cutoff-key ожидания освобождает SA row и leased connection.
	holder, err := w.r.runtime.Begin(w.r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, holder)
	_, err = holder.Exec(w.r.ctx, `INSERT INTO kaname.minted_token_revocations(subject,revoke_before,reason,revoked_by) VALUES($1,clock_timestamp(),'held','test') ON CONFLICT(subject) DO UPDATE SET reason=EXCLUDED.reason`, string(w.sa.ID))
	require.NoError(t, err)
	waitCtx, waitCancel := context.WithCancel(w.r.ctx)
	stopped := lifecycleAsync(t, waitCtx, func(ctx context.Context) error {
		v, e := w.factory.ServiceAccountStateWriter(ctx, w.sa.ID, true, w.actorSubject())
		if v != nil {
			_ = v.Rollback(context.WithoutCancel(ctx))
		}
		return e
	})
	receiptWaitForBlocker(t, w.r.ctx, w.r.admin, int(holder.Conn().PgConn().PID()))
	waitCancel()
	require.Error(t, lifecycleResult(t, w.r.ctx, stopped))
	require.NoError(t, holder.Rollback(w.r.ctx))
	next, err := w.factory.ServiceAccountStateWriter(w.r.ctx, w.sa.ID, true, w.actorSubject())
	require.NoError(t, err)
	require.NoError(t, next.Rollback(w.r.ctx))
}

func TestMintedCutoffSharedKeyDirectDMLLocalityAndCleanup(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	holder, err := r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, holder)
	_, err = holder.Exec(r.ctx, `INSERT INTO kaname.minted_token_revocations(subject,revoke_before,reason,revoked_by) VALUES('cutoff-one',clock_timestamp()-interval '1 day','first','actor')`)
	require.NoError(t, err)
	var distinct bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT hashtext('cutoff-one')<>hashtext('cutoff-two')`).Scan(&distinct))
	require.True(t, distinct)
	// Чужой subject проходит до отпускания первого; нет SRE/global таблицы.
	ctx, cancel := context.WithTimeout(r.ctx, 3*time.Second)
	defer cancel()
	require.NoError(t, kanamepg.NewMintedTokenRevocationRepo(r.runtime).Revoke(ctx, "cutoff-two", time.Now(), "other", "actor"))
	done := lifecycleAsync(t, r.ctx, func(ctx context.Context) error {
		return kanamepg.NewMintedTokenRevocationRepo(r.runtime).Revoke(ctx, "cutoff-one", time.Now(), "second", "actor")
	})
	receiptWaitForBlocker(t, r.ctx, r.admin, int(holder.Conn().PgConn().PID()))
	require.NoError(t, holder.Commit(r.ctx))
	require.NoError(t, lifecycleResult(t, r.ctx, done))
	// Неупорядоченный UPDATE не пытается ждать key уже после tuple lock.
	_, err = r.runtime.Exec(r.ctx, `UPDATE kaname.minted_token_revocations SET reason='unordered' WHERE subject='cutoff-one'`)
	var pe *pgconn.PgError
	require.ErrorAs(t, err, &pe)
	require.Equal(t, "42501", pe.Code)
	var reason string
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT reason FROM kaname.minted_token_revocations WHERE subject='cutoff-one'`).Scan(&reason))
	require.Equal(t, "second", reason)
	var cutoff time.Time
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT revoke_before FROM kaname.minted_token_revocations WHERE subject='cutoff-one'`).Scan(&cutoff))
	repo := kanamepg.NewMintedTokenRevocationRepo(r.runtime)
	require.NoError(t, repo.Revoke(r.ctx, "cutoff-one", cutoff.Add(-time.Hour), "losing", "losing-actor"))
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT reason FROM kaname.minted_token_revocations WHERE subject='cutoff-one'`).Scan(&reason))
	require.Equal(t, "second", reason)
	require.NoError(t, repo.Revoke(r.ctx, "cutoff-one", cutoff, "tie", "tie-actor"))
	var revoker string
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT reason,revoked_by FROM kaname.minted_token_revocations WHERE subject='cutoff-one'`).Scan(&reason, &revoker))
	require.Equal(t, "tie", reason)
	require.Equal(t, "tie-actor", revoker)
	require.NoError(t, kanamepg.NewMintedTokenRevocationRepo(r.runtime).Revoke(r.ctx, "cutoff-old", time.Now().Add(-48*time.Hour), "old", "actor"))
	n, _, err := kanamepg.NewMintedTokenRevocationRepo(r.runtime).SweepStaleCutoffs(r.ctx, time.Hour, 10)
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	var private bool
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(current_user,'kaname._authority_minted_cutoff_key_v3(text)','EXECUTE') OR has_function_privilege(current_user,'kaname._authority_minted_cutoff_order_v3()','EXECUTE')`).Scan(&private))
	require.False(t, private)
}

func TestFullServiceAccountStateQueuedTruncatePrecedesKey(t *testing.T) {
	w := saStateFixture(t, false)
	insert, err := w.r.runtime.Begin(w.r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, insert)
	_, err = insert.Exec(w.r.ctx, `INSERT INTO kaname.minted_token_revocations(subject,revoke_before,reason,revoked_by) VALUES($1,clock_timestamp(),'held','test')`, string(w.sa.ID))
	require.NoError(t, err)
	truncate := lifecycleAsync(t, w.r.ctx, func(ctx context.Context) error {
		_, e := w.r.runtime.Exec(ctx, `TRUNCATE kaname.minted_token_revocations`)
		return e
	})
	truncatePID := receiptWaitForBlocker(t, w.r.ctx, w.r.admin, int(insert.Conn().PgConn().PID()))
	pending := lifecycleAsync(t, w.r.ctx, func(ctx context.Context) error {
		v, e := w.factory.ServiceAccountStateWriter(ctx, w.sa.ID, false, w.actorSubject())
		if v != nil {
			_ = v.Rollback(context.WithoutCancel(ctx))
		}
		return e
	})
	waiter := receiptWaitForBlocker(t, w.r.ctx, w.r.admin, truncatePID)
	var rxWait, keyHeld bool
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT
 EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='relation' AND relation='kaname.minted_token_revocations'::regclass AND mode='RowExclusiveLock' AND NOT granted),
 EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND classid=1262569302::oid AND granted)`, waiter).Scan(&rxWait, &keyHeld))
	require.True(t, rxWait)
	require.False(t, keyHeld, "key не получен перед queued TRUNCATE")
	require.NoError(t, insert.Commit(w.r.ctx))
	require.NoError(t, lifecycleResult(t, w.r.ctx, truncate))
	require.NoError(t, lifecycleResult(t, w.r.ctx, pending))
	require.True(t, saStateEnabled(t, w), "preflight не выполняет body")
}

func TestFullServiceAccountStateReadinessPinsSharedCutoffGuard(t *testing.T) {
	w := saStateFixture(t, false)
	require.NoError(t, w.full.ValidateFullAuthorityBundle(w.r.ctx, w.r.bundle))
	_, err := w.r.admin.Exec(w.r.ctx, `ALTER TABLE kaname.minted_token_revocations DISABLE TRIGGER authority_minted_cutoff_order_v3`)
	require.NoError(t, err)
	defer func() {
		_, e := w.r.admin.Exec(w.r.ctx, `ALTER TABLE kaname.minted_token_revocations ENABLE TRIGGER authority_minted_cutoff_order_v3`)
		require.NoError(t, e)
	}()
	require.Error(t, w.full.ValidateFullAuthorityBundle(w.r.ctx, w.r.bundle))
	_, err = w.r.admin.Exec(w.r.ctx, `ALTER TABLE kaname.minted_token_revocations ENABLE TRIGGER authority_minted_cutoff_order_v3`)
	require.NoError(t, err)
	require.NoError(t, w.full.ValidateFullAuthorityBundle(w.r.ctx, w.r.bundle))
	_, err = w.r.admin.Exec(w.r.ctx, `GRANT EXECUTE ON FUNCTION kaname._authority_minted_cutoff_key_v3(text) TO PUBLIC`)
	require.NoError(t, err)
	defer func() {
		_, e := w.r.admin.Exec(w.r.ctx, `REVOKE ALL ON FUNCTION kaname._authority_minted_cutoff_key_v3(text) FROM PUBLIC`)
		require.NoError(t, e)
	}()
	require.Error(t, w.full.ValidateFullAuthorityBundle(w.r.ctx, w.r.bundle))
}

// Goose исполняет настоящую latest migration; предыдущая версия берётся из FS.
func saStateMigrationDB(t *testing.T, r protocolRig) (*sql.DB, int64, int64) {
	t.Helper()
	entries, err := fs.ReadDir(migrations.FS, ".")
	require.NoError(t, err)
	var own, previous, latest int64
	var versions []int64
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		head, _, ok := strings.Cut(entry.Name(), "_")
		require.True(t, ok)
		n, e := strconv.ParseInt(head, 10, 64)
		require.NoError(t, e)
		versions = append(versions, n)
		if n > latest {
			latest = n
		}
		if strings.HasSuffix(entry.Name(), "_service_account_state_prepares_all_cutoff_waits.sql") {
			require.Zero(t, own)
			own = n
		}
	}
	require.NotZero(t, own)
	require.GreaterOrEqual(t, latest, own)
	for _, n := range versions {
		if n < own && n > previous {
			previous = n
		}
	}
	require.NotZero(t, previous)
	db := stdlib.OpenDB(*r.admin.Config().ConnConfig)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	// Новые append снимаются только в nonfull GIVEN; cleanup возвращает всю цепь.
	require.NoError(t, goose.DownTo(db, ".", own))
	t.Cleanup(func() { require.NoError(t, goose.UpTo(db, ".", latest)) })
	version, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Equal(t, own, version)
	return db, own, previous
}
func TestServiceAccountStateMigrationGooseDownUpRestoresExact24(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	db, own, previous := saStateMigrationDB(t, r)
	t.Cleanup(func() { require.NoError(t, goose.UpTo(db, ".", own)) })
	require.NoError(t, goose.Down(db, "."))
	version, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Equal(t, previous, version)
	var readiness, grant string
	var absent, ready bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
 (SELECT encode(sha256(convert_to(prosrc,'UTF8')),'hex') FROM pg_proc WHERE oid='kaname._authority_full_contract_storage_v3()'::regprocedure),
 (SELECT encode(sha256(convert_to(prosrc,'UTF8')),'hex') FROM pg_proc WHERE oid='kaname.authority_protocol_grant_runtime(regrole)'::regprocedure),
 to_regprocedure('kaname.authority_sa_state_preflight_v3(text,boolean,text)') IS NULL
 AND to_regprocedure('kaname._authority_minted_cutoff_key_v3(text)') IS NULL
 AND to_regprocedure('kaname._authority_minted_cutoff_order_v3()') IS NULL,
 kaname._authority_full_contract_storage_v3()`).Scan(&readiness, &grant, &absent, &ready))
	require.Equal(t, "65cb032daa7372dfe482ee15bf8f4f3b179ecf24a82028af160eca6b8e65a72f", readiness)
	require.Equal(t, "4b5037c020ac6314ccb6e335658c8ec82ec21829a8e0c4b1d5806b6a2c355eb7", grant)
	require.True(t, absent)
	require.True(t, ready)
	require.NoError(t, goose.UpTo(db, ".", own))
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT kaname._authority_full_contract_storage_v3()`).Scan(&ready))
	require.True(t, ready)
	var public, private bool
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(current_user,'kaname.authority_sa_state_preflight_v3(text,boolean,text)','EXECUTE'),has_function_privilege(current_user,'kaname._authority_minted_cutoff_key_v3(text)','EXECUTE')`).Scan(&public, &private))
	require.True(t, public)
	require.False(t, private)
	require.NoError(t, lifecycleOwner(r).PrepareAuthorityBundle(r.ctx, r.bundle))
	full, _ := fullContractActivate(t, r)
	require.NoError(t, full.ValidateFullAuthorityBundle(r.ctx, r.bundle))
}
func TestServiceAccountStateMigrationGooseDownRefusesFullWithoutChanges(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	db, own, _ := saStateMigrationDB(t, r)
	require.NoError(t, lifecycleOwner(r).PrepareAuthorityBundle(r.ctx, r.bundle))
	full, _ := fullContractActivate(t, r)
	before := rolePrelockMigrationSnapshot(t, r)
	err := goose.Down(db, ".")
	var pe *pgconn.PgError
	require.ErrorAs(t, err, &pe)
	require.Equal(t, "P1036", pe.Code)
	version, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Equal(t, own, version)
	require.Equal(t, before, rolePrelockMigrationSnapshot(t, r))
	require.NoError(t, full.ValidateFullAuthorityBundle(r.ctx, r.bundle))
}
