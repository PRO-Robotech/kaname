// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/multitracer"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

const saWholeCommitMessage = "fixture SA deferred commit serialization"

type saWholeSQLKey struct{}
type saWholeTransaction struct {
	pid   uint32
	xid   string
	start time.Time
}
type saWholeTrace struct {
	admin                     *pgxpool.Pool
	first, release            chan struct{}
	once                      sync.Once
	mu                        sync.Mutex
	active                    bool
	captures, entries, bodies int
	conflicts                 int
	transactions              []saWholeTransaction
	observationErrors         []error
}

func (tr *saWholeTrace) resume() { tr.once.Do(func() { close(tr.release) }) }
func (tr *saWholeTrace) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	tr.mu.Lock()
	active := tr.active
	tr.mu.Unlock()
	if !active {
		return ctx
	}
	if strings.HasPrefix(data.SQL, "SELECT kaname.authority_protocol_enter_full_v3(") {
		tr.mu.Lock()
		tr.entries++
		tr.mu.Unlock()
	}
	if strings.EqualFold(strings.TrimSpace(data.SQL), "commit") {
		// Только наблюдение через ДРУГОЕ соединение. XID создаёт реальный body,
		// прибор не выделяет его и не меняет состояние проверяемой транзакции.
		identity := saWholeTransaction{pid: conn.PgConn().PID()}
		err := tr.admin.QueryRow(ctx, `SELECT backend_xid::text,xact_start FROM pg_stat_activity WHERE pid=$1 AND datname=current_database()`, identity.pid).Scan(&identity.xid, &identity.start)
		tr.mu.Lock()
		if err != nil {
			tr.observationErrors = append(tr.observationErrors, err)
		}
		tr.transactions = append(tr.transactions, identity)
		tr.mu.Unlock()
	}
	return context.WithValue(ctx, saWholeSQLKey{}, data.SQL)
}
func (tr *saWholeTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	sql, observed := ctx.Value(saWholeSQLKey{}).(string)
	if !observed {
		return
	}
	tr.mu.Lock()
	if data.Err == nil {
		if sql == "SELECT xmin::text,to_jsonb(o) FROM kaname.service_accounts o WHERE id=$1" {
			tr.captures++
		}
		if strings.HasPrefix(sql, "UPDATE service_accounts SET enabled = $2 WHERE id = $1 RETURNING ") {
			tr.bodies++
		}
	}
	var pe *pgconn.PgError
	failedCommit := strings.EqualFold(strings.TrimSpace(sql), "commit") && errors.As(data.Err, &pe) && pe.Code == "40001" && pe.Message == saWholeCommitMessage
	first := false
	if failedCommit {
		tr.conflicts++
		first = tr.conflicts == 1
	}
	tr.mu.Unlock()
	if first {
		// Сервер уже отверг COMMIT и откатил body; runner ещё не получил ошибку.
		close(tr.first)
		select {
		case <-tr.release:
		case <-ctx.Done():
		}
	}
}

// Снимок всех бизнес-строк и поколений этой изолированной fixture. Тестовая
// sequence и строка LRO не входят: sequence наблюдает попытки сквозь rollback,
// LRO законно существует независимо от атомарной транзакции изменения SA.
func saWholeSnapshot(t *testing.T, w saStateWorld) string {
	t.Helper()
	var state string
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT jsonb_build_array(
 (SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]') FROM kaname.service_accounts x),
 (SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]') FROM kaname.minted_token_revocations x),
 (SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]') FROM kaname.audit_outbox x),
 (SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]') FROM kaname.resource_journal x),
 (SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]') FROM kaname.resource_reconcile_outbox x),
 (SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]') FROM kaname.subject_change_outbox x),
 (SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]') FROM kaname.fga_outbox x),
 (SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]') FROM kaname.relation_fact x),
 (SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]') FROM kaname.resource_mirror x),
 (SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]') FROM kaname.resource_parent_edge x),
 (SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]') FROM kaname.access_bindings x),
 (SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]') FROM kaname.access_binding_subjects x),
 (SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]') FROM kaname.access_binding_target_members x),
 (SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]') FROM kaname.access_binding_emitted_tuples x),
 (SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]') FROM kaname.authority_policy_epoch x),
 (SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]') FROM kaname.authority_binding_epoch x),
 (SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]') FROM kaname.authority_policy_carrier_pending x))::text`).Scan(&state))
	return state
}

// Настоящий deferred server 40001 — тестовая инъекция ошибки COMMIT, а не
// утверждение естественной carrier race у SA. Порты и ошибки Go не подменяются.
func TestFullServiceAccountStateWholeAttemptInjectedCommitOutcomes(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		name, event := "Disable", "iam.service_account.disabled"
		if enabled {
			name, event = "Enable", "iam.service_account.enabled"
		}
		for _, outcome := range []string{"live", "revoked", "exhausted"} {
			t.Run(name+"/"+outcome, func(t *testing.T) {
				w := saStateFixture(t, false)
				if enabled {
					op, err := w.execute(declarerCtx(w.r.ctx, w.actor), false)
					require.NoError(t, err)
					require.Nil(t, awaitOperation(t, w.r.ctx, w.ops, op.ID).Error)
				}
				require.Equal(t, !enabled, saStateEnabled(t, w))
				trace := &saWholeTrace{admin: w.r.admin, first: make(chan struct{}), release: make(chan struct{})}
				cfg := w.r.runtime.Config()
				previous := cfg.ConnConfig.Tracer
				combined := multitracer.New(trace)
				if previous != nil {
					combined = multitracer.New(previous, trace)
				}
				cfg.ConnConfig.Tracer = combined
				if previous != nil {
					if _, batch := previous.(pgx.BatchTracer); !batch {
						cfg.ConnConfig.Tracer = saRestageQueryOnly{combined}
					}
				}
				pool, err := pgxpool.NewWithConfig(w.r.ctx, cfg)
				require.NoError(t, err)
				t.Cleanup(pool.Close)
				revokeRepo := w.full
				base := kanamepg.New(pool, nil)
				contract, err := kanamepg.NewFullWriterContract(w.r.ctx, base, w.r.bundle)
				require.NoError(t, err)
				w.full, err = base.WithFullWriterContract(contract)
				require.NoError(t, err)
				w.factory, err = kanamepg.NewServiceAccountStateWriters(w.r.ctx, w.full, w.r.bundle)
				require.NoError(t, err)
				// Инъектор установлен владельцем только в собственной test DB.
				// Аргументы trigger привязывают его к одной SA и одному audit event.
				_, err = w.r.admin.Exec(w.r.ctx, fmt.Sprintf(`CREATE SEQUENCE kaname.sa_whole_retry_seq;
CREATE FUNCTION kaname.sa_whole_commit_retry() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE attempt bigint;
BEGIN
 IF NEW.event_payload->>'resource_id'=TG_ARGV[0] AND NEW.event_type=TG_ARGV[1] THEN
  IF lower(btrim(current_query())) NOT IN ('commit','commit;') THEN
   RAISE EXCEPTION 'SA injection must run at actual COMMIT' USING ERRCODE='P0001';
  END IF;
  attempt:=nextval('kaname.sa_whole_retry_seq');
  IF attempt=1 OR TG_ARGV[2]='exhausted' THEN
   RAISE EXCEPTION '%s' USING ERRCODE='40001';
  END IF;
 END IF;
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION kaname.sa_whole_commit_retry() FROM PUBLIC;
CREATE CONSTRAINT TRIGGER sa_whole_commit_retry AFTER INSERT ON kaname.audit_outbox DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION kaname.sa_whole_commit_retry('%s','%s','%s')`, saWholeCommitMessage, w.sa.ID, event, outcome))
				require.NoError(t, err)
				t.Cleanup(func() {
					_, err := w.r.admin.Exec(w.r.ctx, `DROP TRIGGER IF EXISTS sa_whole_commit_retry ON kaname.audit_outbox; DROP FUNCTION IF EXISTS kaname.sa_whole_commit_retry(); DROP SEQUENCE IF EXISTS kaname.sa_whole_retry_seq`)
					require.NoError(t, err)
				})
				var deferred bool
				require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT tgdeferrable AND tginitdeferred FROM pg_trigger WHERE tgrelid='kaname.audit_outbox'::regclass AND tgname='sa_whole_commit_retry'`).Scan(&deferred))
				require.True(t, deferred)
				before := saWholeSnapshot(t, w)
				var cutoffBefore string
				require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT coalesce((SELECT to_jsonb(c) FROM kaname.minted_token_revocations c WHERE subject=$1),'null'::jsonb)::text`, string(w.sa.ID)).Scan(&cutoffBefore))
				var operationsBefore int
				require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.operations`).Scan(&operationsBefore))
				var auditsBefore int
				require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.audit_outbox WHERE event_type=$1 AND event_payload->>'resource_id'=$2`, event, string(w.sa.ID)).Scan(&auditsBefore))
				// Отпускание барьера и настоящий drain worker предшествуют DDL cleanup
				// и pool.Close. Используется исходный rig context без нового срока.
				t.Cleanup(func() {
					trace.resume()
					require.NoError(t, operations.Wait(w.r.ctx), "worker должен завершиться до закрытия своего пула")
				})
				trace.mu.Lock()
				trace.active = true
				trace.mu.Unlock()
				op, err := w.execute(declarerCtx(w.r.ctx, w.actor), enabled)
				require.NoError(t, err)
				select {
				case <-trace.first:
				case <-w.r.ctx.Done():
					t.Fatalf("не наблюдался injected server COMMIT 40001: %v", w.r.ctx.Err())
				}
				require.Equal(t, before, saWholeSnapshot(t, w), "неуспешный COMMIT откатил state/cutoff/audit/проекции/поколения")
				trace.mu.Lock()
				captures, entries, bodies, conflicts := trace.captures, trace.entries, trace.bodies, trace.conflicts
				trace.mu.Unlock()
				require.Equal(t, []int{1, 1, 1, 1}, []int{captures, entries, bodies, conflicts})
				expected := before
				if outcome == "revoked" {
					// Другой настоящий writer фиксирует отзыв, пока первая SA TX уже
					// отменена сервером; следующая попытка обязана перечитать authority.
					intent := w.r.intent(w.r.a)
					intent.Kind = kaname.AuthorityBinding
					revoke, err := revokeRepo.ParticipantAuthorityWriter(w.r.ctx, intent)
					require.NoError(t, err)
					lifecycleWriterCleanup(t, revoke)
					_, err = revoke.AccessBindingsW().RevokeGuarded(w.r.ctx, w.binding, domain.UserID(w.actor))
					require.NoError(t, err)
					require.NoError(t, revoke.Commit(w.r.ctx))
					var revoked bool
					require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT revoked_at IS NOT NULL FROM kaname.access_bindings WHERE id=$1`, string(w.binding)).Scan(&revoked))
					require.True(t, revoked)
					expected = saWholeSnapshot(t, w)
				}
				trace.resume()
				done := awaitOperation(t, w.r.ctx, w.ops, op.ID)
				// awaitOperation сначала делает настоящий drain, затем читает свою
				// terminal строку. Повторы TX не создают новые публичные операции.
				require.Equal(t, op.ID, done.ID)
				require.True(t, done.Done)
				var operationsAfter int
				require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.operations`).Scan(&operationsAfter))
				require.Equal(t, operationsBefore+1, operationsAfter)
				trace.mu.Lock()
				captures, entries, bodies, conflicts = trace.captures, trace.entries, trace.bodies, trace.conflicts
				transactions := append([]saWholeTransaction(nil), trace.transactions...)
				observationErrors := append([]error(nil), trace.observationErrors...)
				trace.mu.Unlock()
				require.Empty(t, observationErrors)
				seen := map[string]bool{}
				for _, tx := range transactions {
					require.NotZero(t, tx.pid)
					require.NotEmpty(t, tx.xid)
					require.False(t, tx.start.IsZero())
					require.False(t, seen[tx.xid], "каждый body/Commit должен принадлежать новой настоящей TX")
					seen[tx.xid] = true
				}
				var attempts int
				require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT last_value FROM kaname.sa_whole_retry_seq`).Scan(&attempts))
				switch outcome {
				case "live":
					require.Nil(t, done.Error)
					require.Equal(t, []int{2, 2, 2, 1, 2, 2}, []int{captures, entries, bodies, conflicts, len(transactions), attempts})
					require.Equal(t, enabled, saStateEnabled(t, w))
					var audits, cutoffs int
					require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT
 (SELECT count(*) FROM kaname.audit_outbox WHERE event_type=$1 AND event_payload->>'resource_id'=$2),
 (SELECT count(*) FROM kaname.minted_token_revocations WHERE subject=$2 AND reason='owner is no longer active' AND revoked_by='kaname:owner-deactivated')`, event, string(w.sa.ID)).Scan(&audits, &cutoffs))
					require.Equal(t, auditsBefore+1, audits)
					require.Equal(t, 1, cutoffs, "Enable сохраняет прежний cutoff; Disable фиксирует единственный cutoff")
					if enabled {
						var cutoffAfter string
						require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT to_jsonb(c)::text FROM kaname.minted_token_revocations c WHERE subject=$1`, string(w.sa.ID)).Scan(&cutoffAfter))
						require.Equal(t, cutoffBefore, cutoffAfter)
					}
				case "revoked":
					require.NotNil(t, done.Error)
					require.EqualValues(t, codes.PermissionDenied, done.Error.Code)
					require.Equal(t, []int{2, 2, 1, 1, 1, 1}, []int{captures, entries, bodies, conflicts, len(transactions), attempts})
					require.Equal(t, expected, saWholeSnapshot(t, w))
				case "exhausted":
					require.NotNil(t, done.Error)
					require.EqualValues(t, codes.Aborted, done.Error.Code)
					require.Equal(t, iamerr.SerializationConflictSyncText, done.Error.Message)
					require.Equal(t, []int{3, 3, 3, 3, 3, 3}, []int{captures, entries, bodies, conflicts, len(transactions), attempts})
					require.Equal(t, before, saWholeSnapshot(t, w))
				}
				authorityWaitReleased(t, pool)
			})
		}
	}
}
