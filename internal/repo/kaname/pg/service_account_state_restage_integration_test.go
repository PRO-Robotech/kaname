// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/multitracer"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Бюджет берётся из production SOURCE: тест не вводит свой лимит попыток.
func saRestageAttemptBudget(t *testing.T) int {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "writer_protocol.go", nil, 0)
	require.NoError(t, err)
	for _, declaration := range file.Decls {
		decl, ok := declaration.(*ast.GenDecl)
		if !ok || decl.Tok != token.CONST {
			continue
		}
		for _, specification := range decl.Specs {
			spec := specification.(*ast.ValueSpec)
			if len(spec.Names) != 1 || spec.Names[0].Name != "authorityEntryAttempts" {
				continue
			}
			require.Len(t, spec.Values, 1)
			value, ok := spec.Values[0].(*ast.BasicLit)
			require.True(t, ok, "бюджет должен оставаться явной production-константой")
			budget, err := strconv.Atoi(value.Value)
			require.NoError(t, err)
			require.Greater(t, budget, 1)
			return budget
		}
	}
	t.Fatal("production authorityEntryAttempts не найден")
	return 0
}

type saRestageRequestKey struct{}
type saRestageSQLKey struct{}
type saRestageGate struct {
	pid                                 uint32
	attempt                             int
	captured, rolledBack, readCommitted bool
	txStatus                            byte
	release                             chan struct{}
}
type saRestageTrace struct {
	gates                               chan saRestageGate
	stop                                <-chan struct{}
	captures, entries, bodies           int
	captured, rolledBack, readCommitted bool
	errors                              []error
}

func (tr *saRestageTrace) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if ctx.Value(saRestageRequestKey{}) == nil {
		return ctx
	}
	if strings.HasPrefix(data.SQL, "SELECT kaname.authority_protocol_enter_full_v3(") {
		tr.entries++
		gate := saRestageGate{conn.PgConn().PID(), tr.entries, tr.captured, tr.rolledBack, tr.readCommitted, conn.PgConn().TxStatus(), make(chan struct{})}
		// Никакого запроса на наблюдаемом conn: даже выделение xid здесь
		// изменило бы предпосылку fresh admission. RR уже закончен.
		select {
		case tr.gates <- gate:
			select {
			case <-gate.release:
			case <-tr.stop:
			case <-ctx.Done():
			}
		case <-tr.stop:
		case <-ctx.Done():
		}
	}
	if strings.HasPrefix(data.SQL, "UPDATE service_accounts SET enabled = $2 WHERE id = $1 RETURNING ") {
		tr.bodies++
	}
	return context.WithValue(ctx, saRestageSQLKey{}, data.SQL)
}
func (tr *saRestageTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	sql, marked := ctx.Value(saRestageSQLKey{}).(string)
	if !marked {
		return
	}
	if data.Err != nil {
		tr.errors = append(tr.errors, data.Err)
		return
	}
	switch sql {
	case "begin isolation level repeatable read read only":
		tr.captured, tr.rolledBack, tr.readCommitted = false, false, false
	case "SELECT xmin::text,to_jsonb(o) FROM kaname.service_accounts o WHERE id=$1":
		tr.captures++
		tr.captured = true
	case "rollback":
		if tr.captured {
			tr.rolledBack = true
		}
	case "begin isolation level read committed":
		tr.readCommitted = true
	}
}

// Сохраняются callbacks прежнего tracer и выбор production batch-ветки.
// multitracer сам реализует BatchTracer; Query-only predecessor не получает его.
type saRestageNonBatch interface {
	pgx.QueryTracer
	pgx.CopyFromTracer
	pgx.PrepareTracer
	pgx.ConnectTracer
	pgxpool.AcquireTracer
	pgxpool.ReleaseTracer
}
type saRestageQueryOnly struct{ saRestageNonBatch }

func (tr *saRestageTrace) combine(previous pgx.QueryTracer) pgx.QueryTracer {
	combined := multitracer.New(tr)
	if previous == nil {
		return combined
	}
	combined = multitracer.New(previous, tr)
	if _, batch := previous.(pgx.BatchTracer); batch {
		return combined
	}
	return saRestageQueryOnly{combined}
}

func saRestageAudit(actor string, sa domain.ServiceAccount, event string) service.AuditEvent {
	return service.AuditEvent{EventType: event, TenantAccountID: string(sa.AccountID), Payload: map[string]any{
		"actor": actor, "resource_type": "service_account", "resource_id": string(sa.ID),
		"account_id": string(sa.AccountID), "enabled": sa.Enabled,
	}}
}

func saRestageMetadataCommit(t *testing.T, w saStateWorld, factory *kanamepg.MetadataMutationWriters, attempt int) {
	t.Helper()
	var before string
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT xmin::text FROM kaname.service_accounts WHERE id=$1`, string(w.sa.ID)).Scan(&before))
	patch := w.sa
	patch.Description = domain.Description(fmt.Sprintf("committed concurrent metadata %d", attempt))
	writer, err := factory.ServiceAccountMetadataWriter(w.r.ctx, patch, []string{"description"}, w.actorSubject())
	require.NoError(t, err)
	lifecycleWriterCleanup(t, writer)
	updated, err := writer.ServiceAccountsW().Update(w.r.ctx, patch, []string{"description"})
	require.NoError(t, err)
	audit := saRestageAudit(w.actor, updated, "iam.service_account.updated")
	delete(audit.Payload, "enabled")
	audit.Payload["changed_fields"] = []string{"description"}
	require.NoError(t, writer.EmitAuditEvent(w.r.ctx, audit))
	require.NoError(t, writer.Commit(w.r.ctx))
	var after, description string
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT xmin::text,description FROM kaname.service_accounts WHERE id=$1`, string(w.sa.ID)).Scan(&after, &description))
	require.NotEqual(t, before, after, "настоящий committed OLD, не подмена результата tracer")
	require.Equal(t, string(patch.Description), description)
}

// §8.3: новое OLD/поколение до admission требует полного bounded restage.
// Ошибки factory проверяются напрямую, без маскировки через Operation.Error.
func TestFullServiceAccountStateRestagesCommittedConcurrentChanges(t *testing.T) {
	budget := saRestageAttemptBudget(t)
	for _, name := range []string{"committed_old_change", "every_attempt_changes", "revoked_source"} {
		t.Run(name, func(t *testing.T) {
			w := saStateFixture(t, false)
			require.True(t, saStateEnabled(t, w))
			metadata, err := kanamepg.NewMetadataMutationWriters(w.r.ctx, w.full, w.r.bundle)
			require.NoError(t, err)
			stop := make(chan struct{})
			trace := &saRestageTrace{gates: make(chan saRestageGate), stop: stop}
			cfg := w.r.runtime.Config()
			cfg.ConnConfig.Tracer = trace.combine(cfg.ConnConfig.Tracer)
			pool, err := pgxpool.NewWithConfig(w.r.ctx, cfg)
			require.NoError(t, err)
			t.Cleanup(pool.Close)
			base := kanamepg.New(pool, nil)
			contract, err := kanamepg.NewFullWriterContract(w.r.ctx, base, w.r.bundle)
			require.NoError(t, err)
			full, err := base.WithFullWriterContract(contract)
			require.NoError(t, err)
			factory, err := kanamepg.NewServiceAccountStateWriters(w.r.ctx, full, w.r.bundle)
			require.NoError(t, err)
			expected := saStateSnapshot(t, w)
			ctx, cancel := context.WithCancel(context.WithValue(w.r.ctx, saRestageRequestKey{}, true))
			finished := make(chan struct{})
			var writer kaname.SemanticAuthorityWriter
			var openErr error
			// Регистрируется до запуска: FailNow контроллера всегда освобождает
			// pause, отменяет дочерний контекст исходного 30s rig и соединяется с worker.
			// В production rollback уже ограничен policyRollback, новый срок не вводится.
			t.Cleanup(func() {
				cancel()
				close(stop)
				<-finished
				if writer != nil {
					err := writer.Rollback(context.WithoutCancel(w.r.ctx))
					if !errors.Is(err, pgx.ErrTxClosed) {
						require.NoError(t, err)
					}
				}
			})
			go func() {
				defer close(finished)
				writer, openErr = factory.ServiceAccountStateWriter(ctx, w.sa.ID, false, w.actorSubject())
			}()
			gates := 0
		waiting:
			for {
				select {
				case gate := <-trace.gates:
					gates++
					require.Equal(t, gates, gate.attempt)
					require.LessOrEqual(t, gates, budget)
					require.True(t, gate.captured && gate.rolledBack && gate.readCommitted, "RR capture/rollback должны завершиться перед реальным RC admission")
					require.Equal(t, byte('T'), gate.txStatus)
					var fresh bool
					var held int
					require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT backend_xid IS NULL AND xact_start IS NOT NULL FROM pg_stat_activity WHERE pid=$1`, gate.pid).Scan(&fresh))
					require.True(t, fresh)
					require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM pg_locks WHERE pid=$1 AND granted AND locktype<>'virtualxid'`, gate.pid).Scan(&held))
					require.Zero(t, held, "ни phase/fence, ни business lock не удерживается во время конкурирующего commit")
					require.Equal(t, expected, saStateSnapshot(t, w), "предыдущая неуспешная state попытка полностью откатилась")
					if name == "every_attempt_changes" || (name == "committed_old_change" && gates == 1) {
						saRestageMetadataCommit(t, w, metadata, gates)
					} else if name == "revoked_source" && gates == 1 {
						intent := w.r.intent(w.r.a)
						intent.Kind = kaname.AuthorityBinding
						revoke, err := w.full.ParticipantAuthorityWriter(w.r.ctx, intent)
						require.NoError(t, err)
						lifecycleWriterCleanup(t, revoke)
						_, err = revoke.AccessBindingsW().RevokeGuarded(w.r.ctx, w.binding, domain.UserID(w.actor))
						require.NoError(t, err)
						require.NoError(t, revoke.Commit(w.r.ctx))
						var revoked bool
						require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT revoked_at IS NOT NULL FROM kaname.access_bindings WHERE id=$1`, string(w.binding)).Scan(&revoked))
						require.True(t, revoked)
					}
					expected = saStateSnapshot(t, w)
					close(gate.release)
				case <-finished:
					break waiting
				case <-w.r.ctx.Done():
					t.Fatalf("контроллер не завершился в исходном rig budget: %v", w.r.ctx.Err())
				}
			}
			t.Logf("factory raw error=%v; primary query errors=%v; captures=%d entries=%d", openErr, trace.errors, trace.captures, trace.entries)
			require.Equal(t, expected, saStateSnapshot(t, w), "до выдачи writer state/cutoff/audit/outbox не меняются")
			require.Zero(t, trace.bodies)
			switch name {
			case "committed_old_change":
				require.NoError(t, openErr)
				require.NotNil(t, writer)
				require.Equal(t, 2, trace.captures)
				require.Equal(t, 2, gates)
				updated, err := writer.ServiceAccountsW().SetEnabled(ctx, w.sa.ID, false)
				require.NoError(t, err)
				require.False(t, updated.Enabled)
				require.Equal(t, domain.Description("committed concurrent metadata 1"), updated.Description)
				require.NoError(t, writer.EmitAuditEvent(ctx, saRestageAudit(w.actor, updated, "iam.service_account.disabled")))
				require.NoError(t, writer.Commit(ctx))
				require.Equal(t, 1, trace.bodies)
				require.False(t, saStateEnabled(t, w))
				var audits, cutoffs int
				require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT
 (SELECT count(*) FROM kaname.audit_outbox WHERE event_payload->>'resource_id'=$1 AND event_payload->>'actor'=$2 AND event_type='iam.service_account.disabled'),
 (SELECT count(*) FROM kaname.minted_token_revocations WHERE subject=$1 AND reason='owner is no longer active' AND revoked_by='kaname:owner-deactivated')`, string(w.sa.ID), w.actor).Scan(&audits, &cutoffs))
				require.Equal(t, 1, audits)
				require.Equal(t, 1, cutoffs)
			case "every_attempt_changes":
				require.Nil(t, writer)
				require.Equal(t, budget, trace.captures)
				require.Equal(t, budget, gates)
				require.ErrorIs(t, openErr, kaname.ErrAuthorityClassificationChanged)
				require.Equal(t, codes.Aborted, status.Code(shared.MapRepoErrAt(ctx, openErr)))
			case "revoked_source":
				require.Nil(t, writer)
				require.ErrorIs(t, openErr, iamerr.ErrPermissionDenied)
				require.Equal(t, codes.PermissionDenied, status.Code(shared.MapRepoErrAt(ctx, openErr)))
			}
		})
	}
}
