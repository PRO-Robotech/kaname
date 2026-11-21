// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

var errNativeDeleteCallerRollback = errors.New("native delete: caller refuses completed pass")

type nativeDeleteQueryKey struct{}

type nativeDeleteObserver struct {
	mu    sync.Mutex
	calls int
}

// Считается завершившийся настоящий запрос: ошибки, подготовка и вызов Go-метода
// не считаются выполненным SQL. Наблюдатель не возвращает строк и не повторяет DML.
func (o *nativeDeleteObserver) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, nativeDeleteQueryKey{}, strings.Join(strings.Fields(d.SQL), " "))
}

func (o *nativeDeleteObserver) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryEndData) {
	query, _ := ctx.Value(nativeDeleteQueryKey{}).(string)
	if d.Err == nil && query == "SELECT kaname.authority_native_delete_emit_v4($1::jsonb[])" {
		o.mu.Lock()
		o.calls++
		o.mu.Unlock()
	}
}

func (o *nativeDeleteObserver) reset()     { o.mu.Lock(); o.calls = 0; o.mu.Unlock() }
func (o *nativeDeleteObserver) count() int { o.mu.Lock(); defer o.mu.Unlock(); return o.calls }

type nativeDeleteCaller struct {
	inner    *kanamepg.ReconcileAdapter
	rollback bool
}

// Сам store передаётся без обёртки: его private capabilities не скрываются.
// Ошибка вызывающего приходит ПОСЛЕ всей реальной работы, до commit WithTx.
func (r *nativeDeleteCaller) WithTx(ctx context.Context, fn func(context.Context, reconcile.ReconcileStore) error) error {
	return r.inner.WithTx(ctx, func(ctx context.Context, s reconcile.ReconcileStore) error {
		if err := fn(ctx, s); err != nil {
			return err
		}
		if r.rollback {
			return errNativeDeleteCallerRollback
		}
		return nil
	})
}

func nativeDeletePublicPool(t *testing.T, ctx context.Context, observer *nativeDeleteObserver) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(setupTestDB(t))
	require.NoError(t, err)
	cfg.ConnConfig.Tracer = observer
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = wdStatementTimeoutMS
	cfg.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"] = wdIdleInTxTimeoutMS
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	return pool
}

// Снимок строк, а не только счётчиков: частичная правка статуса/часов/payload
// тоже нарушает откат. Проверяются также побочные журналы истечения.
func nativeDeletePublicSnapshot(t *testing.T, ctx context.Context, pool *pgxpool.Pool, bid domain.AccessBindingID, subject, userID string) []string {
	t.Helper()
	queries := []struct {
		sql string
		arg any
	}{
		{`SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text FROM kaname.access_bindings t WHERE id=$1`, string(bid)},
		{`SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text FROM kaname.access_binding_target_members t WHERE binding_id=$1`, string(bid)},
		{`SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text FROM kaname.access_binding_emitted_tuples t WHERE binding_id=$1`, string(bid)},
		{`SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text FROM kaname.relation_fact t WHERE subject=$1 AND object_type='compute_instance' AND object_id LIKE 'wdi-%'`, subject},
		{`SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text FROM kaname.fga_outbox t WHERE payload->>'user'=$1 AND payload->>'object' LIKE 'compute_instance:wdi-%'`, subject},
		{`SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text FROM kaname.audit_outbox t WHERE event_payload->>'binding_id'=$1`, string(bid)},
		{`SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text FROM kaname.subject_change_outbox t WHERE subject_id=$1`, userID},
	}
	var out []string
	for _, q := range queries {
		var value string
		require.NoError(t, pool.QueryRow(ctx, q.sql, q.arg).Scan(&value))
		out = append(out, value)
	}
	return out
}

// Публичное истечение: ноль, одна и три группы (user,object). Два перекрывающихся
// правила дают два member, но четыре уникальных отношения и один delete payload
// на объект. Старая реализация обязана пройти семантику и упасть только на маршруте.
func TestReconcileNativeDelete_PublicExpiry(t *testing.T) {
	skipShort(t)
	for _, n := range []int{0, 1, 3} {
		for _, rollback := range []bool{false, true} {
			t.Run(fmt.Sprintf("n=%d/rollback=%t", n, rollback), func(t *testing.T) {
				ctx := context.Background()
				observer := &nativeDeleteObserver{}
				pool := nativeDeletePublicPool(t, ctx, observer)
				fx := setupGamma(t, ctx, pool, "nativedelete")
				seedWDObjects(t, ctx, pool, string(fx.prj), string(fx.accID), n, nil)
				rules := domain.Rules{forwardAnchorRule(), {Module: "compute", Resources: []string{"instance"}, Verbs: []string{"update"}}}
				role := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "nativedeleterole", rules)
				bid := insertThinBinding(t, ctx, fx.repo, fx.member, role, fx.prj)
				adapter := kanamepg.NewReconcileAdapter(pool, catalogfixture.Source())
				forward := reconcile.New(adapter, nil, catalogfixture.Source())
				require.NoError(t, forward.ReconcileBindingForward(ctx, bid))
				subject := "user:" + string(fx.member)
				var members, ledger, facts, writes int
				require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.access_binding_target_members WHERE binding_id=$1`, string(bid)).Scan(&members))
				require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1`, string(bid)).Scan(&ledger))
				require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.relation_fact WHERE subject=$1 AND object_type='compute_instance' AND object_id LIKE 'wdi-%'`, subject).Scan(&facts))
				require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.fga_outbox WHERE event_type='fga.tuple.write' AND payload->>'user'=$1 AND payload->>'object' LIKE 'compute_instance:wdi-%'`, subject).Scan(&writes))
				require.Equal(t, 2*n, members)
				require.Equal(t, 4*n, ledger)
				require.Equal(t, n, facts)
				require.Equal(t, n, writes)
				for i := 0; i < n; i++ {
					for _, relation := range []string{"editor", "v_delete", "v_get", "v_update"} {
						require.True(t, ledgerHasTuple(t, ctx, pool, bid, subject, relation, fmt.Sprintf("compute_instance:wdi-%07d", i)))
					}
				}
				(&ledgerProbe{pool: pool, bid: bid}).expireInPast(t)
				before := nativeDeletePublicSnapshot(t, ctx, pool, bid, subject, string(fx.member))
				var lower, upper time.Time
				require.NoError(t, pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&lower))
				runner := &nativeDeleteCaller{inner: adapter, rollback: rollback}
				rec := reconcile.New(runner, nil, catalogfixture.Source())
				observer.reset()
				passCtx, cancel := context.WithTimeout(ctx, shared.PostCommitTimeout)
				defer cancel()
				err := rec.ExpireBinding(passCtx, bid)
				if rollback {
					require.ErrorIs(t, err, errNativeDeleteCallerRollback)
				} else {
					require.NoError(t, err)
				}
				calls := observer.count()
				require.NoError(t, pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&upper))
				if rollback {
					require.Equal(t, before, nativeDeletePublicSnapshot(t, ctx, pool, bid, subject, string(fx.member)), "все реальные эффекты должны откатиться вместе")
				} else {
					require.Equal(t, string(domain.AccessBindingStatusRevoked), bindingStatus(t, ctx, pool, bid))
					var leftMembers, leftLedger, leftFacts, deletes, uniqueIDs int
					require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.access_binding_target_members WHERE binding_id=$1`, string(bid)).Scan(&leftMembers))
					require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1`, string(bid)).Scan(&leftLedger))
					require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.relation_fact WHERE subject=$1 AND object_type='compute_instance' AND object_id LIKE 'wdi-%'`, subject).Scan(&leftFacts))
					require.Zero(t, leftMembers)
					require.Zero(t, leftLedger)
					require.Zero(t, leftFacts)
					require.NoError(t, pool.QueryRow(ctx, `SELECT count(*),count(DISTINCT id) FROM kaname.fga_outbox WHERE event_type='fga.tuple.delete' AND payload->>'user'=$1 AND payload->>'object' LIKE 'compute_instance:wdi-%'`, subject).Scan(&deletes, &uniqueIDs))
					require.Equal(t, n, deletes)
					require.Equal(t, n, uniqueIDs)
					for i := 0; i < n; i++ {
						object := fmt.Sprintf("compute_instance:wdi-%07d", i)
						var id int64
						var payload string
						var at time.Time
						require.NoError(t, pool.QueryRow(ctx, `SELECT id,payload::text,created_at FROM kaname.fga_outbox WHERE event_type='fga.tuple.delete' AND payload->>'user'=$1 AND payload->>'object'=$2`, subject, object).Scan(&id, &payload, &at))
						require.Positive(t, id)
						expected, marshalErr := json.Marshal(map[string]any{"user": subject, "object": object, "relations": []string{"editor", "v_delete", "v_get", "v_update"}})
						require.NoError(t, marshalErr)
						require.JSONEq(t, string(expected), payload, "delete набора не несёт write-only relation эхо")
						// Грубая граница серверных часов совместима со старым emitter.
						// Отдельно доказать binding времени к INSERT эта проба не может.
						require.False(t, at.Before(lower))
						require.False(t, at.After(upper))
					}
				}
				// ПОСЛЕДНЯЯ проверка: одно реальное SQL на исходный непустой batch,
				// а не на payload/group. На пустой выдаче дверь не вызывается.
				wantCalls := 0
				if n > 0 {
					wantCalls = 1
				}
				require.Equal(t, wantCalls, calls, "public expiry must route each nonempty original delete batch to authority_native_delete_emit_v4")
			})
		}
	}
}
