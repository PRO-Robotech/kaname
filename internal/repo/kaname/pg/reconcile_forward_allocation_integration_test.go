// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

var errForwardAllocationRollback = errors.New("forward allocation: refuse after actual ledger")

type forwardAllocationRunner struct {
	inner *kanamepg.ReconcileAdapter
	fail bool
}

func (p *forwardAllocationRunner) WithTx(ctx context.Context, fn func(context.Context, reconcile.ReconcileStore) error) error {
	return p.inner.WithTx(ctx, func(ctx context.Context, s reconcile.ReconcileStore) error {
		return fn(ctx, &forwardAllocationStore{ReconcileStore: s, fail: p.fail})
	})
}

type forwardAllocationStore struct {
	reconcile.ReconcileStore
	fail bool
}

// Прозрачная обёртка сохраняет capability настоящего pg store; SQL-путь не подменяется.
func (s *forwardAllocationStore) EmitForwardTupleWrite(ctx context.Context, tuples []domain.MembershipTuple) error {
	writer, ok := s.ReconcileStore.(interface {
		EmitForwardTupleWrite(context.Context, []domain.MembershipTuple) error
	})
	if !ok {
		return errors.New("real pg adapter has no forward allocation capability")
	}
	return writer.EmitForwardTupleWrite(ctx, tuples)
}

func (s *forwardAllocationStore) RecordEmittedTuplesBatch(ctx context.Context, refs []reconcile.EmittedTupleRef) error {
	if err := s.ReconcileStore.RecordEmittedTuplesBatch(ctx, refs); err != nil {
		return err
	}
	if s.fail && len(refs) > 0 {
		return errForwardAllocationRollback
	}
	return nil
}

// Нормальные публичные форварды проверяются на пустом, единичном и малом наборе.
// Перекрывающиеся правила повторяют эффекты: member сохраняет оба происхождения,
// ledger и payload — каждый кортеж единожды. Отказ после ledger откатывает все слои.
func TestReconcileForward_AllocationPreservesPublicEffects(t *testing.T) {
	skipShort(t)
	for _, route := range []string{"binding", "object"} {
		for _, n := range []int{0, 1, 3} {
			for _, fail := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/n=%d/rollback=%t", route, n, fail), func(t *testing.T) {
					ctx := context.Background()
					counter := newStmtCounter()
					pool := wdPool(t, ctx, counter)
					pgtest.ClosePoolAtEnd(t, pool)
					fx := setupGamma(t, ctx, pool, "forwardalloc")
					seedWDObjects(t, ctx, pool, string(fx.prj), string(fx.accID), n, nil)
					rules := domain.Rules{forwardAnchorRule(), {Module: "compute", Resources: []string{"instance"}, Verbs: []string{"update"}}}
					role := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "forwardallocrole", rules)
					bid := insertThinBinding(t, ctx, fx.repo, fx.member, role, fx.prj)
					runner := &forwardAllocationRunner{inner: kanamepg.NewReconcileAdapter(pool, catalogfixture.Source()), fail: fail}
					rec := reconcile.New(runner, nil, catalogfixture.Source())
					counter.reset()
					var err error
					if route == "binding" {
						err = rec.ReconcileBindingForward(ctx, bid)
					} else if n == 0 {
						err = rec.ReconcileObjectForward(ctx, "compute.instance", "missing")
					} else {
						for i := 0; i < n; i++ {
							err = rec.ReconcileObjectForward(ctx, "compute.instance", fmt.Sprintf("wdi-%07d", i))
							if err != nil { break }
						}
					}
					if fail && n > 0 { require.ErrorIs(t, err, errForwardAllocationRollback) } else { require.NoError(t, err) }
					wantCalls := int64(0)
					if n > 0 {
						wantCalls = 1
						if route == "object" && !fail { wantCalls = int64(n) }
					}
					counter.mu.Lock()
					calls := counter.byTag["SELECT kaname.authority_forward_emit_v4($1::jsonb[])"]
					counter.mu.Unlock()
					subj := "user:" + string(fx.member)
					wantObjects := n
					if fail { wantObjects = 0 }
					var members, ledger, facts, outbox int
					require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.access_binding_target_members WHERE binding_id=$1`, string(bid)).Scan(&members))
					require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1`, string(bid)).Scan(&ledger))
					require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.relation_fact WHERE subject=$1 AND object_type='compute_instance' AND object_id LIKE 'wdi-%'`, subj).Scan(&facts))
					require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.fga_outbox WHERE payload->>'user'=$1 AND payload->>'object' LIKE 'compute_instance:wdi-%'`, subj).Scan(&outbox))
					require.Equal(t, 2*wantObjects, members)
					require.Equal(t, 4*wantObjects, ledger)
					// Ledger и payload несут четыре эффекта; ordinary v_* выводятся checker,
					// поэтому прежний fold хранит прямым фактом только editor.
					require.Equal(t, wantObjects, facts)
					require.Equal(t, wantObjects, outbox)
					for i := 0; i < wantObjects; i++ {
						id := fmt.Sprintf("wdi-%07d", i)
						object := "compute_instance:" + id
						var event, payload string
						var at time.Time
						require.NoError(t, pool.QueryRow(ctx, `SELECT event_type,payload::text,created_at FROM kaname.fga_outbox WHERE payload->>'user'=$1 AND payload->>'object'=$2`, subj, object).Scan(&event, &payload, &at))
						require.Equal(t, "fga.tuple.write", event)
						expected, marshalErr := json.Marshal(map[string]any{"user": subj, "object": object, "relation": "editor", "relations": []string{"editor", "v_delete", "v_get", "v_update"}})
						require.NoError(t, marshalErr)
						require.JSONEq(t, string(expected), payload)
						var memberTimes, factTimes int
						require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.access_binding_target_members WHERE binding_id=$1 AND object_id=$2 AND created_at=$3 AND updated_at=$3 AND verification_status='ACTIVE'`, string(bid), id, at).Scan(&memberTimes))
						require.Equal(t, 2, memberTimes, "outbox сохраняет точный transaction_timestamp членов")
						require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.relation_fact WHERE subject=$1 AND object_type='compute_instance' AND object_id=$2 AND source_version=$3 AND relation=ANY($4::text[])`, subj, id, at, []string{"editor", "v_delete", "v_get", "v_update"}).Scan(&factTimes))
						require.Equal(t, 1, factTimes)
						var directVerbs int
						require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.relation_fact WHERE subject=$1 AND object_type='compute_instance' AND object_id=$2 AND relation LIKE 'v\_%'`, subj, id).Scan(&directVerbs))
						require.Zero(t, directVerbs, "ordinary binding v_* остаются в ledger и не копируются в прямые факты")
						for _, relation := range []string{"editor", "v_delete", "v_get", "v_update"} {
							require.True(t, ledgerHasTuple(t, ctx, pool, bid, subj, relation, object))
						}
					}
					// Маршрут проверяется последним: old production сначала обязан
					// подтвердить те же state/payload/timestamp/rollback инварианты.
					require.Equal(t, wantCalls, calls, "каждая непустая Emit-фаза делает один actual SQL вызов независимо от размера")
				})
			}
		}
	}
}
