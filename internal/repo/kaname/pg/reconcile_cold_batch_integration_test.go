// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

var errColdBatchRollback = errors.New("cold second ledger batch persisted then refused")

type coldBatchTxProbe struct {
	inner      *kanamepg.ReconcileAdapter
	fail       bool
	batchRows  []int
	ledgerRows []int
}

func (p *coldBatchTxProbe) WithTx(ctx context.Context, fn func(context.Context, reconcile.ReconcileStore) error) error {
	return p.inner.WithTx(ctx, func(ctx context.Context, store reconcile.ReconcileStore) error {
		return fn(ctx, &coldBatchLedgerProbe{ReconcileStore: store, probe: p})
	})
}

type coldBatchLedgerProbe struct {
	reconcile.ReconcileStore
	probe *coldBatchTxProbe
}

func (s *coldBatchLedgerProbe) UpsertMembers(ctx context.Context, members []domain.TargetMember) error {
	s.probe.batchRows = append(s.probe.batchRows, len(members))
	return s.ReconcileStore.UpsertMembers(ctx, members)
}

func (s *coldBatchLedgerProbe) RecordEmittedTuplesBatch(ctx context.Context, refs []reconcile.EmittedTupleRef) error {
	if err := s.ReconcileStore.RecordEmittedTuplesBatch(ctx, refs); err != nil {
		return err
	}
	s.probe.ledgerRows = append(s.probe.ledgerRows, len(refs))
	if s.probe.fail && len(s.probe.ledgerRows) == 2 {
		return errColdBatchRollback
	}
	return nil
}

// Обе партии реально пишут member/outbox/ledger в исходной adapter tx. Отказ
// ПОСЛЕ второго ledger обязан откатить также первую партию и прямые FGA-факты.
func TestReconcileColdBatch_SecondLedgerFailureRollsBackWholeCallerTx(t *testing.T) {
	skipShort(t)
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprintf("fail=%t", fail), func(t *testing.T) {
			ctx := context.Background()
			pool := wdPool(t, ctx, newStmtCounter())
			pgtest.ClosePoolAtEnd(t, pool)
			fx := setupGamma(t, ctx, pool, fmt.Sprintf("coldbatch%t", fail))
			seedWDObjects(t, ctx, pool, string(fx.prj), string(fx.accID), 4097, nil)
			role := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "coldbatchrole", wdRules(1))
			bid := insertThinBinding(t, ctx, fx.repo, fx.member, role, fx.prj)
			probe := &coldBatchTxProbe{inner: kanamepg.NewReconcileAdapter(pool, catalogfixture.Source()), fail: fail}
			r := reconcile.New(probe, nil, catalogfixture.Source())
			passCtx, cancel := context.WithTimeout(ctx, shared.PostCommitTimeout)
			defer cancel()
			err := r.ReconcileBinding(passCtx, bid)
			if fail {
				require.ErrorIs(t, err, errColdBatchRollback)
			} else {
				require.NoError(t, err)
			}
			require.GreaterOrEqual(t, len(probe.batchRows), 2, "предпосылка: несколько настоящих партий достигнуты")
			require.Len(t, probe.ledgerRows, len(probe.batchRows))
			writtenMembers := 0
			for i, rows := range probe.batchRows {
				require.Positive(t, rows)
				require.LessOrEqual(t, rows, 4096)
				require.LessOrEqual(t, probe.ledgerRows[i], 4096, "размер actual ledger ограничен и при нескольких tuples/member")
				writtenMembers += rows
			}
			if fail {
				require.Len(t, probe.batchRows, 2, "отказ произошёл после второго actual ledger SQL")
			} else {
				require.Equal(t, 4097, writtenMembers, "полный исходный positive без усечения")
			}
			var members, ledger int
			require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.access_binding_target_members WHERE binding_id=$1`, string(bid)).Scan(&members))
			require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1`, string(bid)).Scan(&ledger))
			if fail {
				require.Zero(t, members)
				require.Zero(t, ledger)
			} else {
				require.Equal(t, 4097, members)
				require.Positive(t, ledger)
			}
			for _, objectID := range []string{"wdi-0000000", "wdi-0004096"} {
				m, l, facts := bindingResidue(t, ctx, pool, bid, "user:"+string(fx.member), "compute_instance", objectID)
				if fail {
					require.Zero(t, m)
					require.Zero(t, l)
					require.Zero(t, facts)
				} else {
					require.Positive(t, m)
					require.Positive(t, l)
					require.Positive(t, facts)
				}
			}
		})
	}
}
