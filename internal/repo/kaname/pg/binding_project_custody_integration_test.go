// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// Останавливаем автоматический повтор только после получения реального 40001.
// Это позволяет проверить состояние после отклонённого reserve до нового RR.
type bindingCustodyBarrier struct {
	*stageQueryBarrier
	stopRetry context.CancelFunc
	conflict  chan *pgconn.PgError
}

func (b *bindingCustodyBarrier) TraceQueryEnd(_ context.Context, _ *pgx.Conn, d pgx.TraceQueryEndData) {
	var cause *pgconn.PgError
	if errors.As(d.Err, &cause) && cause.Code == "40001" {
		select {
		case b.conflict <- cause:
			b.stopRetry()
		default:
		}
	}
}

func checkBindingProjectCustody(t *testing.T, r protocolRig, binding domain.AccessBindingID) {
	t.Helper()
	for _, tc := range []struct {
		name                 string
		restoreBeforeReserve bool
		message              string
	}{
		{"reader privilege revoked", false, "binding native project reader privilege changed"},
		{"relation generation changed", true, "binding native graph custody changed before sequence reservation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := capturedGroupRequest(t, r)
			ctx, cancel := context.WithCancel(r.ctx)
			defer cancel()
			fence := &bindingCustodyBarrier{
				stageQueryBarrier: stageBarrier(t, "FROM kaname.authority_binding_stage_sequence_prepare_v3("),
				stopRetry:         cancel,
				conflict:          make(chan *pgconn.PgError, 1),
			}
			cfg := r.runtime.Config()
			cfg.ConnConfig.Tracer = fence
			pool, err := pgxpool.NewWithConfig(r.ctx, cfg)
			require.NoError(t, err)
			t.Cleanup(pool.Close)
			t.Cleanup(fence.releaseStage)
			r.runtime, r.repo = pool, kanamepg.New(pool, nil)
			full, contract := fullContractRepository(t, r)
			r.repo, r.ctx = full, contract.Context(r.ctx)
			engine := bindingStageEngine(t, r, nil)

			before := bindingCustodyState(t, r, binding)
			generation, acl, canRead := bindingProjectEdgeACL(t, r)
			require.True(t, canRead)
			done := make(chan error, 1)
			go func() { done <- engine.ReconcileBinding(contract.Context(ctx), binding) }()
			select {
			case <-fence.reached:
			case err := <-done:
				t.Fatalf("reconcile ended before sequence preparation: %v", err)
			case <-r.ctx.Done():
				t.Fatal(r.ctx.Err())
			}

			restore := "GRANT SELECT ON kaname.resource_parent_edge TO " + pgx.Identifier{r.role}.Sanitize()
			tx, err := r.admin.Begin(r.ctx)
			require.NoError(t, err)
			lifecycleRollback(t, tx)
			_, err = tx.Exec(r.ctx, "SET LOCAL lock_timeout = '2s'")
			require.NoError(t, err)
			_, err = tx.Exec(r.ctx, "REVOKE SELECT ON kaname.resource_parent_edge FROM "+pgx.Identifier{r.role}.Sanitize())
			require.NoError(t, err)
			if tc.restoreBeforeReserve {
				_, err = tx.Exec(r.ctx, restore)
				require.NoError(t, err)
			}
			require.NoError(t, tx.Commit(r.ctx))
			if !tc.restoreBeforeReserve {
				t.Cleanup(func() {
					cleanup, finish := context.WithTimeout(context.WithoutCancel(r.ctx), 5*time.Second)
					defer finish()
					_, err := r.admin.Exec(cleanup, restore)
					require.NoError(t, err)
				})
			}
			newGeneration, newACL, canRead := bindingProjectEdgeACL(t, r)
			require.NotEqual(t, generation, newGeneration)
			require.Equal(t, tc.restoreBeforeReserve, canRead)
			if tc.restoreBeforeReserve {
				require.Equal(t, acl, newACL)
			}
			fence.releaseStage()
			err = lifecycleResult(t, r.ctx, done)
			var cause *pgconn.PgError
			if tc.restoreBeforeReserve {
				require.ErrorIs(t, err, context.Canceled)
				select {
				case cause = <-fence.conflict:
				default:
					t.Fatal("missing native reservation conflict")
				}
				require.Equal(t, "40001", cause.Code)
			} else {
				require.ErrorAs(t, err, &cause)
				require.Equal(t, "42501", cause.Code)
			}
			require.Equal(t, tc.message, cause.Message)
			require.EqualValues(t, 1, fence.stages.Load())
			require.Equal(t, before, bindingCustodyState(t, r, binding))
		})
	}
}

// База изолирована. Сравниваем строки с обеих сторон, включая удаление
// кортежей и события независимо от их типа или получателя.
func bindingCustodyState(t *testing.T, r protocolRig, binding domain.AccessBindingID) string {
	t.Helper()
	var hash string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT encode(sha256(convert_to(jsonb_build_array(
		(SELECT to_jsonb(b) FROM ONLY kaname.access_bindings b WHERE b.id=$1),
		(SELECT jsonb_agg(to_jsonb(s) ORDER BY s.ordinal) FROM ONLY kaname.access_binding_subjects s WHERE s.binding_id=$1),
		(SELECT jsonb_agg(to_jsonb(m) ORDER BY to_jsonb(m)) FROM ONLY kaname.access_binding_target_members m WHERE m.binding_id=$1),
		(SELECT jsonb_agg(to_jsonb(e) ORDER BY to_jsonb(e)) FROM ONLY kaname.access_binding_emitted_tuples e WHERE e.binding_id=$1),
		(SELECT jsonb_agg(to_jsonb(f) ORDER BY to_jsonb(f)) FROM ONLY kaname.relation_fact f),
		(SELECT jsonb_agg(to_jsonb(o) ORDER BY o.id) FROM kaname.fga_outbox o),
		(SELECT jsonb_agg(to_jsonb(o) ORDER BY o.id) FROM kaname.audit_outbox o),
		(SELECT jsonb_agg(to_jsonb(o) ORDER BY o.sequence_no) FROM kaname.resource_journal o),
		(SELECT jsonb_agg(to_jsonb(o) ORDER BY to_jsonb(o)) FROM kaname.resource_reconcile_outbox o)
	)::text,'UTF8')),'hex')`, binding).Scan(&hash))
	return hash
}

func bindingProjectEdgeACL(t *testing.T, r protocolRig) (generation, acl string, canRead bool) {
	t.Helper()
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT c.xmin::text,c.relacl::text,
		has_table_privilege($1::name,c.oid,'SELECT') FROM pg_class c
		WHERE c.oid='kaname.resource_parent_edge'::regclass`, r.role).Scan(&generation, &acl, &canRead))
	return
}
