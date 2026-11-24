// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestBindingCommandBatchActualParityAndRefusal(t *testing.T) {
	for _, mirror := range []bool{false, true} {
		name := "legacy_begin_false"
		if mirror {
			name = "mirror_begin_true"
		}
		t.Run(name, func(t *testing.T) {
			var r protocolRig
			var binding domain.AccessBindingID
			if mirror {
				r, binding, _, _ = mirrorLocalityFixture(t)
			} else {
				r = writerProtocolRig(t)
				stageSeedGroups(t, r, r.a, 2, "blue")
				binding = stageBinding(t, r, r.a, false)
			}
			trace := &fullMeasurementTrace{}
			r = fullMeasurementPool(t, r, trace)
			bindingCommandBatchEpochReader(t, r)
			r.repo, _ = fullContractActivate(t, r)
			ctx, cancel := fullMeasurementContext(r.ctx, name)
			defer cancel()
			kanamepg.BindingCommandBatchConformanceForTest(t, ctx, r.repo, r.bundle, binding, r.a, mirror)
			batches := trace.batchIntervals(name)
			require.NotEmpty(t, batches, "нельзя принять fallback как batch conformance")
			for _, batch := range batches {
				require.Equal(t, 2, batch.Queued, "ровно Begin + одно тело, не соседние команды")
				require.False(t, batch.End.IsZero())
				if batch.Error == "" {
					require.Equal(t, 2, batch.Observed)
				}
			}
			members, records := 0, 0
			for _, q := range trace.get(name) {
				if q.Batch == 0 {
					continue
				}
				if strings.HasPrefix(q.SQL, "INSERT INTO kaname.access_binding_target_members") {
					members++
				}
				if strings.HasPrefix(q.SQL, "INSERT INTO kaname.access_binding_emitted_tuples") {
					records++
				}
			}
			require.Positive(t, members)
			require.Positive(t, records)
		})
	}
}

// Только конечный no-arg read-only test reader, как native batch metadata oracle.
// Runtime не получает SELECT на private таблицу и не меняет canonical guards.
func bindingCommandBatchEpochReader(t *testing.T, r protocolRig) {
	t.Helper()
	_, err := r.admin.Exec(r.ctx, `CREATE FUNCTION kaname.test_binding_command_batch_epochs_v1() RETURNS jsonb
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $reader$
 SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY e.key),'[]'::jsonb) FROM kaname.authority_policy_epoch e
 $reader$;
 REVOKE ALL ON FUNCTION kaname.test_binding_command_batch_epochs_v1() FROM PUBLIC`)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, e := r.admin.Exec(ctx, `DROP FUNCTION kaname.test_binding_command_batch_epochs_v1()`)
		require.NoError(t, e)
	})
	_, err = r.admin.Exec(r.ctx, `GRANT EXECUTE ON FUNCTION kaname.test_binding_command_batch_epochs_v1() TO `+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
}

func TestBindingCommandBatchNoParticipantKeepsFirstRefusal(t *testing.T) {
	r := writerProtocolRig(t)
	trace := &fullMeasurementTrace{}
	r = fullMeasurementPool(t, r, trace)
	ctx, cancel := fullMeasurementContext(r.ctx, "no_participant")
	defer cancel()
	tx, err := r.runtime.Begin(ctx)
	require.NoError(t, err)
	defer mirrorLocalityRollback(t, tx)
	err = kanamepg.BindingCommandBatchNoEntryForTest(ctx, tx)
	var pgerr *pgconn.PgError
	require.ErrorAs(t, err, &pgerr)
	require.Equal(t, "42501", pgerr.Code, "первичный Begin refusal, не FK/25P02 тела")
	require.NoError(t, tx.Rollback(ctx), "закрытие batch не оставляет conn busy")
	read, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer stop()
	var count int
	require.NoError(t, r.runtime.QueryRow(read, `SELECT count(*) FROM kaname.access_binding_target_members WHERE binding_id='absent-batch-binding'`).Scan(&count))
	require.Zero(t, count)
	require.Len(t, trace.batchIntervals("no_participant"), 1)
}
