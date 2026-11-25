// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/multitracer"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

type metadataCarrierRequestKey struct{}
type metadataCarrierSQLKey struct{}

// Tracer только наблюдает запросы и полученные PostgreSQL command tags.
// Он не исполняет SQL, не меняет результат и не задерживает production writer.
type metadataCarrierTrace struct {
	mu           sync.Mutex
	phase        string
	rrClosed     bool
	rrRows       []int64
	entryAfterRR []bool
}

func (tr *metadataCarrierTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if ctx.Value(metadataCarrierRequestKey{}) == nil {
		return ctx
	}
	tr.mu.Lock()
	if strings.HasPrefix(data.SQL, "SELECT kaname.authority_protocol_enter_full_v3(") {
		tr.entryAfterRR = append(tr.entryAfterRR, tr.phase == "rc" && tr.rrClosed)
	}
	tr.mu.Unlock()
	return context.WithValue(ctx, metadataCarrierSQLKey{}, data.SQL)
}

func (tr *metadataCarrierTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	sql, marked := ctx.Value(metadataCarrierSQLKey{}).(string)
	if !marked || data.Err != nil {
		return
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	switch sql {
	case "begin isolation level repeatable read read only":
		tr.phase, tr.rrClosed = "rr", false
	case "rollback":
		if tr.phase == "rr" {
			tr.rrClosed = true
		}
	case "begin isolation level read committed":
		tr.phase = "rc"
	}
	// Отличаем первый changes census от последующего coverage census.
	if tr.phase == "rr" && strings.Contains(sql, "FROM kaname.role_rule_selectors s") &&
		strings.Contains(sql, "jsonb_build_object('binding_id',b.id,'changes',") &&
		!strings.Contains(sql, "s.arm='anchor'") {
		tr.rrRows = append(tr.rrRows, data.CommandTag.RowsAffected())
	}
}

func (tr *metadataCarrierTrace) observed() ([]int64, []bool) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return append([]int64(nil), tr.rrRows...), append([]bool(nil), tr.entryAfterRR...)
}

// Сохраняем callbacks прежнего tracer и прежний выбор batch-ветки.
type metadataCarrierNonBatch interface {
	pgx.QueryTracer
	pgx.CopyFromTracer
	pgx.PrepareTracer
	pgx.ConnectTracer
	pgxpool.AcquireTracer
	pgxpool.ReleaseTracer
}
type metadataCarrierQueryOnly struct{ metadataCarrierNonBatch }

func (tr *metadataCarrierTrace) combine(previous pgx.QueryTracer) pgx.QueryTracer {
	combined := multitracer.New(tr)
	if previous == nil {
		return combined
	}
	combined = multitracer.New(previous, tr)
	if _, batch := previous.(pgx.BatchTracer); batch {
		return combined
	}
	return metadataCarrierQueryOnly{combined}
}

const metadataCarrierEffectsSQL = `SELECT jsonb_build_array(
 (SELECT to_jsonb(p) FROM kaname.projects p WHERE id=$1),
 (SELECT count(*) FROM kaname.audit_outbox),
 (SELECT count(*) FROM kaname.resource_journal),
 (SELECT count(*) FROM kaname.resource_reconcile_outbox),
 (SELECT count(*) FROM kaname.fga_outbox),
 (SELECT count(*) FROM kaname.relation_fact),
 (SELECT count(*) FROM kaname.access_binding_emitted_tuples))::text`

// Пустой RR census обязан пережить реальное ожидание с перепроверкой.
// Commit добавляет matching carrier, rollback оставляет прежний законный эффект.
func TestFullMetadataConcurrentMatchingCarrierRechecksAfterWait(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(fmt.Sprintf("commit=%t", committed), func(t *testing.T) {
			var carrier domain.AccessBindingID
			var oldRole, matchingRole domain.RoleID
			w := metadataFixture(t, false, func(r protocolRig) {
				recipient := seedMemberUser(t, r.ctx, r.admin, r.a, "carrier-holder")
				carrier = groupLifecycleBinding(t, r, r.a, recipient, "carrier_before", domain.Rule{
					Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"sharing": "disabled"},
				})
				oldRole = bindingRow(t, r, carrier).RoleID
				// Готовим настоящую роль вместе с selectors и role_verbs, затем
				// убираем установочную выдачу: matching carrier пока отсутствует.
				seed := groupLifecycleBinding(t, r, r.a, recipient, "carrier_after", domain.Rule{
					Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"sharing": "enabled"},
				})
				matchingRole = bindingRow(t, r, seed).RoleID
				setup, err := lifecycleOwner(r).Writer(r.ctx)
				require.NoError(t, err)
				defer func() { _ = setup.Rollback(context.WithoutCancel(r.ctx)) }()
				require.NoError(t, setup.AccessBindingsW().DeleteGuarded(r.ctx, seed))
				require.NoError(t, setup.Commit(r.ctx))
			})
			ctx, cancel := context.WithTimeout(w.r.ctx, 20*time.Second)
			defer cancel()
			trace := &metadataCarrierTrace{}
			cfg := w.r.runtime.Config()
			cfg.ConnConfig.Tracer = trace.combine(cfg.ConnConfig.Tracer)
			pool, err := pgxpool.NewWithConfig(ctx, cfg)
			require.NoError(t, err)
			t.Cleanup(pool.Close)
			base := kanamepg.New(pool, nil)
			contract, err := kanamepg.NewFullWriterContract(ctx, base, w.r.bundle)
			require.NoError(t, err)
			full, err := base.WithFullWriterContract(contract)
			require.NoError(t, err)
			factory, err := kanamepg.NewMetadataMutationWriters(ctx, full, w.r.bundle)
			require.NoError(t, err)

			var before string
			require.NoError(t, w.r.admin.QueryRow(ctx, metadataCarrierEffectsSQL, string(w.project.ID)).Scan(&before))
			holder, err := w.r.runtime.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			require.NoError(t, err)
			defer policyFixtureRollback(holder)
			identity := w.r.bundle.Identity()
			// Это full typed binding participant обычного LOGIN. Не resource,
			// не owner DML, не выключенный guard и не свободный GUC.
			_, err = holder.Exec(ctx, `SELECT kaname.authority_protocol_enter_typed_v3(
 'accounts',ARRAY[$1::text],jsonb_build_array(jsonb_build_object('kind','binding','id',$2::text)),
 'binding',$3,$4,$5,'participant')`, w.r.a, string(carrier), identity.ModelID, identity.CatalogID, identity.ProjectorVersion)
			require.NoError(t, err)
			tag, err := holder.Exec(ctx, `UPDATE kaname.access_bindings SET role_id=$2 WHERE id=$1 AND role_id=$3`, string(carrier), string(matchingRole), string(oldRole))
			require.NoError(t, err)
			require.EqualValues(t, 1, tag.RowsAffected())
			// Ожидаемый committed снимок включает собственный журнал конкурента,
			// но ещё не содержит ни одного эффекта проверяемой metadata операции.
			expected := before
			if committed {
				require.NoError(t, holder.QueryRow(ctx, metadataCarrierEffectsSQL, string(w.project.ID)).Scan(&expected))
			}
			changed := w.project
			changed.Labels = domain.Labels{"sharing": "enabled"}
			var writer kaname.SemanticAuthorityWriter
			var openErr error
			finished := make(chan struct{})
			t.Cleanup(func() {
				cancel()
				policyFixtureRollback(holder)
				select {
				case <-finished:
				case <-time.After(5 * time.Second):
					t.Error("писатель меток не завершился после отмены")
					return
				}
				if writer != nil {
					_ = writer.Rollback(context.WithoutCancel(w.r.ctx))
				}
			})
			go func() {
				defer close(finished)
				writer, openErr = factory.ProjectMetadataWriter(context.WithValue(ctx, metadataCarrierRequestKey{}, true), changed, []string{"labels"}, w.subject(w.actor))
			}()
			holderPID := int(holder.Conn().PgConn().PID())
			var waiterPID int
			require.Eventually(t, func() bool {
				err := w.r.admin.QueryRow(ctx, `SELECT a.pid
 FROM pg_catalog.pg_stat_activity a
 JOIN pg_catalog.pg_locks waiting ON waiting.pid=a.pid AND NOT waiting.granted
 JOIN pg_catalog.pg_locks held ON held.pid=$1 AND held.granted
  AND held.locktype=waiting.locktype AND held.database=waiting.database
  AND held.classid=waiting.classid AND held.objid=waiting.objid AND held.objsubid=waiting.objsubid
 WHERE a.datname=current_database() AND a.usename=$3
  AND a.wait_event_type='Lock' AND a.wait_event='advisory'
  AND a.query LIKE 'SELECT kaname.authority_protocol_enter_full_v3(%'
  AND waiting.locktype='advisory' AND waiting.classid=1262569281::oid
  AND waiting.objid=(hashtext($2)::bigint & 4294967295)::oid AND waiting.objsubid=2
  AND waiting.mode='ExclusiveLock' AND held.mode='ExclusiveLock'
  AND $1=ANY(pg_catalog.pg_blocking_pids(a.pid))`, holderPID, w.r.a, w.r.role).Scan(&waiterPID)
				return err == nil
			}, 5*time.Second, 10*time.Millisecond, "metadata RC должна ждать точный account fence конкурента после RR")
			t.Logf("metadata pid=%d ждёт account fence carrier pid=%d; commit=%t", waiterPID, holderPID, committed)
			rows, entries := trace.observed()
			require.Equal(t, []int64{0}, rows, "первый RR действительно видел пустой matching census")
			require.Equal(t, []bool{true}, entries, "RR закрыт до ожидающего RC entry")
			if committed {
				require.NoError(t, holder.Commit(ctx))
			} else {
				require.NoError(t, holder.Rollback(ctx))
			}
			select {
			case <-finished:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			rows, entries = trace.observed()
			var after string
			if committed {
				require.ErrorIs(t, openErr, iamerr.ErrPermissionDenied)
				require.Nil(t, writer)
				require.Equal(t, []int64{0, 1}, rows, "повторный RR census обязан включить новый matching carrier")
				require.Equal(t, []bool{true, true}, entries)
				require.NoError(t, w.r.admin.QueryRow(ctx, metadataCarrierEffectsSQL, string(w.project.ID)).Scan(&after))
				require.Equal(t, expected, after, "отказ не меняет объект, аудит, журнал, reconcile и FGA")
			} else {
				require.NoError(t, openErr)
				require.NotNil(t, writer)
				require.Equal(t, []int64{0}, rows)
				require.Equal(t, []bool{true}, entries)
				updated, err := writer.ProjectsW().Update(ctx, changed, []string{"labels"})
				require.NoError(t, err)
				require.NoError(t, writer.EmitAuditEvent(ctx, service.AuditEvent{
					EventType: "iam.project.updated", TenantAccountID: w.r.a, Payload: map[string]any{
						"actor": w.actor, "resource_type": "project", "resource_id": string(updated.ID),
						"account_id": w.r.a, "changed_fields": []string{"labels"},
					},
				}))
				require.NoError(t, writer.EmitReconcileEvent(ctx, "mirror.upsert", "iam.project", string(updated.ID)))
				require.NoError(t, writer.Commit(ctx))
				var labels string
				require.NoError(t, w.r.admin.QueryRow(ctx, `SELECT labels::text FROM kaname.projects WHERE id=$1`, string(changed.ID)).Scan(&labels))
				require.JSONEq(t, `{"sharing":"enabled"}`, labels, "rollback конкурента сохраняет законную metadata запись")
			}
			var actualRole string
			require.NoError(t, w.r.admin.QueryRow(ctx, `SELECT role_id FROM kaname.access_bindings WHERE id=$1`, string(carrier)).Scan(&actualRole))
			if committed {
				require.Equal(t, string(matchingRole), actualRole)
			} else {
				require.Equal(t, string(oldRole), actualRole)
			}
		})
	}
}
