// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"encoding/json"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	accountapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/account"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"strings"
	"testing"
	"time"
)

func TestSevenCRUDAccountCreateBothIDOriginsHaveCompleteOwnerImage(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "generated", true: "client"}[explicit], func(t *testing.T) {
			w := sevenCRUDPublicFixture(t, "account.create", "", func(w *sevenCRUDPublicWorld) {
				if explicit {
					sevenCRUDSystemRelation(t, w.r, w.actor, "cluster", domain.ClusterSingletonID, "system_admin")
				}
			})
			sevenR2DefaultConflictPolicy(t, w.r)
			request := domain.Account{Name: "complete-owner-image"}
			if explicit {
				request.ID = domain.AccountID(ids.NewID(domain.PrefixAccount))
			}
			op, err := accountapp.NewCreateAccountUseCase(w.full, w.ops).WithRelationStore(w.door, nil).WithAccountCreateWriter(w.factory).Execute(declarerCtx(w.ctx, w.actor), request)
			done := sevenCRUDResult(t, w, op, err, codes.OK)
			var meta iamv1.CreateAccountMetadata
			require.NoError(t, done.Metadata.UnmarshalTo(&meta))
			require.NotEmpty(t, meta.GetAccountId())
			if explicit {
				require.Equal(t, string(request.ID), meta.GetAccountId())
			}
			var binding string
			require.NoError(t, w.r.runtime.QueryRow(w.ctx, `SELECT id FROM kaname.access_bindings WHERE resource_type='account' AND resource_id=$1 AND role_id=$2`, meta.GetAccountId(), string(domain.OwnerRoleID)).Scan(&binding))
			require.Equal(t, 1, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.access_bindings WHERE id=$1
   AND revocation_reason IS NULL AND narrowed_at IS NULL AND grant_capability_version=0
   AND subject_type='user' AND subject_id=$2 AND deletion_protection AND status='ACTIVE'`, binding, w.actor))
			require.Equal(t, 2, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1`, binding))
			require.Equal(t, 1, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.access_binding_subjects WHERE binding_id=$1 AND subject_type='user' AND subject_id=$2`, binding, w.actor))
			require.Equal(t, 1, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.resource_journal WHERE resource_kind='iam_access_binding' AND resource_id=$1 AND event_type='CREATED' AND payload->>'id'=$1`, binding))
			sevenCRUDFact(t, w, "user:"+w.actor, "owner", "account:"+meta.GetAccountId(), true)
			allowed, err := w.door.Check(w.ctx, "user:"+w.actor, "v_delete", "account:"+meta.GetAccountId())
			require.NoError(t, err)
			require.True(t, allowed)
		})
	}
}

func TestSevenCRUDAccountDeleteGroupChildRefusalIsAtomic(t *testing.T) {
	var child string
	w := sevenCRUDPublicFixture(t, "account.delete", "", func(w *sevenCRUDPublicWorld) { child = stageSeedGroups(t, w.r, w.r.a, 1, "child")[0] })
	before := sevenCRUDSnapshot(t, w)
	op, err := accountapp.NewDeleteAccountUseCase(w.full, w.ops).WithAccountDeleteWriter(w.factory).Execute(declarerCtx(w.ctx, w.actor), w.account.ID)
	sevenCRUDResult(t, w, op, err, codes.FailedPrecondition)
	require.Equal(t, before, sevenCRUDSnapshot(t, w), "child refusal откатывает owner binding, журнал, ledger и membership эффекты")
	require.Equal(t, 1, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.groups WHERE id=$1 AND account_id=$2`, child, w.r.a))
}

// Обе формы входного порядка идут через настоящий compiler и публичный Stage
// reconciler. Сначала появляется ledger, затем меняются два действительных
// объекта: один порождает write, другой — непустой stale delete.
func TestBindingStageFullSharedProgramMatchesActualMultiEmitterAndTTL(t *testing.T) {
	for _, variant := range []string{"sorted", "unsorted", "expired-after-RR"} {
		t.Run(variant, func(t *testing.T) {
			r := writerProtocolRig(t)
			old := stageSeedGroups(t, r, r.a, 1, "blue")[0]
			uid := seedMemberUser(t, r.ctx, r.admin, r.a, "sequence-stage-recipient")
			verbs := []string{"get", "list"}
			if variant == "unsorted" {
				verbs = []string{"list", "get"}
			}
			id := groupLifecycleBinding(t, r, r.a, uid, "sequence_stage_role", domain.Rule{Module: "iam", Resources: []string{"group"}, Verbs: verbs, MatchLabels: map[string]string{"tier": "blue"}})
			engine := bindingStageEngine(t, r, nil)
			require.NoError(t, engine.ReconcileBinding(r.ctx, id))
			require.Equal(t, 1, stageCount(t, r, id))
			_, err := r.admin.Exec(r.ctx, `UPDATE kaname.groups SET labels='{"tier":"red"}'::jsonb WHERE id=$1`, old)
			require.NoError(t, err)
			fresh := stageSeedGroups(t, r, r.a, 1, "new")[0]
			_, err = r.admin.Exec(r.ctx, `UPDATE kaname.groups SET labels='{"tier":"blue"}'::jsonb WHERE id=$1`, fresh)
			require.NoError(t, err)
			var expires time.Time
			if variant == "expired-after-RR" {
				require.NoError(t, r.admin.QueryRow(r.ctx, `UPDATE kaname.access_bindings SET expires_at=clock_timestamp()+interval '8 seconds' WHERE id=$1 RETURNING expires_at`, string(id)).Scan(&expires))
			}
			full, contract := fullContractActivate(t, r)
			r.repo = full
			r.ctx = contract.Context(r.ctx)
			var cutoff int64
			require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT coalesce(max(id),0) FROM kaname.fga_outbox`).Scan(&cutoff))
			before := sevenCRUDCommandSnapshot(t, r)
			if variant == "expired-after-RR" {
				barrier := stageBarrier(t, "SELECT kaname.authority_protocol_enter")
				// Dedicated helper устанавливает тот же full contract на tracer pool.
				// Для этого сценария ниже используется отдельный retained-profile helper.
				engine = bindingStageFullTraceEngine(t, r, barrier)
				runCtx, cancelRun := context.WithCancel(r.ctx)
				done := make(chan error, 1)
				stopped := make(chan struct{})
				go func() { defer close(stopped); done <- engine.ReconcileBinding(runCtx, id) }()
				// Cleanup освобождает tracer до закрытия pool и ограниченно ждёт worker.
				defer func() {
					cancelRun()
					select {
					case <-barrier.release:
					default:
						close(barrier.release)
					}
					timer := time.NewTimer(10 * time.Second)
					defer timer.Stop()
					select {
					case <-stopped:
					case <-timer.C:
						t.Error("reconcile worker did not stop after cancellation")
					}
				}()
				stageWait(t, r, barrier.reached)
				// Один срок ограничивает все запросы server clock и синхронный poll;
				// фонового callback, меняющего at после завершения теста, здесь нет.
				clockCtx, cancelClock := context.WithTimeout(r.ctx, 10*time.Second)
				defer cancelClock()
				probe := r
				probe.ctx = clockCtx
				stageAssertBeforeEntry(t, probe, barrier)
				var at time.Time
				require.NoError(t, r.admin.QueryRow(clockCtx, `SELECT clock_timestamp()`).Scan(&at))
				require.True(t, at.Before(expires), "grant жив ПОСЛЕ завершённого настоящего RR capture")
				ticker := time.NewTicker(10 * time.Millisecond)
				defer ticker.Stop()
				for at.Before(expires) {
					select {
					case <-clockCtx.Done():
						t.Fatal(clockCtx.Err())
					case <-ticker.C:
					}
					require.NoError(t, r.admin.QueryRow(clockCtx, `SELECT clock_timestamp()`).Scan(&at))
				}
				require.False(t, at.Before(expires), "server clock достиг expiry, пока реальный RR stage удерживается")
				close(barrier.release)
				waitCtx, cancelWait := context.WithTimeout(r.ctx, 10*time.Second)
				defer cancelWait()
				select {
				case err := <-done:
					require.NoError(t, err)
				case <-waitCtx.Done():
					t.Fatal(waitCtx.Err())
				}
				require.Equal(t, before, sevenCRUDCommandSnapshot(t, r), "истёкшая ветвь выбирает пустую программу без effects")
				return
			}
			engine = bindingStageEngine(t, r, nil)
			require.NoError(t, engine.ReconcileBinding(r.ctx, id))
			require.Equal(t, 1, stageCount(t, r, id))
			var writes, deletes int
			var exact bool
			var deleteClocks int
			require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT
   count(*) FILTER(WHERE event_type='fga.tuple.write'),count(*) FILTER(WHERE event_type='fga.tuple.delete'),
   coalesce(bool_and(CASE WHEN event_type='fga.tuple.write' THEN
    payload=jsonb_build_object('object',$2::text,'user',$4::text,'relations',jsonb_build_array('v_get','v_list','viewer'),'relation','v_get')
    ELSE payload=jsonb_build_object('object',$3::text,'user',$4::text,'relations',jsonb_build_array('v_get','v_list','viewer')) END),false),
   count(DISTINCT created_at) FILTER(WHERE event_type='fga.tuple.delete')
   FROM kaname.fga_outbox WHERE id>$1`, cutoff, "iam_group:"+fresh, "iam_group:"+old, "user:"+uid).Scan(&writes, &deletes, &exact, &deleteClocks))
			require.Equal(t, 1, writes)
			require.Equal(t, 1, deletes)
			require.True(t, exact)
			require.Equal(t, 1, deleteClocks)
			require.True(t, ledgerHasTuple(t, r.ctx, r.runtime, id, "user:"+uid, "v_get", "iam_group:"+fresh))
			require.False(t, ledgerHasTuple(t, r.ctx, r.runtime, id, "user:"+uid, "v_get", "iam_group:"+old))
		})
	}
}

func TestBindingStageFullEmptyMaximumKeepsExactNoEffects(t *testing.T) {
	r := writerProtocolRig(t)
	id := stageBinding(t, r, r.a, false)
	full, contract := fullContractActivate(t, r)
	r.repo = full
	r.ctx = contract.Context(r.ctx)
	before := sevenCRUDCommandSnapshot(t, r)
	require.NoError(t, bindingStageEngine(t, r, nil).ReconcileBinding(r.ctx, id))
	require.Equal(t, before, sevenCRUDCommandSnapshot(t, r))
	require.Zero(t, stageCount(t, r, id))
}

func bindingStageFullTraceEngine(t *testing.T, r protocolRig, barrier *stageQueryBarrier) *reconcile.Reconciler {
	t.Helper()
	cfg := r.runtime.Config()
	cfg.ConnConfig.Tracer = barrier
	pool, err := pgxpool.NewWithConfig(r.ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	repo := kanamepg.New(pool, nil)
	contract, err := kanamepg.NewFullWriterContract(r.ctx, repo, r.bundle)
	require.NoError(t, err)
	r.repo, err = repo.WithFullWriterContract(contract)
	require.NoError(t, err)
	r.runtime = pool
	r.ctx = contract.Context(r.ctx)
	return bindingStageEngine(t, r, nil)
}

func sevenR2DefaultConflictPolicy(t *testing.T, r protocolRig) {
	t.Helper()
	var policy string
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT current_setting('plpgsql.variable_conflict')`).Scan(&policy))
	require.Equal(t, "error", policy, "проверки SQL names проходят при штатном conflict policy без обходного GUC")
}

// В отличие от пустого maximum при существующем selector, здесь candidate
// census действительно пуст: permissions-only роль не задаёт ни одного типа,
// а прежних target_members нет. Наблюдатель читает настоящий RR payload.
func TestBindingStageFullZeroCoordinateCaptureKeepsExactNoEffects(t *testing.T) {
	for _, mode := range []string{"reconcile", "forward", "converge"} {
		t.Run(mode, func(t *testing.T) {
			r := writerProtocolRig(t)
			uid := seedMemberUser(t, r.ctx, r.admin, r.a, "zero-coordinate-recipient")
			stageSeedGroups(t, r, r.b, 1, "foreign-zero-coordinate")
			writer, err := lifecycleOwner(r).Writer(r.ctx)
			require.NoError(t, err)
			defer func() { _ = writer.Rollback(context.WithoutCancel(r.ctx)) }()
			role, err := writer.RolesW().Insert(r.ctx, domain.Role{ID: domain.RoleID(ids.NewID("rol")), AccountID: domain.AccountID(r.a), Name: "zero_coordinate_role", Permissions: domain.Permissions{"iam.account.*.get"}})
			require.NoError(t, err)
			require.Empty(t, role.Rules.MaterializingSelectorsInScope(domain.ScopeAccount))
			binding, err := bindingset.Insert(r.ctx, writer.AccessBindingsW(), domain.AccessBinding{ID: domain.AccessBindingID(ids.NewID("acb")), SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid), RoleID: role.ID, ResourceType: "account", ResourceID: r.a, Scope: domain.ScopeAccount, Status: domain.AccessBindingStatusActive})
			require.NoError(t, err)
			require.NoError(t, writer.Commit(r.ctx))
			var selectors, members int
			var active bool
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT (SELECT count(*) FROM kaname.role_rule_selectors WHERE role_id=$1),(SELECT count(*) FROM kaname.access_binding_target_members WHERE binding_id=$2),(SELECT status='ACTIVE' FROM kaname.access_bindings WHERE id=$2)`, string(role.ID), string(binding.ID)).Scan(&selectors, &members, &active))
			require.Zero(t, selectors)
			require.Zero(t, members)
			require.True(t, active)
			fullContractActivate(t, r)
			observer := &sevenZeroCoordinateObserver{payload: make(chan []byte, 4)}
			cfg := r.runtime.Config()
			cfg.ConnConfig.Tracer = observer
			pool, err := pgxpool.NewWithConfig(r.ctx, cfg)
			require.NoError(t, err)
			t.Cleanup(pool.Close)
			repo := kanamepg.New(pool, nil)
			contract, err := kanamepg.NewFullWriterContract(r.ctx, repo, r.bundle)
			require.NoError(t, err)
			r.repo, err = repo.WithFullWriterContract(contract)
			require.NoError(t, err)
			r.runtime = pool
			r.ctx = contract.Context(r.ctx)
			before := sevenCRUDCommandSnapshot(t, r)
			business := func() string {
				var value string
				require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_build_object(
    'accounts',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM kaname.accounts x),
    'users',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM kaname.users x),
    'groups',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM kaname.groups x),
    'roles',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM kaname.roles x),
    'members',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]') FROM kaname.access_binding_target_members x)
   )::text`).Scan(&value))
				return value
			}
			beforeBusiness := business()
			engine := bindingStageEngine(t, r, nil)
			switch mode {
			case "reconcile":
				err = engine.ReconcileBinding(r.ctx, binding.ID)
			case "forward":
				err = engine.ReconcileBindingForward(r.ctx, binding.ID)
			case "converge":
				err = engine.ConvergeBinding(r.ctx, binding.ID)
			}
			require.NoError(t, err)
			select {
			case payload := <-observer.payload:
				var captured struct {
					Coordinates json.RawMessage `json:"coordinates"`
				}
				require.NoError(t, json.Unmarshal(payload, &captured))
				require.JSONEq(t, "[]", string(captured.Coordinates), "owner compiler получил настоящий пустой массив, не null и не account coordinate")
			default:
				t.Fatal("actual owner RR capture was not observed")
			}
			require.Equal(t, before, sevenCRUDCommandSnapshot(t, r))
			require.Equal(t, beforeBusiness, business())
		})
	}
}

type sevenZeroCoordinateObserver struct{ payload chan []byte }

func (o *sevenZeroCoordinateObserver) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if strings.Contains(d.SQL, "authority_binding_stage_sequence_capture_v3(") && len(d.Args) > 0 {
		var data []byte
		switch value := d.Args[0].(type) {
		case []byte:
			data = append([]byte(nil), value...)
		case string:
			data = []byte(value)
		}
		select {
		case o.payload <- data:
		default:
		}
	}
	return ctx
}
func (*sevenZeroCoordinateObserver) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {
}
