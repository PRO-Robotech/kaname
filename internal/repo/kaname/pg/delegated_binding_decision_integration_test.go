// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	bindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	gdapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/grant_delegation"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	ab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationwriterfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Ожидаем только названную LRO: соседний worker вправе стоять на барьере.
// Глобальный operations.Wait здесь создал бы цикл с удерживающим тестом.
func awaitDelegatedOperation(t *testing.T, ctx context.Context, ops operations.Repo, id string) *operations.Operation {
	t.Helper()
	wait, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		op, err := ops.Get(wait, id)
		require.NoError(t, err)
		require.NotNil(t, op)
		if op.Done {
			return op
		}
		select {
		case <-tick.C:
		case <-wait.Done():
			t.Fatalf("операция %s не завершилась: %v", id, wait.Err())
		}
	}
}

// Тот же public GD Create и actual participant, но ожидание локально для D5.
func createDelegatedFixtureGrant(t *testing.T, w delegationUCWorld, who string) string {
	t.Helper()
	f := delegationObservedFactory{p: w.participant, opened: make(chan kaname.Writer, 1)}
	uc := gdapp.NewCreateGrantDelegationUseCase(w.r.repo, w.ops, w.source).WithRelationStore(w.door, nil).WithAuthorityWriter(f)
	plans, err := authzmodel.New(w.r.bundle.ModelSource())
	require.NoError(t, err)
	uc.WithInstallationModel(plans)
	op, err := uc.Execute(declarerCtx(w.r.ctx, who), w.input)
	require.NoError(t, err)
	require.Nil(t, awaitDelegatedOperation(t, w.r.ctx, w.ops, op.ID).Error)
	select {
	case tx := <-f.opened:
		require.False(t, tx.(kaname.AuthorityWriter).AuthorityFence().DecisionAt().IsZero())
	default:
		t.Fatal("actual Create worker не вызвал participant")
	}
	var id string
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT id FROM kaname.grant_delegations WHERE account_id=$1 AND delegate_id=$2 AND status='ACTIVE'`, w.input.AccountID, w.input.DelegateID).Scan(&id))
	return id
}

type delegatedBindingWorld struct {
	delegationUCWorld
	creator        string
	otherRecipient string
	authority      domain.AccessBindingID
	gd             string
	input          domain.AccessBinding
	actor          context.Context
	writers        *kanamepg.GrantPolicyWriters
}

func delegatedBindingFixture(t *testing.T, administrative bool) delegatedBindingWorld {
	t.Helper()
	w := delegationUCFixture(t)
	creator := w.owner
	var authority domain.AccessBindingID
	if administrative {
		authority = w.grantAdmin(t)
		creator = w.member
	}
	// Дано через реальный GD Create worker, а не INSERT прав делегата.
	gd := createDelegatedFixtureGrant(t, w, creator)
	project := seedProject(t, w.r.ctx, kanamepg.New(w.r.admin, nil), domain.AccountID(w.r.a), "delegated-decision")
	target := "decision-" + ids.NewID("reg")
	uc := newRegisterUCWired(w.r.admin).WithRegistrationAuthority(registrationwriterfixture.Authority{Module: "registry"})
	require.NoError(t, uc.Register(w.r.ctx, &iamv1.RegisterResourceRequest{SubjectId: "project:" + string(project.ID), Relation: "project", Object: "registry_registry:" + target, ParentProjectId: string(project.ID), ParentAccountId: w.r.a, ParentChain: []string{"project:" + string(project.ID), "account:" + w.r.a}}))
	recipient := seedSAID(t, w.r.ctx, w.r.admin, w.r.a, "d5-recipient")
	otherRecipient := seedSAID(t, w.r.ctx, w.r.admin, w.r.a, "d5-earlier-recipient")
	input := domain.AccessBinding{RoleID: domain.RoleID(w.input.RoleIDs[0]), ResourceType: "account", ResourceID: w.r.a, Scope: domain.ScopeAccount, Subjects: []domain.Subject{{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(recipient)}}, Target: domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "registry.registries", ID: target}}}}
	writers, err := kanamepg.NewGrantPolicyWriters(w.r.ctx, w.r.repo, w.r.bundle)
	require.NoError(t, err)
	require.NoError(t, lifecycleOwner(w.r).ActivateAuthorityBundle(w.r.ctx, w.r.bundle))
	actor := operations.WithPrincipal(w.r.ctx, operations.Principal{Type: "service_account", ID: w.input.DelegateID})
	// Делегат не держит обычного права выдавать; иначе положительный тест не D5.
	allowed, err := w.door.Check(w.r.ctx, "service_account:"+w.input.DelegateID, "admin", "account:"+w.r.a)
	require.NoError(t, err)
	require.False(t, allowed)
	return delegatedBindingWorld{delegationUCWorld: w, creator: creator, otherRecipient: otherRecipient, authority: authority, gd: gd, input: input, actor: actor, writers: writers}
}
func (d delegatedBindingWorld) createUC(t *testing.T, runner kaname.BindingDecisionRunner) *bindingapp.CreateAccessBindingUseCase {
	t.Helper()
	stages := withdrawalParticipant(t, d.r, nil)
	engine := reconcile.New(kanamepg.NewReconcileAdapter(d.r.runtime, d.source), slog.Default(), d.source)
	require.NoError(t, engine.WithStagedBindingReconciler(stages))
	return bindingapp.NewCreateAccessBindingUseCase(d.r.repo, d.ops, d.source).
		WithBindingDecisions(runner).WithDelegatedGrantPath(bindingapp.NewDelegatedGrantPath(d.r.repo, d.door)).
		WithRegisteredKeys(kanamepg.NewRegisteredKeys(d.r.runtime)).WithReconciler(engine)
}
func (d delegatedBindingWorld) createBinding(t *testing.T, uc *bindingapp.CreateAccessBindingUseCase, in domain.AccessBinding) string {
	t.Helper()
	op, err := uc.Execute(d.actor, in)
	require.NoError(t, err)
	require.Nil(t, awaitDelegatedOperation(t, d.r.ctx, d.ops, op.ID).Error)
	var id string
	var version int
	require.NoError(t, d.r.runtime.QueryRow(d.r.ctx, `SELECT id,grant_capability_version FROM kaname.access_bindings WHERE delegation_id=$1 AND subject_id=$2 AND revoked_at IS NULL`, d.gd, string(in.Subjects[0].ID)).Scan(&id, &version))
	require.Equal(t, 1, version)
	var creator string
	require.NoError(t, d.r.runtime.QueryRow(d.r.ctx, `SELECT event_payload->>'actor' FROM kaname.audit_outbox WHERE event_payload->>'binding_id'=$1 AND event_type='iam.access_binding.granted' LIMIT 1`, id).Scan(&creator))
	require.Equal(t, d.delegationUCWorld.input.DelegateID, creator, "аудит сохраняет caller, не creator delegation")
	require.Eventually(t, func() bool {
		allowed, e := d.door.Check(d.r.ctx, "service_account:"+string(in.Subjects[0].ID), "v_get", "registry_registry:"+in.Target.Resources[0].ID)
		return e == nil && allowed
	}, 10*time.Second, 10*time.Millisecond, "реальный native доступ должен материализоваться через staged postcommit")
	allowed, e := d.door.Check(d.r.ctx, "service_account:"+d.delegationUCWorld.input.DelegateID, "v_get", "registry_registry:"+in.Target.Resources[0].ID)
	require.NoError(t, e)
	require.False(t, allowed, "делегат не получает выданный доступ себе")
	return id
}

func TestDelegatedBindingDecisionActualCreateAxesAndTypedAdmission(t *testing.T) {
	d := delegatedBindingFixture(t, false)
	uc := d.createUC(t, d.writers)
	// Полный Subjects: последняя запрещённая учётка не скрывается первой допустимой.
	bad := d.input
	bad.Subjects = append(append([]domain.Subject{}, d.input.Subjects...), domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(d.delegationUCWorld.input.DelegateID)})
	_, err := uc.Execute(d.actor, bad)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	bad = d.input
	bad.Target = domain.AccessTarget{AllInScope: true}
	_, err = uc.Execute(d.actor, bad)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	bad = d.input
	bad.RoleID = domain.RoleID(domain.OwnerRoleID)
	_, err = uc.Execute(d.actor, bad)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	bad = d.input
	bad.ResourceID = d.r.b
	_, err = uc.Execute(d.actor, bad)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	bad = d.input
	bad.Subjects = []domain.Subject{{Type: domain.SubjectTypeUser, ID: d.input.Subjects[0].ID}}
	_, err = uc.Execute(d.actor, bad)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	bad = d.input
	bad.Target = domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "registry.registries", ID: "absent-d5-object"}}}
	_, err = uc.Execute(d.actor, bad)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	id := d.createBinding(t, uc, d.input)
	require.Equal(t, domain.GrantDelegationID(d.gd), bindingRow(t, d.r, domain.AccessBindingID(id)).DelegationID)
	var count int
	require.NoError(t, d.r.runtime.QueryRow(d.r.ctx, `SELECT count(*) FROM kaname.access_bindings WHERE delegation_id=$1`, d.gd).Scan(&count))
	require.Equal(t, 1, count)
	// Same raw ID с user типом не становится service_account делегатом.
	_, err = uc.Execute(operations.WithPrincipal(d.r.ctx, operations.Principal{Type: "user", ID: d.delegationUCWorld.input.DelegateID}), d.input)
	require.Error(t, err)
	authorityWaitReleased(t, d.r.runtime)
}

// Барьер на реальном runner оставляет все решения production-коду. Он лишь
// останавливает LRO перед новой TX после успешно завершённого precheck.
type delegatedDecisionWorkerBarrier struct {
	*kanamepg.GrantPolicyWriters
	calls   atomic.Int32
	arrived chan struct{}
	release chan struct{}
}

func (b *delegatedDecisionWorkerBarrier) RunDelegatedBindingDecision(ctx context.Context, a domain.Subject, in domain.AccessBinding, tuples func(domain.AccessBinding, domain.Role) []ab.RelationTuple, apply func(context.Context, kaname.SemanticAuthorityWriter, domain.AccessBinding, domain.Role) error) error {
	if b.calls.Add(1) == 2 {
		close(b.arrived)
		select {
		case <-b.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return b.GrantPolicyWriters.RunDelegatedBindingDecision(ctx, a, in, tuples, apply)
}
func delegatedWorkerBarrier(t *testing.T, d delegatedBindingWorld) *delegatedDecisionWorkerBarrier {
	t.Helper()
	b := &delegatedDecisionWorkerBarrier{GrantPolicyWriters: d.writers, arrived: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(func() {
		select {
		case <-b.release:
		default:
			close(b.release)
		}
	})
	return b
}
func (d delegatedBindingWorld) revoke(t *testing.T) {
	t.Helper()
	uc := gdapp.NewRevokeGrantDelegationUseCase(d.r.repo, d.ops).WithRelationStore(d.door, nil).WithRevokeAuthorityWriter(delegationRevokeParticipant(t, d.delegationUCWorld))
	op, err := uc.Execute(declarerCtx(d.r.ctx, d.owner), domain.GrantDelegationID(d.gd))
	require.NoError(t, err)
	require.Nil(t, awaitDelegatedOperation(t, d.r.ctx, d.ops, op.ID).Error)
}
func TestDelegatedBindingDecisionCapturedIDCannotFollowReplacement(t *testing.T) {
	d := delegatedBindingFixture(t, false)
	barrier := delegatedWorkerBarrier(t, d)
	op, err := d.createUC(t, barrier).Execute(d.actor, d.input)
	require.NoError(t, err)
	stageWait(t, d.r, barrier.arrived)
	d.revoke(t)
	replacement := createDelegatedFixtureGrant(t, d.delegationUCWorld, d.owner)
	require.NotEqual(t, d.gd, replacement)
	close(barrier.release)
	require.NotNil(t, awaitDelegatedOperation(t, d.r.ctx, d.ops, op.ID).Error)
	var count int
	require.NoError(t, d.r.runtime.QueryRow(d.r.ctx, `SELECT count(*) FROM kaname.access_bindings WHERE delegation_id=ANY($1::text[])`, []string{d.gd, replacement}).Scan(&count))
	require.Zero(t, count)
	// Новый явный public Create вправе выбрать новое действующее делегирование.
	d.gd = replacement
	d.createBinding(t, d.createUC(t, d.writers), d.input)
	authorityWaitReleased(t, d.r.runtime)
}

func TestDelegatedBindingDecisionPublicCreatePhantomRestagesRevoke(t *testing.T) {
	d := delegatedBindingFixture(t, false)
	// Отзыв завершил RR census, но ещё не получил authority fence.
	barrier := stageBarrier(t, "authority_protocol_enter")
	cfg := d.r.runtime.Config()
	cfg.ConnConfig.Tracer = barrier
	pool, err := pgxpool.NewWithConfig(d.r.ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	t.Cleanup(func() {
		select {
		case <-barrier.release:
		default:
			close(barrier.release)
		}
	})
	traced := d.delegationUCWorld
	traced.r.runtime = pool
	traced.r.repo = kanamepg.New(pool, nil)
	revoke := gdapp.NewRevokeGrantDelegationUseCase(traced.r.repo, traced.ops).WithRelationStore(traced.door, nil).WithRevokeAuthorityWriter(delegationRevokeParticipant(t, traced))
	op, err := revoke.Execute(declarerCtx(d.r.ctx, d.owner), domain.GrantDelegationID(d.gd))
	require.NoError(t, err)
	stageWait(t, d.r, barrier.reached)
	// Настоящий public Create, не прямой INSERT phantom.
	id := d.createBinding(t, d.createUC(t, d.writers), d.input)
	// Завершение операции и первый native fact ещё не означают, что staged
	// postcommit дописал весь ledger. Штатный повторный проход ждёт того же
	// binding lock и завершает материализацию до снимка; revoke всё ещё на barrier.
	stages := withdrawalParticipant(t, d.r, nil)
	engine := reconcile.New(kanamepg.NewReconcileAdapter(d.r.runtime, d.source), slog.Default(), d.source)
	require.NoError(t, engine.WithStagedBindingReconciler(stages))
	require.NoError(t, engine.ReconcileBinding(d.r.ctx, domain.AccessBindingID(id)))
	// Soft revoke сохраняет historical ledger. Фиксируем его полный снимок
	// и отдельные уже существующие native keys ДО освобождения revoke.
	var ledgerBefore, nativeKeys []byte
	var ledgerCount, nativeCount int
	require.NoError(t, d.r.runtime.QueryRow(d.r.ctx, `SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY e.member_object_type,e.member_object_id,e.fga_user,e.relation,e.object),'[]'::jsonb),count(*) FROM kaname.access_binding_emitted_tuples e WHERE e.binding_id=$1`, id).Scan(&ledgerBefore, &ledgerCount))
	require.Positive(t, ledgerCount, "Дано: actual public Create сохранил ledger")
	require.NoError(t, d.r.runtime.QueryRow(d.r.ctx, `SELECT coalesce(jsonb_agg(jsonb_build_array(f.subject,f.relation,f.object_type,f.object_id)),'[]'::jsonb),count(*) FROM kaname.relation_fact f WHERE EXISTS(SELECT 1 FROM kaname.access_binding_emitted_tuples e WHERE e.binding_id=$1 AND e.fga_user=f.subject AND e.relation=f.relation AND e.object=f.object_type||':'||f.object_id)`, id).Scan(&nativeKeys, &nativeCount))
	require.Positive(t, nativeCount, "Дано: сохранённые keys реально материализованы до revoke")
	close(barrier.release)
	require.Nil(t, awaitDelegatedOperation(t, d.r.ctx, d.ops, op.ID).Error)
	got := bindingRow(t, d.r, domain.AccessBindingID(id))
	require.Equal(t, domain.AccessBindingStatusRevoked, got.Status)
	var ledgerAfter []byte
	require.NoError(t, d.r.runtime.QueryRow(d.r.ctx, `SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY e.member_object_type,e.member_object_id,e.fga_user,e.relation,e.object),'[]'::jsonb) FROM kaname.access_binding_emitted_tuples e WHERE e.binding_id=$1`, id).Scan(&ledgerAfter))
	require.Equal(t, string(ledgerBefore), string(ledgerAfter), "soft revoke сохраняет весь historical ledger")
	var residual int
	// Проверка независима от текущего ledger: удаление ledger само по себе
	// не могло бы дать ложный ноль фактов; ключи взяты из положительного Given.
	require.NoError(t, d.r.runtime.QueryRow(d.r.ctx, `SELECT count(*) FROM kaname.relation_fact f WHERE jsonb_build_array(f.subject,f.relation,f.object_type,f.object_id) IN (SELECT value FROM jsonb_array_elements($1::jsonb))`, nativeKeys).Scan(&residual))
	require.Zero(t, residual, "сохранённые native keys отозванной выдачи удалены")
	allowed, e := d.door.Check(d.r.ctx, "service_account:"+string(d.input.Subjects[0].ID), "v_get", "registry_registry:"+d.input.Target.Resources[0].ID)
	require.NoError(t, e)
	require.False(t, allowed, "каскад реального public Create снимает доступ")
	// Отзыв сериализован первым: новый public Create не создаёт хвост.
	_, err = d.createUC(t, d.writers).Execute(d.actor, d.input)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	authorityWaitReleased(t, d.r.runtime)
}

func TestDelegatedBindingDecisionCreatorExpiryAfterActualGDWait(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "live", true: "expired"}[expired], func(t *testing.T) {
			d := delegatedBindingFixture(t, true)
			earlier := d.input
			earlier.Subjects = []domain.Subject{{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(d.otherRecipient)}}
			existing := d.createBinding(t, d.createUC(t, d.writers), earlier)
			barrier := delegatedWorkerBarrier(t, d)
			op, err := d.createUC(t, barrier).Execute(d.actor, d.input)
			require.NoError(t, err)
			stageWait(t, d.r, barrier.arrived)
			interval := "1 hour"
			if expired {
				interval = "3 seconds"
			}
			var deadline time.Time
			deadline = delegatedAuthorityExpiry(t, d, interval)
			blocker, err := d.r.admin.Begin(d.r.ctx)
			require.NoError(t, err)
			lifecycleRollback(t, blocker)
			var id, xid string
			require.NoError(t, blocker.QueryRow(d.r.ctx, `SELECT id FROM kaname.grant_delegations WHERE id=$1 FOR UPDATE`, d.gd).Scan(&id))
			require.Equal(t, d.gd, id)
			require.NoError(t, blocker.QueryRow(d.r.ctx, `SELECT pg_current_xact_id()::text`).Scan(&xid))
			close(barrier.release)
			semanticWaitIdentity(t, d.r.ctx, d.r.admin, xid)
			var liveAtWait bool
			require.NoError(t, d.r.admin.QueryRow(d.r.ctx, `SELECT clock_timestamp()<$1`, deadline).Scan(&liveAtWait))
			require.True(t, liveAtWait, "контроль: authority ещё живо после начала фактического ожидания")
			if expired {
				require.Eventually(t, func() bool {
					var passed bool
					e := d.r.admin.QueryRow(d.r.ctx, `SELECT clock_timestamp()>$1`, deadline).Scan(&passed)
					return e == nil && passed
				}, 5*time.Second, 10*time.Millisecond)
			}
			require.NoError(t, blocker.Commit(d.r.ctx))
			done := awaitDelegatedOperation(t, d.r.ctx, d.ops, op.ID)
			var count int
			require.NoError(t, d.r.runtime.QueryRow(d.r.ctx, `SELECT count(*) FROM kaname.access_bindings WHERE delegation_id=$1`, d.gd).Scan(&count))
			if expired {
				require.NotNil(t, done.Error)
				require.Equal(t, int32(codes.PermissionDenied), done.Error.Code)
				require.Equal(t, 1, count)
			} else {
				require.Nil(t, done.Error)
				require.Equal(t, 2, count)
			}
			prior := bindingRow(t, d.r, domain.AccessBindingID(existing))
			require.Equal(t, domain.AccessBindingStatusActive, prior.Status, "утрата creator authority не отзывает прошлую выдачу")
			require.Nil(t, prior.ExpiresAt, "срок creator не копируется в выдачу")
			authorityWaitReleased(t, d.r.runtime)
		})
	}
}

// Изменение fixture после strict тоже проходит настоящий participant entry на
// ordinary LOGIN; прямой owner DML не обходится флагом или отключением trigger.
func delegatedAuthorityExpiry(t *testing.T, d delegatedBindingWorld, interval string) time.Time {
	t.Helper()
	tx, err := d.r.runtime.Begin(d.r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	d.r.enter(t, tx, kaname.AuthorityWriteIntent{Kind: kaname.AuthorityBinding, Bundle: d.r.bundle, Plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}, Owners: []kaname.AuthorityOwnerRef{{Kind: "binding", ID: string(d.authority)}}}, "participant")
	var deadline time.Time
	require.NoError(t, tx.QueryRow(d.r.ctx, `UPDATE kaname.access_bindings SET expires_at=clock_timestamp()+$2::interval WHERE id=$1 RETURNING expires_at`, string(d.authority), interval).Scan(&deadline))
	require.NoError(t, tx.Commit(d.r.ctx))
	return deadline
}
