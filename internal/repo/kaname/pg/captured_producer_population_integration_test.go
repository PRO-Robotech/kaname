// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	ab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationscene"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// Здесь настоящий обычный LOGIN, реальная фабрика RR->RC и один физический слот пула.
// Положительный источник — настоящий канонический владелец аккаунта; тест не
// создаёт искусственный receipt или grant. Допустимость producer и ABA проверяются отдельно.
func TestCapturedProducerActualFactoryOneSlotPositiveAndLifecycle(t *testing.T) {
	r := writerProtocolRig(t)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	cfg := r.runtime.Config()
	cfg.MaxConns = 1
	cfg.MinConns = 0
	pool, err := pgxpool.NewWithConfig(r.ctx, cfg)
	require.NoError(t, err)
	defer pool.Close()
	historical, err := kanamepg.NewGrantPolicyWriters(r.ctx, kanamepg.New(pool, nil), r.bundle)
	require.NoError(t, err)
	captured, err := historical.WithCapturedProducerSources()
	require.NoError(t, err)
	actor := policyActor(t, r, r.a)
	ctx, cancel := context.WithTimeout(r.ctx, 10*time.Second)
	defer cancel()
	old, err := historical.RoleAuthorityWriter(ctx, policyNewRole(r.a), true, actor)
	defer policyFixtureRollback(old)
	require.NoError(t, err)
	token, err := old.(kaname.CapturedProducerPopulationReader).CapturedProducerPopulation(ctx, actor)
	require.NoError(t, err)
	require.Nil(t, token, "opt-in must not mutate historical factory")
	require.NoError(t, old.Rollback(ctx))
	w, err := captured.RoleAuthorityWriter(ctx, policyNewRole(r.a), true, actor)
	defer policyFixtureRollback(w)
	require.NoError(t, err)
	require.EqualValues(t, 1, pool.Stat().AcquiredConns())
	token, err = w.(kaname.CapturedProducerPopulationReader).CapturedProducerPopulation(ctx, actor)
	require.NoError(t, err)
	require.NotNil(t, token)
	require.NoError(t, token.Validate(w, actor, w.AuthorityFence().DecisionAt()))
	proof, err := grantpolicy.CollectWitnessedLowerBound(ctx, w, actor)
	require.NoError(t, err)
	require.Same(t, token, proof.Census().ProducerPopulation)
	require.False(t, proof.Census().Component.Complete(), "current original population remains incomplete")
	require.NoError(t, grantpolicy.RequireScopeAdministration(ctx, w, actor, domain.ScopeAnchor{Type: "account", ID: r.a}))
	require.NoError(t, w.Commit(ctx))
	require.EqualValues(t, 0, pool.Stat().AcquiredConns())
	require.ErrorIs(t, token.Validate(w, actor, w.AuthorityFence().DecisionAt()), kaname.ErrSourceUnconfirmed)
	next, err := captured.RoleAuthorityWriter(ctx, policyNewRole(r.a), true, actor)
	defer policyFixtureRollback(next)
	require.NoError(t, err)
	require.ErrorIs(t, token.Validate(next, actor, next.AuthorityFence().DecisionAt()), kaname.ErrSourceUnconfirmed)
	current, err := next.(kaname.CapturedProducerPopulationReader).CapturedProducerPopulation(ctx, actor)
	require.NoError(t, err)
	cancelled, stop := context.WithCancel(ctx)
	stop()
	_, err = next.(kaname.CapturedProducerPopulationReader).CapturedProducerPopulation(cancelled, actor)
	require.ErrorIs(t, err, context.Canceled)
	require.NoError(t, next.Rollback(ctx))
	require.ErrorIs(t, current.Validate(next, actor, next.AuthorityFence().DecisionAt()), kaname.ErrSourceUnconfirmed)
	require.EqualValues(t, 0, pool.Stat().AcquiredConns())
	// Настоящий этап роли использует RR с собственным временным spool и возвращает закрытую
	// обёртку prepared-role. Она обязана использовать тот же ABI захвата, а не молча
	// переходить к историческим сканированиям или отвергать собственную обёртку.
	role := policyNewRole(r.a)
	role.ID = domain.RoleID(ids.NewID("rol"))
	prepared, err := captured.RoleMutationWriter(ctx, kaname.RoleMutationRequest{Role: role, Create: true, Rules: true}, actor)
	defer policyFixtureRollback(prepared)
	require.NoError(t, err)
	preparedToken, err := prepared.(kaname.CapturedProducerPopulationReader).CapturedProducerPopulation(ctx, actor)
	require.NoError(t, err)
	require.NotNil(t, preparedToken)
	require.NoError(t, preparedToken.Validate(prepared, actor, prepared.AuthorityFence().DecisionAt()))
	_, err = grantpolicy.CollectWitnessedLowerBound(ctx, prepared, actor)
	require.NoError(t, err)
	require.NoError(t, prepared.Rollback(ctx))
	require.ErrorIs(t, preparedToken.Validate(prepared, actor, prepared.AuthorityFence().DecisionAt()), kaname.ErrSourceUnconfirmed)

}

// В настоящий callback тела внедряется только новый маркер Unknown. Исполнитель
// обязан прервать и заново захватить всю попытку; он никогда не должен превращать исчерпание
// в отказ в доступе или повторно использовать свидетельства предыдущей попытки.
func TestCapturedProducerUnknownRestagesWholeAttemptWithBoundedBudget(t *testing.T) {
	r := writerProtocolRig(t)
	seed := stageBinding(t, r, r.a, false)
	proposal := bindingRow(t, r, seed)
	actor := policyActor(t, r, r.a)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	cfg := r.runtime.Config()
	cfg.MaxConns = 1
	cfg.MinConns = 0
	pool, err := pgxpool.NewWithConfig(r.ctx, cfg)
	require.NoError(t, err)
	defer pool.Close()
	factory, err := kanamepg.NewGrantPolicyWriters(r.ctx, kanamepg.New(pool, nil), r.bundle)
	require.NoError(t, err)
	factory, err = factory.WithCapturedProducerSources()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(r.ctx, 10*time.Second)
	defer cancel()
	calls := 0
	var previous kaname.CapturedProducerPopulation
	err = factory.RunBindingDecision(ctx, actor, proposal, false, nil, func(ctx context.Context, w kaname.SemanticAuthorityWriter, _ domain.AccessBinding, _ domain.Role) error {
		calls++
		if previous != nil {
			require.ErrorIs(t, previous.Validate(w, actor, w.AuthorityFence().DecisionAt()), kaname.ErrSourceUnconfirmed)
		}
		token, e := w.(kaname.CapturedProducerPopulationReader).CapturedProducerPopulation(ctx, actor)
		require.NoError(t, e)
		require.NoError(t, token.Validate(w, actor, w.AuthorityFence().DecisionAt()))
		previous = token
		return kaname.ErrCapturedProducerInsufficient
	})
	require.ErrorIs(t, err, kaname.ErrCapturedProducerInsufficient)
	require.ErrorIs(t, err, kaname.ErrAuthorityClassificationChanged)
	require.Equal(t, 3, calls, "existing authorityEntryAttempts bounds whole-attempt restaging")
	require.EqualValues(t, 0, pool.Stat().AcquiredConns())
}

// Неприменённый tuple body — настоящее обязательство prepared role, даже если
// builder фикстуры не создаёт кортежей. Отказ инвалидирует proof, сохраняя
// возможность cleanup единственной leased connection.
type capturedPGRoleTuples struct{}

func (capturedPGRoleTuples) BuildRoleTuples(domain.AccessBinding, []domain.Subject, domain.Role) []ab.RelationTuple {
	return nil
}
func TestCapturedPreparedCommitFailureReleasesSingleLeaseOnRollback(t *testing.T) {
	r := writerProtocolRig(t)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	cfg := r.runtime.Config()
	cfg.MaxConns = 1
	cfg.MinConns = 0
	pool, err := pgxpool.NewWithConfig(r.ctx, cfg)
	require.NoError(t, err)
	defer pool.Close()
	factory, err := kanamepg.NewGrantPolicyWriters(r.ctx, kanamepg.New(pool, nil), r.bundle)
	require.NoError(t, err)
	factory, err = factory.WithCapturedProducerSources()
	require.NoError(t, err)
	actor := policyActor(t, r, r.a)
	role := policyNewRole(r.a)
	role.ID = domain.RoleID(ids.NewID("rol"))
	ctx, cancel := context.WithTimeout(r.ctx, 10*time.Second)
	defer cancel()
	w, err := factory.RoleMutationWriter(ctx, kaname.RoleMutationRequest{Role: role, Create: true, Rules: true, Tuples: capturedPGRoleTuples{}}, actor)
	defer policyFixtureRollback(w)
	require.NoError(t, err)
	token, err := w.(kaname.CapturedProducerPopulationReader).CapturedProducerPopulation(ctx, actor)
	require.NoError(t, err)
	require.NoError(t, token.Validate(w, actor, w.AuthorityFence().DecisionAt()))
	require.ErrorIs(t, w.Commit(ctx), kaname.ErrInvalidAuthorityFencePlan)
	require.ErrorIs(t, token.Validate(w, actor, w.AuthorityFence().DecisionAt()), kaname.ErrSourceUnconfirmed)
	_, err = w.(kaname.CapturedProducerPopulationReader).CapturedProducerPopulation(ctx, actor)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	require.NoError(t, w.Rollback(ctx))
	require.EqualValues(t, 0, pool.Stat().AcquiredConns())
	next, err := factory.RoleAuthorityWriter(ctx, policyNewRole(r.a), true, actor)
	defer policyFixtureRollback(next)
	require.NoError(t, err)
	require.NoError(t, next.Rollback(ctx))
}

// Барьер находится после полного RR capture и перед RC BEGIN, до production
// fences. Настоящий producer может завершиться; final epoch protection обязана
// начать новую попытку вместо использования устаревшей популяции.
type capturedReceiptBarrier struct {
	armed       atomic.Bool
	captureSeen atomic.Bool
	captures    atomic.Int32
	queries     atomic.Int32
	reached     chan struct{}
	resume      chan struct{}
	once        sync.Once
}

func (b *capturedReceiptBarrier) release() { b.once.Do(func() { close(b.resume) }) }
func (b *capturedReceiptBarrier) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	b.queries.Add(1)
	if strings.Contains(d.SQL, "r.xmin::text") && strings.Contains(d.SQL, "COLLATE \"C\"") {
		b.captureSeen.Store(true)
		b.captures.Add(1)
	}
	if strings.Contains(strings.ToLower(d.SQL), "begin isolation level read committed") && b.captureSeen.Load() && b.armed.CompareAndSwap(true, false) {
		close(b.reached)
		select {
		case <-b.resume:
		case <-ctx.Done():
		}
	}
	return ctx
}
func (*capturedReceiptBarrier) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestCapturedProducerActualNonemptyPublicationD1AndRestage(t *testing.T) {
	r := writerProtocolRig(t)
	scene := registrationscene.Seed(t, r.ctx, r.admin)
	uid := seedMemberUser(t, r.ctx, r.admin, scene.Account, "captured-public-reader")
	_, err := r.admin.Exec(r.ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=$1`, uid)
	require.NoError(t, err)
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)}
	roster, err := moduleidentity.Parse([]string{"modules/kacho-registry=module-writer"})
	require.NoError(t, err)
	setup, err := lifecycleOwner(r).Writer(r.ctx)
	require.NoError(t, err)
	defer policyFixtureRollback(setup)
	_, err = setup.ServiceAccountsW().Insert(r.ctx, domain.ServiceAccount{ID: domain.ServiceAccountID(authzguard.ServiceAccountIDForService("registry")), AccountID: domain.AccountID(r.a), Name: "kacho-registry", Description: "captured real publication producer"})
	require.NoError(t, err)
	// Актор получает отдельное предусловие create-binding. Проверяемый v_get
	// появится только через настоящий producer; bind-role и admin не выдаются.
	create := domain.Role{ID: domain.RoleID(ids.NewID("rol")), AccountID: domain.AccountID(scene.Account), Name: "captured_create_only", Rules: domain.Rules{{Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"create"}}}}
	create.Permissions, err = domain.CompileRules(create.Rules)
	require.NoError(t, err)
	projection, err := r.bundle.Projection(create)
	require.NoError(t, err)
	_, err = setup.RolesW().Insert(r.ctx, create)
	require.NoError(t, err)
	require.NoError(t, setup.RolesW().ReplaceRoleVerbs(r.ctx, create.ID, projection.Verbs))
	require.NoError(t, setup.RolesW().ReplaceRuleSelectors(r.ctx, create.ID, projection.Selectors))
	require.NoError(t, setup.RolesW().ReplaceGrantCapabilities(r.ctx, create.ID, projection.Capabilities))

	// Полный эффект get включает viewer. Публикация даёт только v_get,
	// поэтому соседний list-носитель обеспечивает viewer, но сам get не даёт.
	listRole := domain.Role{ID: domain.RoleID(ids.NewID("rol")), ProjectID: domain.ProjectID(scene.Project), Name: "captured_list_only", Rules: domain.Rules{{Module: "registry", Resources: []string{"repositories"}, Verbs: []string{"list"}}}}
	listRole.Permissions, err = domain.CompileRules(listRole.Rules)
	require.NoError(t, err)
	listProjection, err := r.bundle.Projection(listRole)
	require.NoError(t, err)
	_, err = setup.RolesW().Insert(r.ctx, listRole)
	require.NoError(t, err)
	require.NoError(t, setup.RolesW().ReplaceRoleVerbs(r.ctx, listRole.ID, listProjection.Verbs))
	require.NoError(t, setup.RolesW().ReplaceRuleSelectors(r.ctx, listRole.ID, listProjection.Selectors))
	require.NoError(t, setup.RolesW().ReplaceGrantCapabilities(r.ctx, listRole.ID, listProjection.Capabilities))

	targetRole := domain.Role{ID: domain.RoleID(ids.NewID("rol")), ProjectID: domain.ProjectID(scene.Project), Name: "captured_public_get", Rules: domain.Rules{{Module: "registry", Resources: []string{"repositories"}, Verbs: []string{"get"}}}}
	targetRole.Permissions, err = domain.CompileRules(targetRole.Rules)
	require.NoError(t, err)
	_, err = setup.RolesW().Insert(r.ctx, targetRole)
	require.NoError(t, err)
	require.NoError(t, setup.Commit(r.ctx))
	require.NoError(t, seed.ApplyRegistrationAccountWriters(r.ctx, kanamepg.NewRegistrationAccountWriterStore(r.admin), roster, seed.RegistrationWriterPlan{Assignments: []domain.RegistrationAccountWriter{{AssignmentID: "captured-registry", AccountID: scene.Account, Module: "registry"}}}))
	participant, err := kanamepg.NewResourceObjectParticipant(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	beginner, err := participant.RegistrationTxBeginner(r.runtime)
	require.NoError(t, err)
	gate := authzguard.NewRelationWriteGate(delegationNativeDoor{r}).WithModuleRoster(roster)
	ctx := grpcsrv.WithCertIdentityIn(r.ctx, grpcsrv.NewTrustDomain("kacho.cloud"), "spiffe://kacho.cloud/ns/modules/sa/kacho-registry", true)
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	require.NoError(t, gate.AuthorizeAccount(ctx, scene.Account))
	uc := newRegisterUCWired(r.runtime).WithRegistrationAuthority(gate).WithResourceTxBeginner(beginner)
	base := time.Now().Add(-time.Hour).UTC().Truncate(time.Microsecond)
	const registry = "captured-registry"
	const object = "captured-registry/team/receipt"
	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{SubjectId: "project:" + scene.Project, Relation: "project", Object: "registry_registry:" + registry, ParentProjectId: scene.Project, ParentAccountId: scene.Account, ParentChain: scene.ProjectChain()}))
	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{SubjectId: "registry_registry:" + registry, Relation: "parent", Object: publicReadObject(object)}))
	publish := func(version time.Time) {
		t.Helper()
		require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{SubjectId: publicReadSubject, Relation: publicReadRelation, Object: publicReadObject(object), SourceVersion: timestamppb.New(version)}))
	}
	publish(base)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(ctx, r.bundle))
	barrier := &capturedReceiptBarrier{reached: make(chan struct{}), resume: make(chan struct{})}
	cfg := r.runtime.Config()
	cfg.MaxConns = 1
	cfg.MinConns = 0
	cfg.ConnConfig.Tracer = barrier
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	defer pool.Close()
	factory, err := kanamepg.NewGrantPolicyWriters(ctx, kanamepg.New(pool, nil), r.bundle)
	require.NoError(t, err)
	owner := policyActor(t, r, scene.Account)
	createBinding := domain.AccessBinding{ID: domain.AccessBindingID(ids.NewID("acb")), RoleID: create.ID, SubjectType: actor.Type, SubjectID: actor.ID, Subjects: []domain.Subject{actor}, ResourceType: "project", ResourceID: scene.Project, Scope: domain.ScopeProject, Status: domain.AccessBindingStatusActive, Target: domain.AccessTarget{AllInScope: true}}
	listBinding := domain.AccessBinding{ID: domain.AccessBindingID(ids.NewID("acb")), RoleID: listRole.ID, SubjectType: actor.Type, SubjectID: actor.ID, Subjects: []domain.Subject{actor}, ResourceType: "project", ResourceID: scene.Project, Scope: domain.ScopeProject, Status: domain.AccessBindingStatusActive, Target: domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "registry.repositories", ID: object}}}}
	for _, binding := range []domain.AccessBinding{createBinding, listBinding} {
		require.NoError(t, factory.RunBindingDecision(ctx, owner, binding, true, nil, func(ctx context.Context, w kaname.SemanticAuthorityWriter, b domain.AccessBinding, role domain.Role) error {
			if e := grantpolicy.RequireBinding(ctx, w, owner, granteffect.Binding{SourceID: string(b.ID), Role: role, Scope: domain.ScopeAnchor{Type: "project", ID: scene.Project}, Recipient: actor, Subjects: []domain.Subject{actor}, Target: b.Target, CapabilityVersion: 1}); e != nil {
				return e
			}
			created, e := w.(kaname.BindingCapabilityInserter).InsertBindingWithCapabilities(ctx, b)
			if e != nil {
				return e
			}
			return w.AccessBindingsW().InsertSubjects(ctx, created.ID, b.Subjects)
		}))
	}
	factory, err = factory.WithCapturedProducerSources()
	require.NoError(t, err)
	proposed := granteffect.Binding{SourceID: "captured-proposal", Role: targetRole, Scope: domain.ScopeAnchor{Type: "project", ID: scene.Project}, Target: domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "registry.repositories", ID: object}}}, Recipient: actor, Subjects: []domain.Subject{actor}, CapabilityVersion: 1}
	proposedEffect := r.bundle.Compile(proposed)
	require.True(t, proposedEffect.Complete(), "%+v", proposedEffect.Obligations())
	require.NotEmpty(t, proposedEffect.Effects())
	bindRole, err := grantcapability.Encode(grantcapability.Coordinate{Kind: domain.GrantCapabilityBindRole, Anchor: proposed.Scope, RoleID: targetRole.ID})
	require.NoError(t, err)
	open := func() (kaname.SemanticAuthorityWriter, error) {
		return factory.RoleAuthorityWriter(ctx, domain.Role{AccountID: domain.AccountID(scene.Account)}, true, actor)
	}
	check := func(w kaname.SemanticAuthorityWriter, wantVersion time.Time) {
		t.Helper()
		proof, e := grantpolicy.CollectWitnessedLowerBound(ctx, w, actor)
		require.NoError(t, e)
		require.Len(t, proof.Census().Producers, 1, "positive must actually read a nonempty captured receipt")
		source := proof.Census().Producers[0]
		require.Empty(t, source.Issue)
		require.Equal(t, domain.PublicationReceipt, source.Receipt.Kind)
		require.Equal(t, object, source.Receipt.ObjectID)
		require.True(t, source.Receipt.SourceVersion.Equal(wantVersion))
		require.False(t, proof.Census().Component.Complete())
		// Оба реальных источника по отдельности недостаточны для того же
		// полного proposal. Никакой эффект не отбрасывается ради разрешения.
		var listEffects granteffect.Set
		for _, binding := range proof.Census().Bindings {
			if binding.Source.Binding.ID == listBinding.ID {
				listEffects = binding.Effects
			}
		}
		require.Contains(t, proof.Census().RoleCheckpoints, listRole.ID)
		require.True(t, listEffects.Complete(), "%+v", listEffects.Obligations())
		require.NotEmpty(t, listEffects.Effects())
		publication := r.bundle.CompileDirect(granteffect.Direct{SourceID: "captured-publication", ObjectType: source.Receipt.ObjectType, ObjectID: source.Receipt.ObjectID, Relation: source.Receipt.Relation, Recipient: source.Receipt.Subject, Condition: granteffect.Condition{Name: source.Receipt.ConditionName, Parameters: source.Receipt.ConditionParameters}})
		require.True(t, publication.Complete(), "%+v", publication.Obligations())
		require.NotEmpty(t, publication.Effects())
		get := r.bundle.CompileDirect(granteffect.Direct{SourceID: "get-obligation", ObjectType: publicReadType, ObjectID: object, Relation: "v_get", Recipient: actor})
		viewer := r.bundle.CompileDirect(granteffect.Direct{SourceID: "viewer-obligation", ObjectType: publicReadType, ObjectID: object, Relation: "viewer", Recipient: actor})
		listHasViewer := false
		for _, effect := range listEffects.Effects() {
			require.False(t, effect.Kind == granteffect.Use && effect.Type == publicReadType && effect.Action == (grantcoverage.Action{Kind: grantcoverage.Verb, Name: "get"}), "list and viewer must not inherit v_get")
			listHasViewer = listHasViewer || effect.Kind == granteffect.Use && effect.Type == publicReadType && effect.Action == (grantcoverage.Action{Kind: grantcoverage.Relation, Name: "viewer"})
		}
		require.True(t, listHasViewer)
		require.Equal(t, grantcoverage.Proved, granteffect.Prove(publication, get).Status)
		require.Equal(t, grantcoverage.ReasonUncovered, granteffect.Prove(publication, viewer).Reason, "publication must not acquire viewer")
		require.Equal(t, grantcoverage.ReasonUncovered, granteffect.Prove(listEffects, proposedEffect).Reason)
		require.Equal(t, grantcoverage.ReasonUncovered, granteffect.Prove(publication, proposedEffect).Reason)
		require.Equal(t, grantcoverage.Proved, granteffect.Prove(granteffect.Union(listEffects, publication), proposedEffect).Status)
		require.Equal(t, grantcoverage.Proved, granteffect.Prove(proof.Effects(), proposedEffect).Status)
		allowed, e := w.SemanticRelationChecker().Check(ctx, "user:"+uid, "admin", "project:"+scene.Project)
		require.NoError(t, e)
		require.False(t, allowed, "D3 must not bypass D1")
		require.ErrorIs(t, grantpolicy.RequireScopeAdministration(ctx, w, actor, proposed.Scope), kaname.ErrCapturedProducerInsufficient, "canonical owner and administrative primitives must not bypass D1")
		allowed, e = w.SemanticRelationChecker().Check(ctx, "user:"+uid, bindRole.Relation, bindRole.Object())
		require.NoError(t, e)
		require.False(t, allowed, "D2 must not bypass D1")
		require.NoError(t, grantpolicy.RequireBinding(ctx, w, actor, proposed), "the actual publication and list binding cover the entire unchanged get effect")
	}
	w, err := open()
	defer policyFixtureRollback(w)
	require.NoError(t, err)
	check(w, base)
	require.NoError(t, w.Rollback(ctx))
	// Настоящие Unregister/Register меняют receipt после RR и до protection.
	// Receipt снова активен (A->B->A), но его версия и состояние должны поступить
	// из новой попытки, а не старого capture.
	barrier.captureSeen.Store(false)
	before := barrier.captures.Load()
	barrier.armed.Store(true)
	type capturedOpenResult struct {
		w   kaname.SemanticAuthorityWriter
		err error
	}
	result := make(chan capturedOpenResult, 1)
	finished := make(chan struct{})
	go func() { defer close(finished); current, e := open(); result <- capturedOpenResult{current, e} }()
	defer func() {
		cancel()
		barrier.release()
		<-finished
		select {
		case unused := <-result:
			policyFixtureRollback(unused.w)
		default:
		}
	}()
	select {
	case <-barrier.reached:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	require.NoError(t, uc.Unregister(ctx, &iamv1.UnregisterResourceRequest{SubjectId: publicReadSubject, Relation: publicReadRelation, Object: publicReadObject(object), SourceVersion: timestamppb.New(base.Add(time.Second))}))
	publish(base.Add(2 * time.Second))
	barrier.release()
	var after capturedOpenResult
	select {
	case after = <-result:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer policyFixtureRollback(after.w)
	require.NoError(t, after.err)
	require.GreaterOrEqual(t, barrier.captures.Load()-before, int32(2), "changed RR population requires another complete capture")
	check(after.w, base.Add(2*time.Second))
	require.NoError(t, after.w.Rollback(ctx))
	// После штатного withdrawal ни create-binding, ни private capture marker
	// не доказывают недостающий effect. Результат Unknown не утверждает
	// отсутствия любых других полномочий в полной текущей популяции.
	require.NoError(t, uc.Unregister(ctx, &iamv1.UnregisterResourceRequest{SubjectId: publicReadSubject, Relation: publicReadRelation, Object: publicReadObject(object), SourceVersion: timestamppb.New(base.Add(3 * time.Second))}))
	absent, err := open()
	defer policyFixtureRollback(absent)
	require.NoError(t, err)
	absentProof, err := grantpolicy.CollectWitnessedLowerBound(ctx, absent, actor)
	require.NoError(t, err)
	require.Equal(t, grantcoverage.ReasonUncovered, granteffect.Prove(absentProof.Effects(), proposedEffect).Reason)
	allowed, err := absent.SemanticRelationChecker().Check(ctx, "user:"+uid, "v_get", publicReadObject(object))
	require.NoError(t, err)
	require.False(t, allowed, "list and viewer do not retain withdrawn public get")
	err = grantpolicy.RequireBinding(ctx, absent, actor, proposed)
	require.ErrorIs(t, err, kaname.ErrCapturedProducerInsufficient)
	require.ErrorIs(t, err, kaname.ErrAuthorityClassificationChanged)
	budget := absent.(interface {
		ChargeSourceRead(kaname.SourceReadCost) error
	})
	exhausted := false
	for i := 0; i < 4097; i++ {
		if e := budget.ChargeSourceRead(kaname.SourceReadCost{Reads: 1}); e != nil {
			require.ErrorIs(t, e, kaname.ErrSourceReadLimit)
			exhausted = true
			break
		}
	}
	require.True(t, exhausted)
	queries := barrier.queries.Load()
	for i := 0; i < 2; i++ {
		allowed, e := absent.SemanticRelationChecker().Check(ctx, "user:"+uid, "admin", "project:"+scene.Project)
		require.False(t, allowed)
		require.ErrorIs(t, e, kaname.ErrSourceReadLimit)
	}
	require.Equal(t, queries, barrier.queries.Load(), "exhausted unbound checker must not issue admission or native SQL")
	require.NoError(t, absent.Rollback(ctx))
	require.EqualValues(t, 0, pool.Stat().AcquiredConns())
	// Настоящая недостаточность после withdrawal исчерпывает конечное число
	// попыток. Каждая получает новый токен; прежний не переносится между ними.
	request := domain.AccessBinding{ID: domain.AccessBindingID(ids.NewID("acb")), RoleID: targetRole.ID, SubjectType: actor.Type, SubjectID: actor.ID, Subjects: proposed.Subjects, ResourceType: "project", ResourceID: scene.Project, Scope: domain.ScopeProject, Status: domain.AccessBindingStatusActive, Target: proposed.Target}
	calls := 0
	var previous kaname.CapturedProducerPopulation
	var lastWriter kaname.SemanticAuthorityWriter
	err = factory.RunBindingDecision(ctx, actor, request, true, nil, func(ctx context.Context, current kaname.SemanticAuthorityWriter, b domain.AccessBinding, role domain.Role) error {
		calls++
		if previous != nil {
			require.ErrorIs(t, previous.Validate(current, actor, current.AuthorityFence().DecisionAt()), kaname.ErrSourceUnconfirmed)
		}
		token, e := current.(kaname.CapturedProducerPopulationReader).CapturedProducerPopulation(ctx, actor)
		require.NoError(t, e)
		require.NoError(t, token.Validate(current, actor, current.AuthorityFence().DecisionAt()))
		previous, lastWriter = token, current
		e = grantpolicy.RequireBinding(ctx, current, actor, granteffect.Binding{SourceID: string(b.ID), Role: role, Scope: domain.ScopeAnchor{Type: string(b.ResourceType), ID: b.ResourceID}, Target: b.Target, Recipient: actor, Subjects: b.Subjects, CapabilityVersion: 1})
		require.ErrorIs(t, e, kaname.ErrCapturedProducerInsufficient)
		require.ErrorIs(t, e, kaname.ErrAuthorityClassificationChanged)
		return e
	})
	require.ErrorIs(t, err, kaname.ErrCapturedProducerInsufficient)
	require.ErrorIs(t, err, kaname.ErrAuthorityClassificationChanged)
	require.Equal(t, 3, calls, "actual insufficient coverage must obey authorityEntryAttempts")
	require.ErrorIs(t, previous.Validate(lastWriter, actor, lastWriter.AuthorityFence().DecisionAt()), kaname.ErrSourceUnconfirmed)
	require.EqualValues(t, 0, pool.Stat().AcquiredConns())
}

// Обе разрешённые формы writer доходят до ошибочного физического Commit.
// Первая вставка настоящая, вторая конфликтует с её PK; rollback PostgreSQL
// должен убрать первую строку и вернуть единственный lease даже при ошибке.
func TestCapturedPhysicalCommitFailureActualWritersReleaseLease(t *testing.T) {
	r := writerProtocolRig(t)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	cfg := r.runtime.Config()
	cfg.MaxConns = 1
	cfg.MinConns = 0
	pool, err := pgxpool.NewWithConfig(r.ctx, cfg)
	require.NoError(t, err)
	defer pool.Close()
	factory, err := kanamepg.NewGrantPolicyWriters(r.ctx, kanamepg.New(pool, nil), r.bundle)
	require.NoError(t, err)
	factory, err = factory.WithCapturedProducerSources()
	require.NoError(t, err)
	actor := policyActor(t, r, r.a)
	ctx, cancel := context.WithTimeout(r.ctx, 15*time.Second)
	defer cancel()
	for _, prepared := range []bool{false, true} {
		role := policyNewRole(r.a)
		role.ID = domain.RoleID(ids.NewID("rol"))
		var w kaname.SemanticAuthorityWriter
		if prepared {
			w, err = factory.RoleMutationWriter(ctx, kaname.RoleMutationRequest{Role: role, Create: true, Rules: true}, actor)
		} else {
			w, err = factory.RoleAuthorityWriter(ctx, role, true, actor)
		}
		defer policyFixtureRollback(w)
		require.NoError(t, err)
		token, e := w.(kaname.CapturedProducerPopulationReader).CapturedProducerPopulation(ctx, actor)
		require.NoError(t, e)
		_, e = w.RolesW().Insert(ctx, role)
		require.NoError(t, e)
		_, e = w.RolesW().Insert(ctx, role)
		require.Error(t, e)
		require.ErrorIs(t, w.Commit(ctx), pgx.ErrTxCommitRollback)
		require.ErrorIs(t, token.Validate(w, actor, w.AuthorityFence().DecisionAt()), kaname.ErrSourceUnconfirmed)
		_, e = w.(kaname.CapturedProducerPopulationReader).CapturedProducerPopulation(ctx, actor)
		require.ErrorIs(t, e, kaname.ErrSourceUnconfirmed)
		require.EqualValues(t, 0, pool.Stat().AcquiredConns())
		var count int
		require.NoError(t, r.admin.QueryRow(ctx, `SELECT count(*) FROM kaname.roles WHERE id=$1`, role.ID).Scan(&count))
		require.Zero(t, count)
	}
}
