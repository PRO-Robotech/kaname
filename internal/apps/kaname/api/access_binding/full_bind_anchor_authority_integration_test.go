// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationwriterfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

const (
	fbAnchorBoxQ = "box0000000000000003"
	fbAnchorBoxB = "box0000000000000004"
)

// Мир меняет только фикстуру этих трёх сценариев. Модульная роль проходит
// настоящий загрузчик и применитель до activation; её cluster home-tier
// допускает A/B и P/Q, но не выдаёт actor управляющих прав на эти области.
type fbAnchorWorld struct {
	*fullBindWorld
	callbacks    *fb11SetupCallbacks
	observerPool *pgxpool.Pool
	ownerB       domain.AccessBindingID
	projectB     domain.ProjectID
	osetr        domain.RoleID
}

func newFBAnchorWorld(t *testing.T) *fbAnchorWorld {
	t.Helper()
	a := newATCWorld(t)
	observerPool := a.pool
	for _, account := range []domain.AccountID{a.accA, a.accB} {
		for _, user := range []domain.UserID{a.usrB, a.usrD, a.usrE} {
			gdSeedMembership(t, a.ctx, a.pool, user, account, "ACTIVE")
		}
	}
	projectB := seedProjectInAccount(t, a.ctx, a.pool, a.accB, "fb-anchor-project-b")
	a.doc = append(append([]byte(nil), a.doc...), []byte(`
roles:
  - id: probemod.fb_anchor_osetr
    description: 'Чтение объектов для проверки якорей полномочий.'
    tier: {tierType: iam.cluster, tierId: cluster_root}
    rules:
      - module: probemod
        resources: [boxes]
        classes: [get, list]
`)...)
	a.applyDelivered("FB05/06/07: настоящая модульная роль", a.manifest(false))
	register := func(id string, project domain.ProjectID, account domain.AccountID) {
		a.reg.WithRegistrationAuthority(registrationwriterfixture.Authority{Module: "probemod"})
		require.NoError(t, a.reg.Register(a.ctx, &iamv1.RegisterResourceRequest{
			SubjectId: "project:" + string(project), Relation: "project", Object: atcBoxType + ":" + id,
			ParentProjectId: string(project), ParentAccountId: string(account),
			ParentChain: []string{"project:" + string(project), "account:" + string(account)},
		}))
	}
	register(atcB1, a.prjA, a.accA)
	register(fbAnchorBoxQ, a.prjB, a.accA)
	register(fbAnchorBoxB, projectB, a.accB)
	a.reg.WithRegistrationAuthority(registrationwriterfixture.Authority{Module: "registry"})

	callbacks := &fb11SetupCallbacks{}
	observe := func(actual *reconcile.Reconciler) accessbindingapp.SelectorReconciler {
		return &fb11SetupReconciler{SelectorReconciler: actual, callbacks: callbacks}
	}
	// Владелец B получает свою обычную авто-выдачу через тот же Create API.
	// Это bootstrap до lifecycle; исследуемые actor никогда её не получают.
	bootstrap := accessbindingapp.NewCreateAccessBindingUseCase(a.repo, a.ops, catalog.Fixed{F: a.facts}).
		WithRelationStore(a.door, nil).WithReconciler(observe(a.rec))
	a.ab = accessbindingapp.NewHandler(bootstrap, nil, nil, nil, nil, nil, nil)
	ownerB := a.createDone(asUser(a.ctx, a.usrC), fbAnchorRequest(a.usrC, domain.RoleID(domain.OwnerRoleID), "account", string(a.accB)), "FB: авто-выдача владельца B")
	require.NoError(t, callbacks.awaitSetup(a.ctx, "iam.accessBinding", ownerB))
	require.NoError(t, a.rec.ReconcileBinding(a.ctx, domain.AccessBindingID(ownerB)))
	plans, err := authzmodel.Shared()
	require.NoError(t, err)
	base := &fullBindWorld{atcWorld: a, plans: plans}
	base.installFullBindParticipants(observe)
	w := &fbAnchorWorld{fullBindWorld: base, callbacks: callbacks, observerPool: observerPool, ownerB: domain.AccessBindingID(ownerB), projectB: projectB}
	require.NoError(t, w.rec.ReconcileBinding(w.ctx, w.ownerB))
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT id FROM kaname.roles WHERE name=$1 AND account_id IS NULL AND project_id IS NULL`, "probemod.fb_anchor_osetr").Scan(&w.osetr))
	rd, err := w.repo.Reader(w.ctx)
	require.NoError(t, err)
	role, err := rd.Roles().Get(w.ctx, w.osetr)
	require.NoError(t, err)
	require.NoError(t, rd.Rollback(w.ctx))
	require.True(t, role.IsSystem)
	require.Equal(t, domain.ClusterID(domain.ClusterSingletonID), role.ClusterID)
	require.Equal(t, "probemod", role.OwnerModule)
	require.Empty(t, role.AccountID)
	require.Empty(t, role.ProjectID)
	require.Len(t, role.Rules, 1)
	require.Equal(t, "probemod", role.Rules[0].Module)
	require.Equal(t, []string{"boxes"}, role.Rules[0].Resources)
	require.ElementsMatch(t, []string{"get", "list"}, role.Rules[0].Verbs)
	require.Empty(t, role.Rules[0].ResourceNames)
	require.Empty(t, role.Rules[0].MatchLabels)
	var hierarchy bool
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT
 EXISTS(SELECT 1 FROM kaname.projects WHERE id=$1 AND account_id=$3) AND
 EXISTS(SELECT 1 FROM kaname.projects WHERE id=$2 AND account_id=$3) AND
 EXISTS(SELECT 1 FROM kaname.projects WHERE id=$4 AND account_id=$5)`, string(w.prjA), string(w.prjB), string(w.accA), string(w.projectB), string(w.accB)).Scan(&hierarchy))
	require.True(t, hierarchy, "P/Q находятся в A, отдельный проект находится в B")
	for _, scope := range []domain.ScopeAnchor{{Type: "account", ID: string(w.accA)}, {Type: "account", ID: string(w.accB)}, {Type: "project", ID: string(w.prjA)}, {Type: "project", ID: string(w.prjB)}} {
		require.True(t, domain.IsRoleAssignable(role, scope.Type, scope.ID), "модульная роль структурно допустима на обоих якорях")
	}
	return w
}

func fbAnchorRequest(subject domain.UserID, role domain.RoleID, kind, id string) *iamv1.CreateAccessBindingRequest {
	return &iamv1.CreateAccessBindingRequest{Subjects: []*iamv1.Subject{userSubject(subject)}, RoleId: string(role), ScopeType: "iam." + kind, ScopeId: id, Target: allInScopeTarget()}
}

// Именованное bind производится публичной custom Role.Create: манифест
// запрещает resourceNames. Обе home-definition создаются заранее; смена
// источника никогда не меняет предложенную модульную роль или запрос.
func (w *fbAnchorWorld) capabilityRole(owner domain.UserID, account domain.AccountID, name string, bind bool) domain.RoleID {
	w.t.Helper()
	rule := &iamv1.Rule{Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"create"}}
	if bind {
		rule = &iamv1.Rule{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{string(w.osetr)}}
	}
	op, err := w.roles.Create(asUser(w.ctx, owner), &iamv1.CreateRoleRequest{Name: name, Rules: []*iamv1.Rule{rule}, DefinitionTier: &iamv1.DefinitionTier{TierType: "iam.account", TierId: string(account)}})
	require.NoError(w.t, err)
	require.NotNil(w.t, op)
	require.Nil(w.t, awaitOp(w.t, w.ctx, w.ops, op.GetId()).Error)
	var md iamv1.CreateRoleMetadata
	require.NoError(w.t, op.GetMetadata().UnmarshalTo(&md))
	require.NotEmpty(w.t, md.GetRoleId())
	require.NoError(w.t, w.rec.ReconcileBinding(w.ctx, w.ownerBinding))
	require.NoError(w.t, w.rec.ReconcileBinding(w.ctx, w.ownerB))
	return domain.RoleID(md.GetRoleId())
}

func (w *fbAnchorWorld) sourceAt(owner, subject domain.UserID, role domain.RoleID, kind, id string) {
	w.t.Helper()
	binding := w.createDone(asUser(w.ctx, owner), fbAnchorRequest(subject, role, kind, id), "FB: реальная выдача источника на точном якоре")
	require.NoError(w.t, w.callbacks.awaitSetup(w.ctx, "iam.accessBinding", binding))
	require.NoError(w.t, w.rec.ReconcileBinding(w.ctx, domain.AccessBindingID(binding)))
	rd, err := w.repo.Reader(w.ctx)
	require.NoError(w.t, err)
	stored, err := rd.AccessBindings().Get(w.ctx, domain.AccessBindingID(binding))
	require.NoError(w.t, err)
	require.NoError(w.t, rd.Rollback(w.ctx))
	require.Equal(w.t, role, stored.RoleID)
	require.Equal(w.t, domain.SubjectTypeUser, stored.SubjectType)
	require.Equal(w.t, string(subject), string(stored.SubjectID))
	require.Equal(w.t, kind, string(stored.ResourceType))
	require.Equal(w.t, id, stored.ResourceID)
	require.Equal(w.t, domain.AccessBindingStatusActive, stored.Status)
	require.True(w.t, stored.Target.AllInScope)
	require.Empty(w.t, stored.Target.Resources)
}

func (w *fbAnchorWorld) capability(subject domain.UserID, kind domain.GrantCapabilityKind, scope domain.ScopeAnchor, want relverdict.Verdict) {
	w.t.Helper()
	c := grantcapability.Coordinate{Kind: kind, Anchor: scope}
	if kind == domain.GrantCapabilityBindRole {
		c.RoleID = w.osetr
	}
	ref, err := grantcapability.Encode(c)
	require.NoError(w.t, err)
	// Capability требует явных часов решения: наблюдатель получает их из БД
	// на той же read-only TX, а не превращает ошибку запроса в ожидаемый Deny.
	tx, err := w.pool.BeginTx(w.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	require.NoError(w.t, err)
	defer func() { _ = tx.Rollback(w.ctx) }()
	var at time.Time
	require.NoError(w.t, tx.QueryRow(w.ctx, `SELECT clock_timestamp()`).Scan(&at))
	require.False(w.t, at.IsZero())
	got, _, err := relverdict.Ask(w.ctx, tx, relverdict.Query{
		PreparedPlans: w.plans, DecisionAt: at, Subject: "user:" + string(subject),
		Relation: ref.Relation, ObjectType: ref.ObjectType, ObjectID: ref.ObjectID,
	})
	require.NoErrorf(w.t, err, "FB: native capability %s %s %s:%s", subject, ref.Relation, ref.ObjectType, ref.ObjectID)
	require.Equal(w.t, want, got)
}

func (w *fbAnchorWorld) noAdmin(subject domain.UserID) {
	w.t.Helper()
	actor := "user:" + string(subject)
	w.native(actor, "system_admin", "cluster", domain.ClusterSingletonID, relverdict.Deny)
	for _, scope := range []domain.ScopeAnchor{{Type: "account", ID: string(w.accA)}, {Type: "account", ID: string(w.accB)}, {Type: "project", ID: string(w.prjA)}, {Type: "project", ID: string(w.prjB)}, {Type: "project", ID: string(w.projectB)}} {
		w.native(actor, "admin", scope.Type, scope.ID, relverdict.Deny)
	}
}

func (w *fbAnchorWorld) useAt(subject domain.UserID, id string, want relverdict.Verdict) {
	w.t.Helper()
	for _, relation := range []string{"v_get", "v_list"} {
		w.native("user:"+string(subject), relation, atcBoxType, id, want)
	}
}

// Снимок полных строк различает не только вставку, но и изменение старого
// состояния. Владелец fixture читает служебные таблицы, не участвуя в решении.
// Все detached setup callbacks уже завершены перед входом в этот метод.
func (w *fbAnchorWorld) artifacts() map[string]string {
	w.t.Helper()
	tx, err := w.observerPool.BeginTx(w.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	require.NoError(w.t, err)
	defer func() { _ = tx.Rollback(w.ctx) }()
	out := make(map[string]string)
	for _, table := range []string{
		"operations", "access_bindings", "access_binding_subjects", "access_binding_target_members", "access_binding_emitted_tuples",
		"fga_outbox", "relation_fact", "audit_outbox", "subject_change_outbox", "resource_reconcile_outbox", "resource_journal", "project_resource_quotas",
		"role_create_binding_rule", "role_bind_role_rule", "authority_policy_epoch", "authority_binding_epoch",
	} {
		var rows string
		require.NoError(w.t, tx.QueryRow(w.ctx, "SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text), '[]'::jsonb)::text FROM kaname."+table+" r").Scan(&rows))
		out[table] = rows
	}
	require.NoError(w.t, tx.Commit(w.ctx))
	return out
}

func (w *fbAnchorWorld) deny(actor domain.UserID, req *iamv1.CreateAccessBindingRequest) {
	w.t.Helper()
	fixed := proto.Clone(req)
	before := w.artifacts()
	op, err := w.ab.Create(asUser(w.ctx, actor), req)
	require.Nil(w.t, op, "отказ синхронный, Operation не принята")
	require.Error(w.t, err)
	require.Equal(w.t, codes.PermissionDenied, status.Code(err))
	require.Equal(w.t, "permission denied", status.Convert(err).Message())
	require.True(w.t, proto.Equal(fixed, req), "обработчик не меняет фиксированный When")
	require.Equal(w.t, before, w.artifacts(), "отказ не меняет ни одной затрагиваемой бизнес-строки")
	require.Empty(w.t, w.listOf(w.usrE))
}

func (w *fbAnchorWorld) allow(actor domain.UserID, req *iamv1.CreateAccessBindingRequest, object string) {
	w.t.Helper()
	fixed := proto.Clone(req)
	require.Empty(w.t, w.listOf(w.usrE))
	op, err := w.ab.Create(asUser(w.ctx, actor), req)
	require.NoError(w.t, err)
	require.NotNil(w.t, op)
	require.NotEmpty(w.t, op.GetId())
	done := awaitOp(w.t, w.ctx, w.ops, op.GetId())
	require.Nil(w.t, done.Error, "положительная Operation завершена без ошибки")
	var md iamv1.CreateAccessBindingMetadata
	require.NoError(w.t, op.GetMetadata().UnmarshalTo(&md))
	require.NotEmpty(w.t, md.GetAccessBindingId())
	// Durable oracle снимается отдельно от ожидания материализации.
	rows := w.listOf(w.usrE)
	require.Len(w.t, rows, 1)
	b := rows[0]
	require.Equal(w.t, md.GetAccessBindingId(), string(b.ID))
	require.Equal(w.t, req.GetRoleId(), string(b.RoleID))
	require.Equal(w.t, domain.SubjectTypeUser, b.SubjectType)
	require.Equal(w.t, string(w.usrE), string(b.SubjectID))
	kind := "account"
	if req.GetScopeType() == "iam.project" {
		kind = "project"
	}
	require.Equal(w.t, kind, string(b.ResourceType))
	require.Equal(w.t, req.GetScopeId(), b.ResourceID)
	require.Equal(w.t, domain.DeriveFromResourceType(kind), b.Scope)
	require.Equal(w.t, domain.AccessBindingStatusActive, b.Status)
	require.True(w.t, b.Target.AllInScope)
	require.Empty(w.t, b.Target.Resources)
	rd, err := w.repo.Reader(w.ctx)
	require.NoError(w.t, err)
	subjects, err := rd.AccessBindings().ListSubjects(w.ctx, b.ID)
	require.NoError(w.t, err)
	require.NoError(w.t, rd.Rollback(w.ctx))
	require.Equal(w.t, []domain.Subject{{Type: domain.SubjectTypeUser, ID: domain.SubjectID(w.usrE)}}, subjects)
	require.True(w.t, proto.Equal(fixed, req), "роль, область, цель и получатель When неизменны")
	require.NoError(w.t, w.callbacks.awaitSetup(w.ctx, "iam.accessBinding", string(b.ID)))
	for _, relation := range []string{"v_get", "v_list"} {
		var got relverdict.Verdict
		var askErr error
		require.Eventually(w.t, func() bool {
			got, askErr = w.askNative("user:"+string(w.usrE), relation, atcBoxType, object)
			return askErr == nil && got == relverdict.Allow
		}, 30*time.Second, 50*time.Millisecond, "отдельный eventual native oracle")
		require.NoError(w.t, askErr)
		require.Equal(w.t, relverdict.Allow, got)
	}
}

// FB05: один и тот же запрос сначала предъявляет другой actor, затем holder.
// Оба имеют одну и ту же явную CreateBinding(A); use и admin отсутствуют.
func TestFullBind_FB05_BindBelongsToTheActingSubject(t *testing.T) {
	w := newFBAnchorWorld(t)
	create := w.capabilityRole(w.usrA, w.accA, "fb05_create", false)
	bind := w.capabilityRole(w.usrA, w.accA, "fb05_bind", true)
	for _, actor := range []domain.UserID{w.usrB, w.usrD} {
		w.sourceAt(w.usrA, actor, create, "account", string(w.accA))
		w.capability(actor, domain.GrantCapabilityCreateBinding, domain.ScopeAnchor{Type: "account", ID: string(w.accA)}, relverdict.Allow)
	}
	w.sourceAt(w.usrA, w.usrD, bind, "account", string(w.accA))
	for _, actor := range []domain.UserID{w.usrB, w.usrD} {
		w.noAdmin(actor)
		w.useAt(actor, atcB1, relverdict.Deny)
		w.useAt(actor, fbAnchorBoxQ, relverdict.Deny)
	}
	w.capability(w.usrB, domain.GrantCapabilityBindRole, domain.ScopeAnchor{Type: "account", ID: string(w.accA)}, relverdict.Deny)
	w.capability(w.usrD, domain.GrantCapabilityBindRole, domain.ScopeAnchor{Type: "account", ID: string(w.accA)}, relverdict.Allow)
	req := fbAnchorRequest(w.usrE, w.osetr, "account", string(w.accA))
	fixed := proto.Clone(req)
	w.useAt(w.usrE, atcB1, relverdict.Deny)
	w.deny(w.usrB, req)
	w.useAt(w.usrE, atcB1, relverdict.Deny)
	w.allow(w.usrD, req, atcB1)
	require.True(t, proto.Equal(fixed, req))
	w.useAt(w.usrE, fbAnchorBoxQ, relverdict.Allow)
	w.useAt(w.usrE, fbAnchorBoxB, relverdict.Deny)
}

// FB06: home-tier одной модульной роли не переносит bind(A) в B. После
// точного отказа добавляется только bind(B); bind(A) остаётся отрицательным
// контролем, уже доказавшим свою недостаточность для того же When.
func TestFullBind_FB06_BindKeepsTheAccountAnchor(t *testing.T) {
	w := newFBAnchorWorld(t)
	createA := w.capabilityRole(w.usrA, w.accA, "fb06_create_a", false)
	createB := w.capabilityRole(w.usrC, w.accB, "fb06_create_b", false)
	bindA := w.capabilityRole(w.usrA, w.accA, "fb06_bind_a", true)
	bindB := w.capabilityRole(w.usrC, w.accB, "fb06_bind_b", true)
	w.sourceAt(w.usrA, w.usrD, createA, "account", string(w.accA))
	w.sourceAt(w.usrC, w.usrD, createB, "account", string(w.accB))
	w.sourceAt(w.usrA, w.usrD, bindA, "account", string(w.accA))
	for _, account := range []domain.AccountID{w.accA, w.accB} {
		w.capability(w.usrD, domain.GrantCapabilityCreateBinding, domain.ScopeAnchor{Type: "account", ID: string(account)}, relverdict.Allow)
	}
	w.capability(w.usrD, domain.GrantCapabilityBindRole, domain.ScopeAnchor{Type: "account", ID: string(w.accA)}, relverdict.Allow)
	w.capability(w.usrD, domain.GrantCapabilityBindRole, domain.ScopeAnchor{Type: "account", ID: string(w.accB)}, relverdict.Deny)
	w.noAdmin(w.usrD)
	for _, box := range []string{atcB1, fbAnchorBoxQ, fbAnchorBoxB} {
		w.useAt(w.usrD, box, relverdict.Deny)
	}
	req := fbAnchorRequest(w.usrE, w.osetr, "account", string(w.accB))
	fixed := proto.Clone(req)
	w.deny(w.usrD, req)
	w.useAt(w.usrE, fbAnchorBoxB, relverdict.Deny)
	w.sourceAt(w.usrC, w.usrD, bindB, "account", string(w.accB))
	w.capability(w.usrD, domain.GrantCapabilityBindRole, domain.ScopeAnchor{Type: "account", ID: string(w.accB)}, relverdict.Allow)
	for _, account := range []domain.AccountID{w.accA, w.accB} {
		w.capability(w.usrD, domain.GrantCapabilityCreateBinding, domain.ScopeAnchor{Type: "account", ID: string(account)}, relverdict.Allow)
	}
	w.noAdmin(w.usrD)
	w.useAt(w.usrD, fbAnchorBoxB, relverdict.Deny)
	w.allow(w.usrD, req, fbAnchorBoxB)
	require.True(t, proto.Equal(fixed, req))
	w.useAt(w.usrE, atcB1, relverdict.Deny)
	w.useAt(w.usrE, fbAnchorBoxQ, relverdict.Deny)
}

// FB07: источник на P не покрывает неизменный Create в Q. Добавление той
// же роли actor на Q — единственная новая выдача между двумя предъявлениями.
// Получатель, proposed roleID, target и запрос остаются теми же.
func TestFullBind_FB07_CoverageKeepsTheProjectAnchor(t *testing.T) {
	w := newFBAnchorWorld(t)
	create := w.capabilityRole(w.usrA, w.accA, "fb07_create", false)
	for _, project := range []domain.ProjectID{w.prjA, w.prjB} {
		w.sourceAt(w.usrA, w.usrD, create, "project", string(project))
		w.capability(w.usrD, domain.GrantCapabilityCreateBinding, domain.ScopeAnchor{Type: "project", ID: string(project)}, relverdict.Allow)
	}
	w.sourceAt(w.usrA, w.usrD, w.osetr, "project", string(w.prjA))
	w.noAdmin(w.usrD)
	for _, project := range []domain.ProjectID{w.prjA, w.prjB} {
		w.capability(w.usrD, domain.GrantCapabilityBindRole, domain.ScopeAnchor{Type: "project", ID: string(project)}, relverdict.Deny)
	}
	w.useAt(w.usrD, atcB1, relverdict.Allow)
	w.useAt(w.usrD, fbAnchorBoxQ, relverdict.Deny)
	req := fbAnchorRequest(w.usrE, w.osetr, "project", string(w.prjB))
	fixed := proto.Clone(req)
	w.deny(w.usrD, req)
	w.useAt(w.usrE, fbAnchorBoxQ, relverdict.Deny)
	w.sourceAt(w.usrA, w.usrD, w.osetr, "project", string(w.prjB))
	w.noAdmin(w.usrD)
	for _, project := range []domain.ProjectID{w.prjA, w.prjB} {
		w.capability(w.usrD, domain.GrantCapabilityCreateBinding, domain.ScopeAnchor{Type: "project", ID: string(project)}, relverdict.Allow)
		w.capability(w.usrD, domain.GrantCapabilityBindRole, domain.ScopeAnchor{Type: "project", ID: string(project)}, relverdict.Deny)
	}
	w.useAt(w.usrD, atcB1, relverdict.Allow)
	w.useAt(w.usrD, fbAnchorBoxQ, relverdict.Allow)
	w.allow(w.usrD, req, fbAnchorBoxQ)
	require.True(t, proto.Equal(fixed, req))
	w.useAt(w.usrE, atcB1, relverdict.Deny)
	w.useAt(w.usrE, fbAnchorBoxB, relverdict.Deny)
}
