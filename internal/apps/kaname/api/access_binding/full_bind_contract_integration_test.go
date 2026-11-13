// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// Полный контракт #1034/#1035: публичные роли и выдачи, настоящий каталог
// probemod и отдельный нижний вердикт PostgreSQL. Проверки не провязывают
// разрешающий дублёр и не записывают исследуемые роли/выдачи напрямую в БД.
// Это первые держатели полной приёмки; остальные FB-сценарии остаются отдельным
// обязательством, а наличие этого файла не означает их исполнения.

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

type fullBindWorld struct {
	*atcWorld
	roles *roleapp.Handler
	plans *authzmodel.Plans
}

func newFullBindWorld(t *testing.T) *fullBindWorld {
	t.Helper()
	a := newATCWorld(t)
	// Личности и членство — общая фикстура. Исследуемые права ниже выдаются API.
	gdSeedMembership(t, a.ctx, a.pool, a.usrD, a.accA, "ACTIVE")
	gdSeedMembership(t, a.ctx, a.pool, a.usrE, a.accA, "ACTIVE")
	plans, err := authzmodel.Shared()
	require.NoError(t, err, "FB: допущенная модель процесса")
	w := &fullBindWorld{atcWorld: a, plans: plans}
	src := catalog.Fixed{F: a.facts}
	w.roles = roleapp.NewHandler(
		roleapp.NewCreateRoleUseCase(a.repo, a.ops, src).
			WithRelationStore(a.door, nil).WithObjectReconciler(a.rec),
		nil, nil, nil, nil)
	a.registerBox(atcB1)
	a.registerBox(atcB2)
	w.native("user:"+string(a.usrD), "v_get", atcBoxType, atcB1, relverdict.Deny)
	w.native("user:"+string(a.usrE), "v_get", atcBoxType, atcB1, relverdict.Deny)
	return w
}

func fullBindBoxRule(verbs ...string) *iamv1.Rule {
	return &iamv1.Rule{Module: "probemod", Resources: []string{"boxes"}, Verbs: verbs}
}

// role использует публичный RoleService.Create, включая definitionTier и
// производственные проекции правил. Имя не подменяет возвращённый roleID.
func (w *fullBindWorld) role(name string, rules ...*iamv1.Rule) domain.RoleID {
	w.t.Helper()
	op, err := w.roles.Create(asUser(w.ctx, w.usrA), &iamv1.CreateRoleRequest{
		Name: name, Rules: rules,
		DefinitionTier: &iamv1.DefinitionTier{TierType: "iam.account", TierId: string(w.accA)},
	})
	require.NoErrorf(w.t, err, "FB: создание роли %s", name)
	done := awaitOp(w.t, w.ctx, w.ops, op.GetId())
	require.Nilf(w.t, done.Error, "FB: создание роли %s завершилось ошибкой", name)
	var md iamv1.CreateRoleMetadata
	require.NoError(w.t, op.GetMetadata().UnmarshalTo(&md))
	require.NotEmpty(w.t, md.GetRoleId())
	return domain.RoleID(md.GetRoleId())
}

func (w *fullBindWorld) request(subject domain.UserID, role domain.RoleID, target *iamv1.AccessTarget) *iamv1.CreateAccessBindingRequest {
	return &iamv1.CreateAccessBindingRequest{
		Subjects: []*iamv1.Subject{userSubject(subject)}, RoleId: string(role),
		ScopeType: "iam.project", ScopeId: string(w.prjA), Target: target,
	}
}

func (w *fullBindWorld) source(role domain.RoleID, target *iamv1.AccessTarget) string {
	w.t.Helper()
	return w.createDone(asUser(w.ctx, w.usrA), w.request(w.usrD, role, target), "FB: источник полномочий actor")
}

func (w *fullBindWorld) createCapability() {
	w.t.Helper()
	w.source(w.createCapabilityRole(), allInScopeTarget())
}

func (w *fullBindWorld) createCapabilityRole() domain.RoleID {
	w.t.Helper()
	return w.role("fb_create_binding", &iamv1.Rule{
		Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"create"},
	})
}

// native различает Allow/Deny/Unknown и ошибку. Ни ошибка запроса, ни Unknown
// не могут засчитываться как ожидаемый запрет.
func (w *fullBindWorld) native(subject, relation, objectType, id string, want relverdict.Verdict) {
	w.t.Helper()
	got, err := w.askNative(subject, relation, objectType, id)
	require.NoErrorf(w.t, err, "FB: нижний порт %s %s %s:%s", subject, relation, objectType, id)
	require.Equalf(w.t, want, got, "FB: нижний порт %s %s %s:%s", subject, relation, objectType, id)
}

func (w *fullBindWorld) askNative(subject, relation, objectType, id string) (relverdict.Verdict, error) {
	tx, err := w.pool.BeginTx(w.ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return relverdict.Unknown, err
	}
	defer func() { _ = tx.Rollback(w.ctx) }()
	v, _, err := relverdict.Ask(w.ctx, tx, relverdict.Query{
		PreparedPlans: w.plans, Subject: subject, Relation: relation, ObjectType: objectType, ObjectID: id,
	})
	return v, err
}

func (w *fullBindWorld) eventuallyNative(subject, relation, id string, want relverdict.Verdict) {
	w.t.Helper()
	var got relverdict.Verdict
	var err error
	require.Eventually(w.t, func() bool {
		got, err = w.askNative(subject, relation, atcBoxType, id)
		return err == nil && got == want
	}, 30*time.Second, 50*time.Millisecond, "FB: материализация %s %s %s", subject, relation, id)
	require.NoError(w.t, err)
	require.Equal(w.t, want, got)
}

// ordinary проверяет исход до Operation отдельно от durable результата.
// Доступ после фиксации спрашивается другим методом, без превращения его
// eventual таймаута в ошибку уже совершённой операции.
func (w *fullBindWorld) ordinary(req *iamv1.CreateAccessBindingRequest, allow bool) string {
	w.t.Helper()
	before := w.bindingsOf(w.usrE, w.prjA)
	op, err := w.ab.Create(asUser(w.ctx, w.usrD), req)
	if !allow {
		require.Nil(w.t, op, "FB: отказ должен предшествовать принятию операции")
		require.Error(w.t, err)
		require.Equal(w.t, codes.PermissionDenied, status.Code(err))
		require.Equal(w.t, "permission denied", status.Convert(err).Message())
		require.Equal(w.t, before, w.bindingsOf(w.usrE, w.prjA), "FB: отказ не создаёт выдачу")
		return ""
	}
	require.NoError(w.t, err)
	done := awaitOp(w.t, w.ctx, w.ops, op.GetId())
	require.Nil(w.t, done.Error, "FB: принятая операция завершилась ошибкой")
	var md iamv1.CreateAccessBindingMetadata
	require.NoError(w.t, op.GetMetadata().UnmarshalTo(&md))
	require.NotEmpty(w.t, md.GetAccessBindingId())
	require.Equal(w.t, before+1, w.bindingsOf(w.usrE, w.prjA))
	rows := w.listOf(w.usrE)
	require.Len(w.t, rows, 1)
	require.Equal(w.t, md.GetAccessBindingId(), string(rows[0].ID))
	require.Equal(w.t, req.GetRoleId(), string(rows[0].RoleID))
	require.Equal(w.t, string(w.prjA), rows[0].ResourceID)
	require.Equal(w.t, domain.AccessBindingStatusActive, rows[0].Status)
	require.Equal(w.t, string(w.usrE), string(rows[0].SubjectID))
	require.Equal(w.t, req.GetTarget().GetAllInScope() != nil, rows[0].Target.AllInScope)
	var wantResources []domain.ResourceRef
	for _, r := range req.GetTarget().GetResources().GetResources() {
		wantResources = append(wantResources, domain.ResourceRef{Type: r.GetType(), ID: r.GetId()})
	}
	if len(wantResources) == 0 {
		require.Empty(w.t, rows[0].Target.Resources)
	} else {
		require.Equal(w.t, wantResources, rows[0].Target.Resources)
	}
	return md.GetAccessBindingId()
}

func (w *fullBindWorld) revokeSource(id string) {
	w.t.Helper()
	w.ownerMayRemove("FB: владелец отзывает источник", id)
	u := accessbindingapp.NewRevokeAccessBindingUseCase(w.repo, w.ops).WithRelationStore(w.door, nil)
	op, err := u.Execute(asUser(w.ctx, w.usrA), domain.AccessBindingID(id))
	require.NoError(w.t, err)
	require.Nil(w.t, awaitOp(w.t, w.ctx, w.ops, op.ID).Error)
}

func (w *fullBindWorld) actorHasNoScopeAdminBypass() {
	w.t.Helper()
	w.native("user:"+string(w.usrD), "admin", "project", string(w.prjA), relverdict.Deny)
}

func TestFullBind_FB01_CoverageNeedsSeparateCreateBinding(t *testing.T) {
	for _, allow := range []bool{true, false} {
		t.Run(map[bool]string{true: "with_create", false: "without_create"}[allow], func(t *testing.T) {
			w := newFullBindWorld(t)
			treska := w.role("fb_treska", fullBindBoxRule("get", "list"))
			osetr := w.role("fb_osetr", fullBindBoxRule("get", "list"))
			require.NotEqual(t, treska, osetr)
			w.source(treska, allInScopeTarget())
			create := w.createCapabilityRole()
			if allow {
				w.source(create, allInScopeTarget())
			}
			w.native("user:"+string(w.usrD), "v_get", atcBoxType, atcB1, relverdict.Allow)
			w.actorHasNoScopeAdminBypass()
			w.ordinary(w.request(w.usrE, osetr, allInScopeTarget()), allow)
			want := relverdict.Deny
			if allow {
				want = relverdict.Allow
			}
			w.eventuallyNative("user:"+string(w.usrE), "v_get", atcB1, want)
			w.eventuallyNative("user:"+string(w.usrE), "v_list", atcB2, want)
		})
	}
}

func TestFullBind_FB03_CoverageUsesTheUnionOfActiveRoles(t *testing.T) {
	for _, allow := range []bool{true, false} {
		t.Run(map[bool]string{true: "both_active", false: "list_revoked"}[allow], func(t *testing.T) {
			w := newFullBindWorld(t)
			get := w.role("fb_get", fullBindBoxRule("get"))
			list := w.role("fb_list", fullBindBoxRule("list"))
			osetr := w.role("fb_osetr", fullBindBoxRule("get", "list"))
			w.source(get, allInScopeTarget())
			listBinding := w.source(list, allInScopeTarget())
			w.createCapability()
			// Административный источник принадлежит только владельцу фикстуры,
			// actor не получает его ни в одной половине пары.
			w.ownerMayRemove("FB03: общий мир отзыва", listBinding)
			if !allow {
				w.revokeSource(listBinding)
			}
			w.actorHasNoScopeAdminBypass()
			w.ordinary(w.request(w.usrE, osetr, allInScopeTarget()), allow)
			want := relverdict.Deny
			if allow {
				want = relverdict.Allow
			}
			w.eventuallyNative("user:"+string(w.usrE), "v_get", atcB1, want)
			w.eventuallyNative("user:"+string(w.usrE), "v_list", atcB1, want)
		})
	}
}

func TestFullBind_FB02_OneMissingVerbPreventsWholeGrant(t *testing.T) {
	for _, allow := range []bool{true, false} {
		t.Run(map[bool]string{true: "complete", false: "missing_list"}[allow], func(t *testing.T) {
			w := newFullBindWorld(t)
			verbs := []string{"get"}
			if allow {
				verbs = append(verbs, "list")
			}
			treska := w.role("fb_treska", fullBindBoxRule(verbs...))
			osetr := w.role("fb_osetr", fullBindBoxRule("get", "list"))
			w.source(treska, allInScopeTarget())
			w.createCapability()
			w.actorHasNoScopeAdminBypass()
			w.ordinary(w.request(w.usrE, osetr, allInScopeTarget()), allow)
			want := relverdict.Deny
			if allow {
				want = relverdict.Allow
			}
			w.eventuallyNative("user:"+string(w.usrE), "v_get", atcB1, want)
			w.eventuallyNative("user:"+string(w.usrE), "v_list", atcB1, want)
		})
	}
}

func TestFullBind_FB04_BindNamesTheGrantedRole(t *testing.T) {
	for _, allow := range []bool{true, false} {
		t.Run(map[bool]string{true: "bind_osetr", false: "bind_treska"}[allow], func(t *testing.T) {
			w := newFullBindWorld(t)
			treska := w.role("fb_treska", fullBindBoxRule("get"))
			osetr := w.role("fb_osetr", fullBindBoxRule("get"))
			bound := treska
			if allow {
				bound = osetr
			}
			bind := w.role("fb_bind", &iamv1.Rule{
				Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{string(bound)},
			})
			w.source(bind, allInScopeTarget())
			w.createCapability()
			w.native("user:"+string(w.usrD), "v_get", atcBoxType, atcB1, relverdict.Deny)
			w.actorHasNoScopeAdminBypass()
			w.ordinary(w.request(w.usrE, osetr, allInScopeTarget()), allow)
			want := relverdict.Deny
			if allow {
				want = relverdict.Allow
			}
			w.eventuallyNative("user:"+string(w.usrE), "v_get", atcB1, want)
		})
	}
}

func TestFullBind_FB08_EveryNamedTargetNeedsCoverage(t *testing.T) {
	for _, allow := range []bool{true, false} {
		t.Run(map[bool]string{true: "both_targets", false: "first_only"}[allow], func(t *testing.T) {
			w := newFullBindWorld(t)
			treska := w.role("fb_treska", fullBindBoxRule("get"))
			osetr := w.role("fb_osetr", fullBindBoxRule("get"))
			targets := []*iamv1.ResourceRef{rr(atcBoxes, atcB1)}
			if allow {
				targets = append(targets, rr(atcBoxes, atcB2))
			}
			w.source(treska, resourcesTarget(targets...))
			w.createCapability()
			w.actorHasNoScopeAdminBypass()
			w.ordinary(w.request(w.usrE, osetr, resourcesTarget(rr(atcBoxes, atcB1), rr(atcBoxes, atcB2))), allow)
			want := relverdict.Deny
			if allow {
				want = relverdict.Allow
			}
			for _, id := range []string{atcB1, atcB2} {
				w.eventuallyNative("user:"+string(w.usrE), "v_get", id, want)
			}
		})
	}
}

func TestFullBind_FB09_CurrentObjectsDoNotCoverTheWholeScope(t *testing.T) {
	const futureBox = "box0000000000000003"
	for _, allow := range []bool{true, false} {
		t.Run(map[bool]string{true: "symbolic_scope", false: "current_inventory"}[allow], func(t *testing.T) {
			w := newFullBindWorld(t)
			treska := w.role("fb_treska", fullBindBoxRule("get"))
			osetr := w.role("fb_osetr", fullBindBoxRule("get"))
			sourceTarget := resourcesTarget(rr(atcBoxes, atcB1), rr(atcBoxes, atcB2))
			if allow {
				sourceTarget = allInScopeTarget()
			}
			w.source(treska, sourceTarget)
			w.createCapability()
			for _, id := range []string{atcB1, atcB2} {
				w.native("user:"+string(w.usrD), "v_get", atcBoxType, id, relverdict.Allow)
			}
			w.actorHasNoScopeAdminBypass()
			w.ordinary(w.request(w.usrE, osetr, allInScopeTarget()), allow)
			// Будущий объект появляется после решения: перечисление прежнего
			// инвентаря не может служить доказательством всеобщей области.
			w.registerBox(futureBox)
			want := relverdict.Deny
			if allow {
				want = relverdict.Allow
			}
			w.eventuallyNative("user:"+string(w.usrE), "v_get", futureBox, want)
		})
	}
}

func TestFullBind_FB10_ResourceNamesAreAuthorityCoordinates(t *testing.T) {
	const otherBox = "box0000000000000003"
	for _, allow := range []bool{true, false} {
		t.Run(map[bool]string{true: "covering_names", false: "disjoint_names"}[allow], func(t *testing.T) {
			w := newFullBindWorld(t)
			actorRule := fullBindBoxRule("get")
			actorRule.ResourceNames = []string{otherBox}
			if allow {
				actorRule.ResourceNames = []string{atcB1, atcB2}
			}
			proposedRule := fullBindBoxRule("get")
			proposedRule.ResourceNames = []string{atcB1}
			treska := w.role("fb_treska", actorRule)
			osetr := w.role("fb_osetr", proposedRule)
			w.source(treska, allInScopeTarget())
			w.createCapability()
			w.actorHasNoScopeAdminBypass()
			w.ordinary(w.request(w.usrE, osetr, allInScopeTarget()), allow)
			want := relverdict.Deny
			if allow {
				want = relverdict.Allow
			}
			w.eventuallyNative("user:"+string(w.usrE), "v_get", atcB1, want)
			w.native("user:"+string(w.usrE), "v_get", atcBoxType, atcB2, relverdict.Deny)
		})
	}
}

func TestFullBind_FB12_FiniteVerbsDoNotCoverTheSymbolicWildcard(t *testing.T) {
	for _, allow := range []bool{true, false} {
		t.Run(map[bool]string{true: "symbolic_verbs", false: "all_current_verbs"}[allow], func(t *testing.T) {
			w := newFullBindWorld(t)
			verbs := []string{"get", "list", "create", "update", "delete"}
			if allow {
				verbs = []string{"*"}
			}
			treska := w.role("fb_treska", fullBindBoxRule(verbs...))
			osetr := w.role("fb_osetr", fullBindBoxRule("*"))
			w.source(treska, allInScopeTarget())
			w.createCapability()
			w.actorHasNoScopeAdminBypass()
			w.ordinary(w.request(w.usrE, osetr, allInScopeTarget()), allow)
			want := relverdict.Deny
			if allow {
				want = relverdict.Allow
			}
			w.eventuallyNative("user:"+string(w.usrE), "v_get", atcB1, want)
		})
	}
}
