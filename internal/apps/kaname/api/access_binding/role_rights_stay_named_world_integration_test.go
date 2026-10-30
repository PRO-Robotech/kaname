// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// role_rights_stay_named_world_integration_test.go — мир Э приёмки
// docs/engineering/acceptance/role-rights-stay-within-what-is-named.md
// (редакция 3, отпечаток 8f141cbd7fed24693847bc1344bcd77a7f7490431bba7c2edc71378bd2ed7b26;
// эпик PRO-Robotech/kaname#1034, задачи PRO-Robotech/kaname#1035, PRO-Robotech/kaname#1036,
// PRO-Robotech/kaname#1037, PRO-Robotech/kaname#1039).
//
// Мир Э (§4.1) — мир Д (`newGDWorld`) плюс роли аккаунта с правилами, люди с
// выдачами, роли под правку, группы с выдачами и обработчик `AuthorizeService`
// с живым каталогом модуля. Пробы лежат в соседних файлах
// `role_rights_stay_named_*_integration_test.go`; каждая называется
// `TestRoleRightsStayNamed_ESC<NN>_…` — один сценарий, одна проба, свежий мир.
//
// Порядок пробы несущий: посев и его положительные контроли (`newEscWorld`) —
// сломанный посев краснеет здесь, называя контроль; затем тело сценария.
// Ожидание `false` утверждается после того, как в том же мире парный контроль
// стал `true`: окно материализации к этому моменту пройдено.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/operations"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	authorizeapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/authorize"
	groupapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/group"
	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/moduleroster"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// escWorld — мир Э одной базы.
type escWorld struct {
	*gdWorld

	// Роли аккаунта acc-A (§4.1, таблица ролей).
	rolDel, rolUpdDel, rolStar, rolAccDel domain.RoleID
	rolE1, rolE0, rolER, rolE2, rolG      domain.RoleID
	rolRoleEdit, rolGroupEdit             domain.RoleID

	// Люди мира Э (§4.1, таблица людей). Имена полей — роли людей в приёмке.
	usrDel, usrUpdDel, usrStar, usrAccDel domain.UserID
	usrRoleEd, usrRoleEdGrant             domain.UserID
	usrGroupEd, usrGroupEdGrant           domain.UserID

	// Выдачи, на которые ссылаются сценарии.
	bDel, bStar         string // rol-del → usr-D, rol-star → usr-W (prj-A)
	bE1R                string // rol-e1 → usr-R (prj-A)
	bER                 string // rol-er → sva-A3 (prj-A), отозвана
	bE2R, bE2Acc        string // rol-e2 → usr-R (prj-A), → sva-A3 (acc-A)
	bG1                 string // rol-g → grp-e1 (prj-A)
	bG2Prj, bG2Acc      string // rol-g → grp-e2 (prj-A, acc-A)
	grpE0, grpE1, grpE2 string

	// rulesE — правила ролей под правку до сценария (§4.1).
	rulesE domain.Rules

	authzH  *authorizeapp.Handler
	rolesX  *roleapp.Handler
	groupsX *groupapp.Handler
}

// escRegistryRule — правило над реестрами модуля registry с названными глаголами.
func escRegistryRule(verbs ...string) domain.Rule {
	return domain.Rule{Module: "registry", Resources: []string{"registries"}, Verbs: verbs}
}

// escProjectRule — правило над проектом модуля iam с названными глаголами.
func escProjectRule(verbs ...string) domain.Rule {
	return domain.Rule{Module: "iam", Resources: []string{"project"}, Verbs: verbs}
}

// newEscWorld поднимает мир Э и доказывает живость посева положительными
// контролями.
func newEscWorld(t *testing.T) *escWorld {
	t.Helper()
	w := &escWorld{gdWorld: newGDWorld(t)}
	ctx, pool := w.ctx, w.pool

	// ── роли аккаунта acc-A ────────────────────────────────────────────────
	w.rolDel = w.seedRole("esc_del", domain.Rules{escProjectRule("delete"), escRegistryRule("delete")})
	w.rolUpdDel = w.seedRole("esc_upd_del", domain.Rules{escProjectRule("update", "delete"), escRegistryRule("update", "delete")})
	w.rolStar = w.seedRole("esc_star", domain.Rules{escProjectRule("*"), escRegistryRule("*")})
	w.rolAccDel = w.seedRole("esc_acc_del",
		domain.Rules{{Module: "iam", Resources: []string{"account"}, Verbs: []string{"delete"}}})
	w.rulesE = domain.Rules{escRegistryRule("get")}
	w.rolE1 = w.seedRole("esc_e1", w.rulesE)
	w.rolE0 = w.seedRole("esc_e0", w.rulesE)
	w.rolER = w.seedRole("esc_er", w.rulesE)
	w.rolE2 = w.seedRole("esc_e2", w.rulesE)
	w.rolG = w.seedRole("esc_g", w.rulesE)
	w.rolRoleEdit = w.roleByName("iam.role.edit")
	w.rolGroupEdit = w.roleByName("iam.group.edit")

	// ── люди ───────────────────────────────────────────────────────────────
	w.usrDel = mustSeedUser(t, ctx, pool, "escd")
	w.usrUpdDel = mustSeedUser(t, ctx, pool, "escu")
	w.usrStar = mustSeedUser(t, ctx, pool, "escw")
	w.usrAccDel = mustSeedUser(t, ctx, pool, "escda")
	w.usrRoleEd = mustSeedUser(t, ctx, pool, "escr")
	w.usrRoleEdGrant = mustSeedUser(t, ctx, pool, "escrp")
	w.usrGroupEd = mustSeedUser(t, ctx, pool, "escg")
	w.usrGroupEdGrant = mustSeedUser(t, ctx, pool, "escgp")
	verifyAddresses(t, ctx, pool)

	// ── выдачи людям (от usr-A, цель — вся область) ────────────────────────
	w.bDel = w.escGrant(userSubject(w.usrDel), w.rolDel, "iam.project", string(w.prjA), "usr-D: rol-del на prj-A")
	w.escGrant(userSubject(w.usrUpdDel), w.rolUpdDel, "iam.project", string(w.prjA), "usr-U: rol-upd-del на prj-A")
	w.bStar = w.escGrant(userSubject(w.usrStar), w.rolStar, "iam.project", string(w.prjA), "usr-W: rol-star на prj-A")
	w.escGrant(userSubject(w.usrAccDel), w.rolAccDel, "iam.account", string(w.accA), "usr-Da: rol-acc-del на acc-A")
	w.escGrant(userSubject(w.usrRoleEd), w.rolRoleEdit, "iam.account", string(w.accA), "usr-R: iam.role.edit на acc-A")
	w.bE1R = w.escGrant(userSubject(w.usrRoleEd), w.rolE1, "iam.project", string(w.prjA), "usr-R: rol-e1 на prj-A")
	w.bE2R = w.escGrant(userSubject(w.usrRoleEd), w.rolE2, "iam.project", string(w.prjA), "usr-R: rol-e2 на prj-A")
	w.escGrant(userSubject(w.usrRoleEdGrant), w.rolRoleEdit, "iam.account", string(w.accA), "usr-RP: iam.role.edit на acc-A")
	w.escGrant(userSubject(w.usrRoleEdGrant), w.rolStar, "iam.project", string(w.prjA), "usr-RP: rol-star на prj-A")
	w.escGrant(userSubject(w.usrGroupEd), w.rolGroupEdit, "iam.account", string(w.accA), "usr-G: iam.group.edit на acc-A")
	w.escGrant(userSubject(w.usrGroupEdGrant), w.rolGroupEdit, "iam.account", string(w.accA), "usr-GP: iam.group.edit на acc-A")
	w.escGrant(userSubject(w.usrGroupEdGrant), w.rolStar, "iam.project", string(w.prjA), "usr-GP: rol-star на prj-A")

	// ── выдачи ролей под правку ────────────────────────────────────────────
	w.bER = w.escGrant(svaSubject(w.svaA3), w.rolER, "iam.project", string(w.prjA), "rol-er → sva-A3 на prj-A")
	w.revokeDone(w.bER, "мир Э: отзыв rol-er → sva-A3")
	w.bE2Acc = w.escGrant(svaSubject(w.svaA3), w.rolE2, "iam.account", string(w.accA), "rol-e2 → sva-A3 на acc-A")

	// ── группы и их выдачи ─────────────────────────────────────────────────
	w.grpE0 = seedGroup(t, ctx, pool, w.accA, "grp-esc-e0")
	w.grpE1 = seedGroup(t, ctx, pool, w.accA, "grp-esc-e1")
	w.grpE2 = seedGroup(t, ctx, pool, w.accA, "grp-esc-e2")
	w.bG1 = w.escGrant(groupSubject(w.grpE1), w.rolG, "iam.project", string(w.prjA), "rol-g → grp-e1 на prj-A")
	w.bG2Prj = w.escGrant(groupSubject(w.grpE2), w.rolG, "iam.project", string(w.prjA), "rol-g → grp-e2 на prj-A")
	w.bG2Acc = w.escGrant(groupSubject(w.grpE2), w.rolG, "iam.account", string(w.accA), "rol-g → grp-e2 на acc-A")

	w.buildEscHandlers()

	// ── положительные контроли посева ──────────────────────────────────────
	x := pcrRegType + ":" + pcrX
	prj := "project:" + string(w.prjA)
	w.pollRelation(escUser(w.usrDel), "v_delete", x, true, "контроль мира Э: usr-D держит v_delete на X")
	w.pollRelation(escUser(w.usrDel), "v_delete", prj, true, "контроль мира Э: usr-D держит v_delete на prj-A")
	w.pollRelation(escUser(w.usrUpdDel), "v_update", x, true, "контроль мира Э: usr-U держит v_update на X")
	w.pollRelation(escUser(w.usrStar), "admin", prj, true, "контроль мира Э: usr-W держит admin на prj-A")
	w.pollRelation(escUser(w.usrRoleEdGrant), "admin", prj, true, "контроль мира Э: usr-RP держит admin на prj-A")
	w.pollRelation(escUser(w.usrStar), "admin", x, true, "контроль мира Э: usr-W держит admin на X")
	w.pollRelation(escUser(w.usrRoleEd), "v_update", "iam_role:"+string(w.rolE1), true,
		"контроль мира Э: usr-R держит v_update на rol-e1")
	w.pollRelation(escUser(w.usrRoleEd), "v_update", "iam_role:"+string(w.rolE2), true,
		"контроль мира Э: usr-R держит v_update на rol-e2")
	w.pollRelation(escUser(w.usrGroupEd), "v_update", "iam_group:"+w.grpE1, true,
		"контроль мира Э: usr-G держит v_update на grp-e1")
	require.Equal(t, []iamv1.AccessBinding_Status{iamv1.AccessBinding_REVOKED}, w.statusesByRole(w.rolER),
		"контроль мира Э: у rol-er одна выдача, отозванная")
	require.Equal(t, []iamv1.AccessBinding_Status{iamv1.AccessBinding_ACTIVE, iamv1.AccessBinding_ACTIVE},
		w.statusesByRole(w.rolE2), "контроль мира Э: у rol-e2 две действующие выдачи")
	return w
}

// escGrant — выдача от владельца usr-A, цель — вся область; отдаёт id.
func (w *escWorld) escGrant(sub *iamv1.Subject, role domain.RoleID, scopeType, scopeID, what string) string {
	w.t.Helper()
	return w.createDoneX(asUser(w.ctx, w.usrA), &iamv1.CreateAccessBindingRequest{
		Subjects:  []*iamv1.Subject{sub},
		RoleId:    string(role),
		ScopeType: scopeType,
		ScopeId:   scopeID,
		Target:    allInScopeTarget(),
	}, "мир Э: "+what)
}

// buildEscHandlers — обработчики мира Э теми же частями, что корень службы
// (`cmd/kaname/wiring.go`): `AuthorizeService` с живым каталогом модуля мира и
// воротами права спрашивать о чужом субъекте; роли и группы с глаголами,
// которые трогают сценарии.
func (w *escWorld) buildEscHandlers() {
	w.t.Helper()
	src := catalog.Fixed{F: w.facts}
	svc := service.NewAuthorizeService(service.AuthorizeServiceConfig{
		Relations:           w.door,
		ClusterAdminChecker: w.door,
		Catalog:             src,
	})
	w.authzH = authorizeapp.NewHandler(svc, authorizeapp.NewWhoAmIUseCase(nil, nil)).
		WithModuleRoster(moduleroster.Roster(w.t)).
		WithCallerAuthority(w.door)
	w.rolesX = roleapp.NewHandler(
		roleapp.NewCreateRoleUseCase(w.repo, w.ops, src).WithRelationStore(w.door, nil),
		w.escRoleUpdate(),
		nil,
		roleapp.NewGetRoleUseCase(w.repo, src).WithRelationStore(w.door),
		nil)
	w.groupsX = groupapp.NewHandler(
		groupapp.NewCreateGroupUseCase(w.repo, w.ops).WithRelationStore(w.door, nil),
		nil, nil, nil, nil,
		groupapp.NewAddMemberUseCase(w.repo, w.ops),
		groupapp.NewRemoveMemberUseCase(w.repo, w.ops),
		groupapp.NewListMembersUseCase(w.repo).WithRelationStore(w.door))
}

// escRoleUpdate — правка роли теми же частями, что корень службы.
func (w *escWorld) escRoleUpdate() *roleapp.UpdateRoleUseCase {
	return w.escRoleUpdateOver(w.door)
}

// escRoleUpdateOver — та же правка с проверкой Р2 над названной дверью решения.
func (w *escWorld) escRoleUpdateOver(relations accessbindingapp.GrantAuthorityRelations) *roleapp.UpdateRoleUseCase {
	return w.escRoleUpdateOn(w.ops, relations)
}

// escRoleUpdateOn — та же правка над названным хранилищем операций (гонка
// подставляет хранилище с задвижкой).
func (w *escWorld) escRoleUpdateOn(ops operations.Repo, relations accessbindingapp.GrantAuthorityRelations) *roleapp.UpdateRoleUseCase {
	u := roleapp.NewUpdateRoleUseCase(w.repo, ops, catalog.Fixed{F: w.facts}).
		WithTupleReconciler(accessbindingapp.NewRoleTupleReconciler()).
		WithMembershipFanout(accessbindingapp.NewRoleMembershipFanout(w.repo, w.rec))
	return escWireRoleAuthority(w, u, relations)
}

// statusesByRole — статусы выдач роли по `ListByRole` от владельца, включая
// отозванные, по порядку ответа.
func (w *escWorld) statusesByRole(role domain.RoleID) []iamv1.AccessBinding_Status {
	w.t.Helper()
	resp, err := w.abx.ListByRole(asUser(w.ctx, w.usrA),
		&iamv1.ListAccessBindingsByRoleRequest{RoleId: string(role), PageSize: 1000, IncludeRevoked: true})
	require.NoErrorf(w.t, err, "ListByRole(%s) от usr-A", role)
	out := []iamv1.AccessBinding_Status{}
	for _, b := range resp.GetAccessBindings() {
		out = append(out, b.GetStatus())
	}
	return out
}

// escUser — субъект-человек в форме вопроса к модели.
func escUser(id domain.UserID) string { return "user:" + string(id) }

// checkAction — `AuthorizeService.Check` с действием, без отношения: вызывающий —
// модуль платформы (§4.1 «Вопрос модели», форма «с действием»).
func (w *escWorld) checkAction(subject, action, objType, objID string) bool {
	w.t.Helper()
	resp, err := w.authzH.Check(moduleCtx(), &iamv1.AuthorizeCheckRequest{
		Subject:  subject,
		Resource: &iamv1.ResourceRef{Type: objType, Id: objID},
		Action:   action,
	})
	require.NoErrorf(w.t, err, "Check(%s, %s, %s:%s) не ответил", subject, action, objType, objID)
	return resp.GetAllowed()
}

// listSubjects — `AuthorizeService.ListSubjects` о реестре X с вызывающим ctx.
func (w *escWorld) listSubjects(ctx context.Context, action string) ([]string, error) {
	w.t.Helper()
	resp, err := w.authzH.ListSubjects(ctx, &iamv1.ListSubjectsRequest{
		Resource: &iamv1.ResourceRef{Type: pcrRegType, Id: pcrX},
		Action:   action,
		PageSize: 100,
	})
	if err != nil {
		return nil, err
	}
	return resp.GetSubjects(), nil
}

// vE — тело выдачи V-E (§4.1): область prj-A, роль rol-g, субъект sva-A2, вся область.
func (w *escWorld) vE() *iamv1.CreateAccessBindingRequest {
	return &iamv1.CreateAccessBindingRequest{
		Subjects:  []*iamv1.Subject{svaSubject(w.svaA2)},
		RoleId:    string(w.rolG),
		ScopeType: "iam.project",
		ScopeId:   string(w.prjA),
		Target:    allInScopeTarget(),
	}
}

// activeBindingsOn — число действующих выдач на области.
func (w *escWorld) activeBindingsOn(scopeType, scopeID string) int {
	w.t.Helper()
	var n int
	require.NoError(w.t, w.pool.QueryRow(w.ctx,
		`SELECT count(*) FROM kaname.access_bindings WHERE resource_type = $1 AND resource_id = $2 AND revoked_at IS NULL`,
		scopeType, scopeID).Scan(&n))
	return n
}

// revokeDone — отзыв выдачи владельцем до `done` без ошибки.
func (w *escWorld) revokeDone(id, why string) {
	w.t.Helper()
	op, err := w.revokeBinding(asUser(w.ctx, w.usrA), id)
	w.requireOpDone(op, err, why)
}

// rulesOf — правила роли по `RoleService.Get` от владельца.
func (w *escWorld) rulesOf(role domain.RoleID) []*iamv1.Rule {
	w.t.Helper()
	pb, err := w.rolesX.Get(asUser(w.ctx, w.usrA), &iamv1.GetRoleRequest{RoleId: string(role)})
	require.NoErrorf(w.t, err, "RoleService.Get(%s) от usr-A", role)
	return pb.GetRules()
}
