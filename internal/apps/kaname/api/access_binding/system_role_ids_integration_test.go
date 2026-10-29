// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// system_role_ids_integration_test.go — сценарии SRCI-01…08, SRCI-10…12 приёмки
// docs/engineering/acceptance/system-roles-carry-canonical-ids.md (kaname#543).
// Сценарий ↔ одна функция `TestSystemRoleIDs_SRCI<NN>_<Суть>`; близнец — в той же
// функции либо `…_SRCI<NN>b_…`. Девятый номер снят приёмкой и здесь не используется.
//
// Порядок каждой пробы несущий: посев и его положительный контроль, затем
// `requireSubject` (есть ли миграция и новые id), затем предмет. Посев, сломанный
// до предмета, краснеет текстом «НЕ-ВЫПОЛНИЛОСЬ(фикстура)», а не «ИСПЫТУЕМОГО НЕТ».

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/subscriptionjournal"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// srciMalformed — роли ответа, которым судья формы фундамента отказывает.
func srciMalformed(roles []*iamv1.Role) []string {
	var bad []string
	for _, r := range roles {
		if !ids.HasKnownPrefix(r.GetId()) {
			bad = append(bad, r.GetName())
		}
	}
	sort.Strings(bad)
	return bad
}

// SRCI-01 — после всей цепочки каждый id роли, который отдаёт List, канонической
// формы; близнец SRCI-01б — без новой миграции таких ровно две, и это роли предмета.
func TestSystemRoleIDs_SRCI01_SeededRoleIDsAreCanonical(t *testing.T) {
	w := newSRCIWorldAt(t, 0)

	roles := w.listAllRoles()
	t.Logf("SRCI-01: прочитано ролей %d (голова цепочки %d)", len(roles), w.subj.head())
	require.GreaterOrEqual(t, len(roles), 48, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): List отдал меньше посеянных ролей")

	byName := map[string]string{}
	for _, r := range roles {
		byName[r.GetName()] = r.GetId()
	}
	assert.Empty(t, srciMalformed(roles), "SRCI-01: роли, чей id не проходит ids.HasKnownPrefix")
	assert.Equal(t, domain.SystemAdminRoleID, byName[domain.SystemAdminRoleName], "SRCI-01: id system.admin")
	assert.Equal(t, domain.SystemViewerRoleID, byName[domain.SystemViewerRoleName], "SRCI-01: id system.viewer")
}

func TestSystemRoleIDs_SRCI01b_WithoutTheMigrationExactlyTheTwoAreMalformed(t *testing.T) {
	subj := srciReadSubject(t)
	w := newSRCIWorldAt(t, subj.preceding())

	roles := w.listAllRoles()
	t.Logf("SRCI-01б: прочитано ролей %d на версии %d", len(roles), subj.preceding())
	require.GreaterOrEqual(t, len(roles), 48, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): List отдал меньше посеянных ролей")
	assert.Equal(t, []string{domain.SystemAdminRoleName, domain.SystemViewerRoleName}, srciMalformed(roles),
		"SRCI-01б: без новой миграции не в форме ровно две роли предмета")
}

// SRCI-02 — константы домена канонической формы, различны и не совпадают ни с
// одним из прочих посеянных id; близнец SRCI-02б — прежние id формы не проходят.
func TestSystemRoleIDs_SRCI02_ConstantsAreCanonical(t *testing.T) {
	subj := srciReadSubject(t)

	// Близнец SRCI-02б — первым: он же контроль разбора прежних id.
	assert.False(t, ids.HasKnownPrefix(subj.oldAdmin), "SRCI-02б: прежний id admin проходит судью формы")
	assert.False(t, ids.HasKnownPrefix(subj.oldViewer), "SRCI-02б: прежний id viewer проходит судью формы")

	assert.True(t, ids.HasKnownPrefix(domain.SystemAdminRoleID), "SRCI-02: SystemAdminRoleID не канонической формы")
	assert.True(t, ids.HasKnownPrefix(domain.SystemViewerRoleID), "SRCI-02: SystemViewerRoleID не канонической формы")
	assert.NotEqual(t, domain.SystemAdminRoleID, domain.SystemViewerRoleID, "SRCI-02: значения различны")
	for _, id := range subj.seeded {
		if id == subj.oldAdmin || id == subj.oldViewer {
			continue
		}
		assert.NotEqual(t, id, domain.SystemAdminRoleID, "SRCI-02: SystemAdminRoleID совпал с посеянным id")
		assert.NotEqual(t, id, domain.SystemViewerRoleID, "SRCI-02: SystemViewerRoleID совпал с посеянным id")
	}
}

// SRCI-03 — роль читается по НОВОМУ id: Get и GetRoleCompiled.
func TestSystemRoleIDs_SRCI03_RoleIsReadByTheNewID(t *testing.T) {
	w := newSRCIWorldAt(t, 0)

	for _, c := range []struct{ id, name string }{
		{domain.SystemAdminRoleID, domain.SystemAdminRoleName},
		{domain.SystemViewerRoleID, domain.SystemViewerRoleName},
	} {
		r, err := w.roles.Get(asUser(w.ctx, w.k), &iamv1.GetRoleRequest{RoleId: c.id})
		require.NoErrorf(t, err, "SRCI-03: Get %s", c.name)
		assert.Equal(t, c.id, r.GetId(), "SRCI-03: id")
		assert.Equal(t, c.name, r.GetName(), "SRCI-03: name")
		assert.True(t, r.GetIsSystem(), "SRCI-03: isSystem")

		compiled, err := w.iiam.GetRoleCompiled(w.ctx, &iamv1.GetRoleCompiledRequest{RoleId: c.id})
		require.NoErrorf(t, err, "SRCI-03: GetRoleCompiled %s", c.name)
		assert.Equal(t, c.id, compiled.GetRoleId(), "SRCI-03: GetRoleCompiled.roleId")
		assert.NotEmpty(t, compiled.GetPermissions(), "SRCI-03: GetRoleCompiled отдал пустой набор")
	}
	// Читается ли роль по ИМЕННО новому id, а не по прежнему, — предмет.
	w.subj.requireSubject(t, "SRCI-03")
}

// SRCI-04 — прежние id не адресуют ничего: Get admin — NOT_FOUND, Get viewer —
// INVALID_ARGUMENT, выдача на прежний id admin — FAILED_PRECONDITION без операции.
// Близнецы — SRCI-03 (Get по новому id) и SRCI-08 (выдача на новый id).
func TestSystemRoleIDs_SRCI04_OldIDsAddressNothing(t *testing.T) {
	w := newSRCIWorldAt(t, 0)
	old := w.subj

	// Контроль пути: тот же глагол с id той же формы и длины, что у прежнего id
	// admin, отвечает тем же отказом «нет такой роли» — путь отказа жив.
	ghost := domain.PrefixRole + strings.Repeat("z", domain.ShortIDLen-len(domain.PrefixRole))
	_, err := w.roles.Get(asUser(w.ctx, w.k), &iamv1.GetRoleRequest{RoleId: ghost})
	requireSyncRefusal(t, err, codes.NotFound, "Role "+ghost+" not found", "SRCI-04 контроль: несуществующая роль")

	_, err = w.roles.Get(asUser(w.ctx, w.k), &iamv1.GetRoleRequest{RoleId: old.oldAdmin})
	assert.Equal(t, codes.NotFound, status.Code(err), "SRCI-04: Get прежнего id admin — код (ошибка %v)", err)
	assert.Equal(t, "Role "+old.oldAdmin+" not found", status.Convert(err).Message(), "SRCI-04: Get прежнего id admin — текст")

	_, err = w.roles.Get(asUser(w.ctx, w.k), &iamv1.GetRoleRequest{RoleId: old.oldViewer})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "SRCI-04: Get прежнего id viewer — код (ошибка %v)", err)
	assert.Equal(t, "invalid role id '"+old.oldViewer+"'", status.Convert(err).Message(), "SRCI-04: Get прежнего id viewer — текст")

	before := w.opsCount()
	op, err := w.ab.Create(asUser(w.ctx, w.k), w.clusterAllInScope(old.oldAdmin))
	if op != nil {
		// Операция всё же отчеканена: доводим её до конца, чтобы фон не писал в
		// базу, которую снимает уборка.
		awaitOp(t, w.ctx, w.ops, op.GetId())
	}
	assert.Equal(t, codes.FailedPrecondition, status.Code(err), "SRCI-04: выдача на прежний id admin — код (ошибка %v)", err)
	assert.Equal(t, "Role "+old.oldAdmin+" not found", status.Convert(err).Message(), "SRCI-04: выдача на прежний id admin — текст")
	assert.Equal(t, before, w.opsCount(), "SRCI-04: отказ отчеканил Operation")
}

// srciAsk — один вопрос среза: субъект и глагол на O1.
type srciAsk struct{ subject, verb string }

// srciAsks — Ч1–Ч5 редакции 3 по порядку; столбец «ожидание» — srciWant.
func (w *srciWorld) srciAsks() []srciAsk {
	u := func(id domain.UserID) string { return fmtSubject("user", string(id)) }
	return []srciAsk{
		{u(w.u1), "update"}, // Ч1 — B1
		{u(w.u2), "get"},    // Ч2 — B2 через G1
		{u(w.u2), "update"}, // Ч3 — близнец Ч2, отличие — глагол
		{u(w.u3), "get"},    // Ч4 — близнец Ч2, отличие — субъект
		{u(w.u3), "update"}, // Ч5 — близнец Ч1, отличие — субъект
	}
}

// srciWant — столбец «ожидание» Ч1–Ч5.
var srciWant = []bool{true, true, false, false, false}

// srciAnswer — ответ Check с очищенным `checked_at` (условие ревью R1).
func (w *srciWorld) srciAnswer(q srciAsk) *iamv1.AuthorizeCheckResponse {
	w.t.Helper()
	resp, err := w.check(q.subject, q.verb, srciObj)
	require.NoErrorf(w.t, err, "Check(%s, %s)", q.subject, q.verb)
	c := proto.Clone(resp).(*iamv1.AuthorizeCheckResponse)
	c.CheckedAt = nil
	return c
}

// srciCheckSnapshot — ответы Ч1–Ч5.
func (w *srciWorld) srciCheckSnapshot() []*iamv1.AuthorizeCheckResponse {
	w.t.Helper()
	var out []*iamv1.AuthorizeCheckResponse
	for _, q := range w.srciAsks() {
		out = append(out, w.srciAnswer(q))
	}
	return out
}

// srciRequireCheckColumn — срез обязан дать ровно столбец «ожидание» (Ч1 и Ч2 —
// разрешено, Ч3–Ч5 — отказ): положительный контроль посева.
func srciRequireCheckColumn(t *testing.T, snap []*iamv1.AuthorizeCheckResponse, why string) {
	t.Helper()
	require.Len(t, snap, len(srciWant), "%s: число ответов среза", why)
	for i, r := range snap {
		require.Equalf(t, srciWant[i], r.GetAllowed(), "%s: Ч%d (deny %v)", why, i+1, r.GetDenyReasons())
	}
}

// seedSRCI05Materialized — посев SRCI-05 и ожидание окна материализации: срез Ч1–Ч5
// обязан дать столбец «ожидание» (опрос раз в 200 мс до 30 с, окно SC-13). Не дал —
// отказ называет все пять ответов и то, из чего доступ выводится, чтобы несозданное
// условие читалось условием, а не предметом.
func (w *srciWorld) seedSRCI05Materialized() {
	w.seedSRCI05()
	deadline := time.Now().Add(30 * time.Second)
	for {
		snap := w.srciCheckSnapshot()
		got := make([]bool, len(snap))
		for i, r := range snap {
			got[i] = r.GetAllowed()
		}
		if assert.ObjectsAreEqual(srciWant, got) {
			return
		}
		if time.Now().After(deadline) {
			w.t.Fatalf("НЕ-ВЫПОЛНИЛОСЬ(фикстура) SRCI-05: срез до за 30 с не дал столбец «ожидание» "+
				"(Ч1 U1 update, Ч2 U2 get, Ч3 U2 update, Ч4 U3 get, Ч5 U3 update): ждали %v, получили %v; %s",
				srciWant, got, w.srciGrantBasis())
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// srciGrantBasis — из чего выводится доступ по B1, B2 и B6: селекторы и глаголы
// ролей, факты о субъектах, члены цели.
func (w *srciWorld) srciGrantBasis() string {
	w.t.Helper()
	q := func(sql string, args ...any) string {
		rows, err := w.pool.Query(w.ctx, sql, args...)
		if err != nil {
			return "ошибка чтения: " + err.Error()
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				return "ошибка чтения: " + err.Error()
			}
			out = append(out, s)
		}
		return "[" + strings.Join(out, "; ") + "]"
	}
	roles := []string{w.roleIDByName(domain.SystemAdminRoleName), w.roleIDByName(domain.SystemViewerRoleName)}
	subjects := []string{fmtSubject("user", string(w.u1)), fmtSubject("group", w.g1+"#member"),
		fmtSubject("user", string(w.u2)), fmtSubject("user", string(w.u4))}
	return "селекторы ролей " + q(`SELECT role_id || ' ' || arm::text || ' ' || object_types::text FROM kaname.role_rule_selectors WHERE role_id = ANY($1)`, roles) +
		"; глаголы на vpc_network " + q(`SELECT role_id || ' ' || verb FROM kaname.role_verb WHERE role_id = ANY($1) AND object_type = 'vpc_network'`, roles) +
		"; факты " + q(`SELECT object_type || ':' || object_id || '#' || relation || '@' || subject FROM kaname.relation_fact WHERE subject = ANY($1)`, subjects) +
		"; члены цели " + q(`SELECT binding_id || ' ' || t::text FROM kaname.access_binding_target_members t WHERE binding_id = ANY($1)`, []string{w.b1, w.b2, w.b6})
}

// SRCI-05 — выдачи работающей базы переходят на новые id без потери.
func TestSystemRoleIDs_SRCI05_GrantsCrossOverWithoutLoss(t *testing.T) {
	subj := srciReadSubject(t)
	w := newSRCIWorldAt(t, subj.preceding())
	w.seedSRCI05Materialized()

	before := w.srciCheckSnapshot()
	srciRequireCheckColumn(t, before, "НЕ-ВЫПОЛНИЛОСЬ(фикстура) SRCI-05 срез до")
	// Ч6 — минор ревью редакции 3 (ab4986a4…, COVERAGE): U4 (субъект B6) update на O1.
	// Значение НЕ закрепляется (Д6, kaname#1073): утверждается лишь «после равно до».
	ch6 := srciAsk{fmtSubject("user", string(w.u4)), "update"}
	ch6Before := w.srciAnswer(ch6)
	t.Logf("SRCI-05: Ч6 до наката (не закрепляется, Д6) allowed=%v", ch6Before.GetAllowed())
	b1, b2, b6 := w.getBinding(w.b1), w.getBinding(w.b2), w.getBinding(w.b6)
	require.Equal(t, w.subj.oldAdmin, b1.GetRoleId(), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): B1 на прежнем id admin")
	require.Equal(t, w.subj.oldViewer, b2.GetRoleId(), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): B2 на прежнем id viewer")
	require.Equal(t, w.subj.oldAdmin, b6.GetRoleId(), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): B6 на прежнем id admin")
	bindingsBefore := w.countRows("kaname.access_bindings")

	w.subj.requireSubject(t, "SRCI-05")
	w.up("SRCI-05")

	for _, c := range []struct {
		before *iamv1.AccessBinding
		role   string
	}{{b1, domain.SystemAdminRoleID}, {b2, domain.SystemViewerRoleID}, {b6, domain.SystemAdminRoleID}} {
		after := w.getBinding(c.before.GetId())
		assert.Equal(t, c.before.GetId(), after.GetId(), "SRCI-05: id")
		assert.Truef(t, proto.Equal(&iamv1.AccessBinding{Subjects: c.before.GetSubjects()}, &iamv1.AccessBinding{Subjects: after.GetSubjects()}),
			"SRCI-05: subjects %v → %v", c.before.GetSubjects(), after.GetSubjects())
		assert.Equal(t, c.before.GetScopeType(), after.GetScopeType(), "SRCI-05: scopeType")
		assert.Equal(t, c.before.GetScopeId(), after.GetScopeId(), "SRCI-05: scopeId")
		assert.Truef(t, proto.Equal(c.before.GetTarget(), after.GetTarget()), "SRCI-05: target %v → %v", c.before.GetTarget(), after.GetTarget())
		assert.Truef(t, proto.Equal(c.before.GetCreatedAt(), after.GetCreatedAt()), "SRCI-05: createdAt")
		assert.Equal(t, c.role, after.GetRoleId(), "SRCI-05: roleId — новый id")
	}
	afterChecks := w.srciCheckSnapshot()
	for i := range before {
		assert.Truef(t, proto.Equal(before[i], afterChecks[i]), "SRCI-05: Ч%d разошёлся: %v → %v", i+1, before[i], afterChecks[i])
	}
	ch6After := w.srciAnswer(ch6)
	assert.Truef(t, proto.Equal(ch6Before, ch6After), "SRCI-05: Ч6 (U4, B6) разошёлся: %v → %v", ch6Before, ch6After)
	list, err := w.ab.ListByRole(asUser(w.ctx, w.k), &iamv1.ListAccessBindingsByRoleRequest{RoleId: domain.SystemAdminRoleID, PageSize: 1000})
	require.NoError(t, err, "SRCI-05: listByRole")
	var listed []string
	for _, b := range list.GetAccessBindings() {
		listed = append(listed, b.GetId())
	}
	assert.Contains(t, listed, w.b1, "SRCI-05: listByRole нового id admin отдаёт B1")
	assert.Contains(t, listed, w.b6, "SRCI-05: listByRole нового id admin отдаёт B6")
	assert.Equal(t, bindingsBefore, w.countRows("kaname.access_bindings"), "SRCI-05: число выдач")
}

// srciCreateOutcome — выдача глаголом `Create` от имени K: id выдачи и исход —
// синхронный отказ либо ошибка операции; nil — операция завершилась без ошибки.
func (w *srciWorld) srciCreateOutcome(req *iamv1.CreateAccessBindingRequest) (string, error) {
	w.t.Helper()
	op, err := w.ab.Create(asUser(w.ctx, w.k), req)
	if err != nil {
		return "", err
	}
	done := awaitOp(w.t, w.ctx, w.ops, op.GetId())
	if done.Error != nil {
		return "", status.ErrorProto(done.Error)
	}
	var md iamv1.CreateAccessBindingMetadata
	require.NoError(w.t, op.GetMetadata().UnmarshalTo(&md), "метаданные операции")
	return md.GetAccessBindingId(), nil
}

// srciSettled — ответ Check после окна материализации: опрос раз в 200 мс до 30 с,
// пока не «разрешено»; по истечении — последний ответ. Отказ, переживший окно, —
// отказ, а не ещё не доставленное право.
func (w *srciWorld) srciSettled(subject, verb string) bool {
	w.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		resp, err := w.check(subject, verb, srciObj)
		require.NoErrorf(w.t, err, "Check(%s, %s)", subject, verb)
		if resp.GetAllowed() || time.Now().After(deadline) {
			return resp.GetAllowed()
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// Контроль фикстуры SRCI-05 (не сценарий приёмки; §5 редакции 3). Посев (писатель
// §5) строит B1, B2, B6 мимо глагола. Контроль спрашивает глагол `Create` о тех же
// формах: близнецы B1v (U5), B2v (G2#member, член U6), B6v (U7). Отличие по предмету —
// писатель; субъект и id роли — по построению (минор ревью ab4986a4…). Исход каждого
// `Create` — без ошибки; ответы Check близнецов равны ответам посева: Ч1 (U1↔U5
// update), Ч2–Ч3 (U2↔U6 get, update) и ответ по B6 (U4↔U7 update, значение не
// закрепляется — Д6). Мир — вся цепочка дерева, роль адресуется чтением по имени:
// глагол принимает её id и до реализации, и после. Красное здесь — посев строит не
// то, что глагол: состояние вымышлено либо отвечает иначе.
//
// Глагол проходит все ворота в порядке вызова, включая ворота обработчика (форма
// id роли, наличие цели) и право выдавать (`delegatedGrantAuthority`), которых
// таблица ворот приёмки не перечисляет (минор ревью) — исход их и судит.
func TestSystemRoleIDs_SRCI05Fixture_SeedIsWhatTheVerbMakes(t *testing.T) {
	w := newSRCIWorldAt(t, 0)
	w.seedSRCI05()

	u5 := mustSeedUser(t, w.ctx, w.pool, "srciu5")
	u6 := mustSeedUser(t, w.ctx, w.pool, "srciu6")
	u7 := mustSeedUser(t, w.ctx, w.pool, "srciu7")
	g2 := seedGroup(t, w.ctx, w.pool, w.a1, "grp-srci-g2")
	_, err := w.pool.Exec(w.ctx, `
		INSERT INTO kaname.group_members (group_id, member_type, member_id, added_at)
		VALUES ($1, 'user', $2, now())`, g2, string(u6))
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): член группы G2")
	verifyAddresses(t, w.ctx, w.pool)

	admin, viewer := w.roleIDByName(domain.SystemAdminRoleName), w.roleIDByName(domain.SystemViewerRoleName)
	// B1v — форма B1: человек, system.admin, аккаунт A1, все объекты.
	_, b1err := w.srciCreateOutcome(&iamv1.CreateAccessBindingRequest{
		Subjects: []*iamv1.Subject{userSubject(u5)}, RoleId: admin,
		ScopeType: "iam.account", ScopeId: string(w.a1), Target: allInScopeTarget(),
	})
	// B2v — форма B2: группа, system.viewer, аккаунт A1, все объекты.
	_, b2err := w.srciCreateOutcome(&iamv1.CreateAccessBindingRequest{
		Subjects: []*iamv1.Subject{groupSubject(g2)}, RoleId: viewer,
		ScopeType: "iam.account", ScopeId: string(w.a1), Target: allInScopeTarget(),
	})
	// B6v — форма B6: человек, system.admin, кластер, все объекты.
	_, b6err := w.srciCreateOutcome(&iamv1.CreateAccessBindingRequest{
		Subjects: []*iamv1.Subject{userSubject(u7)}, RoleId: admin,
		ScopeType: "iam.cluster", ScopeId: domain.ClusterSingletonID, Target: allInScopeTarget(),
	})
	t.Logf("SRCI-05 контроль фикстуры: глагол о форме B1 (роль %s) — %v; B2 (роль %s) — %v; B6 (роль %s) — %v",
		admin, b1err, viewer, b2err, admin, b6err)
	assert.NoError(t, b1err, "посев B1: форму B1 глагол не принимает — состояние вымышлено")
	assert.NoError(t, b2err, "посев B2: форму B2 глагол не принимает — состояние вымышлено")
	assert.NoError(t, b6err, "посев B6: форму B6 глагол не принимает — состояние вымышлено")

	u := func(id domain.UserID) string { return fmtSubject("user", string(id)) }
	seeded := []bool{w.srciSettled(u(w.u1), "update"), w.srciSettled(u(w.u2), "get"),
		w.srciSettled(u(w.u2), "update"), w.srciSettled(u(w.u4), "update")}
	t.Logf("SRCI-05 контроль фикстуры: посев Ч1–Ч3 и ответ по B6 %v (столбец приёмки Ч1–Ч3 [true true false]; B6 не закрепляется); факты U1 %s; факты U4 %s",
		seeded, w.srciFactsOf(u(w.u1)), w.srciFactsOf(u(w.u4)))
	if b1err == nil {
		got := w.srciSettled(u(u5), "update")
		t.Logf("SRCI-05 контроль фикстуры: Ч1 близнеца B1v (U5 update) %v; факты U5 %s", got, w.srciFactsOf(u(u5)))
		assert.Equal(t, seeded[0], got, "посев B1 отвечает на Ч1 иначе, чем та же выдача глаголом")
	}
	if b2err == nil {
		got := []bool{w.srciSettled(u(u6), "get"), w.srciSettled(u(u6), "update")}
		t.Logf("SRCI-05 контроль фикстуры: Ч2–Ч3 близнеца B2v (U6 get, update) %v", got)
		assert.Equal(t, seeded[1:3], got, "посев B2 отвечает на Ч2–Ч3 иначе, чем та же выдача глаголом")
	}
	if b6err == nil {
		got := w.srciSettled(u(u7), "update")
		t.Logf("SRCI-05 контроль фикстуры: ответ близнеца B6v (U7 update) %v; факты U7 %s", got, w.srciFactsOf(u(u7)))
		assert.Equal(t, seeded[3], got, "посев B6 отвечает иначе, чем та же выдача глаголом")
	}
}

// srciFactsOf — факты модели прав о субъекте: из чего выводится его доступ.
func (w *srciWorld) srciFactsOf(subject string) string {
	w.t.Helper()
	rows, err := w.pool.Query(w.ctx, `
		SELECT object_type || ':' || object_id || '#' || relation FROM kaname.relation_fact
		 WHERE subject = $1 ORDER BY 1`, subject)
	require.NoError(w.t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		require.NoError(w.t, rows.Scan(&s))
		out = append(out, s)
	}
	require.NoError(w.t, rows.Err())
	return "[" + strings.Join(out, "; ") + "]"
}

// SRCI-06 — ни одна строка базы, кроме ленты подписки, не сохраняет прежний id;
// лента дописывается, прежние её строки не меняются.
func TestSystemRoleIDs_SRCI06_NoRowKeepsTheOldID(t *testing.T) {
	subj := srciReadSubject(t)
	w := newSRCIWorldAt(t, subj.preceding())
	w.seedSRCI05()

	tables := w.tables(false)
	oldBefore := map[string]map[string]int{
		"admin": w.countWith(tables, subj.oldAdmin), "viewer": w.countWith(tables, subj.oldViewer)}
	var total int
	for _, m := range oldBefore {
		for _, n := range m {
			total += n
		}
	}
	t.Logf("SRCI-06: таблиц обойдено %d (без ленты); строк с прежними id до наката %d: admin %v, viewer %v",
		len(tables), total, oldBefore["admin"], oldBefore["viewer"])
	require.Positive(t, total, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): прежних id в схеме 0 — равенство выполнялось бы тождественно")
	journal := []string{strings.TrimPrefix(subscriptionjournal.Table, "kaname.")}
	jOld := map[string]int{"admin": w.countWith(journal, subj.oldAdmin)[journal[0]], "viewer": w.countWith(journal, subj.oldViewer)[journal[0]]}
	s0 := w.journalHead()
	journalBefore := w.journalUpTo(s0)
	// Предикат приёмки (`<таблица>::text LIKE`) байтовых колонок не видит: `bytea`
	// выводится шестнадцатеричной строкой. Вопрос В1 к приёмке открыт, поэтому число
	// печатается, а не утверждается.
	t.Logf("SRCI-06: байтовые колонки с прежними id до наката (не утверждается, В1): admin %v, viewer %v",
		w.countInBytea(subj.oldAdmin), w.countInBytea(subj.oldViewer))
	defer func() {
		t.Logf("SRCI-06: байтовые колонки после (не утверждается, В1): прежний admin %v, прежний viewer %v",
			w.countInBytea(subj.oldAdmin), w.countInBytea(subj.oldViewer))
	}()

	w.subj.requireSubject(t, "SRCI-06")
	for role, id := range map[string]string{"admin": domain.SystemAdminRoleID, "viewer": domain.SystemViewerRoleID} {
		require.Emptyf(t, w.countWith(w.tables(true), id), "НЕ-ВЫПОЛНИЛОСЬ(фикстура) SRCI-06: новый id %s в базе до наката", role)
	}
	w.up("SRCI-06")

	for role, pair := range map[string][2]string{
		"admin":  {subj.oldAdmin, domain.SystemAdminRoleID},
		"viewer": {subj.oldViewer, domain.SystemViewerRoleID},
	} {
		assert.Emptyf(t, w.countWith(tables, pair[0]), "SRCI-06: строки с прежним id %s после наката", role)
		assert.Equalf(t, oldBefore[role], w.countWith(tables, pair[1]), "SRCI-06: строки с новым id %s — по таблицам", role)
	}
	assert.Equal(t, journalBefore, w.journalUpTo(s0), "SRCI-06: строки ленты до наката изменены")
	appended := w.journalAfter(s0)
	for role, pair := range map[string][2]string{
		"admin":  {subj.oldAdmin, domain.SystemAdminRoleID},
		"viewer": {subj.oldViewer, domain.SystemViewerRoleID},
	} {
		var withOld, withNew int
		for _, e := range appended {
			if strings.Contains(e.rowContent, pair[0]) {
				withOld++
			}
			if strings.Contains(e.rowContent, pair[1]) {
				withNew++
			}
		}
		assert.Equalf(t, jOld[role]+withOld, w.countWith(journal, pair[0])[journal[0]], "SRCI-06: лента, прежний id %s", role)
		assert.Equalf(t, withNew, w.countWith(journal, pair[1])[journal[0]], "SRCI-06: лента, новый id %s", role)
	}
}

// pollChanges — опрос `PollSubjectChanges` с курсора.
func (w *srciWorld) pollChanges(since int64, why string) *iamv1.PollSubjectChangesResponse {
	w.t.Helper()
	resp, err := w.iiam.PollSubjectChanges(w.ctx, &iamv1.PollSubjectChangesRequest{SinceId: since, Limit: 1000})
	require.NoErrorf(w.t, err, "%s: PollSubjectChanges", why)
	return resp
}

// SRCI-07 — миграция не выдаёт и не отзывает: опрос с курсора до наката пуст,
// очереди прав и смены субъекта не выросли; близнец SRCI-07б — выдача глаголом
// после наката даёт событие о субъекте.
func TestSystemRoleIDs_SRCI07_MigrationNeitherGrantsNorRevokes(t *testing.T) {
	subj := srciReadSubject(t)
	w := newSRCIWorldAt(t, subj.preceding())
	w.seedSRCI05()

	cursor := w.pollChanges(0, "НЕ-ВЫПОЛНИЛОСЬ(фикстура) SRCI-07: курсор до наката").GetHeadId()
	require.Positive(t, cursor, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): посев выдач оставил курсор смены субъекта на нуле")
	fga, sco := w.countRows("kaname.fga_outbox"), w.countRows("kaname.subject_change_outbox")

	w.subj.requireSubject(t, "SRCI-07")
	w.up("SRCI-07")

	assert.Empty(t, w.pollChanges(cursor, "SRCI-07").GetChanges(), "SRCI-07: опрос с курсора до наката отдал события")
	assert.Equal(t, fga, w.countRows("kaname.fga_outbox"), "SRCI-07: fga_outbox вырос")
	assert.Equal(t, sco, w.countRows("kaname.subject_change_outbox"), "SRCI-07: subject_change_outbox вырос")

	// Близнец SRCI-07б: выдача B3 (форма B2 редакции 3 — аккаунт A1, все объекты).
	w.createDone(asUser(w.ctx, w.k), &iamv1.CreateAccessBindingRequest{
		Subjects: []*iamv1.Subject{userSubject(w.u3)}, RoleId: domain.SystemViewerRoleID,
		ScopeType: "iam.account", ScopeId: string(w.a1), Target: allInScopeTarget(),
	}, "SRCI-07б: выдача B3")
	var about []string
	for _, c := range w.pollChanges(cursor, "SRCI-07б").GetChanges() {
		about = append(about, c.GetSubjectId())
	}
	assert.Contains(t, about, string(w.u3), "SRCI-07б: опрос с того же курсора не отдал события о U3")
}

// SRCI-08 — исключение суперпользователя следует за новым id; близнец SRCI-08б —
// новый id наблюдателя суперпользователем не признаётся.
func TestSystemRoleIDs_SRCI08_SuperuserExceptionFollowsTheNewID(t *testing.T) {
	w := newSRCIWorldAt(t, 0)
	const trunkRule = "GLOBAL scope requires names or labels selector for non-cluster-admin roles"

	before := w.opsCount()
	_, err := w.ab.Create(asUser(w.ctx, w.k), w.clusterAllInScope(domain.SystemViewerRoleID))
	requireSyncRefusal(t, err, codes.InvalidArgument, trunkRule, "SRCI-08б: роль наблюдателя на кластере")
	assert.Equal(t, before, w.opsCount(), "SRCI-08б: отказ отчеканил Operation")

	w.subj.requireSubject(t, "SRCI-08")
	id := w.createDone(asUser(w.ctx, w.k), w.clusterAllInScope(domain.SystemAdminRoleID), "SRCI-08: выдача system.admin")
	assert.Equal(t, domain.SystemAdminRoleID, w.getBinding(id).GetRoleId(), "SRCI-08: roleId выдачи — новый id")
}

// srciRoleEventsRule — правило SRCI-12 о событиях роли: последнее о «уходящем» id —
// DELETED, первое о «приходящем» — CREATED и DELETED о нём нет.
func srciRoleEventsRule(t *testing.T, ev []srciEvent, gone, came, why string) {
	t.Helper()
	var goneLast, cameFirst string
	cameDeleted := false
	for _, e := range ev {
		if e.kind != subscriptionjournal.KindRole {
			continue
		}
		switch e.id {
		case gone:
			goneLast = e.change
		case came:
			if cameFirst == "" {
				cameFirst = e.change
			}
			if e.change == "DELETED" {
				cameDeleted = true
			}
		}
	}
	assert.Equalf(t, "DELETED", goneLast, "%s: последнее событие о %s", why, gone)
	assert.Equalf(t, "CREATED", cameFirst, "%s: первое событие о %s", why, came)
	assert.Falsef(t, cameDeleted, "%s: DELETED о %s", why, came)
}

// srciBindingEvents — по выдаче: были ли UPDATED и CREATED/DELETED.
func srciBindingEvents(ev []srciEvent) (updated, createdOrDeleted map[string]bool) {
	updated, createdOrDeleted = map[string]bool{}, map[string]bool{}
	for _, e := range ev {
		if e.kind != subscriptionjournal.KindAccessBinding {
			continue
		}
		if e.change == "UPDATED" {
			updated[e.id] = true
		} else {
			createdOrDeleted[e.id] = true
		}
	}
	return updated, createdOrDeleted
}

// srciPairs — мультимножество пар «вид, id, изменение».
func srciPairs(ev []srciEvent) []string {
	out := make([]string, 0, len(ev))
	for _, e := range ev {
		out = append(out, e.kind+"|"+e.id+"|"+e.change)
	}
	sort.Strings(out)
	return out
}

// srciSchema — определения ограничений, триггеров и индексов схемы kaname.
func (w *srciWorld) srciSchema() []string {
	w.t.Helper()
	rows, err := w.pool.Query(w.ctx, `
		SELECT 'c ' || conrelid::regclass::text || ' ' || conname || ' ' || pg_get_constraintdef(oid)
		  FROM pg_constraint WHERE connamespace = 'kaname'::regnamespace
		UNION ALL
		SELECT 't ' || tgrelid::regclass::text || ' ' || pg_get_triggerdef(oid)
		  FROM pg_trigger WHERE NOT tgisinternal
		   AND tgrelid IN (SELECT oid FROM pg_class WHERE relnamespace = 'kaname'::regnamespace)
		UNION ALL
		SELECT 'i ' || indexdef FROM pg_indexes WHERE schemaname = 'kaname'`)
	require.NoError(w.t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		require.NoError(w.t, rows.Scan(&s))
		out = append(out, s)
	}
	require.NoError(w.t, rows.Err())
	sort.Strings(out)
	return out
}

// SRCI-10 — обратимость: откат возвращает полный срез, повторный накат даёт срез
// первого; лента только дописывается.
func TestSystemRoleIDs_SRCI10_MigrationIsReversible(t *testing.T) {
	subj := srciReadSubject(t)
	w := newSRCIWorldAt(t, subj.preceding())
	w.seedSRCI05()

	tables := w.tables(false)
	full0, schema0 := w.snapshot(tables), w.srciSchema()
	s0 := w.journalHead()
	journal0 := w.journalUpTo(s0)
	require.NotEmpty(t, w.countWith(tables, subj.oldAdmin), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): прежнего id admin в схеме нет")
	br := w.bindingsOnRoles(subj.oldAdmin, subj.oldViewer)
	require.NotEmpty(t, br, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): выдач на прежние id нет")

	w.subj.requireSubject(t, "SRCI-10")
	w.up("SRCI-10: первый накат")
	full1, s1 := w.snapshot(tables), w.journalHead()
	firstUp := w.journalAfter(s0)
	// Ключи, временно несущие `ON UPDATE CASCADE`, обязаны вернуться дословно уже
	// накатом, а не только откатом: иначе после наката навсегда осталась бы дорога
	// тихим переименованиям (замысел К3).
	assert.Equal(t, schema0, w.srciSchema(), "SRCI-10: схема после наката разошлась (ключи, триггеры, индексы)")

	w.down("SRCI-10")
	assert.Equal(t, full0, w.snapshot(tables), "SRCI-10: полный срез после отката разошёлся со срезом до наката")
	assert.Equal(t, schema0, w.srciSchema(), "SRCI-10: схема после отката разошлась (ключи, триггеры, индексы)")
	s2 := w.journalHead()
	downEv := w.journalAfter(s1)
	srciRoleEventsLastAfterDown(t, downEv, subj)
	updated, _ := srciBindingEvents(downEv)
	for _, id := range br {
		assert.Truef(t, updated[id], "SRCI-10: откат — нет UPDATED о выдаче %s", id)
	}

	w.up("SRCI-10: повторный накат")
	assert.Equal(t, schema0, w.srciSchema(), "SRCI-10: схема после повторного наката разошлась")
	assert.Equal(t, full1, w.snapshot(tables), "SRCI-10: срез повторного наката разошёлся с первым")
	assert.Equal(t, srciPairs(firstUp), srciPairs(w.journalAfter(s2)), "SRCI-10: события повторного наката разошлись с первым")
	assert.Equal(t, journal0, w.journalUpTo(s0), "SRCI-10: строки ленты до наката изменены")
}

// srciRoleEventsLastAfterDown — откат зеркально: о прежнем id последнее —
// CREATED либо UPDATED, о новом — DELETED.
func srciRoleEventsLastAfterDown(t *testing.T, ev []srciEvent, subj srciSubject) {
	t.Helper()
	last := map[string]string{}
	for _, e := range ev {
		if e.kind == subscriptionjournal.KindRole {
			last[e.id] = e.change
		}
	}
	for _, id := range []string{subj.oldAdmin, subj.oldViewer} {
		assert.Containsf(t, []string{"CREATED", "UPDATED"}, last[id], "SRCI-10: откат — последнее событие о прежнем id %s", id)
	}
	for _, id := range []string{domain.SystemAdminRoleID, domain.SystemViewerRoleID} {
		assert.Equalf(t, "DELETED", last[id], "SRCI-10: откат — последнее событие о новом id %s", id)
	}
}

// SRCI-10б — выдача, рождённая между накатом и откатом, откатом не теряется.
func TestSystemRoleIDs_SRCI10b_GrantMadeBetweenUpAndDownSurvives(t *testing.T) {
	subj := srciReadSubject(t)
	w := newSRCIWorldAt(t, subj.preceding())
	w.seedSRCI05()
	require.NotEmpty(t, w.bindingsOnRoles(subj.oldAdmin), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): выдачи на прежний id admin нет")

	w.subj.requireSubject(t, "SRCI-10б")
	w.up("SRCI-10б")
	b4 := w.createDone(asUser(w.ctx, w.k), w.clusterAllInScope(domain.SystemAdminRoleID), "SRCI-10б: выдача B4")
	s1 := w.journalHead()
	w.down("SRCI-10б")

	var role string
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT role_id FROM kaname.access_bindings WHERE id = $1`, b4).Scan(&role),
		"SRCI-10б: B4 после отката")
	assert.Equal(t, subj.oldAdmin, role, "SRCI-10б: roleId B4 после отката — прежний id admin")
	for _, id := range []string{domain.SystemAdminRoleID, domain.SystemViewerRoleID} {
		assert.Emptyf(t, w.countWith(w.tables(false), id), "SRCI-10б: строки с новым id %s после отката", id)
	}
	updated, _ := srciBindingEvents(w.journalAfter(s1))
	assert.True(t, updated[b4], "SRCI-10б: в ленте после отката нет UPDATED о B4")
}

// SRCI-11 — выдача, конкурирующая с миграцией: миграция фиксируется, каждая
// вставка либо зафиксирована и несёт новый id, либо отвергнута отсутствием роли.
func TestSystemRoleIDs_SRCI11_GrantRacingTheMigration(t *testing.T) {
	subj := srciReadSubject(t)
	w := newSRCIWorldAt(t, subj.preceding())
	w.seedSRCI05()
	before := map[string]bool{}
	for _, id := range w.bindingsOnRoles(subj.oldAdmin, subj.oldViewer) {
		before[id] = true
	}
	require.NotEmpty(t, before, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): выдач на прежние id нет")

	const n = 8
	for i := 0; i < n; i++ {
		w.racers = append(w.racers, mustSeedUser(t, w.ctx, w.pool, fmt.Sprintf("srcir%d", i)))
	}

	w.subj.requireSubject(t, "SRCI-11")

	type outcome struct {
		id         string
		err        error
		start, end time.Time
	}
	results := make([]outcome, n)
	var migErr error
	var migStart, migEnd time.Time
	gate := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(n + 1)
	go func() {
		defer wg.Done()
		<-gate
		migStart = time.Now()
		migErr = goose.UpTo(w.db, ".", w.subj.migration)
		migEnd = time.Now()
	}()
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			<-gate
			results[i].start = time.Now()
			results[i].id, results[i].err = w.insertOnRole(subj.oldAdmin)
			results[i].end = time.Now()
		}(i)
	}
	close(gate)
	wg.Wait()

	require.NoError(t, migErr, "SRCI-11: транзакция миграции отвергнута")
	overlapped := false
	for _, r := range results {
		if r.start.Before(migEnd) && r.end.After(migStart) {
			overlapped = true
		}
	}
	require.True(t, overlapped, "НЕ-ВЫПОЛНИЛОСЬ(условие гонки): ни одна вставка не пересеклась с миграцией по времени")
	committed := map[string]bool{}
	for i, r := range results {
		if r.err == nil {
			committed[r.id] = true
			continue
		}
		mapped := status.Convert(shared.MapRepoErr(r.err))
		assert.Equalf(t, codes.FailedPrecondition, mapped.Code(), "SRCI-11: вставка %d — отказ не «нет роли» (%v)", i, r.err)
	}
	t.Logf("SRCI-11: вставок %d, зафиксировано %d", n, len(committed))
	for _, id := range []string{subj.oldAdmin, subj.oldViewer} {
		assert.Emptyf(t, w.countWith(w.tables(false), id), "SRCI-11: строки с прежним id %s после фиксации", id)
	}
	newOnes := 0
	for _, id := range w.bindingsOnRoles(domain.SystemAdminRoleID) {
		if !before[id] {
			newOnes++
			assert.Truef(t, committed[id], "SRCI-11: выдача %s на новом id не из зафиксированных вставок", id)
		}
	}
	assert.Equal(t, len(committed), newOnes, "SRCI-11: зафиксированных вставок и новых выдач на новом id")
}

// insertOnRole — вставка выдачи U3 на роль писателем репозитория (одна транзакция).
func (w *srciWorld) insertOnRole(role string) (string, error) {
	wr, err := w.repo.Writer(w.ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = wr.Rollback(w.ctx) }()
	b := domain.AccessBinding{
		ID:          domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)),
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(mustSeedUserNoT(w)),
		RoleID: domain.RoleID(role), ResourceType: "cluster", ResourceID: domain.ClusterSingletonID,
		Scope: domain.ScopeCluster, Status: domain.AccessBindingStatusActive,
		Target: domain.AccessTarget{AllInScope: true},
	}
	if _, err := bindingset.Insert(w.ctx, wr.AccessBindingsW(), b); err != nil {
		return "", err
	}
	return string(b.ID), wr.Commit(w.ctx)
}

// mustSeedUserNoT — получатель вставки SRCI-11. Выдача на кластер со «всей
// областью» уникальна по субъекту и роли, поэтому у каждой вставки свой субъект;
// посев идёт до старта гонки, здесь берётся из запаса.
func mustSeedUserNoT(w *srciWorld) domain.UserID {
	w.racersMu.Lock()
	defer w.racersMu.Unlock()
	u := w.racers[0]
	w.racers = w.racers[1:]
	return u
}

// SRCI-12 — лента подписки сообщает о смене id; близнец SRCI-12б — B5 на роли
// вне предмета событий не получает.
func TestSystemRoleIDs_SRCI12_SubscriptionJournalTellsOfTheNewIDs(t *testing.T) {
	subj := srciReadSubject(t)
	w := newSRCIWorldAt(t, subj.preceding())
	w.seedSRCI05()
	r0 := seedRulesRoleWithSelectors(t, w.ctx, w.repo, w.a1, "srci_r0",
		domain.Rules{{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}}})
	b5 := w.seedBinding(domain.AccessBinding{
		SubjectType: domain.SubjectTypeGroup, SubjectID: domain.SubjectID(w.g1),
		RoleID: r0, ResourceType: "account", ResourceID: string(w.a1), Scope: domain.ScopeAccount,
		Target: domain.AccessTarget{AllInScope: true},
	}, "B5")

	s0 := w.journalHead()
	br := w.bindingsOnRoles(subj.oldAdmin, subj.oldViewer)
	t.Logf("SRCI-12: позиция S0 %d, выдач на прежние id (BR) %d", s0, len(br))
	require.NotEmpty(t, br, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): перечень BR пуст")
	require.Contains(t, br, w.b1, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): B1 в BR")
	require.Contains(t, br, w.b2, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): B2 в BR")
	require.Contains(t, br, w.b6, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): B6 в BR")

	w.subj.requireSubject(t, "SRCI-12")
	w.up("SRCI-12")

	ev := w.journalAfter(s0)
	srciRoleEventsRule(t, ev, subj.oldAdmin, domain.SystemAdminRoleID, "SRCI-12 admin")
	srciRoleEventsRule(t, ev, subj.oldViewer, domain.SystemViewerRoleID, "SRCI-12 viewer")
	updated, createdOrDeleted := srciBindingEvents(ev)
	for _, id := range br {
		assert.Truef(t, updated[id], "SRCI-12: нет UPDATED о выдаче %s", id)
		assert.Falsef(t, createdOrDeleted[id], "SRCI-12: CREATED/DELETED о выдаче %s", id)
	}
	allowed := map[string]bool{
		subscriptionjournal.KindRole + "|" + subj.oldAdmin:             true,
		subscriptionjournal.KindRole + "|" + subj.oldViewer:            true,
		subscriptionjournal.KindRole + "|" + domain.SystemAdminRoleID:  true,
		subscriptionjournal.KindRole + "|" + domain.SystemViewerRoleID: true,
	}
	for _, id := range br {
		allowed[subscriptionjournal.KindAccessBinding+"|"+id] = true
	}
	for _, e := range ev {
		assert.Truef(t, allowed[e.kind+"|"+e.id], "SRCI-12: событие о посторонней паре %s|%s", e.kind, e.id)
	}
	assert.False(t, updated[b5], "SRCI-12б: событие о B5 — выдаче на роль вне предмета")
	assert.True(t, updated[w.b2], "SRCI-12б: нет события о B2")

	// Подписчик, перечитавший предметы, получает состояние SRCI-03/-04/-05.
	_, err := w.roles.Get(asUser(w.ctx, w.k), &iamv1.GetRoleRequest{RoleId: subj.oldAdmin})
	assert.Equal(t, codes.NotFound, status.Code(err), "SRCI-12: перечитанный прежний id admin")
	for _, id := range []string{domain.SystemAdminRoleID, domain.SystemViewerRoleID} {
		_, err := w.roles.Get(asUser(w.ctx, w.k), &iamv1.GetRoleRequest{RoleId: id})
		assert.NoErrorf(t, err, "SRCI-12: перечитанный новый id %s", id)
	}
	for _, id := range br {
		assert.Containsf(t, []string{domain.SystemAdminRoleID, domain.SystemViewerRoleID}, w.getBinding(id).GetRoleId(),
			"SRCI-12: перечитанная выдача %s", id)
	}
}
