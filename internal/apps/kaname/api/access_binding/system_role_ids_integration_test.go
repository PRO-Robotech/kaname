// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// system_role_ids_integration_test.go — сценарии SRCI-01…08, SRCI-10…12 приёмки
// docs/engineering/acceptance/system-roles-carry-canonical-ids.md (kaname#543).
// Сценарий ↔ одна функция `TestSystemRoleIDs_SRCI<NN>_<Суть>`; близнец — в той же
// функции либо `…_SRCI<NN>b_…`. Номер SRCI-09 снят приёмкой и не используется.
//
// Порядок каждой пробы несущий: посев и его положительный контроль, затем
// `requireSubject` (есть ли миграция и новые id), затем предмет. Посев, сломанный
// до предмета, краснеет текстом «НЕ-ВЫПОЛНИЛОСЬ(фикстура)», а не «ИСПЫТУЕМОГО НЕТ».

import (
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

// srciCheckSnapshot — ответы Ч1–Ч4 с очищенным `checked_at` (условие ревью R1).
func (w *srciWorld) srciCheckSnapshot() []*iamv1.AuthorizeCheckResponse {
	w.t.Helper()
	var out []*iamv1.AuthorizeCheckResponse
	for _, q := range []struct {
		subject string
		verb    string
	}{
		{fmtSubject("user", string(w.u1)), "update"}, // Ч1
		{fmtSubject("user", string(w.u2)), "get"},    // Ч2
		{fmtSubject("user", string(w.u2)), "update"}, // Ч3
		{fmtSubject("user", string(w.u3)), "get"},    // Ч4
	} {
		resp, err := w.check(q.subject, q.verb, srciObj)
		require.NoErrorf(w.t, err, "Check(%s, %s)", q.subject, q.verb)
		c := proto.Clone(resp).(*iamv1.AuthorizeCheckResponse)
		c.CheckedAt = nil
		out = append(out, c)
	}
	return out
}

// srciRequireCheckColumn — срез обязан дать ровно столбец «ожидание» (Ч1 и Ч2 —
// разрешено, Ч3 и Ч4 — отказ): положительный контроль посева.
func srciRequireCheckColumn(t *testing.T, snap []*iamv1.AuthorizeCheckResponse, why string) {
	t.Helper()
	want := []bool{true, true, false, false}
	for i, r := range snap {
		require.Equalf(t, want[i], r.GetAllowed(), "%s: Ч%d (deny %v)", why, i+1, r.GetDenyReasons())
	}
}

// seedSRCI05Materialized — посев SRCI-05 и ожидание окна материализации Ч1, Ч2.
func (w *srciWorld) seedSRCI05Materialized() {
	w.seedSRCI05()
	w.pollCheck(fmtSubject("user", string(w.u1)), "update", srciObj, true,
		"НЕ-ВЫПОЛНИЛОСЬ(фикстура) SRCI-05 Ч1: B1 материализуется")
	w.pollCheck(fmtSubject("user", string(w.u2)), "get", srciObj, true,
		"НЕ-ВЫПОЛНИЛОСЬ(фикстура) SRCI-05 Ч2: B2 материализуется")
}

// SRCI-05 — выдачи работающей базы переходят на новые id без потери.
func TestSystemRoleIDs_SRCI05_GrantsCrossOverWithoutLoss(t *testing.T) {
	subj := srciReadSubject(t)
	w := newSRCIWorldAt(t, subj.preceding())
	w.seedSRCI05Materialized()

	before := w.srciCheckSnapshot()
	srciRequireCheckColumn(t, before, "НЕ-ВЫПОЛНИЛОСЬ(фикстура) SRCI-05 срез до")
	b1, b2 := w.getBinding(w.b1), w.getBinding(w.b2)
	require.Equal(t, w.roleIDByName(domain.SystemAdminRoleName), b1.GetRoleId(), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): B1 на прежнем id admin")
	require.Equal(t, w.roleIDByName(domain.SystemViewerRoleName), b2.GetRoleId(), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): B2 на прежнем id viewer")
	bindingsBefore := w.countRows("kaname.access_bindings")

	w.subj.requireSubject(t, "SRCI-05")
	w.up("SRCI-05")

	for _, c := range []struct {
		before *iamv1.AccessBinding
		role   string
	}{{b1, domain.SystemAdminRoleID}, {b2, domain.SystemViewerRoleID}} {
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
	list, err := w.ab.ListByRole(asUser(w.ctx, w.k), &iamv1.ListAccessBindingsByRoleRequest{RoleId: domain.SystemAdminRoleID, PageSize: 1000})
	require.NoError(t, err, "SRCI-05: listByRole")
	var listed []string
	for _, b := range list.GetAccessBindings() {
		listed = append(listed, b.GetId())
	}
	assert.Contains(t, listed, w.b1, "SRCI-05: listByRole нового id admin отдаёт B1")
	assert.Equal(t, bindingsBefore, w.countRows("kaname.access_bindings"), "SRCI-05: число выдач")
}

// SRCI-06 — ни одна строка базы, кроме ленты подписки, не сохраняет прежний id;
// лента дописывается, прежние её строки не меняются.
func TestSystemRoleIDs_SRCI06_NoRowKeepsTheOldID(t *testing.T) {
	subj := srciReadSubject(t)
	w := newSRCIWorldAt(t, subj.preceding())
	w.seedSRCI05Materialized()

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
func (w *srciWorld) pollChanges(since int64) *iamv1.PollSubjectChangesResponse {
	w.t.Helper()
	resp, err := w.iiam.PollSubjectChanges(w.ctx, &iamv1.PollSubjectChangesRequest{SinceId: since, Limit: 1000})
	require.NoError(w.t, err, "PollSubjectChanges")
	return resp
}

// SRCI-07 — миграция не выдаёт и не отзывает: опрос с курсора до наката пуст,
// очереди прав и смены субъекта не выросли; близнец SRCI-07б — выдача глаголом
// после наката даёт событие о субъекте.
func TestSystemRoleIDs_SRCI07_MigrationNeitherGrantsNorRevokes(t *testing.T) {
	subj := srciReadSubject(t)
	w := newSRCIWorldAt(t, subj.preceding())
	w.seedSRCI05Materialized()

	cursor := w.pollChanges(0).GetHeadId()
	require.Positive(t, cursor, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): посев выдач оставил курсор смены субъекта на нуле")
	fga, sco := w.countRows("kaname.fga_outbox"), w.countRows("kaname.subject_change_outbox")

	w.subj.requireSubject(t, "SRCI-07")
	w.up("SRCI-07")

	assert.Empty(t, w.pollChanges(cursor).GetChanges(), "SRCI-07: опрос с курсора до наката отдал события")
	assert.Equal(t, fga, w.countRows("kaname.fga_outbox"), "SRCI-07: fga_outbox вырос")
	assert.Equal(t, sco, w.countRows("kaname.subject_change_outbox"), "SRCI-07: subject_change_outbox вырос")

	// Близнец SRCI-07б: выдача B3 (форма B2, условие ревью R2 — цель формой провода).
	w.createDone(asUser(w.ctx, w.k), &iamv1.CreateAccessBindingRequest{
		Subjects: []*iamv1.Subject{userSubject(w.u3)}, RoleId: domain.SystemViewerRoleID,
		ScopeType: "iam.account", ScopeId: string(w.a1),
		Target: resourcesTarget(&iamv1.ResourceRef{Type: scTargetType, Id: srciObj}),
	}, "SRCI-07б: выдача B3")
	var about []string
	for _, c := range w.pollChanges(cursor).GetChanges() {
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
	w.seedSRCI05Materialized()

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
	w.seedSRCI05Materialized()
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
	w.seedSRCI05Materialized()
	before := map[string]bool{}
	for _, id := range w.bindingsOnRoles(subj.oldAdmin, subj.oldViewer) {
		before[id] = true
	}
	require.NotEmpty(t, before, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): выдач на прежние id нет")

	const n = 8
	for i := 0; i < n; i++ {
		w.racers = append(w.racers, mustSeedUser(t, w.ctx, w.pool, "srcir"))
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
	w.seedSRCI05Materialized()
	r0 := seedRulesRoleWithSelectors(t, w.ctx, w.repo, w.a1, "srci_r0",
		domain.Rules{{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}}})
	b5 := w.seedBinding(domain.AccessBinding{
		SubjectType: domain.SubjectTypeGroup, SubjectID: domain.SubjectID(w.g1),
		RoleID: r0, ResourceType: "account", ResourceID: string(w.a1), Scope: domain.ScopeAccount,
		Target: domain.AccessTarget{Resources: []domain.ResourceRef{{Type: scTargetType, ID: srciObj}}},
	}, "B5")

	s0 := w.journalHead()
	br := w.bindingsOnRoles(subj.oldAdmin, subj.oldViewer)
	t.Logf("SRCI-12: позиция S0 %d, выдач на прежние id (BR) %d", s0, len(br))
	require.NotEmpty(t, br, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): перечень BR пуст")
	require.Contains(t, br, w.b1, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): B1 в BR")
	require.Contains(t, br, w.b2, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): B2 в BR")

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
		subscriptionjournal.KindRole + "|" + subj.oldAdmin:            true,
		subscriptionjournal.KindRole + "|" + subj.oldViewer:           true,
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
