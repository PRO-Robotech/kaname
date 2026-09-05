// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package role

// integrity_test.go — целость роли заполняется ОДИНАКОВО в Get и в List.
//
// Приёмка `role-degradation-is-visible-in-get-and-list.md`, RED-шаг 2 (§9).
//
// # Почему здесь есть проба на СИСТЕМНУЮ роль, которой нет в §5 приёмки
//
// `GetRoleUseCase.Execute` имеет ДВА успешных возврата, и решение модели о
// видимости стоит только перед вторым: системная роль — пол каталога, она
// выходит РАНЬШЕ, не спрашивая модель вовсе. Помощник, поставленный «после
// резолва видимости», на этом пути не исполнился бы НИКОГДА.
//
// Цена этого промаха — ровно мимо предмета: двенадцать ролей инцидента 513001
// были СИСТЕМНЫМИ, и путь снятия каталога их не задевает (переселение
// ограничено `is_system = false`). То есть для системной роли форма 513001 —
// единственный путь к деградации, и он же единственный, который такая
// расстановка глушит. Найдено разбором замысла до кода.

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	reporole "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/role"
	"github.com/PRO-Robotech/kacho-iam/internal/testsupport/catalogfixture"
)

// ruleOn — правило с названными глаголами на одном точечном ресурсе.
func ruleOn(module, resource string, verbs ...string) domain.Rule {
	return domain.Rule{Module: module, Resources: []string{resource}, Verbs: verbs}
}

// integrityOf — тройка, которую наблюдает арендатор.
func integrityOf(r domain.Role) (domain.RoleHealth, int, int) {
	return r.Integrity.Health, r.Integrity.Declared, r.Integrity.Unresolved
}

// IAM-RH-1-09/10/11 — Get и List говорят одно, построчно.
func TestRoleIntegrity_IAMRH0109_0111_GetAndListAgreePerRow(t *testing.T) {
	h := newIntegrityHarness(t)
	healthy := h.addCustomRole("rol0000000000000hlth", ruleOn("vpc", "network", "get", "list"))
	h.project(healthy, "vpc.network", "get", "list")

	degraded := h.addCustomRole("rol0000000000000dgrd", ruleOn("vpc", "network", "get", "list"))
	h.project(degraded, "vpc.network", "get") // второй глагол не спроецирован

	empty := h.addCustomRole("rol0000000000000mpty", ruleOn("probe", "thing", "get"))
	// проекции нет вовсе — форма 513001

	for _, tc := range []struct {
		id         string
		wantHealth domain.RoleHealth
		declared   int
		unresolved int
	}{
		{healthy, domain.RoleHealthHealthy, 2, 0},   // IAM-RH-1-10, положительный контроль
		{degraded, domain.RoleHealthDegraded, 2, 1}, // IAM-RH-1-03
		{empty, domain.RoleHealthEmpty, 1, 1},       // IAM-RH-1-02
	} {
		got, err := h.get(tc.id)
		require.NoError(t, err, "Get %s", tc.id)
		gh, gd, gu := integrityOf(got)
		require.Equal(t, tc.wantHealth, gh, "Get %s: состояние", tc.id)
		require.Equal(t, tc.declared, gd, "Get %s: объявлено", tc.id)
		require.Equal(t, tc.unresolved, gu, "Get %s: неразрешённых", tc.id)

		lst := h.listRole(t, tc.id)
		lh, ld, lu := integrityOf(lst)
		require.Equal(t, gh, lh, "%s: List разошёлся с Get по состоянию", tc.id)
		require.Equal(t, gd, ld, "%s: List разошёлся с Get по объявленным", tc.id)
		require.Equal(t, gu, lu, "%s: List разошёлся с Get по неразрешённым", tc.id)
	}
}

// IAM-RH-1-17 — СИСТЕМНАЯ роль читается обоими путями одинаково.
//
// Эта проба КРАСНА на расстановке «помощник после резолва видимости»: `Get`
// вернул бы UNSPECIFIED (ранний возврат), `List` — EMPTY.
func TestRoleIntegrity_IAMRH0117_SystemRoleAgreesToo(t *testing.T) {
	h := newIntegrityHarness(t)
	sys := h.addSystemRole("rol0000000000000sys9", ruleOn("probe", "thing", "get"))
	// проекции нет — форма 513001 в её ИСХОДНОЙ популяции

	got, err := h.get(sys)
	require.NoError(t, err, "Get системной роли")
	gh, gd, gu := integrityOf(got)
	require.Equal(t, domain.RoleHealthEmpty, gh,
		"системная роль без проекции обязана читаться EMPTY; UNSPECIFIED означает, "+
			"что помощник не исполнился на раннем возврате Get")
	require.Equal(t, 1, gd)
	require.Equal(t, 1, gu)

	lst := h.listRole(t, sys)
	lh, ld, lu := integrityOf(lst)
	require.Equal(t, gh, lh, "системная роль: List разошёлся с Get по состоянию")
	require.Equal(t, gd, ld)
	require.Equal(t, gu, lu)
}

// IAM-RH-1-14 — страница стоит ОДНУ выборку, а не одну на роль.
func TestRoleIntegrity_IAMRH0114_PageCostsOneCall(t *testing.T) {
	h := newIntegrityHarness(t)
	for _, id := range []string{"rol000000000000000a1", "rol000000000000000a2", "rol000000000000000a3", "rol000000000000000a4"} {
		r := h.addCustomRole(id, ruleOn("vpc", "network", "get"))
		h.project(r, "vpc.network", "get")
	}
	h.calls = 0
	_, _, err := h.list()
	require.NoError(t, err)
	require.Equal(t, 1, h.calls,
		"страница из четырёх ролей обязана стоить ОДНУ выборку целости, а не одну на роль")
}

// IAM-RH-1-14а — пустой странице вопрос не задаётся ВОВСЕ.
func TestRoleIntegrity_IAMRH0114a_NothingToAskCostsZero(t *testing.T) {
	h := newIntegrityHarness(t)
	// роль без адресуемых сегментов: подстановка сегментов не даёт
	h.addSystemRole("rol0000000000000wild", domain.Rule{Module: "*", Resources: []string{"*"}, Verbs: []string{"*"}})
	h.calls = 0
	rows, _, err := h.list()
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, 0, h.calls,
		"спрашивать не о чем — значит не спрашивать: иначе каждая страница системного "+
			"каталога платит за вопрос, ответ на который известен заранее")
	gh, gd, gu := integrityOf(rows[0])
	require.Equal(t, domain.RoleHealthHealthy, gh, "роль `*.*` обязана быть здоровой, а не пустой")
	require.Equal(t, 0, gd)
	require.Equal(t, 0, gu)
}

// IAM-RH-1-15 — отказ выборки роняет чтение ЦЕЛИКОМ.
func TestRoleIntegrity_IAMRH0115_PortFailureFailsTheRead(t *testing.T) {
	h := newIntegrityHarness(t)
	r := h.addCustomRole("rol00000000000000x01", ruleOn("vpc", "network", "get"))
	h.project(r, "vpc.network", "get")
	h.fail = stderrors.New("проекция недоступна")

	_, gerr := h.get(r)
	require.Error(t, gerr, "Get обязан отказать: «не смог посчитать» не есть «здорова»")
	_, _, lerr := h.list()
	require.Error(t, lerr, "List обязан отказать по той же причине")
}

// IAM-RH-1-16 — положительный контроль к IAM-RH-1-15.
func TestRoleIntegrity_IAMRH0116_PortWorksThenReadSucceeds(t *testing.T) {
	h := newIntegrityHarness(t)
	r := h.addCustomRole("rol00000000000000y01", ruleOn("vpc", "network", "get"))
	h.project(r, "vpc.network", "get")

	got, gerr := h.get(r)
	require.NoError(t, gerr, "без отказа порта чтение обязано проходить")
	gh, _, _ := integrityOf(got)
	require.Equal(t, domain.RoleHealthHealthy, gh)
	rows, _, lerr := h.list()
	require.NoError(t, lerr)
	require.Len(t, rows, 1)
}

// listRole — строка страницы с названным идентификатором.
func (h *integrityHarness) listRole(t *testing.T, id string) domain.Role {
	t.Helper()
	rows, _, err := h.list()
	require.NoError(t, err)
	for _, r := range rows {
		if string(r.ID) == id {
			return r
		}
	}
	t.Fatalf("роль %s не найдена на странице", id)
	return domain.Role{}
}

var _ = context.Background
var _ reporole.ListFilter

// ───────────── харнесс: реальные use-case'ы над дублёром ─────────────

type integrityHarness struct {
	repo  *roleListFakeRepo
	fga   *roleFGAStub
	ctx   context.Context
	calls int
	fail  error
	// wdCalls / wdFail — та же пара, что `calls`/`fail`, но для ведомости
	// ПЕРЕСЕЛЕНИЯ; psCalls / psFail — для ведомости ВЫРЕЗАНИЯ.
	//
	// Ручки заведены здесь, а не у каждой пробы: единица стоимости и полоса
	// fail-closed у трёх ведомостей ОДНИ И ТЕ ЖЕ, и три харнесса разошлись бы
	// молча — ровно тем классом, который эти пробы и закрывают (#2001).
	wdCalls int
	wdFail  error
	psCalls int
	psFail  error
}

func newIntegrityHarness(t *testing.T) *integrityHarness {
	t.Helper()
	h := &integrityHarness{repo: newRoleListFakeRepo(), fga: newRoleFGAStub()}
	h.ctx = ctxUser("usr-u1")
	return h
}

// addCustomRole заводит пользовательскую роль и делает её видимой вызывающему.
func (h *integrityHarness) addCustomRole(id string, rules ...domain.Rule) string {
	h.repo.roles[id] = domain.Role{
		ID:        domain.RoleID(id),
		AccountID: domain.AccountID("acc-A000000000000000"),
		Name:      domain.RoleName(id),
		Rules:     domain.Rules(rules),
	}
	granted := make([]string, 0, len(h.repo.roles))
	for k, r := range h.repo.roles {
		if !r.IsSystem {
			granted = append(granted, k)
		}
	}
	h.fga.set("user:usr-u1", granted)
	return id
}

// addSystemRole заводит СИСТЕМНУЮ роль — пол каталога, видимый каждому без выдачи.
func (h *integrityHarness) addSystemRole(id string, rules ...domain.Rule) string {
	h.repo.roles[id] = domain.Role{
		ID:        domain.RoleID(id),
		ClusterID: domain.ClusterID("cluster_kacho_root"),
		IsSystem:  true,
		Name:      domain.RoleName(id),
		Rules:     domain.Rules(rules),
	}
	return id
}

// project кладёт строки проекции, которые читает вердикт.
func (h *integrityHarness) project(roleID, objectType string, verbs ...string) {
	for _, v := range verbs {
		h.repo.projected[roleID+"|"+objectType+"|"+v] = true
	}
}

func (h *integrityHarness) sync() {
	h.repo.segFail = h.fail
	h.repo.segCalls = h.calls
	h.repo.wdFail = h.wdFail
	h.repo.wdCalls = h.wdCalls
	h.repo.psFail = h.psFail
	h.repo.psCalls = h.psCalls
}

// readBack снимает счётчики ВСЕХ трёх ведомостей одним заходом.
//
// Порознь у каждого чтения они разъехались бы: пробе, читающей один счётчик,
// два других остались бы от прошлого прогона, и «вопрос один» зеленело бы на
// несброшенном счётчике.
func (h *integrityHarness) readBack() {
	h.calls = h.repo.segCalls
	h.wdCalls = h.repo.wdCalls
	h.psCalls = h.repo.psCalls
}

// withdraw кладёт строку ведомости переселения — то, чем платформа ОБЪЯСНЯЕТ
// потерю сегмента (#1962). Без неё та же потеря остаётся необъяснённой, и это
// РАЗНЫЕ состояния, а не оттенки одного.
func (h *integrityHarness) withdraw(roleID, objectType, verb, reason string) {
	if h.repo.withdrawn == nil {
		h.repo.withdrawn = map[string][]domain.WithdrawnGrant{}
	}
	h.repo.withdrawn[roleID] = append(h.repo.withdrawn[roleID], domain.WithdrawnGrant{
		ObjectType: objectType,
		Verb:       verb,
		Source:     domain.WithdrawnGrantSourceGrant,
		Reason:     reason,
	})
}

func (h *integrityHarness) get(id string) (domain.Role, error) {
	h.sync()
	uc := NewGetRoleUseCase(h.repo, catalogfixture.Source()).WithRelationStore(h.fga)
	out, err := uc.Execute(h.ctx, domain.RoleID(id))
	h.readBack()
	return out, err
}

func (h *integrityHarness) list() ([]domain.Role, string, error) {
	h.sync()
	uc := NewListRolesUseCase(h.repo, catalogfixture.Source()).WithRelationStore(h.fga)
	rows, next, err := uc.Execute(h.ctx, reporole.ListFilter{PageSize: 100})
	h.readBack()
	return rows, next, err
}
