// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// ledger_read_cost_test.go — стоимость страницы и полоса fail-closed у ДВУХ
// ведомостей, объясняющих потерю права: переселения (#1992) и вырезания (#1988).
//
// # Что было неверно (#2001)
//
// Ручки дублёра `wdCalls`/`wdFail` и `psCalls`/`psFail` были заведены вместе со
// своими читателями и не читались НИ ОДНИМ утверждением. Это класс «пишут и не
// читают», применённый к фикстуре, и он хуже отсутствия ручек: счётчик создаёт
// вид, что стоимость страницы под наблюдением, — следующий читатель пробы
// увидит его и заключит, что свойство закреплено.
//
// Закрепляются ровно два свойства, ради которых ручки и заводились:
//
//  1. ОДИН ВОПРОС НА СТРАНИЦУ. Стоимость обязана следовать странице, величина
//     которой ограничена контрактом, а не популяции ролей, которая не ограничена
//     ничем. Поролевой читатель даёт N вопросов на страницу из N ролей и на
//     четырёх ролях выглядит исправным;
//  2. FAIL-CLOSED. Отказ ведомости обязан ронять чтение, а не отдавать роль без
//     записей: «не смог прочитать» не есть «отобранного нет». Со стороны
//     арендатора проглоченный отказ неотличим от роли, у которой ничего не
//     отбирали, — то есть ровно от состояния, ради различения которого ведомость
//     и заведена.
//
// # Чем это НЕ является: третьего свойства соседа здесь нет НАМЕРЕННО
//
// У ведомости целости есть третья проба — «пустой странице вопрос не задаётся
// ВОВСЕ» (`IAMRH0114a`). Сюда она НЕ переносится, и это замер, а не пропуск:
// `attachIntegrity` спрашивает целость под условием `len(segments) > 0`, а обе
// ведомости — безусловно при `len(roles) > 0`. Роль без адресуемых сегментов
// (`*.*`) сегментов не даёт, но ролью быть не перестаёт, и отобранное у неё
// спросить надо. Перенеси я третью пробу сюда «для симметрии» — она утверждала
// бы о продукте то, чего он не делает и делать не должен.
//
// # Способность упасть доказана ИНЪЕКЦИЕЙ, а не прочтением
//
// Продукт оба свойства уже несёт, поэтому красного «по дефекту» здесь нет и быть
// не может: предмет проб — не починка, а наблюдение. Доказательство — в
// `ledger_read_cost_injection_test.go`: он подаёт поролевого читателя и
// проглоченный отказ ТЕМ ЖЕ утверждениям и требует от них красного, а на
// законном близнеце — молчания.
package role

import (
	stderrors "errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// pageOfFourRoles — общий вход обеих проб стоимости.
//
// Четыре роли, а не одна: на одной «вопрос один» и «вопрос на роль» дают ОДНО И
// ТО ЖЕ число, и утверждение зеленело бы у поролевого читателя.
func pageOfFourRoles(t *testing.T) *integrityHarness {
	t.Helper()
	h := newIntegrityHarness(t)
	for _, id := range []string{
		"rol000000000000000b1", "rol000000000000000b2",
		"rol000000000000000b3", "rol000000000000000b4",
	} {
		r := h.addCustomRole(id, ruleOn("vpc", "network", "get"))
		h.project(r, "vpc.network", "get")
	}
	return h
}

// TestRoleLedger_WithdrawnPageCostsOneCall — ведомость ПЕРЕСЕЛЕНИЯ: один вопрос
// на страницу.
func TestRoleLedger_WithdrawnPageCostsOneCall(t *testing.T) {
	h := pageOfFourRoles(t)
	h.wdCalls = 0

	rows, _, err := h.list()
	require.NoError(t, err)
	require.Len(t, rows, 4, "предпосылка пробы: страница обязана нести четыре роли, "+
		"иначе «вопрос один» неотличимо от «вопрос на роль»")
	require.Equal(t, 1, h.wdCalls,
		"страница из четырёх ролей обязана стоить ОДНУ выборку ведомости переселения, "+
			"а не одну на роль: стоимость обязана следовать СТРАНИЦЕ, величина которой "+
			"ограничена контрактом, а не популяции ролей, не ограниченной ничем")
}

// TestRoleLedger_PrunedPageCostsOneCall — ведомость ВЫРЕЗАНИЯ: один вопрос на
// страницу.
func TestRoleLedger_PrunedPageCostsOneCall(t *testing.T) {
	h := pageOfFourRoles(t)
	h.psCalls = 0

	rows, _, err := h.list()
	require.NoError(t, err)
	require.Len(t, rows, 4, "предпосылка пробы: страница обязана нести четыре роли")
	require.Equal(t, 1, h.psCalls,
		"страница из четырёх ролей обязана стоить ОДНУ выборку ведомости вырезания, "+
			"а не одну на роль")
}

// TestRoleLedger_WithdrawnFailureFailsTheRead — ведомость ПЕРЕСЕЛЕНИЯ:
// fail-closed на ОБОИХ чтениях.
//
// Оба, а не одно: читателя два (`Get` и `List`), они идут через одного
// помощника, и молчание одного из них здесь читалось бы как роль без отобранного.
func TestRoleLedger_WithdrawnFailureFailsTheRead(t *testing.T) {
	h := newIntegrityHarness(t)
	r := h.addCustomRole("rol00000000000000w01", ruleOn("vpc", "network", "get"))
	h.project(r, "vpc.network", "get")
	h.wdFail = stderrors.New("ведомость переселения недоступна")

	_, gerr := h.get(r)
	require.Error(t, gerr, "Get обязан отказать: «не смог прочитать ведомость» не есть "+
		"«отобранного нет» — проглоченный отказ отдал бы роль без записей, и со стороны "+
		"арендатора это неотличимо от роли, у которой ничего не отбирали")
	_, _, lerr := h.list()
	require.Error(t, lerr, "List обязан отказать по той же причине")
}

// TestRoleLedger_PrunedFailureFailsTheRead — ведомость ВЫРЕЗАНИЯ: fail-closed на
// обоих чтениях.
func TestRoleLedger_PrunedFailureFailsTheRead(t *testing.T) {
	h := newIntegrityHarness(t)
	r := h.addCustomRole("rol00000000000000p01", ruleOn("vpc", "network", "get"))
	h.project(r, "vpc.network", "get")
	h.psFail = stderrors.New("ведомость вырезания недоступна")

	_, gerr := h.get(r)
	require.Error(t, gerr, "Get обязан отказать по ведомости вырезания")
	_, _, lerr := h.list()
	require.Error(t, lerr, "List обязан отказать по той же причине")
}

// TestRoleLedger_LawfulTwinIsReadAndCarriesTheLedgers — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ
// к обеим полосам сразу.
//
// Без него четыре утверждения выше зеленели бы у читателя, отказывающего ВСЕГДА:
// два отказа не отличались бы от отказа всему. Контроль утверждает ТРИ вещи —
// чтение проходит, обе ведомости спрошены ровно по разу, и спрошенное доехало до
// роли; последнее отделяет «спросил» от «положил в ответ».
func TestRoleLedger_LawfulTwinIsReadAndCarriesTheLedgers(t *testing.T) {
	h := newIntegrityHarness(t)
	r := h.addCustomRole("rol00000000000000t01", ruleOn("vpc", "network", "get"))
	h.project(r, "vpc.network", "get")
	h.repo.withdrawn = map[string][]domain.WithdrawnGrant{
		r: {{ObjectType: "vpc.network", Verb: "get", Reason: "не объявлен манифестом"}},
	}
	h.repo.pruned = map[string][]domain.PrunedSelectorType{
		r: {{ObjectType: "vpc.network", Outcome: domain.SelectorPruneOutcomeShortened}},
	}
	h.wdCalls, h.psCalls = 0, 0

	got, gerr := h.get(r)
	require.NoError(t, gerr, "без отказа ведомостей чтение обязано проходить")
	require.Equal(t, 1, h.wdCalls, "ведомость переселения обязана быть спрошена ровно раз")
	require.Equal(t, 1, h.psCalls, "ведомость вырезания обязана быть спрошена ровно раз")
	require.Len(t, got.Withdrawn, 1,
		"спрошенное обязано ДОЕХАТЬ до роли: «спросил» и «положил в ответ» — разные факты")
	require.Len(t, got.PrunedSelectorTypes, 1, "то же для ведомости вырезания")
}
