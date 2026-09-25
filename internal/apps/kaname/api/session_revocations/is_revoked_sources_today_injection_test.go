// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_revocations

// is_revoked_sources_today_injection_test.go — опыт: гейт перечня источников
// «сегодня» способен упасть по каждой стороне и способен смолчать.
//
// Перечень берётся из дерева; инъекция и её законный близнец отличаются ровно
// одним фактом — числом вызовов писателя записи выпуска при том же перечне.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// familyItem — пункт перечня, называющий отзыв семейства.
const familyItem = "  - Revocation of a token family of the service's own authorization ceremony."

// treeListWithFamily и treeListWithoutFamily — перечень дерева с пунктом о
// семействе и без упоминания семейства.
func treeListWithFamily(tree sourcesTodayFacts) string {
	return tree.List + "\n" + familyItem
}

func treeListWithoutFamily(tree sourcesTodayFacts) string {
	return sourceMarker[sourceFamily].ReplaceAllString(tree.List, "row")
}

// TestSourcesTodayGate_FallsOnEachSide — порча по одному факту.
func TestSourcesTodayGate_FallsOnEachSide(t *testing.T) {
	tree, _ := treeSourcesToday(t)

	t.Run("семейство в перечне, писатель не позван", func(t *testing.T) {
		found := auditSourcesToday(sourcesTodayFacts{WriterCalls: 0, List: treeListWithFamily(tree)})
		require.Len(t, found, 1)
		require.Contains(t, found[0], issuanceWriter)
		require.Contains(t, found[0], "не зовёт ни один не-тестовый вызов")
	})

	t.Run("писатель позван, семейства в перечне нет", func(t *testing.T) {
		found := auditSourcesToday(sourcesTodayFacts{WriterCalls: 1, List: treeListWithoutFamily(tree)})
		require.Len(t, found, 1)
		require.Contains(t, found[0], "пережила свой предмет")
	})

	// Ось сборки: факт один — оговорка о несобранной церемонии в перечне.
	t.Run("писатель вне собираемого корнем, оговорки нет", func(t *testing.T) {
		found := auditSourcesToday(sourcesTodayFacts{WriterCalls: 1, List: treeListWithoutCaveat(tree)})
		require.Len(t, found, 1)
		require.Contains(t, found[0], serviceRoot)
		require.Contains(t, found[0], "оговорки о несобранной церемонии нет")
	})

	t.Run("писатель в собираемом корнем, оговорка осталась", func(t *testing.T) {
		found := auditSourcesToday(sourcesTodayFacts{WriterCalls: 1, WriterMounted: true, List: treeListWithFamily(tree)})
		require.Len(t, found, 1)
		require.Contains(t, found[0], serviceRoot)
		require.Contains(t, found[0], "оговорка о несобранной церемонии пережила свой предмет")
	})
}

// treeListWithoutCaveat — перечень дерева без оговорки о несобранной
// церемонии; семейство в нём названо по-прежнему.
func treeListWithoutCaveat(tree sourcesTodayFacts) string {
	return unmountedCaveat.ReplaceAllString(tree.List, "mounted")
}

// TestSourcesTodayGate_TreeCarriesTheCaveatItIsJudgedBy — предпосылка оси
// сборки: оговорка в перечне дерева распознаётся, а её снятие — нет. Иначе
// инъекция «оговорки нет» совпала бы с деревом и ничего бы не доказала.
func TestSourcesTodayGate_TreeCarriesTheCaveatItIsJudgedBy(t *testing.T) {
	tree, _ := treeSourcesToday(t)
	require.True(t, unmountedCaveat.MatchString(tree.List), "в перечне дерева не распознана оговорка о несобранной церемонии")
	require.False(t, unmountedCaveat.MatchString(treeListWithoutCaveat(tree)), "снятая оговорка распознаётся по-прежнему")
	require.True(t, sourceMarker[sourceFamily].MatchString(treeListWithoutCaveat(tree)),
		"снятие оговорки унесло с собой семейство — инъекция меняет два факта")
}

// TestSourcesTodayGate_SilentOnTwins — законные близнецы.
func TestSourcesTodayGate_SilentOnTwins(t *testing.T) {
	tree, _ := treeSourcesToday(t)

	t.Run("дерево", func(t *testing.T) {
		require.Empty(t, auditSourcesToday(tree),
			"гейт находит нарушение на согласном дереве — он ловит форму, а не существо")
	})
	t.Run("писатель позван, семейство в перечне", func(t *testing.T) {
		require.Empty(t, auditSourcesToday(sourcesTodayFacts{WriterCalls: 1, List: treeListWithFamily(tree)}))
	})
	t.Run("писатель не позван, семейства в перечне нет", func(t *testing.T) {
		require.Empty(t, auditSourcesToday(sourcesTodayFacts{WriterCalls: 0, List: treeListWithoutFamily(tree)}))
	})
	t.Run("писатель в собираемом корнем, оговорки нет", func(t *testing.T) {
		require.Empty(t, auditSourcesToday(sourcesTodayFacts{WriterCalls: 1, WriterMounted: true, List: treeListWithoutCaveat(tree)}))
	})
}

// TestSourcesTodayGate_ListEndsAtTheFirstBlankLine — перечень кончается первой
// пустой строкой: семейство, названное абзацем ниже, в перечень не входит, а
// текст без заголовка перечня — «не прочитано», а не «перечень пуст».
func TestSourcesTodayGate_ListEndsAtTheFirstBlankLine(t *testing.T) {
	service := strings.Join([]string{
		"Service header.",
		"",
		producedTodayHeading,
		"  - User-initiated logout.",
		"",
		"Revocation of a token family is not produced at this revision.",
	}, "\n")

	list, ok := producedTodayList(service)
	require.True(t, ok)
	require.Equal(t, "  - User-initiated logout.", list)
	require.False(t, sourceMarker[sourceFamily].MatchString(list),
		"абзац после перечня засчитан за пункт перечня")

	_, ok = producedTodayList(strings.Replace(service, producedTodayHeading, "Revocation sources:", 1))
	require.False(t, ok, "текст без заголовка перечня прочитан как перечень")
}

// TestSourcesTodayGate_ImportClosureFollowsTransitiveEdges — замыкание судит
// рёбра, а не соседство: пакет за промежуточным достижим, а тот же пакет без
// ребра к нему — нет.
func TestSourcesTodayGate_ImportClosureFollowsTransitiveEdges(t *testing.T) {
	const port = "internal/ceremonyport"
	graph := map[string]map[string]bool{
		serviceRoot:            {"internal/composition": true},
		"internal/composition": {port: true},
		port:                   {"internal/domain": true},
	}
	require.True(t, importClosure(graph, serviceRoot)[port], "пакет за промежуточным не засчитан собранным")
	require.True(t, importClosure(graph, serviceRoot)["internal/domain"], "замыкание остановилось на втором шаге")

	delete(graph["internal/composition"], port)
	require.False(t, importClosure(graph, serviceRoot)[port], "пакет без ребра к нему засчитан собранным")
}
