// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_revocations

// is_revoked_doc_injection_test.go — опыт: способен ли гейт шапки упасть и
// способен ли он смолчать.
//
// Инъекция идёт по КАЖДОЙ оси отдельно. Одна общая проба «сломай что-нибудь»
// зеленела бы на гейте, у которого работает лишь одна половина: находка есть,
// а какая именно — не сказано.
//
// Вход берётся ИЗ ДЕРЕВА и портится по одной величине за раз. Полностью
// синтетический вход доказывал бы лишь то, что предикат различает две строки.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestIsRevokedDocGate_SilentOnTheTree — положительный контроль.
//
// Без него всякое отрицание ниже зеленело бы и на предикате, который находит
// нарушение всегда.
func TestIsRevokedDocGate_SilentOnTheTree(t *testing.T) {
	root := monorepoRootForDoc(t)
	callers, _, _ := isRevokedCallSites(t, root, true)
	facts := isRevokedDocFacts{
		Comments:        laneComments(t, root),
		CallerFiles:     callers,
		EdgeExportsRead: fileDeclaresMethod(t, root+"/"+edgeClientFile, edgeReadMethod),
	}
	require.Empty(t, auditIsRevokedDoc(facts),
		"гейт находит нарушение на исправном дереве — он ловит форму, а не существо")
}

// TestIsRevokedDocGate_FallsOnEachAxis — четыре порчи, каждая по одной величине.
func TestIsRevokedDocGate_FallsOnEachAxis(t *testing.T) {
	root := monorepoRootForDoc(t)
	callers, _, _ := isRevokedCallSites(t, root, true)
	comments := laneComments(t, root)
	edge := fileDeclaresMethod(t, root+"/"+edgeClientFile, edgeReadMethod)

	require.True(t, edge,
		"ПРЕДПОСЫЛКА ОПЫТА: клиент края обязан экспонировать %s — иначе оси про край "+
			"ниже поменялись бы местами, и опыт доказывал бы не то, что называет", edgeReadMethod)
	require.NotEmpty(t, callers, "ПРЕДПОСЫЛКА ОПЫТА: вызывающие обязаны быть найдены")

	t.Run("вызывающий появился, шапка молчит", func(t *testing.T) {
		// Дерево получило ещё одного вызывающего — число в шапке отстало.
		grown := append(append([]string(nil), callers...), "services/iam/internal/synthetic/caller.go")
		found := auditIsRevokedDoc(isRevokedDocFacts{Comments: comments, CallerFiles: grown, EdgeExportsRead: edge})
		requireFinding(t, found, "разбор дерева нашёл")
	})

	t.Run("вызывающий исчез, шапка держит прежнее число", func(t *testing.T) {
		shrunk := callers[:len(callers)-1]
		found := auditIsRevokedDoc(isRevokedDocFacts{Comments: comments, CallerFiles: shrunk, EdgeExportsRead: edge})
		requireFinding(t, found, "разбор дерева нашёл")
	})

	// Ровно исходный дефект #1156, и по КАЖДОМУ файлу набора отдельно: молчание
	// одного файла не должно прикрываться тем, что о крае сказал сосед.
	for _, rel := range laneFiles {
		t.Run("край читает, комментарий молчит: "+rel, func(t *testing.T) {
			silent := copyComments(comments)
			silent[rel] = strings.ReplaceAll(silent[rel], edgeReadMethod, "Revoke")
			require.NotEqualf(t, comments[rel], silent[rel],
				"ПРЕДПОСЫЛКА: в %s нечего было портить — файл не называет %s, и опыт "+
					"доказывал бы пустоту", rel, edgeReadMethod)
			found := auditIsRevokedDoc(isRevokedDocFacts{
				Comments: silent, CallerFiles: callers, EdgeExportsRead: edge})
			requireFinding(t, found, rel+": клиент края экспонирует")
		})
	}

	t.Run("край читать перестал, комментарии держат прежнее", func(t *testing.T) {
		found := auditIsRevokedDoc(isRevokedDocFacts{
			Comments: comments, CallerFiles: callers, EdgeExportsRead: false})
		requireFinding(t, found, "которого клиент края больше не экспонирует")
	})

	t.Run("маркер числа исчез", func(t *testing.T) {
		blind := copyComments(comments)
		for k, v := range blind {
			blind[k] = strings.ReplaceAll(v, "ВЫЗЫВАЮЩИХ В ПРОД-КОДЕ:", "вызывающих примерно")
		}
		found := auditIsRevokedDoc(isRevokedDocFacts{
			Comments: blind, CallerFiles: callers, EdgeExportsRead: edge})
		requireFinding(t, found, "встречается 0 раз(а)")
	})
}

// TestIsRevokedDocGate_ProdOnlyCensusIsNotVacuous — исключение проб и стабов
// обязано что-то ИСКЛЮЧАТЬ.
//
// Фильтр, который ничего не отсеивает, выглядит работающим и не работает: число
// в шапке совпало бы с полным составом, и первый же вызов из пробы читался бы
// как вызывающий на пути запроса.
func TestIsRevokedDocGate_ProdOnlyCensusIsNotVacuous(t *testing.T) {
	root := monorepoRootForDoc(t)
	prod, _, _ := isRevokedCallSites(t, root, true)
	all, _, _ := isRevokedCallSites(t, root, false)

	require.Greaterf(t, len(all), len(prod),
		"полный состав (%d) не шире прод-состава (%d) — исключение проб и сгенерённых стабов "+
			"перестало исключать, и перепись меряет не то", len(all), len(prod))

	for _, p := range prod {
		require.NotContainsf(t, p, "_test.go", "проба %q зачтена за вызывающего прод-кода", p)
		require.NotContainsf(t, p, "pkg/api/", "сгенерённый стаб %q зачтён за вызывающего прод-кода", p)
	}
	t.Logf("перепись: вызывающих всего %d, из них прод-кода %d", len(all), len(prod))
}

func copyComments(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func requireFinding(t *testing.T, found []string, want string) {
	t.Helper()
	require.NotEmptyf(t, found, "порча не найдена: гейт молчит там, где обязан назвать координату (%s)", want)
	require.Truef(t, strings.Contains(strings.Join(found, "\n"), want),
		"находка есть, но не та: ждали %q, получили %v", want, found)
}
