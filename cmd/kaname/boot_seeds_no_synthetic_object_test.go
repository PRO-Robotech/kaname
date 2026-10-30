// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// boot_seeds_no_synthetic_object_test.go — ПРОД-КОД НЕ НЕСЁТ ДЫМОВОЙ ПРОБЫ,
// ЗАВОДЯЩЕЙ СИНТЕТИЧЕСКИЙ ОБЪЕКТ В БОЕВОМ ЗЕРКАЛЕ (#119, #148).
//
// # Что наблюдалось
//
// Загрузочная дымовая проба прямого пути заводила внутри настоящего аккаунта
// объект ЧУЖОГО домена, сводила его, проверяла ведомость и снимала строку
// зеркала — но не строки ведомости, которые сама и вызвала. Следующий отчёт
// честно находил материализованное чтение на объекте, которого больше нет, и
// печатал на исправной установке отказ о СОБСТВЕННОЙ синтетике.
//
// #119 снял вызов из композиционного корня, но механизм остался в прод-дереве:
// метод стража, его спецификация, три метода порта и их реализации в адаптере,
// и звали их ТОЛЬКО пробы (#148). Прод-поверхность, чей единственный
// потребитель — проба, и которая пишет синтетику в боевую таблицу, — та же
// беда, отложенная до первого, кто её снова позовёт.
//
// # Почему гейт по ДЕРЕВУ, а не проба поведения
//
// Свойство отрицательное: «прод-код этого НЕ делает». Проба поведения на
// снятом механизме молчит тождественно. Гейт судит состав не-тестового дерева
// и краснеет на возвращении механизма под любым из его имён.
//
// # Почему узел разбора, а не подстрока
//
// Прежняя редакция искала подстроку «имя(» в композиционном корне. Она слепа к
// значению метода без вызова (`f := g.ForwardSmoke`), к объявлению типа и к
// порту; и краснела бы на собственной прозе, не отсекай она комментарии
// эвристикой. Идентификатор синтаксического дерева — ровно то, что компилятор
// свяжет: комментарий и строковый литерал им не являются по построению.
//
// # Что делать, если гейт покраснел
//
// Не снимать его. Дымовая проба — запись чужого домена в боевое зеркало и
// отчёт, который ничего не гейтит. Свойство, ради которого она стояла, покрыто
// интеграционно против настоящего сведения: селекторная полоса —
// `TestP8_05_VerifyGate_NoAccessLoss_ForwardMaterializes`,
// `TestReconcileForward_04_Backstop_FullConverges_NoDuplicate`,
// `TestC22_MatchLabels_PerObject_NoOverGrant`; владельческая —
// `Test224_OwnerWildcard_ForwardMaterializesContent`. Нужна снова — значит
// нужен разговор о том, что она пишет и кто читает её вердикт.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
)

// syntheticMirrorSmokeNames — имена, под которыми механизм жил в дереве.
// Перечислены ВСЕ: одного имени мало, снятый механизм вернулся бы под соседним.
var syntheticMirrorSmokeNames = map[string]bool{
	"RunBootForwardSmoke":        true,
	"SmokeOwnerBindingCandidate": true,
	"ForwardSmoke":               true,
	"ForwardSmokeSpec":           true,
	"fgaObjectForSmoke":          true,
	"SeedSmokeMirrorObject":      true,
	"RemoveSmokeMirrorObject":    true,
	"LedgerHasObject":            true,
}

// smokeCensus — объём осмотренного: без него «находок нет» неотличимо от
// «ничего не читали».
type smokeCensus struct {
	filesRead int
	nodesSeen int
}

// judgeSyntheticMirrorSmoke разбирает каждый НЕ-тестовый `.go` из files и
// возвращает координаты идентификаторов из перечня. Пустой обход — ошибка, а
// не пустой успех; неразборный файл — тоже ошибка: пропустить его значило бы
// объявить чистым то, чего не читали.
func judgeSyntheticMirrorSmoke(files []string) (smokeCensus, []string, error) {
	var (
		census   smokeCensus
		findings []string
	)
	fset := token.NewFileSet()
	for _, path := range files {
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			continue
		}
		// testdata инструмент Go не собирает: там законно лежат входы проб.
		if strings.Contains(filepath.ToSlash(path), "/testdata/") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return census, nil, fmt.Errorf("разбор %s: %w", path, err)
		}
		census.filesRead++
		ast.Inspect(file, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			census.nodesSeen++
			if syntheticMirrorSmokeNames[id.Name] {
				findings = append(findings, fmt.Sprintf("%s: %s", fset.Position(id.Pos()), id.Name))
			}
			return true
		})
	}
	if census.filesRead == 0 {
		return census, nil, fmt.Errorf("обход пуст: прочитано НОЛЬ не-тестовых файлов — " +
			"вердикт беспредметен, а «находок нет» неотличимо от «ничего не читали»")
	}
	sort.Strings(findings)
	return census, findings, nil
}

func TestProductionTreeCarriesNoSyntheticMirrorSmoke(t *testing.T) {
	root := iamServiceRoot(t)
	files, err := treecorpus.UnderWithSuffix(root, ".go")
	if err != nil {
		t.Fatalf("перечень файлов дерева: %v", err)
	}
	census, findings, err := judgeSyntheticMirrorSmoke(files)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("перепись: не-тестовых файлов прочитано %d, идентификаторов осмотрено %d, имён механизма %d",
		census.filesRead, census.nodesSeen, len(syntheticMirrorSmokeNames))

	if len(findings) > 0 {
		t.Fatalf("прод-дерево снова несёт дымовую пробу, заводящую синтетический объект "+
			"в боевом зеркале (#119, #148): находок %d\n%s", len(findings), strings.Join(findings, "\n"))
	}
}
