// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmap_test

// module_set_drift_test.go — набор модулей платформы: ПИН состава и сверка с
// объявлением написаний.
//
// # Что здесь было и почему половина утверждений СНЯТА ВМЕСТЕ С ПРЕДМЕТОМ
//
// Прежняя редакция сверяла ДВА объявления набора: приставки ключей
// `objectTypes` и литерал домена `knownModules`. Литерал снят задачей #1927 —
// набор выводится из тех же ключей одним производителем
// (`CatalogSeedModules`), — и обе стороны сверки стали одной. Оставить её как
// есть было нельзя: `domain.IsKnownModule` перестал существовать, и утверждения
// (1) и (2) не «ослабли», а лишились ВХОДА, продолжая выглядеть работающими
// (`testing.md` §«Гейт на класс», п. 9).
//
// # Что осталось и почему это не пустая проба
//
// Дрейф между приставками и производителем невозможен by construction, поэтому
// утверждать о нём нечего. Но набор по-прежнему объявлен в ДВУХ независимых
// местах дерева, и второе — не домен, а `pkg/platformmodules`: там у каждого
// модуля платформы записан домен типов объекта, и модуль с НЕПУСТЫМ доменом по
// определению обязан иметь грантуемые пары, а с пустым — не иметь ни одной.
// Эти два места ничем не связаны, растут порознь и разойдутся молча — их
// сверка и есть предмет пробы.
//
// Плюс ПИН точного состава: он даёт читаемый отказ, когда набор изменился, и
// заставляет назвать изменение решением, а не побочным эффектом правки таблицы
// типов.

import (
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/pkg/platformmodules"
)

// TestModuleSet_PinnedComposition — ПИН точного состава набора.
//
// Набор закрыт, растёт решением и попадает в клиентские поверхности (перечни
// модулей в документации и в комментариях контракта, гейт
// `internal/repohygiene` `TestClientTruthIAMModuleSet`). Изменение состава
// обязано ронять эту пробу, а не проезжать вместе с новой строкой `objectTypes`.
func TestModuleSet_PinnedComposition(t *testing.T) {
	got := authzmap.CatalogSeedModules()
	want := []string{"compute", "iam", "loadbalancer", "registry", "storage", "vpc"}

	t.Logf("перепись: модулей выведено %d (%s); грантуемых пар %d",
		len(got), strings.Join(got, ", "), len(authzmap.Catalog()))

	if len(got) == 0 {
		t.Fatal("набор пуст — обход беспредметен: «сошлось» здесь неотличимо от «не прочитано»")
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("набор модулей = %v, ожидался %v — состав изменился; "+
			"это решение, и оно обязано быть названо, а не проехать с новой строкой objectTypes",
			got, want)
	}
}

// TestModuleSet_MatchesTheSpellingDeclaration — сверка с `pkg/platformmodules`.
//
// Утверждается РАВЕНСТВО двух множеств, а не включение одного в другое:
// одностороннее сравнение молчало бы ровно на том исходе, ради которого сверка
// и заведена, — модуль объявил домен типов, а грантуемых пар у него ни одной
// (правило его назвать можно, а резолвиться оно не будет ничем).
func TestModuleSet_MatchesTheSpellingDeclaration(t *testing.T) {
	catalogSide := authzmap.CatalogSeedModules()

	var spellingSide []string
	for _, m := range platformmodules.All() {
		if m.ObjectDomain == "" {
			// Пустой домен — не «неизвестно», а «модель не объявляет ни одного
			// типа этого модуля» (так у geo). Такой модуль грантуемых пар не
			// имеет by construction и в наборе стоять не должен.
			continue
		}
		spellingSide = append(spellingSide, m.CatalogModule)
	}
	sort.Strings(spellingSide)

	t.Logf("перепись: сторона каталога %d (%s); сторона написаний %d (%s), "+
		"всего объявлено служб %d",
		len(catalogSide), strings.Join(catalogSide, ", "),
		len(spellingSide), strings.Join(spellingSide, ", "),
		len(platformmodules.All()))

	if len(catalogSide) == 0 || len(spellingSide) == 0 {
		t.Fatalf("одна из сторон пуста (%d и %d) — сверять нечего",
			len(catalogSide), len(spellingSide))
	}
	if strings.Join(catalogSide, ",") != strings.Join(spellingSide, ",") {
		t.Errorf("два объявления набора разошлись:\n"+
			"  грантуемые пары дают %v\n"+
			"  объявление написаний дало %v\n"+
			"модуль, стоящий только в первом, не имеет короткого имени службы и "+
			"домена типов; стоящий только во втором обещает грантуемые пары, "+
			"которых нет", catalogSide, spellingSide)
	}
}
