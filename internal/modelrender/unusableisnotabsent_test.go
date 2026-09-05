// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modelrender_test

// unusableisnotabsent_test.go — негодный манифест не объявляется ОТСУТСТВУЮЩИМ
// (задача продукта #2045).
//
// # Предмет
//
// Шапка `findManifests` объявляет: документ, назвавшийся манифестом и манифестом
// не ставший, «не вправе быть засчитан НИ модулем, НИ его отсутствием». Первая
// половина исполнялась — в перечень найденных он не попадал, — вторая нет: цикл
// по модулям видел отсутствие ключа и объявлял модуль непокрытым.
//
// Цена та же, что у #1905, только на второй строке вывода: читатель идёт заводить
// манифест, который уже написан и лежит на месте.
//
// # Почему предмет отдельный от #1905
//
// Та задача чинила ТЕКСТ находки (причина вместо подставленной); эта меняет
// ПОВЕДЕНИЕ: негодный документ приписывается модулю, который он объявил, и вторая
// находка перестаёт производиться. Приписать его нечем было потому, что модуль
// берётся из РАЗОБРАННОЙ оболочки, а она не разобралась.
//
// # Обе стороны обязательны
//
// Документ, не объявивший модуля вовсе, приписать НЕ К ЧЕМУ — и тогда «модуль без
// манифеста» верно и обязано остаться. Без этой половины починка превратилась бы
// в замалчивание непокрытого модуля.

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho-iam/internal/modelrender"
)

// absentFindingFor — находка «модуль закрытого набора без манифеста» у названного
// модуля, либо пусто. Отбор по ПРИЗНАКУ, а не по позиции: перечень несёт соседние.
func absentFindingFor(findings []modelrender.Finding, module string) string {
	for _, f := range findings {
		if f.Module == module && strings.Contains(f.Detail, "без манифеста") {
			return f.Detail
		}
	}
	return ""
}

// unusableFindingFor — находка о негодном документе, либо пусто.
func unusableFindingFor(findings []modelrender.Finding) modelrender.Finding {
	for _, f := range findings {
		if strings.Contains(f.Detail, "манифестом и манифестом не стал") {
			return f
		}
	}
	return modelrender.Finding{}
}

// sweepWithManifest — обход дерева, где у `vpc` лежит названный документ, а
// остальные модули прощены ведомостью.
func sweepWithManifest(t *testing.T, body string) []modelrender.Finding {
	t.Helper()
	root := helperTree(t, twoBlockCanon)
	writeManifest(t, root, "vpc", body)
	_, findings, code := modelrender.Sweep(seed.LiteralRows().Resources, root, allWaivers("vpc"))
	if code != modelrender.SweepFinding {
		t.Fatalf("исход %d, ожидалась находка (%d)", code, modelrender.SweepFinding)
	}
	if len(findings) == 0 {
		t.Fatal("находок 0 при исходе «находка» — обход беспредметен, судить не по чему")
	}
	return findings
}

// TestUnusableManifestIsNotReportedAsAbsent — документ ОБЪЯВИЛ модуль и не
// разобрался: находка одна, и она называет причину негодности.
func TestUnusableManifestIsNotReportedAsAbsent(t *testing.T) {
	// Модуль объявлен строкой; отвергает документ загрузчик, а не разбор YAML,
	// поэтому оболочка читается и приписать документ ЕСТЬ К ЧЕМУ.
	findings := sweepWithManifest(t, "apiVersion: iam/v1\nmodule: vpc\nresources:\n"+
		"  - name: network\n    objectType: vpc_network\n    parents: [project]\n"+
		"    producer: derived\n    verbs:\n      - addCidrBlocks\n")

	t.Logf("объём осмотренного: находок %d", len(findings))

	if d := absentFindingFor(findings, "vpc"); d != "" {
		t.Errorf("модуль vpc объявлен непокрытым, а его манифест ЛЕЖИТ НА МЕСТЕ и просто "+
			"не разобран — читатель идёт заводить документ, который уже написан:\n  %s", d)
	}

	u := unusableFindingFor(findings)
	if u.Detail == "" {
		t.Fatal("находки о негодном документе нет вовсе — вторая половина утверждения " +
			"проверялась бы на пустом месте")
	}
	if u.Module != "vpc" {
		t.Errorf("находка о негодном документе не приписана модулю (Module=%q), "+
			"а документ объявил `module: vpc`", u.Module)
	}
}

// TestManifestThatNamesNoModuleStaysAbsent — ЗАКОННЫЙ БЛИЗНЕЦ: документ модуля не
// объявил, приписать нечему, «модуль без манифеста» верно и обязано остаться.
func TestManifestThatNamesNoModuleStaysAbsent(t *testing.T) {
	// Негодно уже как YAML: оболочки нет вовсе, имени не даст ни один читатель.
	findings := sweepWithManifest(t, "apiVersion: iam/v1\nresources: [unclosed\n")

	t.Logf("объём осмотренного: находок %d", len(findings))

	if absentFindingFor(findings, "vpc") == "" {
		t.Errorf("модуль vpc не объявлен непокрытым, хотя документ модуля НЕ НАЗВАЛ — "+
			"починка выродилась бы в замалчивание непокрытого модуля: %v", findings)
	}
	if u := unusableFindingFor(findings); u.Detail == "" {
		t.Error("находки о негодном документе нет — обе находки обязаны стоять вместе")
	} else if u.Module != "" {
		t.Errorf("находка приписана модулю %q, хотя документ модуля не объявил: "+
			"приписывать нечему", u.Module)
	}
}
