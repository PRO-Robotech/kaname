// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// platform_import_confined_to_residual_injection_test.go — доказательство
// падучести В ОБЕ СТОРОНЫ (порт-зеркало одноимённой пробы репозитория
// платформы, снят там вынесением службы доступа — `kacho#2597`).
//
// Инъекция идёт по СИНТЕТИЧЕСКОМУ дереву (`treecorpus.SyntheticTree` — обход
// диска, не индекса): настоящее дерево службы править нельзя, а без подачи
// входа гейт остаётся утверждением о самом себе.
//
// Отрицательная строка стоит в паре с положительной того же вида, и пара
// отличается РОВНО ОДНИМ фактом — тем, который гейт и судит: назван путь в
// ведомости остатка или нет.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
)

// platformImportFixture — синтетическое дерево из одного Go-файла с заданным
// набором импортов платформенного модуля.
func platformImportFixture(t *testing.T, body string) *treecorpus.Tree {
	t.Helper()
	root := t.TempDir()
	full := filepath.Join(root, "internal", "probe", "site.go")
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatalf("подготовить каталог: %v", err)
	}
	if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
		t.Fatalf("записать %s: %v", full, err)
	}
	tree, err := treecorpus.SyntheticTree(root)
	if err != nil {
		t.Fatalf("обход синтетики: %v", err)
	}
	return tree
}

// TestPlatformImportRecognizer_RedOnSharedFoundationTakenFromThePlatform —
// ИНЪЕКЦИЯ НЕСУЩЕГО КЛАССА: общий фундамент, взятый у ПЛАТФОРМЫ, а не у модуля
// фундамента. Именно на этой оси прежняя редакция гейта (префикс `pkg/`)
// молчала, и именно она разворачивает целевое направление ребра.
func TestPlatformImportRecognizer_RedOnSharedFoundationTakenFromThePlatform(t *testing.T) {
	t.Parallel()
	body := `package probe

import _ "github.com/PRO-Robotech/kacho/pkg/ids"
`
	tree := platformImportFixture(t, body)
	findings, census, err := scanPlatformImports(tree)
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("ожидалась 1 находка, получено %d: %v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Import, "pkg/ids") {
		t.Errorf("находка не называет путь импорта: %+v", findings[0])
	}
	if findings[0].Ground != platformImportGroundForeign {
		t.Errorf("основание неверно: %q — путь без `internal` обязан считаться решением "+
			"владельца, а не правилом языка", findings[0].Ground)
	}
	if census.Allowed != 0 {
		t.Errorf("путь фундамента у платформы зачтён в остаток: %d", census.Allowed)
	}
}

// TestPlatformImportRecognizer_SilentOnTheSameFoundationTakenFromTheFoundation —
// ЗАКОННЫЙ БЛИЗНЕЦ предыдущей: ТОТ ЖЕ пакет, взятый из модуля фундамента.
// Отличие ровно одно — имя модуля в пути.
func TestPlatformImportRecognizer_SilentOnTheSameFoundationTakenFromTheFoundation(t *testing.T) {
	t.Parallel()
	body := `package probe

import _ "github.com/PRO-Robotech/corelib/ids"
`
	tree := platformImportFixture(t, body)
	findings, census, err := scanPlatformImports(tree)
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("гейт краснеет на импорте из модуля ФУНДАМЕНТА: %v", findings)
	}
	if census.Foundation != 1 {
		t.Errorf("импорт фундамента не попал в парный контроль: %d", census.Foundation)
	}
	if census.PlatformModule != 0 {
		t.Errorf("импорт фундамента зачтён платформенным: %d", census.PlatformModule)
	}
}

// TestPlatformImportRecognizer_RedOnForeignDomain — ИНЪЕКЦИЯ ПРОВЕРЯЕМОГО:
// импорт соседнего домена платформы — находка с ЧУЖИМ основанием
// (не языковым: путь не несёт `internal`).
func TestPlatformImportRecognizer_RedOnForeignDomain(t *testing.T) {
	t.Parallel()
	body := `package probe

import _ "github.com/PRO-Robotech/kacho/services/vpc/domain"
`
	tree := platformImportFixture(t, body)
	findings, census, err := scanPlatformImports(tree)
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("ожидалась 1 находка, получено %d: %v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Import, "services/vpc/domain") {
		t.Errorf("находка не называет путь импорта: %+v", findings[0])
	}
	if findings[0].Ground != platformImportGroundForeign {
		t.Errorf("основание неверно: %q — путь без `internal` обязан считаться решением "+
			"владельца, а не правилом языка", findings[0].Ground)
	}
	if census.LanguageBound != 0 {
		t.Errorf("инъекция чужого домена задела счётчик языковых находок: %d", census.LanguageBound)
	}
}

// TestPlatformImportRecognizer_RedOnInternalWithLanguageGround — та же ось,
// путь платформы несёт `internal` — основание ОБЯЗАНО стать языковым.
func TestPlatformImportRecognizer_RedOnInternalWithLanguageGround(t *testing.T) {
	t.Parallel()
	body := `package probe

import _ "github.com/PRO-Robotech/kacho/internal/dropguard"
`
	tree := platformImportFixture(t, body)
	findings, census, err := scanPlatformImports(tree)
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("ожидалась 1 находка, получено %d: %v", len(findings), findings)
	}
	if findings[0].Ground != platformImportGroundLanguage {
		t.Errorf("основание неверно: %q — путь с `internal` обязан считаться правилом "+
			"языка: он недостижим извне дерева платформы by construction", findings[0].Ground)
	}
	if census.LanguageBound != 1 {
		t.Errorf("счётчик языковых находок не отражает инъекцию: %d", census.LanguageBound)
	}
}

// TestPlatformImportRecognizer_SilentOnTheNamedResidual — ЗАКОННЫЙ БЛИЗНЕЦ:
// импорт, названный в ведомости остатка, молчит — и КАЖДАЯ запись ведомости
// проверяется отдельно. Перечень подаётся не литералом, а самой ведомостью:
// своя копия разошлась бы с гейтом молча.
func TestPlatformImportRecognizer_SilentOnTheNamedResidual(t *testing.T) {
	t.Parallel()
	for _, e := range platformResidual {
		t.Run(e.Path, func(t *testing.T) {
			t.Parallel()
			body := "package probe\n\nimport _ \"" + platformModulePath + "/" + e.Path + "\"\n"
			tree := platformImportFixture(t, body)
			findings, census, err := scanPlatformImports(tree)
			if err != nil {
				t.Fatalf("обход: %v", err)
			}
			if len(findings) != 0 {
				t.Errorf("гейт краснеет на НАЗВАННОМ остатке: %v", findings)
			}
			if census.Allowed != 1 || census.PerResidual[e.Path] != 1 {
				t.Errorf("запись остатка не зачтена: allowed=%d, perResidual[%s]=%d",
					census.Allowed, e.Path, census.PerResidual[e.Path])
			}
		})
	}
}

// TestPlatformImportRecognizer_SilentOnASubpathOfTheNamedResidual — покрытие
// идёт по поддереву, а не по точному совпадению: иначе каждый подпакет
// остаточного каталога пришлось бы выписывать отдельной строкой.
func TestPlatformImportRecognizer_SilentOnASubpathOfTheNamedResidual(t *testing.T) {
	t.Parallel()
	body := `package probe

import _ "github.com/PRO-Robotech/kacho/pkg/subjectchange/subjectchangetest"
`
	tree := platformImportFixture(t, body)
	findings, census, err := scanPlatformImports(tree)
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("гейт краснеет на ПОДПАКЕТЕ названного остатка: %v", findings)
	}
	if census.PerResidual["pkg/subjectchange"] != 1 {
		t.Errorf("подпакет не зачтён своей записи: %d", census.PerResidual["pkg/subjectchange"])
	}
}

// TestPlatformImportRecognizer_RedOnASiblingOfTheNamedResidual — ОТРИЦАТЕЛЬНЫЙ
// близнец предыдущей: покрытие по поддереву не обязано покрывать СОСЕДА с тем
// же началом имени. Без этой пробы запись `pkg/api/kaname/cloud/iam/v1` тихо
// разрешила бы `pkg/api/kaname/cloud/iam/v1beta`.
func TestPlatformImportRecognizer_RedOnASiblingOfTheNamedResidual(t *testing.T) {
	t.Parallel()
	body := `package probe

import _ "github.com/PRO-Robotech/kacho/pkg/subjectchangelog"
`
	tree := platformImportFixture(t, body)
	findings, _, err := scanPlatformImports(tree)
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("сосед записи остатка с тем же началом имени принят за неё: находок %d", len(findings))
	}
}

// TestPlatformImportRecognizer_SilentOnForeignModuleAndStdlib — путь стороннего
// модуля и stdlib не являются предметом гейта вовсе (не платформенный модуль).
func TestPlatformImportRecognizer_SilentOnForeignModuleAndStdlib(t *testing.T) {
	t.Parallel()
	body := `package probe

import (
	"context"

	_ "github.com/PRO-Robotech/kaname/internal/domain"
	_ "github.com/stretchr/testify/require"
)
`
	tree := platformImportFixture(t, body)
	findings, census, err := scanPlatformImports(tree)
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("гейт краснеет на импортах ВНЕ платформенного модуля: %v", findings)
	}
	if census.PlatformModule != 0 {
		t.Errorf("счётчик платформенных импортов ненулевой на дереве без них: %d", census.PlatformModule)
	}
	if census.Foundation != 0 {
		t.Errorf("счётчик импортов фундамента ненулевой на дереве без них: %d", census.Foundation)
	}
}

// TestPlatformImportRecognizer_SilentOnItsOwnExplanation — путь платформы в
// КОММЕНТАРИИ, объясняющем эту же проверку, не находка: судится узел импорта, а
// не текст.
func TestPlatformImportRecognizer_SilentOnItsOwnExplanation(t *testing.T) {
	t.Parallel()
	body := `package probe

// Предмет: github.com/PRO-Robotech/kacho/pkg/ids вне остатка — находка.
// А github.com/PRO-Robotech/kacho/internal/dropguard недостижим языком.
func explain() {}
`
	tree := platformImportFixture(t, body)
	findings, census, err := scanPlatformImports(tree)
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("гейт краснеет на КОММЕНТАРИИ, объясняющем проверку: %v", findings)
	}
	if census.PlatformModule != 0 {
		t.Errorf("путь из комментария зачтён импортом: %d", census.PlatformModule)
	}
}

// TestPlatformImportGround_KnowsTheInternalSegmentAnywhereInThePath — основание
// зависит от наличия сегмента `internal`, а не от его позиции.
func TestPlatformImportGround_KnowsTheInternalSegmentAnywhereInThePath(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"internal/dropguard":      platformImportGroundLanguage,
		"services/iam/internal/x": platformImportGroundLanguage,
		"services/vpc/domain":     platformImportGroundForeign,
		"cmd/something":           platformImportGroundForeign,
	}
	for inner, want := range cases {
		if got := platformImportGround(inner); got != want {
			t.Errorf("platformImportGround(%q) = %q, ожидалось %q", inner, got, want)
		}
	}
}
