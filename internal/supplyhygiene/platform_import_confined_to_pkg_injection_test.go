// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// platform_import_confined_to_pkg_injection_test.go — доказательство падучести
// В ОБЕ СТОРОНЫ (порт-зеркало одноимённой пробы репозитория платформы, снят
// там вынесением службы доступа — `kacho#2597`).
//
// Инъекция идёт по СИНТЕТИЧЕСКОМУ дереву (`treecorpus.SyntheticTree` — обход
// диска, не индекса): настоящее дерево службы править нельзя, а без подачи
// входа гейт остаётся утверждением о самом себе.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
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

// TestPlatformImportRecognizer_RedOnForeignDomain — ИНЪЕКЦИЯ ПРОВЕРЯЕМОГО:
// импорт соседнего домена платформы ВНЕ pkg/ — находка с ЧУЖИМ основанием
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

// TestPlatformImportRecognizer_SilentOnPkg — ЗАКОННЫЙ БЛИЗНЕЦ: импорт из
// разрешённого фундамента молчит.
func TestPlatformImportRecognizer_SilentOnPkg(t *testing.T) {
	t.Parallel()
	body := `package probe

import (
	_ "github.com/PRO-Robotech/kacho/pkg/ids"
	_ "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
)
`
	tree := platformImportFixture(t, body)
	findings, census, err := scanPlatformImports(tree)
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("гейт краснеет на РАЗРЕШЁННОМ фундаменте: %v", findings)
	}
	if census.Allowed != 2 {
		t.Errorf("счётчик разрешённых импортов не отражает оба: %d", census.Allowed)
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
}

// TestPlatformImportRecognizer_SilentOnItsOwnExplanation — путь платформы в
// КОММЕНТАРИИ, объясняющем эту же проверку, не находка: судится узел импорта, а
// не текст.
func TestPlatformImportRecognizer_SilentOnItsOwnExplanation(t *testing.T) {
	t.Parallel()
	body := `package probe

// Предмет: github.com/PRO-Robotech/kacho/services/vpc/domain вне pkg/ — находка.
// А github.com/PRO-Robotech/kacho/internal/dropguard недостижим языком.
func explain() {}
`
	tree := platformImportFixture(t, body)
	findings, _, err := scanPlatformImports(tree)
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("гейт краснеет на КОММЕНТАРИИ, объясняющем проверку: %v", findings)
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
