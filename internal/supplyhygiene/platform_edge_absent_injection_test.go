// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// platform_edge_absent_injection_test.go — доказательство падучести G2 В ОБЕ
// СТОРОНЫ.
//
// Инъекция идёт по СИНТЕТИЧЕСКОМУ входу: настоящее дерево и настоящий `go.mod`
// править нельзя, а без подачи входа гейт остаётся утверждением о самом себе.
// Каждая отрицательная проба стоит в паре с положительной того же вида, и пара
// отличается РОВНО ОДНИМ фактом — тем, который гейт и судит: назван модуль
// платформы или модуль фундамента.
//
// Четыре предиката гейта разведены по своим функциям намеренно: вход каждой
// приносит вызывающий, поэтому инъекция подаёт его напрямую, а не запускает
// команду в подложном дереве.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
)

// platformEdgeFixture — синтетическое дерево из одного Go-файла и минимального
// `go.mod`: путь своего модуля нужен обходу, чтобы отличить свой импорт от
// платформенного.
func platformEdgeFixture(t *testing.T, body string) *treecorpus.Tree {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"),
		[]byte("module github.com/PRO-Robotech/kaname\n\ngo 1.26\n"), 0o600); err != nil {
		t.Fatalf("записать go.mod синтетики: %v", err)
	}
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

// TestPlatformEdge_RedOnTheVeryStubPathThatWasSwitched — ИНЪЕКЦИЯ НЕСУЩЕГО
// КЛАССА: возвращённый импорт заглушек службы ИЗ МОДУЛЯ ПЛАТФОРМЫ. Это те самые
// 251 узел, которые сняла ступень S0a, и именно этот путь прежняя редакция гейта
// разрешала записью ведомости.
func TestPlatformEdge_RedOnTheVeryStubPathThatWasSwitched(t *testing.T) {
	t.Parallel()
	body := `package probe

import _ "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
`
	findings, census, err := scanPlatformImports(platformEdgeFixture(t, body))
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("ожидалась 1 находка, получено %d: %v", len(findings), findings)
	}
	if findings[0].Ground != platformEdgeGroundImport {
		t.Errorf("основание неверно: %q", findings[0].Ground)
	}
	if !strings.Contains(findings[0].What, "pkg/api/kaname/cloud/iam/v1") {
		t.Errorf("находка не называет путь импорта: %+v", findings[0])
	}
	if census.PlatformModule != 1 {
		t.Errorf("счётчик платформенных узлов: %d, ожидалась 1", census.PlatformModule)
	}
}

// TestPlatformEdge_SilentOnTheSameStubPathTakenFromTheOwnModule — ЗАКОННЫЙ
// БЛИЗНЕЦ предыдущей: ТОТ ЖЕ пакет, взятый из своего модуля. Отличие ровно
// одно — имя модуля в пути. Без этой пары гейт, краснеющий на обоих, объявлял бы
// находкой саму правку S0a.
func TestPlatformEdge_SilentOnTheSameStubPathTakenFromTheOwnModule(t *testing.T) {
	t.Parallel()
	body := `package probe

import _ "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
`
	findings, census, err := scanPlatformImports(platformEdgeFixture(t, body))
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("гейт краснеет на импорте СВОИХ заглушек: %v", findings)
	}
	if census.Own != 1 {
		t.Errorf("импорт своего модуля не попал в парный контроль: %d", census.Own)
	}
	if census.PlatformModule != 0 {
		t.Errorf("импорт своего модуля зачтён платформенным: %d", census.PlatformModule)
	}
}

// TestPlatformEdge_RedOnTheTwoPackagesThatMovedHome — те же два пакета, что
// перенесены ступенью S0a (`pkg/ownerregister`, `pkg/subjectchange`), взятые
// снова у платформы. Прежняя ведомость разрешала оба.
func TestPlatformEdge_RedOnTheTwoPackagesThatMovedHome(t *testing.T) {
	t.Parallel()
	for _, inner := range []string{"pkg/ownerregister", "pkg/subjectchange"} {
		t.Run(inner, func(t *testing.T) {
			t.Parallel()
			body := "package probe\n\nimport _ \"" + platformModulePath + "/" + inner + "\"\n"
			findings, _, err := scanPlatformImports(platformEdgeFixture(t, body))
			if err != nil {
				t.Fatalf("обход: %v", err)
			}
			if len(findings) != 1 {
				t.Fatalf("ожидалась 1 находка на %s, получено %d", inner, len(findings))
			}
			if findings[0].Ground != platformEdgeGroundImport {
				t.Errorf("основание неверно: %q", findings[0].Ground)
			}
		})
	}
}

// TestPlatformEdge_SilentOnTheSameTwoPackagesAtTheirNewHome — ЗАКОННЫЙ БЛИЗНЕЦ:
// те же два пути в СВОЁМ модуле молчат.
func TestPlatformEdge_SilentOnTheSameTwoPackagesAtTheirNewHome(t *testing.T) {
	t.Parallel()
	for _, inner := range []string{"pkg/ownerregister", "pkg/subjectchange"} {
		t.Run(inner, func(t *testing.T) {
			t.Parallel()
			body := "package probe\n\nimport _ \"github.com/PRO-Robotech/kaname/" + inner + "\"\n"
			findings, census, err := scanPlatformImports(platformEdgeFixture(t, body))
			if err != nil {
				t.Fatalf("обход: %v", err)
			}
			if len(findings) != 0 {
				t.Errorf("гейт краснеет на пути в СВОЁМ модуле: %v", findings)
			}
			if census.Own != 1 {
				t.Errorf("импорт своего модуля не зачтён: %d", census.Own)
			}
		})
	}
}

// TestPlatformEdge_RedOnInternalWithLanguageGround — путь платформы несёт
// `internal`: основание ОБЯЗАНО стать языковым, потому что такой импорт
// отвергает компилятор, а не решение владельца.
func TestPlatformEdge_RedOnInternalWithLanguageGround(t *testing.T) {
	t.Parallel()
	body := `package probe

import _ "github.com/PRO-Robotech/kacho/internal/dropguard"
`
	findings, census, err := scanPlatformImports(platformEdgeFixture(t, body))
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("ожидалась 1 находка, получено %d", len(findings))
	}
	if findings[0].Ground != platformEdgeGroundLanguage {
		t.Errorf("основание неверно: %q — путь с `internal` недостижим извне дерева "+
			"платформы by construction", findings[0].Ground)
	}
	if census.LanguageBound != 1 {
		t.Errorf("счётчик языковых находок не отражает инъекцию: %d", census.LanguageBound)
	}
}

// TestPlatformEdge_SilentOnTheFoundationModule — ЗАКОННОЕ РЕБРО: фундамент.
func TestPlatformEdge_SilentOnTheFoundationModule(t *testing.T) {
	t.Parallel()
	body := `package probe

import _ "github.com/PRO-Robotech/corelib/authz"
`
	findings, census, err := scanPlatformImports(platformEdgeFixture(t, body))
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("гейт краснеет на импорте из модуля ФУНДАМЕНТА: %v", findings)
	}
	if census.Foundation != 1 {
		t.Errorf("импорт фундамента не попал в парный контроль: %d", census.Foundation)
	}
}

// TestPlatformEdge_SilentOnItsOwnExplanation — путь платформы в КОММЕНТАРИИ,
// объясняющем эту же проверку, находкой не является: судится узел импорта, а не
// текст. В этом дереве такой текст есть по-настоящему — шапка гейта, ведомость
// входных контрактов, фикстуры соседних гейтов.
func TestPlatformEdge_SilentOnItsOwnExplanation(t *testing.T) {
	t.Parallel()
	body := `package probe

// Предмет: github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1 — ребро.
// А github.com/PRO-Robotech/kacho/internal/dropguard недостижим языком.
const ledger = "github.com/PRO-Robotech/kacho/pkg/subjectchange"

func explain() string { return ledger }
`
	findings, census, err := scanPlatformImports(platformEdgeFixture(t, body))
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("гейт краснеет на комментарии и строковом литерале: %v", findings)
	}
	if census.PlatformModule != 0 {
		t.Errorf("путь из текста зачтён импортом: %d", census.PlatformModule)
	}
}

// TestPlatformEdge_EmptyTreeIsNotSilence — пустой обход не вердикт: без файлов
// «находок ноль» истинно всегда. Проба судит СЧЁТЧИК, потому что именно его
// читает гейт, прежде чем вынести вердикт.
func TestPlatformEdge_EmptyTreeIsNotSilence(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	tree, err := treecorpus.SyntheticTree(root)
	if err != nil {
		t.Fatalf("обход синтетики: %v", err)
	}
	_, census, err := scanPlatformImports(tree)
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	if census.Files != 0 || census.Imports != 0 {
		t.Fatalf("пустое дерево дало непустую перепись: %s", census)
	}
}

// TestModuleDeclaration_RedOnRequireOfThePlatform — ИНЪЕКЦИЯ ОБЪЯВЛЕННОГО
// РЕБРА: `require` платформы находится даже при нуле импортов.
func TestModuleDeclaration_RedOnRequireOfThePlatform(t *testing.T) {
	t.Parallel()
	var decl goModDeclaration
	decl.Module.Path = "github.com/PRO-Robotech/kaname"
	decl.Require = []struct {
		Path    string `json:"Path"`
		Version string `json:"Version"`
	}{
		{Path: platformModulePath, Version: "v0.1.1-0.20260912212223-96c5c6e10b99"},
		{Path: foundationModulePath, Version: "v1.4.0"},
	}
	findings, census := judgeModuleDeclaration(decl)
	if len(findings) != 1 {
		t.Fatalf("ожидалась 1 находка, получено %d: %v", len(findings), findings)
	}
	if findings[0].Ground != platformEdgeGroundRequire {
		t.Errorf("основание неверно: %q", findings[0].Ground)
	}
	if census.FoundationRequire != 1 {
		t.Errorf("require фундамента не зачтён парным контролем: %d", census.FoundationRequire)
	}
}

// TestModuleDeclaration_SilentOnRequireOfTheFoundationAlone — ЗАКОННЫЙ БЛИЗНЕЦ:
// объявление, в котором остался только фундамент. Отличие от предыдущей ровно
// одно — снятая запись платформы.
func TestModuleDeclaration_SilentOnRequireOfTheFoundationAlone(t *testing.T) {
	t.Parallel()
	var decl goModDeclaration
	decl.Module.Path = "github.com/PRO-Robotech/kaname"
	decl.Require = []struct {
		Path    string `json:"Path"`
		Version string `json:"Version"`
	}{
		{Path: foundationModulePath, Version: "v1.4.0"},
	}
	findings, census := judgeModuleDeclaration(decl)
	if len(findings) != 0 {
		t.Errorf("гейт краснеет на объявлении, где платформы нет: %v", findings)
	}
	if census.FoundationRequire != 1 {
		t.Errorf("require фундамента не зачтён: %d", census.FoundationRequire)
	}
}

// TestModuleDeclaration_RedOnReplaceOfThePlatform — `replace` на локальный путь
// есть ПОДДЕЛКА снятия ребра: `require` уходит из вида, ребро остаётся, а версия
// перестаёт быть объявленной. Эта ось названа в задании прямо как запрещённая.
func TestModuleDeclaration_RedOnReplaceOfThePlatform(t *testing.T) {
	t.Parallel()
	var decl goModDeclaration
	decl.Module.Path = "github.com/PRO-Robotech/kaname"
	decl.Require = []struct {
		Path    string `json:"Path"`
		Version string `json:"Version"`
	}{
		{Path: foundationModulePath, Version: "v1.4.0"},
	}
	decl.Replace = []struct {
		Old struct{ Path string } `json:"Old"`
		New struct{ Path string } `json:"New"`
	}{
		{Old: struct{ Path string }{Path: platformModulePath}, New: struct{ Path string }{Path: "../kacho"}},
	}
	findings, census := judgeModuleDeclaration(decl)
	if len(findings) != 1 {
		t.Fatalf("ожидалась 1 находка, получено %d: %v", len(findings), findings)
	}
	if findings[0].Ground != platformEdgeGroundReplace {
		t.Errorf("основание неверно: %q", findings[0].Ground)
	}
	if census.Replace != 1 {
		t.Errorf("счётчик replace не отражает инъекцию: %d", census.Replace)
	}
}

// TestSum_RedOnAPlatformFingerprint — ИНЪЕКЦИЯ ТРЕТЬЕГО ПУТИ: строка `go.sum`
// платформы. Единица счёта — строка, и у одного модуля их две.
func TestSum_RedOnAPlatformFingerprint(t *testing.T) {
	t.Parallel()
	raw := []byte(`github.com/PRO-Robotech/corelib v1.4.0 h1:gO2HTr1fuvp9AtsoRL7QzTBnS2qnOm8pShKQ++drHIo=
github.com/PRO-Robotech/corelib v1.4.0/go.mod h1:q8r4k3+ip391S0T4LHOkcQxz8UbWqUKmmxzXzZP39jA=
github.com/PRO-Robotech/kacho v0.1.1-0.20260912212223-96c5c6e10b99 h1:qSYKgOqFLIwNZndMl4t6MzfdHqT55f3NW4AV6AeFAZw=
`)
	findings, census := judgeSum(raw)
	if len(findings) != 1 {
		t.Fatalf("ожидалась 1 находка, получено %d: %v", len(findings), findings)
	}
	if findings[0].Ground != platformEdgeGroundSum {
		t.Errorf("основание неверно: %q", findings[0].Ground)
	}
	if census.FoundationSum != 2 {
		t.Errorf("строки фундамента не зачтены парным контролем: %d, ожидалось 2", census.FoundationSum)
	}
}

// TestSum_SilentOnTheFoundationFingerprintsAlone — ЗАКОННЫЙ БЛИЗНЕЦ: тот же
// `go.sum` без строки платформы.
func TestSum_SilentOnTheFoundationFingerprintsAlone(t *testing.T) {
	t.Parallel()
	raw := []byte(`github.com/PRO-Robotech/corelib v1.4.0 h1:gO2HTr1fuvp9AtsoRL7QzTBnS2qnOm8pShKQ++drHIo=
github.com/PRO-Robotech/corelib v1.4.0/go.mod h1:q8r4k3+ip391S0T4LHOkcQxz8UbWqUKmmxzXzZP39jA=
`)
	findings, census := judgeSum(raw)
	if len(findings) != 0 {
		t.Errorf("гейт краснеет на go.sum без платформы: %v", findings)
	}
	if census.FoundationSum != 2 {
		t.Errorf("строки фундамента не зачтены: %d", census.FoundationSum)
	}
}

// TestBuildGraph_RedOnATransitivePlatformPackage — ИНЪЕКЦИЯ НЕСУЩЕГО ЧЕТВЁРТОГО
// ПУТИ: пакет платформы В ГРАФЕ СБОРКИ при нуле узлов импорта в дереве. Ровно
// этот класс прежде искал `internal/contracthome`
// TestBothCopiesOfAContractNeverReachOneBinary обходом кэша модулей: вторая
// копия дескриптора приезжает НОСИТЕЛЕМ, и двоичное падает паникой регистрации,
// не назвав ни одного платформенного пути.
func TestBuildGraph_RedOnATransitivePlatformPackage(t *testing.T) {
	t.Parallel()
	packages := []string{
		"context",
		"github.com/PRO-Robotech/kaname/internal/domain",
		"github.com/PRO-Robotech/corelib/authz",
		"github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1",
	}
	findings, census := judgeBuildGraph(packages)
	if len(findings) != 1 {
		t.Fatalf("ожидалась 1 находка, получено %d: %v", len(findings), findings)
	}
	if findings[0].Ground != platformEdgeGroundGraph {
		t.Errorf("основание неверно: %q", findings[0].Ground)
	}
	if census.GraphPackages != 4 {
		t.Errorf("объём осмотренного не совпал: %d, ожидалось 4", census.GraphPackages)
	}
	if census.FoundationGraph != 1 {
		t.Errorf("пакет фундамента не зачтён парным контролем: %d", census.FoundationGraph)
	}
}

// TestBuildGraph_SilentOnTheSameGraphWithoutThePlatform — ЗАКОННЫЙ БЛИЗНЕЦ: тот
// же граф, отличающийся РОВНО снятым пакетом платформы.
func TestBuildGraph_SilentOnTheSameGraphWithoutThePlatform(t *testing.T) {
	t.Parallel()
	packages := []string{
		"context",
		"github.com/PRO-Robotech/kaname/internal/domain",
		"github.com/PRO-Robotech/corelib/authz",
		"github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1",
	}
	findings, census := judgeBuildGraph(packages)
	if len(findings) != 0 {
		t.Errorf("гейт краснеет на графе без платформы: %v", findings)
	}
	if census.FoundationGraph != 1 {
		t.Errorf("пакет фундамента не зачтён: %d", census.FoundationGraph)
	}
}

// TestBuildGraph_EmptyGraphIsNotSilence — пустой перечень не вердикт.
func TestBuildGraph_EmptyGraphIsNotSilence(t *testing.T) {
	t.Parallel()
	findings, census := judgeBuildGraph(nil)
	if len(findings) != 0 {
		t.Errorf("пустой перечень дал находки: %v", findings)
	}
	if census.GraphPackages != 0 {
		t.Fatalf("пустой перечень дал непустую перепись: %d", census.GraphPackages)
	}
}
