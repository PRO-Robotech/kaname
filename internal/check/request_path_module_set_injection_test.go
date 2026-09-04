// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package check

// request_path_module_set_injection_test.go — доказательство, что гейт
// `TestIAM1927_RequestPathAsksLiveRowsForModuleMembership` СПОСОБЕН упасть и
// способен смолчать.
//
// # Почему синтетика, а не живое дерево
//
// Доказательство, требующее испортить рабочую копию, в конвейере не исполняется
// никогда, а на машине разработчика оставляет след в чужом дереве. Ядро гейта
// принимает состав ПАРАМЕТРОМ ровно затем, чтобы инъекция подала ему свой.
//
// Пара «красное до · зелёное после» снята и на ЖИВОМ дереве, однократно, и её
// вывод стоит в шапке соседа: подстановка канона в `role/create.go` даёт находку
// с координатой `create.go:138`, откат — молчание. Здесь это же свойство
// закреплено воспроизводимо.
//
// # Инъекция роняет ТОЛЬКО проверяемое
//
// Форма «завести ещё один файл» негодна: новый файл нарушает всё, что требуется
// от файлов вообще, и красное пришло бы от соседа. Поэтому каждый случай ниже —
// ОДИН файл в досягаемости, у которого снято ровно одно свойство, а рядом стоит
// его законный близнец той же формы.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// injectedFile — один файл синтетического дерева.
type injectedFile struct {
	rel  string // путь от корня синтетического дерева
	body string
}

// writeSyntheticReach раскладывает файлы и возвращает корень и их абсолютные пути.
func writeSyntheticReach(t *testing.T, files []injectedFile) (root string, paths []string) {
	t.Helper()
	root = t.TempDir()
	for _, f := range files {
		abs := filepath.Join(root, filepath.FromSlash(f.rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o750); err != nil {
			t.Fatalf("каталог для %s: %v", f.rel, err)
		}
		if err := os.WriteFile(abs, []byte(f.body), 0o600); err != nil {
			t.Fatalf("записать %s: %v", f.rel, err)
		}
		paths = append(paths, abs)
	}
	return root, paths
}

// Тела ниже — минимальные компилируемые файлы Go. Разбору достаточно
// синтаксиса; сборка синтетики не производится намеренно, иначе фикстура
// потянула бы за собой весь модуль.

const usecaseWithCanon = `package role

import (
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

func validate(r domain.Rules) error {
	return r.Validate(domain.PolicyOfRole(false, ""), domain.ModuleSetOf(authzmap.CatalogSeedModules()...))
}
`

const usecaseWithAliasedCanon = `package role

import (
	am "github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

func validate(r domain.Rules) error {
	return r.Validate(domain.PolicyOfRole(false, ""), domain.ModuleSetOf(am.CatalogSeedModules()...))
}
`

const usecaseWithSpellings = `package role

import "github.com/PRO-Robotech/kacho/pkg/platformmodules"

func modules() int { return len(platformmodules.All()) }
`

// domainWithReturnedLiteral — СНЯТОЕ объявление, вернувшееся дословно. Предикат
// тела задачи #1927 («инъекция возвращает литерал и краснеет») — частный случай
// свойства, и он обязан выполняться.
const domainWithReturnedLiteral = `package domain

var knownModules = []string{"iam", "vpc", "compute", "loadbalancer", "registry", "storage"}

func IsKnownModule(m string) bool {
	for _, k := range knownModules {
		if k == m {
			return true
		}
	}
	return false
}
`

const usecaseWithVariadicNames = `package role

import "github.com/PRO-Robotech/kacho/services/iam/internal/domain"

func known() domain.ModuleSet {
	return domain.ModuleSetOf("iam", "vpc", "compute", "loadbalancer", "registry", "storage")
}
`

// ── законные близнецы ────────────────────────────────────────────────────────

// usecaseNamingCanonInProse — та же форма, но канон стоит В КОММЕНТАРИИ. Это и
// есть трап, ради которого гейт разбирает узел: по слову файл неотличим от
// нарушителя.
const usecaseNamingCanonInProse = `package role

import "github.com/PRO-Robotech/kacho/services/iam/internal/domain"

// Набор модулей — ЖИВЫЕ строки каталога, а не канон authzmap.CatalogSeedModules:
// снятый модуль обязан перестать приниматься без перезапуска службы (#1927).
func validate(r domain.Rules, facts domain.ModuleSet) error {
	return r.Validate(domain.PolicyOfRole(false, ""), facts)
}
`

// usecaseWithAPairOfNames — ДВА имени в одной последовательности: законная
// форма, ниже порога.
const usecaseWithAPairOfNames = `package role

func labelSelectable() []string { return []string{"vpc", "compute"} }
`

// usecaseWithBlankImport — пустой импорт канона: выражения выбора он не даёт и
// набора не читает.
const usecaseWithBlankImport = `package role

import _ "github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"

func nothing() {}
`

// probeOnTheRequestPath — проба В ДОСЯГАЕМОСТИ, спрашивающая канон. Путём
// запроса она не является: фикстура вправе называть канон.
const probeOnTheRequestPath = `package role

import "github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"

func canon() []string { return authzmap.CatalogSeedModules() }
`

// applierOutsideTheReach — применитель ролей модуля. Канон спрашивает ЗАКОННО:
// его вопрос — «объявлен ли модуль платформой». В досягаемость не входит, и
// гейт обязан молчать на нём, даже если состав ему подали.
const applierOutsideTheReach = probeOnTheRequestPath

func TestIAM1927_InjectionRedsTheCompiledSetAndKeepsQuietOnItsLawfulTwins(t *testing.T) {
	// Каждый случай — ОДИН файл в досягаемости плюс её законный сосед, чтобы
	// обход не был пуст и перепись не вырождалась.
	const neighbour = "services/iam/internal/apps/kacho/api/role/read.go"
	const neighbourBody = `package role

func read() string { return "ok" }
`

	cases := []struct {
		name   string
		rel    string
		body   string
		finds  bool
		reason string // подстрока, которую находка обязана НАЗВАТЬ
	}{
		{
			name: "канон на пути запроса — находка", rel: "services/iam/internal/apps/kacho/api/role/create.go",
			body: usecaseWithCanon, finds: true, reason: "канон дерева authzmap.CatalogSeedModules",
		},
		{
			name: "канон под псевдонимом — находка", rel: "services/iam/internal/apps/kacho/api/role/create.go",
			body: usecaseWithAliasedCanon, finds: true, reason: "канон дерева am.CatalogSeedModules",
		},
		{
			name: "словарь написаний — находка", rel: "services/iam/internal/apps/kacho/api/role/create.go",
			body: usecaseWithSpellings, finds: true, reason: "словарь написаний модулей платформы",
		},
		{
			name: "снятый литерал вернулся — находка", rel: "services/iam/internal/domain/module_set.go",
			body: domainWithReturnedLiteral, finds: true, reason: "перечень из 6 имён модулей",
		},
		{
			name: "имена аргументами вариадического вызова — находка", rel: "services/iam/internal/apps/kacho/api/role/create.go",
			body: usecaseWithVariadicNames, finds: true, reason: "перечень из 6 имён модулей",
		},
		{
			name: "канон ТОЛЬКО в комментарии — молчание", rel: "services/iam/internal/apps/kacho/api/role/create.go",
			body: usecaseNamingCanonInProse, finds: false,
		},
		{
			name: "пара имён — молчание", rel: "services/iam/internal/apps/kacho/api/role/create.go",
			body: usecaseWithAPairOfNames, finds: false,
		},
		{
			name: "пустой импорт канона — молчание", rel: "services/iam/internal/apps/kacho/api/role/create.go",
			body: usecaseWithBlankImport, finds: false,
		},
		{
			name: "проба в досягаемости — молчание", rel: "services/iam/internal/apps/kacho/api/role/create_test.go",
			body: probeOnTheRequestPath, finds: false,
		},
		{
			name: "применитель вне досягаемости — молчание", rel: "services/iam/internal/apps/kacho/moduleroles/apply.go",
			body: applierOutsideTheReach, finds: false,
		},
		{
			name: "загрузчик манифеста вне досягаемости — молчание", rel: "services/iam/internal/manifest/roles.go",
			body: applierOutsideTheReach, finds: false,
		},
		{
			name: "страж паритета вне досягаемости — молчание", rel: "services/iam/internal/apps/kacho/seed/catalog_parity.go",
			body: applierOutsideTheReach, finds: false,
		},
		{
			name: "оснастка дерева вне досягаемости — молчание", rel: "services/iam/internal/modelrender/sweep.go",
			body: applierOutsideTheReach, finds: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := []injectedFile{{rel: neighbour, body: neighbourBody}, {rel: tc.rel, body: tc.body}}
			root, paths := writeSyntheticReach(t, files)

			// Вне досягаемости лежащий файл ядру НЕ подаётся — так его отбирает
			// `requestPathFiles` в живом дереве, и инъекция обязана повторять
			// отбор, а не обходить его.
			var given []string
			for i, f := range files {
				if inRequestPathReach(f.rel) {
					given = append(given, paths[i])
				}
			}

			uses, census, err := compiledModuleSetUses(root, given)
			if err != nil {
				t.Fatalf("%v", err)
			}
			t.Logf("%s", census.Summary())
			if census.Parsed == 0 {
				t.Fatalf("обход синтетики пуст — фикстура не подана ядру, и вердикт беспредметен")
			}

			switch {
			case tc.finds && len(uses) == 0:
				t.Fatalf("гейт СМОЛЧАЛ на внесённом дефекте (%s) — он не способен упасть", tc.rel)
			case !tc.finds && len(uses) > 0:
				t.Fatalf("гейт покраснел на ЗАКОННОЙ форме (%s): %s:%d — %s — "+
					"ложная находка отключает гейт первой",
					tc.rel, uses[0].File, uses[0].Line, uses[0].Reason)
			}
			if !tc.finds {
				return
			}
			// Находка обязана НАЗВАТЬ координату и причину: покрасневший молча
			// гейт посылает читателя искать не там.
			var named bool
			for _, u := range uses {
				if u.File == tc.rel && u.Line > 0 && strings.Contains(u.Reason, tc.reason) {
					named = true
				}
			}
			if !named {
				t.Fatalf("находка есть, но координату либо причину не назвала: %+v "+
					"(ждали файл %s и причину, содержащую %q)", uses, tc.rel, tc.reason)
			}
		})
	}
}

// inRequestPathReach — тот же отбор, что делает `requestPathFiles` индексом
// дерева. Своя копия здесь нужна затем, чтобы инъекция подавала ядру ровно то,
// что подаёт живое дерево: подай она файл вне досягаемости — доказала бы
// молчание, которого гейт не производит.
func inRequestPathReach(rel string) bool {
	for _, p := range requestPathReach {
		if strings.HasPrefix(rel, p+"/") {
			return true
		}
	}
	return false
}

// TestIAM1927_InjectionProvesTheEmptyWalkIsRefused — премиса гейта: обход, не
// прочитавший ничего, обязан быть отказом, а не молчаливым успехом.
func TestIAM1927_InjectionProvesTheEmptyWalkIsRefused(t *testing.T) {
	root := t.TempDir()
	uses, census, err := compiledModuleSetUses(root, nil)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(uses) != 0 {
		t.Fatalf("на пустом составе найдено %d — ядро выдумывает находки", len(uses))
	}
	if census.Parsed != 0 || census.Files != 0 {
		t.Fatalf("перепись пустого состава непуста: %s", census.Summary())
	}
	// Именно это условие живой гейт превращает в отказ; здесь доказано, что
	// величина, на которую он смотрит, на пустом обходе действительно нулевая.
	t.Logf("пустой состав: %s — живой гейт на такой переписи ОТКАЗЫВАЕТ", census.Summary())
}

// TestIAM1927_InjectionProvesTheWordPredicateWouldRedOnItsOwnExplanation —
// третий прогон пары: доказывает, что выбор «узел, а не слово» не украшение.
// Тот же файл, что молчит у разбора, предикатом по подстроке был бы находкой.
func TestIAM1927_InjectionProvesTheWordPredicateWouldRedOnItsOwnExplanation(t *testing.T) {
	root, paths := writeSyntheticReach(t, []injectedFile{
		{rel: "services/iam/internal/apps/kacho/api/role/create.go", body: usecaseNamingCanonInProse},
	})
	uses, census, err := compiledModuleSetUses(root, paths)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(uses) != 0 {
		t.Fatalf("разбор покраснел на прозе — гейт судит слово: %+v", uses)
	}
	if census.CanonByWord == 0 {
		t.Fatalf("фикстура не содержит имени канона по слову — трап не воспроизведён")
	}
	if census.CanonByNode != 0 {
		t.Fatalf("по узлу найдено %d при ожидаемом нуле", census.CanonByNode)
	}
	t.Logf("тот же файл: по слову %d, по узлу %d — предикат по подстроке краснел бы "+
		"на СОБСТВЕННОМ объяснении проверяемого", census.CanonByWord, census.CanonByNode)
}
