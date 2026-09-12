// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// generation_roots_test.go — дерево контрактов службы порождает заглушки
// ТОЛЬКО для собственного корня, и ни для одного входного.
//
// # ПРЕДМЕТ — НЕ ОХВАТ, А ЕДИНСТВЕННОСТЬ РЕГИСТРАЦИИ
//
// Под `proto/` лежат ДВА разных вида файлов, и различие несёт исход:
//
//	kaname/…    собственные контракты службы  → заглушки порождаются ЗДЕСЬ
//	corelib/…   контракт фундамента           → заглушки публикует модуль фундамента
//	kacho/…     контракт фундамента           → то же
//	google/…    контракт поставщика           → то же (genproto)
//
// Входные лежат в дереве потому, что оператор `import` резолвится ФАЙЛОМ:
// без них контракты службы не компилируются нигде (см. `contract_closure_test.go`).
// Породи их заглушки ЕЩЁ РАЗ сюда — и двоичное слинкует два пакета, каждый из
// которых регистрирует ОДНО И ТО ЖЕ имя файла контракта.
//
// # ОТКАЗ ПРИХОДИТ НЕ СБОРКОЙ, И ЭТО ЗАМЕРЕНО, А НЕ ПРЕДПОЛОЖЕНО
//
// Двоичное из двух строк — только импорты двух таких пакетов — отвечает:
//
//	panic: proto: file "corelib/authz/v1/authz_options.proto" is already registered
//	        previously from: "…/corelib/api/corelib/authz/v1"
//	        currently from:  "…/pkg/api/corelib/authz/v1"
//
// Сборка при этом проходит. Отказ — времени выполнения, в инициализации, и
// приходит ТРАНЗИТИВНО: у потребителя, который ни одного из двух путей не
// называл. Гейт на компиляцию этот класс не ловит по построению, поэтому он
// закрывается здесь — объявлением входов генерации.
//
// # ДВЕ СТОРОНЫ, И ВТОРАЯ НЕСУЩАЯ
//
// Первая: во входах генерации назван чужой корень — заглушка фундамента будет
// порождена вторично. Вторая: под каталогом заглушек лежит корень, которого во
// входах нет либо который службе не принадлежит, — то есть заглушка уже
// порождена вторично, а объявление об этом молчит. Без второй стороны правка
// объявления «чинила» бы находку, оставляя её файлы в дереве.
package contracthome

import (
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"gopkg.in/yaml.v3"
)

// bufGenFile — объявление генерации в каталоге контрактов.
const bufGenFile = "buf.gen.yaml"

// stubRootDir — каталог порождённых заглушек в дереве службы.
const stubRootDir = "pkg/api"

// bufGenDeclaration — ровно та часть объявления, которая решает, ЧТО
// порождается. Остальные поля намеренно не читаются: гейт судит охват
// генерации, а не набор плагинов.
type bufGenDeclaration struct {
	Inputs []struct {
		Directory    string   `yaml:"directory"`
		Paths        []string `yaml:"paths"`
		ExcludePaths []string `yaml:"exclude_paths"`
	} `yaml:"inputs"`
}

const (
	generationGroundForeignRoot = "во входах генерации назван не собственный корень службы: " +
		"заглушки этого контракта публикует его собственный модуль, и второе их порождение " +
		"даёт двойную регистрацию дескриптора — панику инициализации у транзитивного потребителя"
	generationGroundOwnRootAbsent = "собственный корень контрактов службы во входах генерации " +
		"не назван: заглушки не порождаются вовсе, и дерево собирается лишь пока их кто-то " +
		"публикует за службу"
	generationGroundForeignStub = "под каталогом заглушек лежит не собственный корень службы: " +
		"дескриптор чужого контракта уже порождён вторично"
)

// generationFinding — одна находка объявления либо дерева заглушек.
type generationFinding struct {
	Where  string
	Root   string
	Ground string
}

func (f generationFinding) String() string {
	return fmt.Sprintf("%s — корень %q: %s", f.Where, f.Root, f.Ground)
}

// generationCensus — объём осмотренного.
type generationCensus struct {
	ProtoRoots      []string
	GenerationPaths []string
	ExcludePaths    []string
	StubRoots       []string
	Inputs          int
}

func (c generationCensus) String() string {
	return fmt.Sprintf("корней контрактов в дереве %d (%s); входов генерации %d, "+
		"названных путей %d (%s), исключённых %d (%s); корней заглушек %d (%s)",
		len(c.ProtoRoots), strings.Join(c.ProtoRoots, " "),
		c.Inputs,
		len(c.GenerationPaths), strings.Join(c.GenerationPaths, " "),
		len(c.ExcludePaths), strings.Join(c.ExcludePaths, " "),
		len(c.StubRoots), strings.Join(c.StubRoots, " "))
}

// topRoots — верхние каталоги состава дерева под названной приставкой.
func topRoots(tree *treecorpus.Tree, prefix string) []string {
	set := map[string]bool{}
	for _, rel := range tree.SortedFiles() {
		if !strings.HasPrefix(rel, prefix+"/") {
			continue
		}
		rest := strings.TrimPrefix(rel, prefix+"/")
		seg := strings.SplitN(rest, "/", 2)
		if len(seg) < 2 {
			continue // файл в самом каталоге (объявления, лицензия) — не корень
		}
		set[seg[0]] = true
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// scanGenerationRoots читает объявление генерации и дерево заглушек и
// возвращает несовпадения с правилом «порождаем только своё».
func scanGenerationRoots(tree *treecorpus.Tree) (generationCensus, []generationFinding, error) {
	census := generationCensus{
		ProtoRoots: topRoots(tree, protoRoot),
		StubRoots:  topRoots(tree, stubRootDir),
	}

	declPath := path.Join(protoRoot, bufGenFile)
	raw, err := os.ReadFile(path.Join(tree.Root(), declPath))
	if err != nil {
		return census, nil, fmt.Errorf("объявление генерации %s не прочитано: %w", declPath, err)
	}
	var decl bufGenDeclaration
	if err := yaml.Unmarshal(raw, &decl); err != nil {
		return census, nil, fmt.Errorf("%s: разбор объявления: %w", declPath, err)
	}
	census.Inputs = len(decl.Inputs)
	for _, in := range decl.Inputs {
		census.GenerationPaths = append(census.GenerationPaths, in.Paths...)
		census.ExcludePaths = append(census.ExcludePaths, in.ExcludePaths...)
	}
	sort.Strings(census.GenerationPaths)
	sort.Strings(census.ExcludePaths)

	own := func(p string) bool {
		return p == ownContractRoot || strings.HasPrefix(p, ownContractRoot+"/")
	}

	var findings []generationFinding
	ownNamed := false
	for _, p := range census.GenerationPaths {
		if own(p) {
			ownNamed = true
			continue
		}
		findings = append(findings, generationFinding{
			Where: declPath, Root: p, Ground: generationGroundForeignRoot,
		})
	}
	if !ownNamed {
		findings = append(findings, generationFinding{
			Where: declPath, Root: ownContractRoot, Ground: generationGroundOwnRootAbsent,
		})
	}
	for _, r := range census.StubRoots {
		if own(r) {
			continue
		}
		findings = append(findings, generationFinding{
			Where: stubRootDir, Root: r, Ground: generationGroundForeignStub,
		})
	}
	return census, findings, nil
}

// TestGenerationProducesOnlyThisServicesOwnContracts — сам гейт.
func TestGenerationProducesOnlyThisServicesOwnContracts(t *testing.T) {
	t.Parallel()

	tree, err := treecorpus.NewTree(serviceRoot)
	if err != nil {
		t.Fatalf("состав дерева службы (%s) не прочитан у индекса — вердикт беспредметен: %v",
			serviceRoot, err)
	}

	census, findings, err := scanGenerationRoots(tree)
	if err != nil {
		t.Fatalf("перепись: %s\nобъявление генерации: %v", census, err)
	}
	t.Logf("перепись: %s", census)

	if len(census.ProtoRoots) == 0 {
		t.Fatalf("под %s/ не прочитано ни одного корня контрактов — вердикт беспредметен", protoRoot)
	}
	if census.Inputs == 0 {
		t.Fatalf("%s не объявляет ни одного входа — генерация не порождает ничего, "+
			"и «лишнего не порождаем» здесь означало бы «не порождаем вовсе»",
			path.Join(protoRoot, bufGenFile))
	}
	if len(census.StubRoots) == 0 {
		t.Fatalf("под %s/ не прочитано ни одного корня заглушек — либо генерация не прогонялась, "+
			"либо её выход не в дереве; вердикт беспредметен", stubRootDir)
	}

	for _, f := range findings {
		t.Errorf("%s", f)
	}
}
