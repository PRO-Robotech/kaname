// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// rule_policy_single_source_test.go — политика послабления подстановки
// выводится из строки роли ОДНИМ местом (порт с монорепо
// `internal/repohygiene/rulepolicysinglesource_test.go`, держатель
// `TestRulePolicyIsDerivedInOnePlace`, снят вынесением службы доступа —
// `kacho#2597`; исходная приёмка
// `docs/engineering/acceptance/role-ownership-tier-apart-from-cluster-anchor.md`,
// §2.2 и §8 п. 6; задача продукта #1032).
//
// Способность гейта упасть и смолчать доказана инъекцией —
// rule_policy_single_source_injection_test.go.
//
// # Что изменилось при переносе, а что осталось дословно
//
// Изменилось: пакет (`repohygiene` → `domain_test`, по образцу соседних
// `scope_tier_one_declaration_test.go` и
// `platform_coordinate_tree_touch_gate_test.go` — тип и его единственный дом
// живут в самом пакете `internal/domain`, поэтому обход сужен до текущего
// каталога, а не до пути `services/iam/internal/domain` от корня платформы, —
// прежний путь тоже переезжает следом, а не отменяется); нет отдельного
// `impl.go` (как и в монорепо — сканирующий код жил в `package repohygiene`
// рядом с тестом, а не экспортировался). Осталось дословно: имя типа
// `RulePolicy`, имя функции вывода `PolicyOfRole`, форма находки (узел-литерал
// разобранного AST, а не текст файла) и имя держателя
// `TestRulePolicyIsDerivedInOnePlace`.
//
// # Предмет
//
// До #1032 политика была одна булева — «системный контекст», — и признак
// `is_system` нёс два смысла сразу: «арендатор эту роль не правит» и «этой
// роли можно подставлять звёздочку». Разделение держится ЗНАЧЕНИЕМ закрытого
// перечня (`RulePolicy`), выводимым из строки функцией `PolicyOfRole`.
// Второе объявление «системная ли роль для целей подстановки» — находка: два
// места об одном предмете разойдутся, и разойдутся молча, потому что на
// законном входе оба отвечают одинаково.
//
// # Чего разбор НЕ видит — названо, а не спрятано
//
// Политику, собранную рефлексией либо приехавшую из другого пакета готовым
// значением. Первого в этом дереве нет; второе неопасно by construction:
// поля `RulePolicy` и весь перечень ярусов НЕ ЭКСПОРТИРОВАНЫ — собрать
// непустую политику вне пакета `domain` невозможно, это ловит компилятор, а
// не гейт.
package domain_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
)

// rulePolicyTypeName — имя типа политики.
const rulePolicyTypeName = "RulePolicy"

// rulePolicyDeriverName — имя функции вывода политики из строки.
const rulePolicyDeriverName = "PolicyOfRole"

// rulePolicyHomeFile — единственный файл, которому литералы политики законны
// (относительно каталога `internal/domain`, где живёт этот гейт).
const rulePolicyHomeFile = "rule_policy.go"

// rulePolicyCensusFloor — файлов пакета, ниже которого обход беспредметен.
const rulePolicyCensusFloor = 5

// rulePolicySite — место, где политика СОБИРАЕТСЯ (составным литералом) либо
// ВЫВОДИТСЯ (объявлением функции вывода).
type rulePolicySite struct {
	File    string
	Line    int
	Kind    string // "литерал" | "вывод"
	Snippet string
}

// rulePolicyCensus — объём осмотренного. Печатается всегда: «ноль находок»
// обязано быть отличимо от «ноль прочитанного».
type rulePolicyCensus struct {
	FilesRead int
	Literals  int
	Derivers  int
}

// scanRulePolicySites берёт состав каталога `dir` у индекса git и собирает
// места сборки политики. Гейт зовёт её с "." (пакет internal/domain, где
// исполняется тест); инъекция — с синтетическим корнем, чтобы не править
// настоящее дерево. Пробные файлы исключены: проба вправе собрать любую
// политику — она проверяет поведение, а не объявляет его.
func scanRulePolicySites(dir string) ([]rulePolicySite, rulePolicyCensus, error) {
	var (
		sites  []rulePolicySite
		census rulePolicyCensus
	)
	files, err := treecorpus.UnderWithSuffix(dir, ".go")
	if err != nil {
		return nil, census, err
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, rerr := os.ReadFile(path) // #nosec G304 -- имя пришло из обхода ЭТОГО дерева
		if rerr != nil {
			return nil, census, rerr
		}
		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
		if perr != nil {
			return nil, census, perr
		}
		census.FilesRead++
		rel := filepath.Base(path)

		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CompositeLit:
				id, ok := node.Type.(*ast.Ident)
				if !ok || id.Name != rulePolicyTypeName {
					return true
				}
				census.Literals++
				sites = append(sites, rulePolicySite{
					File: rel, Line: fset.Position(node.Pos()).Line,
					Kind: "литерал", Snippet: rulePolicyTypeName + "{…}",
				})
			case *ast.FuncDecl:
				if node.Recv != nil || node.Name == nil || node.Name.Name != rulePolicyDeriverName {
					return true
				}
				census.Derivers++
				sites = append(sites, rulePolicySite{
					File: rel, Line: fset.Position(node.Pos()).Line,
					Kind: "вывод", Snippet: "func " + rulePolicyDeriverName,
				})
			}
			return true
		})
	}
	return sites, census, nil
}

// rulePolicyFindings — предикат находки. Тот же зовёт инъекция.
func rulePolicyFindings(sites []rulePolicySite, census rulePolicyCensus) []string {
	var out []string
	for _, s := range sites {
		if s.Kind == "литерал" && s.File != rulePolicyHomeFile {
			out = append(out, s.File+":"+strconv.Itoa(s.Line)+
				": политика подстановки собирается ВТОРЫМ местом ("+s.Snippet+"). "+
				"Решение «системная ли роль для целей подстановки» принимает "+
				rulePolicyDeriverName+" в "+rulePolicyHomeFile+
				"; второе объявление разойдётся с первым молча — на законном входе "+
				"оба отвечают одинаково")
		}
	}
	if census.Derivers != 1 {
		out = append(out, "объявлений "+rulePolicyDeriverName+" — "+strconv.Itoa(census.Derivers)+
			", а обязано быть ровно одно: перечень политик закрыт ровно тем, что вывод у него один")
	}
	return out
}

// TestRulePolicyIsDerivedInOnePlace — сам гейт.
func TestRulePolicyIsDerivedInOnePlace(t *testing.T) {
	t.Parallel()
	sites, census, err := scanRulePolicySites(".")
	if err != nil {
		t.Fatalf("обход пакета домена не состоялся, вердикта нет ни по одному файлу: %v", err)
	}

	t.Logf("перепись: файлов домена прочитано %d · литералов политики %d · объявлений вывода %d",
		census.FilesRead, census.Literals, census.Derivers)

	if census.FilesRead < rulePolicyCensusFloor {
		t.Fatalf("прочитано файлов %d — обход пуст либо усечён, и молчание гейта было бы "+
			"неотличимо от чистоты", census.FilesRead)
	}
	if census.Literals == 0 {
		t.Fatalf("литералов политики ноль: тип %q переименован или снят, и гейт стережёт "+
			"предмет, которого нет", rulePolicyTypeName)
	}

	if findings := rulePolicyFindings(sites, census); len(findings) > 0 {
		t.Fatalf("политика подстановки объявляется не одним местом:\n%s",
			strings.Join(findings, "\n"))
	}
}
