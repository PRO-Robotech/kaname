// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// platform_import_confined_to_pkg_test.go — из платформенного модуля служба
// импортирует ТОЛЬКО общий фундамент `pkg/` (порт-ЗЕРКАЛО с монорепо
// `internal/repohygiene/standaloneserviceimports_test.go`, снят вынесением
// службы доступа — `kacho#2597`; держатель там был
// `TestStandaloneServiceImportsOnlyTheSharedFoundation`).
//
// # Почему это ЗЕРКАЛО, а не копия
//
// Монорепошный гейт судил ОДНУ сторону разреза: до выноса iam жил ПОДДЕРЕВОМ
// монорепо и обязан был импортировать из него только `pkg/` и себя — предикат
// над `services/iam/...` внутри модуля `kacho`. Разрез СОСТОЯЛСЯ: `services/iam`
// в дереве монорепо больше нет, и этот предикат по буквальной координате
// действительно снят верно (см. `internal/repohygiene/retired_gate_carriers.json`,
// запись `standaloneserviceimports`).
//
// Но у разреза ДВЕ стороны, и вторая ЖИВА: теперь kaname — самостоятельный
// модуль, ссылающийся на `kacho` ВЕРСИОНИРОВАННОЙ зависимостью (`go.mod`,
// `require github.com/PRO-Robotech/kacho`), и класс, ради которого монорепошный
// гейт был написан, — сервис, тянущий из соседа больше объявленного фундамента,
// — воспроизводится ЗЕРКАЛЬНО: тем же импортом, только в обратном направлении.
// Предмет не переехал координатой (кода в монорепо, который можно перенести
// файлом, здесь нет), а воспроизведён заново над своим деревом — тем самым
// способом, каким `internal/supplyhygiene/own_module_test.go` уже воспроизводит
// соседнюю ось того же разреза (собственный самодостаточный модуль).
//
// # Чем это отличается от own_module_test.go — они СОСЕДИ, не дубликаты
//
// `own_module_test.go` (`TestServiceCarriesItsOwnSelfSufficientModule`) судит
// «покрыт ли импорт своим модулем ИЛИ любым объявленным `require`» — широкий
// вопрос сборки вне дерева монорепо. Он МОЛЧАЛ БЫ на гипотетическом
// `github.com/PRO-Robotech/kacho/services/vpc/...`: такой путь покрыт записью
// `require`, значит собирается, — а зависимость от соседнего домена платформы
// это ровно тот класс, который монорепошный `standaloneserviceimports`
// запрещал. Здесь — УЖЕ УЖЕ: единственный законный вход в платформенный модуль
// — префикс `pkg/` (плюс сам корень `pkg`).
//
// # Основания у находки ДВА, и они разной силы — перенесено дословно
//
//	раздел платформенного модуля   что будет                         основание
//	.../internal/**                правило языка Go: путь недостижим  компилятор
//	всё прочее вне pkg/            собирается, но зависимость не та    решение владельца
//
// Первое доказано опытом (см. монорепошную шапку-предшественника): внешний
// модуль с `replace` на дерево платформы не может импортировать её `internal/`
// — рекомпилировать это в kaname незачем, свойство языка от адреса модуля не
// зависит.
//
// # Импорты читаются РАЗБОРОМ, а не поиском по образцу
//
// Путь `github.com/PRO-Robotech/kacho/...` встречается в этом дереве не только
// импортом: он стоит в комментариях (в том числе в шапке этого файла) и в
// строковых литералах синтетических фикстур соседних гейтов. Судится узел
// импорта, полученный `parser.ImportsOnly`, а не текст.
package supplyhygiene

import (
	"fmt"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
)

// platformModulePath — платформенный модуль, чей общий фундамент остаётся
// внешней зависимостью службы.
const platformModulePath = "github.com/PRO-Robotech/kacho"

// platformAllowedPrefixes — то, что из платформенного модуля законно тянуть.
// `pkg/api/...` отдельной записи не требует: это подкаталог `pkg/`.
var platformAllowedPrefixes = []string{"pkg/"}

// platformImportGroundLanguage / platformImportGroundForeign — основания
// находки. Различие несёт исход: элемент пути `internal` закрывает компилятор
// (сборка вне дерева платформы отказывает языком), всё остальное — решение о
// составе внешней зависимости (соберётся, но зависимость не та).
const (
	platformImportGroundLanguage = "правило языка: этот путь платформы недостижим извне её дерева"
	platformImportGroundForeign  = "вне общего фундамента pkg/: этого пути у платформы служба брать не должна"
)

// platformImportFinding — один импорт вне разрешённого фундамента.
type platformImportFinding struct {
	File   string // rel-путь от корня дерева службы
	Line   int
	Import string
	Ground string
}

func (f platformImportFinding) String() string {
	return fmt.Sprintf("%s:%d — %s (%s)", f.File, f.Line, f.Import, f.Ground)
}

// platformImportCensus — объём осмотренного. Печатается всегда: «ноль находок»
// обязано быть отличимо от «ноль прочитанного».
type platformImportCensus struct {
	Files          int
	Imports        int
	PlatformModule int
	Allowed        int
	FindingFiles   int
	FindingEdges   int
	LanguageBound  int
}

func (c platformImportCensus) String() string {
	return fmt.Sprintf("файлов Go %d; импортов %d, из них платформенного модуля %d "+
		"(в разрешённом фундаменте %d); находок — файлов %d, рёбер %d (из них сборка "+
		"откажет языком на %d)",
		c.Files, c.Imports, c.PlatformModule, c.Allowed, c.FindingFiles, c.FindingEdges, c.LanguageBound)
}

// platformImportGround — основание, по которому путь назван находкой.
func platformImportGround(innerPath string) string {
	for _, seg := range strings.Split(innerPath, "/") {
		if seg == "internal" {
			return platformImportGroundLanguage
		}
	}
	return platformImportGroundForeign
}

// scanPlatformImports разбирает импорты файлов службы и возвращает те, что
// тянут из платформенного модуля больше объявленного фундамента.
//
// СОСТАВ ПРИНОСИТ ВЫЗЫВАЮЩИЙ: у настоящего дерева службы авторитет — ИНДЕКС
// git, у синтетики инъекции — обход диска (`treecorpus.SyntheticTree`).
// Обход вынесен из теста, чтобы способность гейта упасть проверялась подачей
// настоящего входа, а не чтением.
func scanPlatformImports(tree *treecorpus.Tree) ([]platformImportFinding, platformImportCensus, error) {
	var census platformImportCensus
	root := tree.Root()

	allowed := make([]string, 0, len(platformAllowedPrefixes))
	for _, p := range platformAllowedPrefixes {
		allowed = append(allowed, platformModulePath+"/"+p)
	}

	var findings []platformImportFinding
	seenFiles := map[string]bool{}
	fset := token.NewFileSet()

	for _, rel := range tree.SortedFiles() {
		if !strings.HasSuffix(rel, ".go") {
			continue
		}
		path := root + "/" + rel
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return nil, census, fmt.Errorf("%s: разбор импортов: %w", rel, err)
		}
		census.Files++
		for _, spec := range f.Imports {
			census.Imports++
			value, unquoteErr := strconv.Unquote(spec.Path.Value)
			if unquoteErr != nil || !strings.HasPrefix(value, platformModulePath+"/") {
				continue // чужой модуль, stdlib или сам платформенный корень — не предмет
			}
			census.PlatformModule++

			ok := false
			for _, a := range allowed {
				if strings.HasPrefix(value, a) {
					ok = true
					break
				}
			}
			if ok {
				census.Allowed++
				continue
			}

			inner := strings.TrimPrefix(value, platformModulePath+"/")
			ground := platformImportGround(inner)
			if ground == platformImportGroundLanguage {
				census.LanguageBound++
			}
			census.FindingEdges++
			seenFiles[rel] = true
			findings = append(findings, platformImportFinding{
				File: rel, Line: fset.Position(spec.Path.Pos()).Line,
				Import: value, Ground: ground,
			})
		}
	}
	census.FindingFiles = len(seenFiles)
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Line < findings[j].Line
	})
	return findings, census, nil
}

// TestPlatformImportsAreConfinedToTheSharedFoundation — сам гейт.
func TestPlatformImportsAreConfinedToTheSharedFoundation(t *testing.T) {
	t.Parallel()
	if len(platformAllowedPrefixes) == 0 {
		t.Fatal("разрешённый фундамент пуст — тогда находкой становится КАЖДЫЙ импорт " +
			"платформенного модуля, и гейт краснеет на верном дереве")
	}

	tree, err := treecorpus.NewTree(serviceRoot)
	if err != nil {
		t.Fatalf("состав дерева службы (%s) не прочитан у индекса — вердикт беспредметен: "+
			"обход диска вместо индекса читал бы каталоги, которых в репозитории нет",
			serviceRoot)
	}

	findings, census, err := scanPlatformImports(tree)
	if err != nil {
		t.Fatalf("обход дерева службы: %v", err)
	}

	t.Logf("перепись: %s", census)

	if census.Files == 0 {
		t.Fatal("обход пуст: файлов Go не разобрано ни одного — вердикт беспредметен")
	}
	if census.Imports == 0 {
		t.Fatal("обход пуст: импортов не осмотрено ни одного — вердикт беспредметен")
	}
	// Предпосылка: служба ВООБЩЕ импортирует платформенный модуль. Ноль означал
	// бы, что зависимость снята целиком, и «фундамент не превышен» стало бы
	// утверждением ни о чём — тогда эту пробу снимают вместе с предметом, а не
	// оставляют зелёной вхолостую.
	if census.PlatformModule == 0 {
		t.Fatalf("платформенных импортов не найдено ни одного — либо зависимость от %s "+
			"снята целиком (тогда снимите этот гейт вместе с её предметом), либо разбор "+
			"больше не видит платформенный путь", platformModulePath)
	}

	for _, f := range findings {
		t.Errorf("%s:%d — %q за пределами общего фундамента (%s): служба ссылается на "+
			"платформенный модуль %s ВЕРСИОНИРОВАННОЙ зависимостью, и законный вход в него "+
			"— только %v. %s",
			f.File, f.Line, f.Import, f.Ground, platformModulePath, platformAllowedPrefixes, f)
	}
}
