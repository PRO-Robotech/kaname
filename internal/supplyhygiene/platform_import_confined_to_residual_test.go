// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// platform_import_confined_to_residual_test.go — из платформенного модуля служба
// импортирует ТОЛЬКО НАЗВАННЫЙ ОСТАТОК, а общий фундамент берёт из модуля
// фундамента (порт-ЗЕРКАЛО с монорепо
// `internal/repohygiene/standaloneserviceimports_test.go`, снят вынесением
// службы доступа — `kacho#2597`; держатель там был
// `TestStandaloneServiceImportsOnlyTheSharedFoundation`).
//
// # Почему ПЕРЕЧЕНЬ, а не префикс `pkg/`
//
// Прежняя редакция разрешала из платформенного модуля ВСЁ поддерево `pkg/`, и на
// день своего заведения это было верно: общий фундамент физически лежал там.
// Решением владельца фундамент выделен отдельным модулем
// (`github.com/PRO-Robotech/corelib`), и после этого широкий префикс стал
// молчать на том самом классе, ради которого гейт написан: импорт
// `github.com/PRO-Robotech/kacho/pkg/db` покрыт префиксом `pkg/` — значит зелен,
// — а зависеть служба обязана от ФУНДАМЕНТА, общего для обеих сторон, а не от
// платформы. Целевое направление — `corelib ← kaname ← kacho`; всякое ребро
// `kaname → kacho` его разворачивает.
//
// Поэтому законный вход в платформенный модуль теперь ВЫПИСАН ПОИМЕННО, и у
// каждой записи назван предикат снятия. Перечень — это не послабление, а
// ВЕДОМОСТЬ ОСТАТКА: она сходится к пустоте, и каждая её запись обязана
// сопровождаться работой, которая её снимет.
//
// # Чем это отличается от own_module_test.go — они СОСЕДИ, не дубликаты
//
// `own_module_test.go` (`TestServiceCarriesItsOwnSelfSufficientModule`) судит
// «покрыт ли импорт своим модулем ИЛИ любым объявленным `require`» — широкий
// вопрос сборки вне дерева монорепо. Он молчит на `kacho/pkg/db`: путь покрыт
// записью `require`, значит собирается. Здесь — УЖЕ: законный вход в
// платформенный модуль ограничен перечнем остатка.
//
// Он же несёт и обратную половину этой проверки: импорт модуля фундамента обязан
// быть покрыт `require`, иначе сборка вне дерева отказывает. Второго экземпляра
// той проверки здесь нет намеренно.
//
// # Основания у находки ТРИ, и они разной силы — первые два перенесены дословно
//
//	раздел платформенного модуля   что будет                          основание
//	.../internal/**                правило языка Go: путь недостижим   компилятор
//	всё прочее вне остатка          собирается, но зависимость не та    решение владельца
//
// Первое доказано опытом (см. монорепошную шапку-предшественника): внешний
// модуль с `replace` на дерево платформы не может импортировать её `internal/`
// — рекомпилировать это в kaname незачем, свойство языка от адреса модуля не
// зависит.
//
// # Класс каталога здесь НЕ вычисляется, и это намеренно
//
// Какой пакет относится к фундаменту, а какой к платформе, решает карта приёмки
// K3-1 — источник ОДИН, и вторым экземпляром он тут не выписывается: разойдясь с
// ним, копия объявляла бы находкой законное. Гейт судит ровно то, что умеет
// судить сам: путь либо назван в остатке, либо нет.
//
// # Импорты читаются РАЗБОРОМ, а не поиском по образцу
//
// Путь `github.com/PRO-Robotech/kacho/...` встречается в этом дереве не только
// импортом: он стоит в комментариях (в том числе в шапке этого файла) и в
// строковых литералах синтетических фикстур соседних гейтов. Замер по стволу на
// день правки: поиск по тексту находит `kacho/internal/dropguard`,
// `kacho/services/vpc/domain`, `kacho/pkg/thing` и
// `kacho/services/iam/internal/repo/prevhome/pg/resource_mirror` — узлом импорта
// не является НИ ОДИН из четырёх, все четыре живут внутри строк фикстур.
// Судится узел импорта, полученный `parser.ImportsOnly`, а не текст.
package supplyhygiene

import (
	"fmt"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
)

// platformModulePath — платформенный модуль, чей остаток пока остаётся внешней
// зависимостью службы.
const platformModulePath = "github.com/PRO-Robotech/kacho"

// foundationModulePath — модуль фундамента, общий для службы и платформы. Ребро
// службы обязано идти сюда, а не в платформу.
const foundationModulePath = "github.com/PRO-Robotech/corelib"

// platformResidualEntry — одна запись ведомости остатка: путь внутри
// платформенного модуля и основание, по которому он ещё законен.
type platformResidualEntry struct {
	// Path — путь ВНУТРИ платформенного модуля, без имени модуля. Покрывает сам
	// путь и его поддерево.
	Path string
	// Ground — почему запись ещё здесь и чем снимается. Запись без предиката
	// снятия — послабление без срока, то есть ровно тот класс, который этот
	// гейт и ловит.
	Ground string
}

// platformResidual — ВСЁ, что из платформенного модуля служба берёт законно.
// Перечень сходится к пустоте; каждая запись снимается своей работой.
var platformResidual = []platformResidualEntry{
	{
		Path: "pkg/api/kaname/cloud/iam/v1",
		Ground: "контракты САМОЙ службы. Решением владельца (2026-09-13, дословно: «прото так же " +
			"должно уехать в канаме то что к нему относится в качо их не должно быть») они " +
			"уезжают в этот репозиторий, и у платформы их не остаётся вовсе — то есть запись " +
			"снимается не выбором, а вливанием соседней полосы (kacho#2131). ЭТО " +
			"ЕДИНСТВЕННЫЙ путь остатка, чьё снятие принадлежит чужому изменению",
	},
	{
		Path: "pkg/ownerregister",
		Ground: "производитель родительской цепи владения — ОДИН, и живёт он у платформы. " +
			"Приёмка K3-1 относит каталог к классу `kaname` (вопрос 3: меняется с контрактом " +
			"доступа), то есть его дом — этот репозиторий, и платформа станет его потребителем. " +
			"Своя копия цепи здесь разошлась бы с производителем молча, поэтому до переезда " +
			"импорт законен. Снимается kacho#2614",
	},
	{
		Path: "pkg/subjectchange",
		Ground: "контракт журнала смен субъекта: потерянная позиция, порог уборки, читатель. " +
			"Служба его ПРОИЗВОДИТ, платформенный край — потребляет; приёмка K3-1 относит " +
			"каталог к классу `kaname` (вопрос 3), то есть дом — этот репозиторий. Переезд " +
			"упирается в контракты: `reader.go` привязан к ним, и до их переезда копия здесь " +
			"тянула бы платформенный путь заново. Снимается kacho#2614",
	},
}

// platformImportGroundLanguage / platformImportGroundForeign — основания
// находки. Различие несёт исход: элемент пути `internal` закрывает компилятор
// (сборка вне дерева платформы отказывает языком), всё остальное — решение о
// составе внешней зависимости (соберётся, но зависимость не та).
const (
	platformImportGroundLanguage = "правило языка: этот путь платформы недостижим извне её дерева"
	platformImportGroundForeign  = "вне названного остатка: этого пути у платформы служба брать не должна"
)

// platformImportFinding — один импорт вне названного остатка.
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
	Foundation     int
	Allowed        int
	FindingFiles   int
	FindingEdges   int
	LanguageBound  int
	// PerResidual — сколько импортов пришлось на каждую запись ведомости.
	// Запись с нулём — исключение, которому нечего исключать.
	PerResidual map[string]int
}

func (c platformImportCensus) String() string {
	used := make([]string, 0, len(c.PerResidual))
	for _, e := range platformResidual {
		used = append(used, fmt.Sprintf("%s=%d", e.Path, c.PerResidual[e.Path]))
	}
	return fmt.Sprintf("файлов Go %d; импортов %d, из них платформенного модуля %d "+
		"(в названном остатке %d: %s), модуля фундамента %d; находок — файлов %d, рёбер %d "+
		"(из них сборка откажет языком на %d)",
		c.Files, c.Imports, c.PlatformModule, c.Allowed, strings.Join(used, " "),
		c.Foundation, c.FindingFiles, c.FindingEdges, c.LanguageBound)
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

// residualCovering — запись ведомости, покрывающая путь внутри платформенного
// модуля, либо пустая строка.
func residualCovering(innerPath string) string {
	for _, e := range platformResidual {
		if innerPath == e.Path || strings.HasPrefix(innerPath, e.Path+"/") {
			return e.Path
		}
	}
	return ""
}

// scanPlatformImports разбирает импорты файлов службы и возвращает те, что тянут
// из платформенного модуля больше названного остатка. Импорты модуля фундамента
// считаются отдельно: это ПАРНЫЙ контроль, без которого ноль находок неотличим
// от «разбор перестал читать».
//
// СОСТАВ ПРИНОСИТ ВЫЗЫВАЮЩИЙ: у настоящего дерева службы авторитет — ИНДЕКС
// git, у синтетики инъекции — обход диска (`treecorpus.SyntheticTree`).
// Обход вынесен из теста, чтобы способность гейта упасть проверялась подачей
// настоящего входа, а не чтением.
func scanPlatformImports(tree *treecorpus.Tree) ([]platformImportFinding, platformImportCensus, error) {
	census := platformImportCensus{PerResidual: map[string]int{}}
	root := tree.Root()

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
			if unquoteErr != nil {
				continue
			}
			if value == foundationModulePath || strings.HasPrefix(value, foundationModulePath+"/") {
				census.Foundation++
				continue
			}
			if !strings.HasPrefix(value, platformModulePath+"/") {
				continue // чужой модуль, stdlib или сам платформенный корень — не предмет
			}
			census.PlatformModule++

			inner := strings.TrimPrefix(value, platformModulePath+"/")
			if covering := residualCovering(inner); covering != "" {
				census.Allowed++
				census.PerResidual[covering]++
				continue
			}

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

// TestPlatformResidualLedgerIsWellFormed — ведомость остатка судится раньше
// дерева: перечень, у записи которого нет основания, либо запись, вложенная в
// соседнюю, расширяют разрешённое молча.
func TestPlatformResidualLedgerIsWellFormed(t *testing.T) {
	t.Parallel()
	if len(platformResidual) == 0 {
		t.Fatal("ведомость остатка пуста — тогда находкой становится КАЖДЫЙ импорт " +
			"платформенного модуля; если остатка действительно нет, гейт снимают вместе " +
			"с его предметом, а не оставляют краснеть на верном дереве")
	}
	for _, e := range platformResidual {
		if strings.TrimSpace(e.Ground) == "" {
			t.Errorf("запись остатка %q без основания: послабление без предиката снятия "+
				"переживает свою причину", e.Path)
		}
		if strings.HasPrefix(e.Path, platformModulePath) {
			t.Errorf("запись остатка %q несёт имя модуля: путь пишется ВНУТРИ модуля, "+
				"иначе покрытие не сработает ни на одном импорте", e.Path)
		}
	}
	for i, a := range platformResidual {
		for j, b := range platformResidual {
			if i == j {
				continue
			}
			if a.Path == b.Path || strings.HasPrefix(b.Path, a.Path+"/") {
				t.Errorf("запись остатка %q вложена в %q: вложенная не судится ничем, "+
					"и её основание перестаёт читаться", b.Path, a.Path)
			}
		}
	}
}

// TestPlatformImportsAreConfinedToTheNamedResidual — сам гейт.
func TestPlatformImportsAreConfinedToTheNamedResidual(t *testing.T) {
	t.Parallel()

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
	// ПАРНЫЙ КОНТРОЛЬ. Ноль находок сам по себе неотличим от «разбор перестал
	// видеть путь»: ровно поэтому рядом стоит число импортов ФУНДАМЕНТА. Ноль
	// здесь означает, что служба не берёт общий фундамент ниоткуда, — то есть
	// либо разбор ослеп, либо ребро завели вторым путём.
	// Отказ здесь — Errorf, а не Fatalf, и это несёт смысл: ноль импортов
	// фундамента есть находка О ДЕРЕВЕ, а не признак нечитаемого вердикта, и
	// прогон обязан назвать её ВМЕСТЕ с находками остатка. Fatal оборвал бы
	// перечень рёбер, ради которого гейт и заведён.
	if census.Foundation == 0 {
		t.Errorf("импортов модуля фундамента (%s) не найдено ни одного: служба обязана "+
			"брать общий фундамент оттуда. Ноль означает либо что разбор перестал видеть "+
			"путь, либо что фундамент тянут вторым путём", foundationModulePath)
	}
	// Предпосылка: служба ВООБЩЕ импортирует платформенный модуль. Ноль означал
	// бы, что остаток исчерпан, и «остаток не превышен» стало бы утверждением ни
	// о чём — тогда эту пробу снимают вместе с предметом, а не оставляют зелёной
	// вхолостую.
	if census.PlatformModule == 0 {
		t.Fatalf("платформенных импортов не найдено ни одного — либо зависимость от %s "+
			"снята целиком (тогда снимите этот гейт вместе с её предметом), либо разбор "+
			"больше не видит платформенный путь", platformModulePath)
	}
	// Исключение, которому нечего исключать, — находка: оно переживает свою
	// причину и разрешает вперёд то, чего никто не решал.
	for _, e := range platformResidual {
		if census.PerResidual[e.Path] == 0 {
			t.Errorf("запись остатка %q не покрывает НИ ОДНОГО импорта: исключению нечего "+
				"исключать, снимите запись. Основание, которое она несла: %s", e.Path, e.Ground)
		}
	}

	for _, f := range findings {
		t.Errorf("%s:%d — %q вне названного остатка (%s): служба ссылается на платформенный "+
			"модуль %s ВЕРСИОНИРОВАННОЙ зависимостью, и целевое направление "+
			"`corelib ← kaname ← kacho` такое ребро разворачивает. Общий фундамент берётся "+
			"из %s; законный вход в платформу — только ведомость остатка. %s",
			f.File, f.Line, f.Import, f.Ground, platformModulePath, foundationModulePath, f)
	}
}
