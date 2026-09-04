// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package check

// request_path_module_set_test.go — гейт «путь запроса спрашивает членство
// модуля у ЖИВЫХ СТРОК, а не у набора, вкомпилированного в двоичный файл»
// (kacho#1927).
//
// # Что задача купила и чем это НЕ удержано
//
// Задача сняла литерал `domain.knownModules` — закрытый перечень шести имён,
// который путь запроса спрашивал на создании и правке роли. Членство отвечают
// теперь строки `catalog_module`, читаемые снимком каталога, поэтому снятый
// модуль перестаёт приниматься за один период обновления снимка, БЕЗ
// перезапуска службы, а заведённый строкой начинает приниматься БЕЗ релиза.
//
// Само по себе снятие литерала свойства не держит. В дереве остался ВТОРОЙ
// набор тех же шести имён — канон `authzmap.CatalogSeedModules()`, — и он
// экспортирован, задокументирован и законно спрашивается соседями. Передать его
// валидатору из use-case'а пути запроса:
//
//	r.Rules.Validate(policy, domain.ModuleSetOf(authzmap.CatalogSeedModules()...))
//
// значит вернуть дефект ЦЕЛИКОМ — снятие модуля снова перестаёт доезжать до
// пути запроса, — и это СОБИРАЕТСЯ, проходит все пробы сервиса и не краснит ни
// один гейт дерева. Замер 2026-09-02: подстановка выше внесена в
// `role/create.go`, прогнаны `services/iam/internal/check`,
// `internal/repohygiene` (образцы `Module|Catalog|ClientTruth|ModuleSet`) и
// пакет самой роли — находок НОЛЬ.
//
// # Почему предикат задачи переписан
//
// Тело задачи называло предикатом «инъекция возвращает ЛИТЕРАЛ и краснеет».
// Такой гейт судил бы ИМЯ снятого объявления и молчал бы на канонe — форме,
// которая (а) уже в дереве, (б) экспортирована, (в) законна у соседей, то есть
// на единственной форме, в которой дефект реально возвращается. Предикат
// заменён на СВОЙСТВО: на пути запроса нет набора модулей, вкомпилированного в
// двоичный файл, ни в одной из форм, которыми он выразим.
//
// # Досягаемость пути запроса — ДВА поддерева, и они названы слоем
//
//	services/iam/internal/domain            чистый домен: его достигает КАЖДЫЙ RPC
//	services/iam/internal/apps/kacho/api    слой use-case, обслуживающий RPC
//
// Это имена СЛОЁВ (`architecture.md`), а не перечень файлов, поэтому список не
// стареет вместе с деревом. Переедет слой — обход опустеет, и гейт откажет, а не
// смолчит.
//
// # Чего гейт НЕ судит, и это решение, а не пропуск
//
// Вне досягаемости — применитель ролей модуля (`apps/kacho/moduleroles`), страж
// паритета (`apps/kacho/seed`), загрузчик манифеста (`manifest`) и оснастка
// дерева (`modelrender`). Все они спрашивают канон ЗАКОННО: их вопрос — «объявлен
// ли модуль платформой», и ответ обязан быть воспроизводим ИЗ ДЕРЕВА, потому что
// у них базы нет by construction. Разведение двух вопросов — решение #1927,
// записанное в `domain/module_set.go`; гейт его исполняет, а не пересматривает.
// Молчание на каждом из четырёх доказано инъекцией, а не заявлено здесь.
//
// # Гейт судит УЗЕЛ РАЗБОРА, а не слово, и цена этого ИЗМЕРЕНА
//
// Имя канона встречается в досягаемости ДВАЖДЫ — и оба раза в комментарии,
// объясняющем как раз это устройство (`domain/module_set.go`,
// `domain/derived_id.go`). Предикат по подстроке краснел бы на СОБСТВЕННОМ
// объяснении проверяемого; разбор даёт ноль. Обе величины печатаются переписью
// рядом, чтобы решение было видно, а не подразумевалось.
//
// # Границы, названные вслух
//
// Точечный импорт (`. "…/authzmap"`) выражения выбора не даёт и потому этим
// гейтом неразличим. В дереве такой формы нет; появившись, она обязана быть
// запрещена своим изменением, а не проглочена этим.
//
// Набор, СОБРАННЫЙ в рантайме (прочитанный из файла, склеенный из переменных),
// не ловится ничем: это остаток, а не покрытие. Он назван здесь, чтобы «ноль
// находок» не читалось шире, чем есть.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/internal/treecorpus"
	"github.com/PRO-Robotech/kacho/pkg/platformmodules"
)

// requestPathReach — поддеревья, которые достигает путь запроса. Пути от корня
// монорепо.
var requestPathReach = []string{
	"services/iam/internal/domain",
	"services/iam/internal/apps/kacho/api",
}

// canonImportPath — пакет, чей канон набора модулей выводится ИЗ ДЕРЕВА.
const canonImportPath = "github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"

// canonModuleSymbol — производитель канона. Один символ, а не набор: остальные
// экспортированные имена пакета отвечают на другие вопросы, и запрещать их
// здесь значило бы судить импорт, а не предмет.
const canonModuleSymbol = "CatalogSeedModules"

// spellingsImportPath — словарь написаний модулей платформы. Тот же класс, что
// канон: набор, вкомпилированный в двоичный файл. На пути запроса не читается ни
// одним файлом (перепись это печатает), и запрет вооружает наблюдение вперёд.
const spellingsImportPath = "github.com/PRO-Robotech/kacho/pkg/platformmodules"

// namesInARowIsASet — сколько имён модулей подряд в ОДНОЙ последовательности
// выражений считать объявлением набора.
//
// Порог, а не единица: пара имён — законная форма («vpc/compute остаются
// label-selectable»), и гейт, у которого находки ложные, отключают первым. Тот
// же порог и по той же причине держит соседний анализатор клиентских
// поверхностей (`internal/repohygiene/clienttruth_iam_moduleset.go`).
//
// Замер по досягаемости на день заведения: последовательностей с ДВУМЯ именами
// — ноль, с тремя и более — ноль. Молчание на паре доказано инъекцией, а не этим
// числом.
const namesInARowIsASet = 3

// moduleNameVocabulary — имена модулей платформы, по которым узнаётся
// вкомпилированный набор. ВЫВОДЯТСЯ из единственного объявления написаний, а не
// выписываются: рукописная копия разошлась бы с ним молча, а сам словарь сверяет
// с деревом гейт `internal/repohygiene` `TestPlatformModuleVocabularyMatchesTheTree`.
//
// Берётся написание КАТАЛОГА (`loadbalancer`, не `nlb`): именно им клиент
// выражает грант, и именно оно стояло в снятом литерале.
func moduleNameVocabulary() map[string]bool {
	v := make(map[string]bool)
	for _, m := range platformmodules.All() {
		v[m.CatalogModule] = true
	}
	return v
}

// compiledSetUse — одно распознанное обращение к вкомпилированному набору.
type compiledSetUse struct {
	File   string // путь от корня монорепо
	Line   int
	Reason string
}

// reachCensus — объём осмотренного. Печатается ВСЕГДА и независимо от исхода:
// «ноль находок» обязано быть отличимо от «ноль прочитанного».
type reachCensus struct {
	Files       int // прод-файлы досягаемости
	Parsed      int // из них разобрано
	ExprSeqs    int // последовательностей выражений осмотрено
	NameLits    int // строковых литералов — имён модулей — увидено
	CanonByWord int // упоминаний канона ПО СЛОВУ (включая прозу)
	CanonByNode int // он же ПО УЗЛУ разбора
}

func (c reachCensus) Summary() string {
	return fmt.Sprintf(
		"прод-файлов досягаемости %d · разобрано %d · последовательностей выражений %d · "+
			"строковых имён модулей %d · канон по слову %d, по узлу %d",
		c.Files, c.Parsed, c.ExprSeqs, c.NameLits, c.CanonByWord, c.CanonByNode)
}

// compiledModuleSetUses разбирает ПЕРЕЧЕНЬ файлов и возвращает обращения к
// вкомпилированному набору модулей.
//
// СОСТАВ ПРИХОДИТ ПАРАМЕТРОМ по тем же двум причинам, что у соседа
// (`literal_is_not_a_read_source_test.go`): в живом дереве его обязан давать
// индекс git, а инъекция подаёт синтетический перечень — доказательство,
// требующее испортить живое дерево, в конвейере не исполняется никогда.
func compiledModuleSetUses(root string, files []string) (uses []compiledSetUse, c reachCensus, err error) {
	vocab := moduleNameVocabulary()
	fset := token.NewFileSet()
	for _, path := range files {
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			continue
		}
		c.Files++
		src, rerr := os.ReadFile(path) // #nosec G304 -- путь приходит из индекса дерева
		if rerr != nil {
			return nil, c, fmt.Errorf("прочитать %s: %w", path, rerr)
		}
		c.CanonByWord += strings.Count(string(src), canonModuleSymbol)

		file, perr := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
		if perr != nil {
			return nil, c, fmt.Errorf("разобрать %s: %w", path, perr)
		}
		c.Parsed++

		rel, rerr2 := filepath.Rel(root, path)
		if rerr2 != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)

		add := func(pos token.Pos, reason string) {
			uses = append(uses, compiledSetUse{File: rel, Line: fset.Position(pos).Line, Reason: reason})
		}

		// (1) КАНОН — выражение выбора через ЛОКАЛЬНОЕ имя импорта.
		if local := localNameOfImportPath(file, canonImportPath); local != "" {
			ast.Inspect(file, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				ident, ok2 := sel.X.(*ast.Ident)
				if !ok2 || ident.Name != local || sel.Sel.Name != canonModuleSymbol {
					return true
				}
				c.CanonByNode++
				add(sel.Sel.Pos(), fmt.Sprintf(
					"канон дерева %s.%s на пути запроса: он не меняется без релиза, "+
						"поэтому снятие модуля перестаёт доезжать до проверки правила",
					local, canonModuleSymbol))
				return true
			})
		}

		// (2) СЛОВАРЬ НАПИСАНИЙ — сам факт импорта: весь его смысл есть
		// вкомпилированный перечень модулей, поэтому запрещается импорт, а не
		// отдельный символ.
		if local := localNameOfImportPath(file, spellingsImportPath); local != "" {
			for _, imp := range file.Imports {
				if p, uerr := strconv.Unquote(imp.Path.Value); uerr == nil && p == spellingsImportPath {
					add(imp.Pos(), "словарь написаний модулей платформы на пути запроса: "+
						"тот же вкомпилированный набор, только другим именем")
				}
			}
		}

		// (3) ПЕРЕЧЕНЬ ИМЁН — три и более имени модуля строковыми литералами в
		// одной последовательности выражений. Судятся ОБЕ формы, которыми набор
		// записывается: элементы составного литерала и аргументы вызова
		// (`domain.ModuleSetOf("iam", "vpc", …)` — вариадический вызов, а не
		// составной литерал, и распознаватель, знающий только вторую форму,
		// молчал бы на первой).
		ast.Inspect(file, func(n ast.Node) bool {
			var seq []ast.Expr
			var pos token.Pos
			switch x := n.(type) {
			case *ast.CompositeLit:
				seq, pos = x.Elts, x.Pos()
			case *ast.CallExpr:
				seq, pos = x.Args, x.Pos()
			default:
				return true
			}
			c.ExprSeqs++
			names := 0
			for _, e := range seq {
				lit, ok := e.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				s, uerr := strconv.Unquote(lit.Value)
				if uerr != nil || !vocab[s] {
					continue
				}
				c.NameLits++
				names++
			}
			if names >= namesInARowIsASet {
				add(pos, fmt.Sprintf(
					"перечень из %d имён модулей на пути запроса: набор, вписанный в Go, "+
						"членство обязаны отвечать строки каталога", names))
			}
			return true
		})
	}
	sort.Slice(uses, func(i, j int) bool {
		if uses[i].File != uses[j].File {
			return uses[i].File < uses[j].File
		}
		return uses[i].Line < uses[j].Line
	})
	return uses, c, nil
}

// localNameOfImportPath — ЛОКАЛЬНОЕ имя, под которым файл импортировал путь;
// пустая строка означает «файл его не импортирует».
//
// Своя копия рядом с `localNameOfImport` соседа не заводится наспех: тот пиннит
// умолчание именем `authzmap` константой и о втором пакете не знает. Здесь
// умолчание — последний сегмент пути, что верно для обоих судимых пакетов.
// Псевдоним учитывается: гейт, знающий одно написание, не увидел бы
// `am "…/authzmap"` — форму столь же законную.
func localNameOfImportPath(file *ast.File, path string) string {
	for _, imp := range file.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || p != path {
			continue
		}
		if imp.Name != nil {
			if imp.Name.Name == "_" || imp.Name.Name == "." {
				return ""
			}
			return imp.Name.Name
		}
		return path[strings.LastIndex(path, "/")+1:]
	}
	return ""
}

// requestPathFiles — состав досягаемости ИЗ ИНДЕКСА дерева.
func requestPathFiles(root string) ([]string, error) {
	var all []string
	for _, rel := range requestPathReach {
		files, err := treecorpus.UnderWithSuffix(filepath.Join(root, rel), ".go")
		if err != nil {
			return nil, err
		}
		all = append(all, files...)
	}
	return all, nil
}

// TestIAM1927_RequestPathAsksLiveRowsForModuleMembership — гейт задачи #1927.
func TestIAM1927_RequestPathAsksLiveRowsForModuleMembership(t *testing.T) {
	root := catalogRepoRoot(t)

	files, err := requestPathFiles(root)
	if err != nil {
		t.Fatalf("%v", err)
	}
	uses, census, err := compiledModuleSetUses(root, files)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Перепись — ДО вердикта и независимо от него.
	t.Logf("досягаемость пути запроса: %s", strings.Join(requestPathReach, " · "))
	t.Logf("%s", census.Summary())

	// Обход пуст ⇒ вердикт беспредметен.
	if census.Parsed == 0 {
		t.Fatalf("обход не разобрал НИ ОДНОГО прод-файла под %s — вердикт беспредметен: "+
			"«ноль находок» здесь неотличимо от «ноль прочитанного». Слой переехал — "+
			"переезжает и досягаемость, в том же изменении",
			strings.Join(requestPathReach, " · "))
	}
	// Распознаватель последовательностей обязан быть доказуемо живым: слой
	// use-case из полутора сотен файлов без единого вызова невозможен, и ноль
	// здесь означает сломанный разбор, а не чистое дерево.
	if census.ExprSeqs == 0 {
		t.Fatalf("осмотрено ноль последовательностей выражений при %d разобранных файлах — "+
			"это отказ РАЗБОРА, а не чистое дерево", census.Parsed)
	}

	for _, u := range uses {
		t.Errorf("%s:%d — %s", u.File, u.Line, u.Reason)
	}
	if len(uses) > 0 {
		t.Logf("членство модуля на пути запроса отвечает СНИМОК каталога " +
			"(`catalog.Facts`, взятый у use-case'а как `u.cat.Facts()`), а канон — " +
			"левая сторона паритета: его спрашивают страж старта, применитель ролей и " +
			"оснастка дерева, у которой базы нет by construction (решение #1927, " +
			"`services/iam/internal/domain/module_set.go`)")
	}
}
