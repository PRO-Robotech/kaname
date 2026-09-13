// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// migrator_verb_roster_test.go — перечень подкоманд накатчика, названный прозой
// и текстом отказа, сходится с деревом команд.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ (kaname#38)
//
// Три места дерева называли накатчику четыре подкоманды — `up`, `down`,
// `status` и `create`. Конструкторов в дереве три, и четвёртого нет НЕ по
// недосмотру: отсутствие `create` объявлено решением в шапке самого накатчика
// (имя миграции пишет автор, инструмент принял бы форму молча и всегда
// одинаково).
//
// То есть два места об одном предмете, и верно то, которое исполняется. Хуже
// прочего было третье вхождение: не проза, а ТЕКСТ ОТКАЗА, велящий оператору
// звать несуществующий глагол. Оператор, попробовавший `kaname-migrator create`,
// получает второй отказ — по неизвестной подкоманде — и остаётся без пути
// дальше.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ГЕЙТ, А НЕ ТРИ ПРАВКИ
//
// Пробы накатчика утверждают НАЛИЧИЕ трёх подкоманд и ничего не говорят об
// отсутствии четвёртой. Держателя на ПЕРЕЧЕНЬ не было ни одного, поэтому проза
// и дерево разошлись молча и прожили так до адъюдикации. Заведут четвёртую
// команду — перечни разойдутся снова, теперь в обратную сторону, и заметить это
// будет нечем ровно так же.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ИМЕННО УТВЕРЖДАЕТСЯ
//
// Всякий ПЕРЕЧЕНЬ на строке, называющей двоичный файл накатчика, совпадает как
// МНОЖЕСТВО с набором подкоманд, зарегистрированных у корневой команды. Обе
// стороны обязательны: лишний глагол в прозе — обещание несуществующего,
// недостающий — умолчание о существующем.
//
// Имя двоичного файла и набор подкоманд берутся у ПРОИЗВОДИТЕЛЯ — разбором
// `cmd/migrator/main.go`, — а не выписываются. Выписанный набор разошёлся бы с
// деревом тем же способом, каким разошлась проза.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ РАЗБОР, А НЕ ПОИСК ПО ТЕКСТУ
//
// Конструктор, объявленный и НЕ зарегистрированный, подкомандой не является:
// оператор его не позовёт. Поэтому набор берётся по узлу РЕГИСТРАЦИИ
// (`root.AddCommand(...)`), а не по именам функций и не по числу литералов
// `cobra.Command` в файле.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ЭТА ПРОВЕРКА НЕ ЗАКРЫВАЕТ — сказано прямо
//
//  1. Суждение ПООКОННО: перечень и имя двоичного файла обязаны стоять на одной
//     строке. Перечень, отнесённый абзацем ниже имени, ось не видит — и это
//     граница, а не слепота: строка, не называющая накатчика, принадлежит
//     чужому перечню, а сужать её нечем.
//  2. Флаги (`--target`, `--dsn`) предметом оси не являются: их держат пробы
//     самого накатчика.
//  3. Проза БЕЗ перечня («накатчик умеет создавать миграции») машинного
//     предиката не имеет — это суждение о смысле, и здесь оно не обещается.
package supplyhygiene

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/stretchr/testify/require"
)

// migratorCommandFile — единственная точка сборки CLI накатчика: и корневая
// команда, и регистрация подкоманд объявлены здесь.
const migratorCommandFile = "cmd/migrator/main.go"

// cobraCommandType — тип литерала, чьё поле `Use` несёт имя команды.
const cobraCommandType = "cobra.Command"

// addCommandSelector — узел РЕГИСТРАЦИИ подкоманды у корневой команды.
const addCommandSelector = "AddCommand"

// verbRoster — ПЕРЕЧЕНЬ: два и более слова, соединённые `|` либо `/` без
// пробелов, закрытые скобкой прозы. Обе половины формы несущие.
//
// Закрывающая скобка отсекает ПУТИ: `$TMP/mig-ok/kaname-migrator` — такой же
// набор слов через косую черту, и без этого условия ось краснела бы на каждой
// строке сборочного скрипта, называющей накатчик по пути. Запрет на ведущую
// косую черту отсекает вторую половину того же класса (`/usr/local/bin/…`).
var verbRoster = regexp.MustCompile(
	"(?:^|[^/A-Za-z0-9_.-])(`?[a-z][a-z0-9-]{1,15}`?(?:[|/]`?[a-z][a-z0-9-]{1,15}`?)+)[)\\]}]")

// migratorProducerCensus — объём осмотренного у ПРОИЗВОДИТЕЛЯ набора.
type migratorProducerCensus struct {
	commandLiterals int
	registrations   int
	verbs           int
}

// rosterFinding — одно попадание: координата и расхождение множеств.
type rosterFinding struct {
	file    string
	line    int
	roster  []string
	missing []string
	extra   []string
}

// migratorRosterCensus — объём осмотренного по дереву.
type migratorRosterCensus struct {
	filesTracked int
	filesRead    int
	linesScanned int
	namingLines  int
	rostersSeen  int
}

// commandUse — первое слово поля `Use` у литерала `cobra.Command`. Первое
// слово, а не строка целиком: cobra принимает в `Use` форму вызова с
// аргументами (`up [--target]`), и именем команды является её голова.
func commandUse(lit *ast.CompositeLit) (string, bool) {
	sel, ok := lit.Type.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name+"."+sel.Sel.Name != cobraCommandType {
		return "", false
	}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != "Use" {
			continue
		}
		basic, ok := kv.Value.(*ast.BasicLit)
		if !ok || basic.Kind != token.STRING {
			continue
		}
		unquoted, err := strconv.Unquote(basic.Value)
		if err != nil {
			return "", false
		}
		fields := strings.Fields(unquoted)
		if len(fields) == 0 {
			return "", false
		}
		return fields[0], true
	}
	return "", false
}

// firstCommandUseIn — имя команды, объявленной первым литералом `cobra.Command`
// внутри этого объявления функции.
func firstCommandUseIn(decl *ast.FuncDecl) (string, bool) {
	var (
		name  string
		found bool
	)
	ast.Inspect(decl, func(n ast.Node) bool {
		if found {
			return false
		}
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if use, ok := commandUse(lit); ok {
			name, found = use, true
			return false
		}
		return true
	})
	return name, found
}

// parseMigratorCommands — имя двоичного файла и набор ЗАРЕГИСТРИРОВАННЫХ
// подкоманд, прочитанные у производителя.
func parseMigratorCommands(root string) (string, []string, migratorProducerCensus, error) {
	var census migratorProducerCensus

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(root, migratorCommandFile), nil, parser.ParseComments)
	if err != nil {
		return "", nil, census, err
	}

	byName := map[string]*ast.FuncDecl{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil {
			continue
		}
		byName[fn.Name.Name] = fn
	}

	ast.Inspect(file, func(n ast.Node) bool {
		if lit, ok := n.(*ast.CompositeLit); ok {
			if _, ok := commandUse(lit); ok {
				census.commandLiterals++
			}
		}
		return true
	})

	var (
		binary string
		verbs  []string
	)

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != addCommandSelector {
				return true
			}
			census.registrations++
			// Корневая команда объявлена в том же теле, что и регистрация:
			// именно её `Use` оператор пишет в строке вызова.
			if use, ok := firstCommandUseIn(fn); ok && binary == "" {
				binary = use
			}
			for _, arg := range call.Args {
				argCall, ok := arg.(*ast.CallExpr)
				if !ok {
					continue
				}
				ident, ok := argCall.Fun.(*ast.Ident)
				if !ok {
					continue
				}
				ctor, ok := byName[ident.Name]
				if !ok {
					continue
				}
				if use, ok := firstCommandUseIn(ctor); ok {
					verbs = append(verbs, use)
					census.verbs++
				}
			}
			return true
		})
	}

	sort.Strings(verbs)
	return binary, verbs, census, nil
}

// rosterItems — слова перечня без обрамляющих обратных кавычек.
func rosterItems(raw string) []string {
	parts := regexp.MustCompile(`[|/]`).Split(raw, -1)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.Trim(p, "`"))
	}
	sort.Strings(out)
	return out
}

// setDifference — что есть в a и нет в b.
func setDifference(a, b []string) []string {
	have := make(map[string]struct{}, len(b))
	for _, v := range b {
		have[v] = struct{}{}
	}
	var out []string
	for _, v := range a {
		if _, ok := have[v]; !ok {
			out = append(out, v)
		}
	}
	return out
}

// scanMigratorRosters — разбор над ПРОИЗВОЛЬНЫМ деревом: и производитель, и
// перечни берутся оттуда же. Вынесено из теста затем, чтобы способность гейта
// упасть доказывалась подачей входа, а не чтением.
func scanMigratorRosters(tree *treecorpus.Tree) (migratorRosterCensus, []rosterFinding, error) {
	var census migratorRosterCensus

	root := tree.Root()
	binary, verbs, _, err := parseMigratorCommands(root)
	if err != nil {
		return census, nil, err
	}
	if binary == "" || len(verbs) == 0 {
		return census, nil, errNoMigratorProducer
	}

	var findings []rosterFinding
	census.filesTracked = tree.Count()

	for _, rel := range tree.SortedFiles() {
		raw, readErr := os.ReadFile(filepath.Join(root, rel))
		if readErr != nil {
			continue
		}
		// Двоичное содержимое перечней не несёт и строками не читается.
		if strings.IndexByte(string(raw), 0) >= 0 {
			continue
		}
		census.filesRead++

		for idx, line := range strings.Split(string(raw), "\n") {
			census.linesScanned++
			if !strings.Contains(line, binary) {
				continue
			}
			census.namingLines++
			for _, m := range verbRoster.FindAllStringSubmatch(line, -1) {
				items := rosterItems(m[1])
				// Перечень, не пересекающийся с набором подкоманд вовсе,
				// принадлежит чужому предмету (пути, флаги, имена файлов).
				if len(setDifference(items, verbs)) == len(items) {
					continue
				}
				census.rostersSeen++
				missing := setDifference(verbs, items)
				extra := setDifference(items, verbs)
				if len(missing) == 0 && len(extra) == 0 {
					continue
				}
				findings = append(findings, rosterFinding{
					file: rel, line: idx + 1, roster: items, missing: missing, extra: extra,
				})
			}
		}
	}

	return census, findings, nil
}

// errNoMigratorProducer — производитель не прочитан: вердикт беспредметен.
var errNoMigratorProducer = errNoProducer("производитель набора подкоманд не прочитан: " +
	"имя двоичного файла либо набор подкоманд пусты — вердикт беспредметен")

// errNoProducer — местный тип отказа, чтобы отсутствие производителя было
// отличимо от ошибки чтения файла.
type errNoProducer string

func (e errNoProducer) Error() string { return string(e) }

func TestMigratorVerbRosterMatchesTheCommandTree(t *testing.T) {
	tree, err := treecorpus.NewTree(serviceRoot)
	require.NoError(t, err, "состав дерева не прочитан")

	binary, verbs, producer, err := parseMigratorCommands(serviceRoot)
	require.NoError(t, err, "производитель набора подкоманд не разобран")

	census, findings, err := scanMigratorRosters(tree)
	require.NoError(t, err)

	t.Logf(
		"перепись: двоичный %q · литералов команд %d · узлов регистрации %d · подкоманд зарегистрировано %d (%s) · "+
			"файлов в составе %d · прочитано %d · строк %d · из них называют накатчик %d · перечней распознано %d · находок %d",
		binary, producer.commandLiterals, producer.registrations, producer.verbs, strings.Join(verbs, ","),
		census.filesTracked, census.filesRead, census.linesScanned, census.namingLines, census.rostersSeen, len(findings),
	)

	require.NotEmpty(t, binary, "имя двоичного файла не прочитано — вердикт беспредметен")
	require.NotEmpty(t, verbs, "подкоманд не прочитано ни одной — вердикт беспредметен")
	require.NotZero(t, census.filesRead, "обход пуст: файлов не прочитано ни одного — вердикт беспредметен")
	require.NotZero(t, census.namingLines, "обход пуст: строк, называющих накатчик, не найдено — вердикт беспредметен")
	require.NotZero(t, census.rostersSeen, "обход пуст: перечней не распознано ни одного — распознаватель ослеп")

	for _, f := range findings {
		t.Errorf(
			"%s:%d — перечень подкоманд накатчика (%s) расходится с деревом команд (%s): "+
				"обещано сверх дерева %v · умолчано о существующем %v. "+
				"Перечень читает оператор: лишний глагол он позовёт и получит отказ, о недостающем не узнает",
			f.file, f.line, strings.Join(f.roster, ","), strings.Join(verbs, ","), f.extra, f.missing,
		)
	}
}
