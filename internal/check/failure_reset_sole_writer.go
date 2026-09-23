// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// failure_reset_sole_writer.go — разбор «кто обнуляет счёт неверных
// предъявлений по адресу» (приёмка Ф12 Р7 редакция 11,
// `docs/engineering/acceptance/second-factor-totp-and-recovery-codes.md`;
// Ф3 Р10 редакция 11,
// `docs/engineering/acceptance/login-lane-issues-our-session-and-logout-ends-it-server-side.md`;
// задача PRO-Robotech/kaname#287).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Счёт по адресу обнуляет вход, ЗАВЕРШЁННЫЙ до уровня всех заведённых у
// личности факторов. Условие это — свойство того, какие СТРОКИ СПОСОБОВ ВХОДА
// заведены, и того, что ПРЕДЪЯВЛЕНО в сессии; свойством полосы, из которой
// обнуление зовётся, оно не является. Поэтому решать его обязано ОДНО место, и
// всякая полоса обязана проходить через него.
//
// Полоса, зовущая обнуление напрямую, решает это условие СВОИМ путём — либо не
// решает вовсе, и тогда успех одного первого фактора открывает свежее окно
// подбора второго. Класс не ловится ни сборкой, ни типом: прямой вызов
// компилируется и выглядит ровно так же, как правильный.
//
// ─────────────────────────────────────────────────────────────────────────────
// СУДИТСЯ ОБРАЩЕНИЕ, А НЕ ИМЯ ФАЙЛА
//
// Разбор ищет обращения к имени порта и классифицирует КАЖДОЕ по узлу:
//
//	w.ResetFailures(ctx, …)            ВЫЗОВ           — судится домом
//	f := w.ResetFailures               ЗНАЧЕНИЕ-МЕТОД  — судится домом (вызовут позже)
//	ResetFailures(ctx, …) в интерфейсе ОБЪЯВЛЕНИЕ      — порт, молчит
//	func (w *…) ResetFailures(…)       РЕАЛИЗАЦИЯ      — адаптер, молчит
//
// Значение-метод названо отдельной формой намеренно: распознаватель, знающий
// только прямой вызов, пропустил бы обнуление, вынесенное в переменную, — и
// пропустил бы МОЛЧА, не дав ни красного, ни зелёного
// (`.claude/rules/testing.md` §«Гейт на класс», п. 7).
//
// ─────────────────────────────────────────────────────────────────────────────
// ГРАНИЦА НАЗВАНА
//
// Гейт ловит БОЛЬШЕ обещанного и слеп там, где обещает видеть: по имени он
// находит и формы сверх четырёх перечисленных (отложенный вызов, выражение
// метода), а стережёт он «имя не упомянуто селектором вне дома» — не то же, что
// «счёт не обнуляется без вопроса об уровне». Первое влечёт второе, пока
// обнулить счёт можно только селектором этого имени, а это свойство того, как
// дерево написано сегодня, а не следствие разбора.
//
// Эта посылка судится ОТДЕЛЬНО, по дереву, а не утверждается
// (`JudgeFailureRowRemovals` ниже), и по признаку, а не по началу оператора:
// текст, называющий таблицу счёта и несущий изменяющее слово в любом месте,
// законен ровно в двух местах — удалением по ключу в реализации порта и по
// возрасту в уборщике `SweepAgedFailures`; всякий иной — находка, как и текст с
// таблицей, который разбор не классифицирует. Пока посылка верна, молчание гейта
// значит то, что обещает, — в пределах её границы, названной ниже.
//
// Границы остаются, обе названы:
//
//	разбор судит ИМЯ, а не тип приёмника — одноимённый метод чужого типа был бы
//	   сочтён обращением к порту, и гейт покраснел бы на невиновном;
//	обёртка ВНУТРИ дома гейту невидима: он судит координату файла, поэтому
//	   второй безусловный путь, заведённый в самом доме, он не увидит — это
//	   держит таблица решений `completed_login_test.go`, а не он.
//
// У посылки своя граница: она судит ЗНАЧЕНИЕ строкового выражения, которое
// сворачивается при разборе дерева, — литерала, склейки, имени константы либо
// связанного имени пакета этого модуля. Ей не видны оператор, собранный во
// время исполнения, — вызовом (`fmt.Sprintf`, `strings.Join`), в переменной
// функции, присваиванием переменной пакета, из константы чужого модуля (судятся
// тогда лишь его звенья-литералы, и имя таблицы с изменяющим словом в РАЗНЫХ
// звеньях не видно), — и оператор вне Go (триггер, правило либо функция
// миграции).
package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"sort"
	"strings"
)

const (
	// FailureResetPort — имя порта, обнуляющего счёт по адресу.
	FailureResetPort = "ResetFailures"
	// FailureResetHomeRel — дом единственного писателя от корня модуля: здесь
	// решается «завершён ли вход до уровня всех заведённых факторов».
	FailureResetHomeRel = "internal/apps/kaname/api/humansession/completed_login.go"
)

// sessionLevelWriters — вызовы, которыми полоса ПИШЕТ уровень сессии: выдача
// новой сессии и предъявление внутри живой. Ими выводится ПОПУЛЯЦИЯ гейта —
// полосы, завершающие вход, — вместо перечня, выписанного по памяти.
var sessionLevelWriters = map[string]bool{"IssueSession": true, "PresentInSession": true}

// FailureResetUseKind — род обращения к порту обнуления.
type FailureResetUseKind string

const (
	// FailureResetCall — прямой вызов обнуления.
	FailureResetCall FailureResetUseKind = "вызов"
	// FailureResetMethodValue — метод, взятый значением: вызовут позже.
	FailureResetMethodValue FailureResetUseKind = "значение-метод"
	// FailureResetDeclaration — объявление метода в интерфейсе порта.
	FailureResetDeclaration FailureResetUseKind = "объявление порта"
	// FailureResetImplementation — реализация порта адаптером.
	FailureResetImplementation FailureResetUseKind = "реализация порта"
	// FailureResetLevelWrite — запись уровня сессии: выводит популяцию гейта.
	FailureResetLevelWrite FailureResetUseKind = "запись уровня сессии"
)

// FailureResetUse — одно обращение к порту с координатой.
type FailureResetUse struct {
	File string
	Line int
	Kind FailureResetUseKind
	// Func — функция, внутри которой стоит обращение; пусто вне функции.
	Func string
}

func (u FailureResetUse) String() string {
	if u.Func != "" {
		return fmt.Sprintf("%s:%d %s в %s()", u.File, u.Line, u.Kind, u.Func)
	}
	return fmt.Sprintf("%s:%d %s", u.File, u.Line, u.Kind)
}

// FailureResetCensus — объём осмотренного.
type FailureResetCensus struct {
	Files           int
	FilesNamingPort int
	Calls           int
	MethodValues    int
	Declarations    int
	Implementations int
}

// Add — сложение переписей по файлам.
func (c *FailureResetCensus) Add(o FailureResetCensus) {
	c.Files += o.Files
	c.FilesNamingPort += o.FilesNamingPort
	c.Calls += o.Calls
	c.MethodValues += o.MethodValues
	c.Declarations += o.Declarations
	c.Implementations += o.Implementations
}

// ScanFailureResetUses разбирает один Go-файл и классифицирует обращения к
// порту обнуления счёта по узлу.
func ScanFailureResetUses(path string, src []byte) ([]FailureResetUse, FailureResetCensus, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		return nil, FailureResetCensus{}, err
	}
	census := FailureResetCensus{Files: 1}

	var uses []FailureResetUse
	at := func(n ast.Node, kind FailureResetUseKind, fn string) {
		uses = append(uses, FailureResetUse{
			File: path, Line: fset.Position(n.Pos()).Line, Kind: kind, Func: fn,
		})
	}

	// Объявления порта: метод с этим именем в объявлении интерфейса.
	ast.Inspect(f, func(n ast.Node) bool {
		it, ok := n.(*ast.InterfaceType)
		if !ok || it.Methods == nil {
			return true
		}
		for _, m := range it.Methods.List {
			for _, name := range m.Names {
				if name.Name == FailureResetPort {
					census.Declarations++
					at(name, FailureResetDeclaration, "")
				}
			}
		}
		return true
	})

	// Реализации и обращения — по объявлениям верхнего уровня.
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok {
			// Обращение вне функции (инициализатор переменной) — тоже обращение.
			scanFailureResetBody(d, "", at, &census)
			continue
		}
		if fd.Recv != nil && fd.Name.Name == FailureResetPort {
			census.Implementations++
			at(fd.Name, FailureResetImplementation, "")
			continue
		}
		if fd.Body == nil {
			continue
		}
		scanFailureResetBody(fd.Body, fd.Name.Name, at, &census)
	}
	if len(uses) != 0 {
		census.FilesNamingPort = 1
	}
	return uses, census, nil
}

// scanFailureResetBody — обращения внутри узла: вызов и значение-метод.
//
// Вызов узнаётся по позиции селектора В ФУНКЦИИ вызова; всякое иное вхождение
// того же селектора — значение-метод. Разделение несущее: знай разбор только
// вызов, обнуление, вынесенное в переменную, ушло бы из-под наблюдения.
func scanFailureResetBody(root ast.Node, fn string, at func(ast.Node, FailureResetUseKind, string), census *FailureResetCensus) {
	called := map[ast.Node]bool{}
	ast.Inspect(root, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == FailureResetPort {
			called[sel] = true
		}
		return true
	})
	ast.Inspect(root, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != FailureResetPort {
			return true
		}
		if called[sel] {
			census.Calls++
			at(sel, FailureResetCall, fn)
			return true
		}
		census.MethodValues++
		at(sel, FailureResetMethodValue, fn)
		return true
	})
}

// FailureResetVerdictCensus — ДВЕ величины, а не одна: полосы, ПИШУЩИЕ уровень
// сессии, и то, как каждая решает счёт. Одно число (по порту) скрывало бы ровно
// тот случай, ради которого гейт заведён, — полосу, завершающую вход и не
// решающую счёт ВОВСЕ: она порт не зовёт, поэтому в перепись по порту не
// попадает и остаётся невидимой.
type FailureResetVerdictCensus struct {
	FailureResetCensus
	// LevelWritingFiles — файлы прод-кода, пишущие уровень сессии.
	LevelWritingFiles int
	// LevelWritingCalls — вызовы записи уровня в них.
	LevelWritingCalls int
	// ThroughHome — из них зовут дом единственного писателя.
	ThroughHome int
	// InLedger — из них названы ведомостью.
	InLedger int
	// HomeCalls — обращения к порту в самом доме: премиса гейта.
	HomeCalls int
}

// FailureResetLedgerEntry — запись ведомости: сколько ПРЯМЫХ обращений к порту
// у этой полосы законно, почему и когда запись снимается.
//
// Число несущее. Ключ-файл без числа прощает файл ЦЕЛИКОМ: второй прямой вызов,
// внесённый в тот же файл, гейт не покраснит, а самоистечение сработает только
// на нуле. Послабление записывается ПО ФАКТУ, а не потолком.
//
// Запись, прощающая хотя бы одно прямое обращение, — ПОСЛАБЛЕНИЕ: условие
// обнуления решается там мимо дома. Такая запись обязана называть предмет
// трекера (`Refs`); без него она неотличима от забытой. Предикат снятия
// (`Removal`) обязателен у всякой записи.
type FailureResetLedgerEntry struct {
	// Resets — сколько прямых обращений к порту в этом файле законно.
	Resets int
	// Subject — почему полоса решает счёт не через дом.
	Subject string
	// Refs — предмет трекера в форме «владелец/репозиторий#номер»; обязателен,
	// если Resets > 0.
	Refs string
	// Removal — предикат снятия записи, исполнимый командой.
	Removal string
}

// failureResetRefsRe — форма ссылки на предмет трекера.
var failureResetRefsRe = regexp.MustCompile(`^PRO-Robotech/[A-Za-z0-9._-]+#[1-9][0-9]*$`)

// FailureResetHomeCall — имя, которым полоса зовёт дом.
const FailureResetHomeCall = "resetFailuresOnCompletedLogin"

// ScanSessionLevelWrites — вызовы, которыми файл пишет уровень сессии, и вызовы
// дома. Оба судятся по УЗЛУ вызова, а не по слову в тексте: имя дома стоит и в
// прозе, объясняющей его, и гейт по подстроке краснел бы на собственном
// объяснении.
func ScanSessionLevelWrites(path string, src []byte) (writes []FailureResetUse, homeCalls int, err error) {
	fset := token.NewFileSet()
	f, perr := parser.ParseFile(fset, path, src, parser.ParseComments)
	if perr != nil {
		return nil, 0, perr
	}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := ""
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			name = fun.Sel.Name
		case *ast.Ident:
			name = fun.Name
		}
		switch {
		case sessionLevelWriters[name]:
			writes = append(writes, FailureResetUse{
				File: path, Line: fset.Position(call.Pos()).Line,
				Kind: FailureResetLevelWrite, Func: name,
			})
		case name == FailureResetHomeCall:
			homeCalls++
		}
		return true
	})
	return writes, homeCalls, nil
}

// JudgeFailureReset — ВЕРДИКТ гейта над корпусом: находки и обе переписи.
//
// Корпус — ПАРАМЕТР, поэтому инъекция подаёт синтетическое дерево и проверяет
// весь путь вердикта: обход, ведомость, сравнение с координатой дома, обе
// переписи. Прежняя редакция судила дерево прямо в теле пробы, и на КРАСНОМ
// дереве эта сборка не исполнялась ни разу — инъекция судила один классификатор.
func JudgeFailureReset(
	corpus TreeCorpus, home string, ledger map[string]FailureResetLedgerEntry,
) ([]string, FailureResetVerdictCensus, error) {
	var (
		census    FailureResetVerdictCensus
		findings  []string
		resets    = map[string]int{}
		writers   []string
		callsHome = map[string]bool{}
	)
	for _, rel := range corpus.Rels() {
		uses, c, err := ScanFailureResetUses(rel, []byte(corpus[rel]))
		if err != nil {
			return nil, census, fmt.Errorf("разбор %s: %w", rel, err)
		}
		census.FailureResetCensus.Add(c)
		for _, u := range uses {
			if u.Kind == FailureResetDeclaration || u.Kind == FailureResetImplementation {
				continue
			}
			if rel == home {
				census.HomeCalls++
				continue
			}
			resets[rel]++
			if _, forgiven := ledger[rel]; !forgiven {
				findings = append(findings, fmt.Sprintf("%s — обнуление счёта по адресу зовётся мимо единственного "+
					"писателя (%s): условие «вход завершён до уровня всех заведённых способов входа» решается "+
					"здесь своей копией либо не решается вовсе", u, home))
			}
		}
		writes, homeCalls, err := ScanSessionLevelWrites(rel, []byte(corpus[rel]))
		if err != nil {
			return nil, census, fmt.Errorf("разбор записи уровня %s: %w", rel, err)
		}
		if homeCalls > 0 {
			callsHome[rel] = true
		}
		if len(writes) == 0 || rel == home {
			continue
		}
		writers = append(writers, rel)
		census.LevelWritingFiles++
		census.LevelWritingCalls += len(writes)
	}

	// ПОПУЛЯЦИЯ — полосы, пишущие уровень сессии. Каждая обязана решить счёт
	// через дом либо быть названной ведомостью.
	for _, rel := range writers {
		switch {
		case callsHome[rel]:
			census.ThroughHome++
		case ledger[rel].Subject != "":
			census.InLedger++
		default:
			findings = append(findings, fmt.Sprintf("%s — полоса ПИШЕТ уровень сессии и счёт по адресу не решает: "+
				"дом (%s) не зовёт и ведомостью не названа. Гейту по ПОРТУ такая полоса невидима — она порт "+
				"не зовёт вовсе", rel, home))
		}
	}

	// Самоистечение — по ЧИСЛУ и по дому, а не по наличию файла.
	for rel, entry := range ledger {
		inPopulation := callsHome[rel] || resets[rel] > 0
		for _, w := range writers {
			if w == rel {
				inPopulation = true
			}
		}
		switch {
		case !inPopulation:
			findings = append(findings, fmt.Sprintf("запись ведомости %q (%s) больше нечего исключать: "+
				"полоса не пишет уровень сессии и порт не зовёт", rel, entry.Subject))
		case callsHome[rel] && resets[rel] == 0:
			findings = append(findings, fmt.Sprintf("запись ведомости %q (%s) больше нечего исключать: "+
				"полоса решает счёт через дом (%s), прямых обращений к порту у неё нет", rel, entry.Subject, home))
		case resets[rel] != entry.Resets:
			findings = append(findings, fmt.Sprintf("запись ведомости %q прощает %d прямых обращений к порту, "+
				"а их %d (%s): послабление записывается ПО ФАКТУ, а не потолком",
				rel, entry.Resets, resets[rel], entry.Subject))
		}
		if entry.Resets > 0 && !failureResetRefsRe.MatchString(entry.Refs) {
			findings = append(findings, fmt.Sprintf("запись ведомости %q прощает %d прямых обращений к порту без "+
				"предмета трекера (Refs = %q; форма «владелец/репозиторий#номер»): послабление без предмета "+
				"неотличимо от забытого", rel, entry.Resets, entry.Refs))
		}
		if strings.TrimSpace(entry.Removal) == "" {
			findings = append(findings, fmt.Sprintf("запись ведомости %q без предиката снятия: запись, у которой "+
				"не названо, чем она снимается, не истекает ничем, кроме памяти", rel))
		}
	}
	sort.Strings(findings)
	return findings, census, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// ПОСЫЛКА ГЕЙТА: КТО СНИМАЕТ СТРОКИ СЧЁТА
//
// Разбор читает ЗНАЧЕНИЕ каждого строкового выражения прод-кода, которое
// сворачивается при разборе: литерал, склейка `+`, имя константы либо
// связанное имя пакета (своего, другого пакета модуля, локальная константа
// функции), приведение к строковому типу. Свёртка — общая с гейтом материала
// способа входа (`newLVIndex`, `login_verifier_containment.go`), лексика SQL —
// общая с ним же (`sqlTokens`, `sql_relation_name.go`): комментарии `--` и
// `/* */` не судятся, `--` и `/*` внутри строки SQL комментария не открывают.
//
// Судится ПРИЗНАК, а не начало оператора:
//
//  1. текст, где таблица счёта не названа (`SQLNamesRelation`), посылке не
//     предмет;
//  2. текст, где она названа и где стоит изменяющее слово — DELETE, UPDATE,
//     MERGE, TRUNCATE, в любом месте, и внутри строк SQL тоже (тело
//     `DO $$ … $$`, `EXECUTE '…'`); вставка `ON CONFLICT … DO UPDATE` несёт
//     UPDATE, — оператор над строками счёта. Законен он ровно в двух формах:
//     один оператор `DELETE FROM` этой таблицы с условием `key =` в реализации
//     порта и с условием `failed_at <` в уборщике. Всякий иной — находка, и в
//     этих двух местах тоже;
//  3. текст с таблицей без изменяющего слова законен, если это один оператор,
//     открытый SELECT, WITH либо INSERT, или одно имя таблицы. Всякий иной —
//     находка: форма, которую разбор не классифицирует, краснеет, а не молчит.
//
// Условие и граница оператора читаются по лексемам вне строк: `key =` внутри
// строки SQL условием не считается, `;` внутри неё операторов не делит.

const (
	// FailureRowsTable — таблица следов неверных предъявлений: её строки и
	// есть счёт по адресу и по источнику.
	FailureRowsTable = "login_failures"
	// FailureRowsSweep — уборщик следов старше самого длинного окна счёта.
	FailureRowsSweep = "SweepAgedFailures"
)

// FailureRowRemovalKind — как текст обходится со строками счёта.
type FailureRowRemovalKind string

const (
	// FailureRowsByKey — удаление по ключу: это и есть обнуление счёта.
	FailureRowsByKey FailureRowRemovalKind = "по ключу"
	// FailureRowsByAge — удаление по возрасту: уборка истёкших следов.
	FailureRowsByAge FailureRowRemovalKind = "по возрасту"
	// FailureRowsOther — текст с изменяющим словом, который посылка не знает.
	FailureRowsOther FailureRowRemovalKind = "неизвестным посылке способом"
	// FailureRowsUnclassified — текст называет таблицу без изменяющего слова, и
	// разбор не узнаёт в нём ни чтения, ни вставки, ни имени таблицы.
	FailureRowsUnclassified FailureRowRemovalKind = "в форме, которую посылка не классифицирует"
)

// FailureRowRemoval — один текст над строками счёта с координатой.
type FailureRowRemoval struct {
	File string
	Line int
	Kind FailureRowRemovalKind
	// Func — функция, в теле которой стоит текст; пусто — объявление пакета.
	Func string
	// Method — функция объявлена методом: реализация порта и уборщик — методы.
	Method bool
	// What — начало текста для находки.
	What string
}

func (r FailureRowRemoval) where() string {
	if r.Func == "" {
		return fmt.Sprintf("%s:%d вне функции (текст оператора в объявлении пакета)", r.File, r.Line)
	}
	return fmt.Sprintf("%s:%d в %s()", r.File, r.Line, r.Func)
}

// FailureRowRemovalCensus — объём осмотренного посылкой.
type FailureRowRemovalCensus struct {
	// Files — прочитанные файлы.
	Files int
	// StringValues — свёрнутые строковые значения: литерал, склейка, имя
	// константы — по одному на наибольшее свёрнутое выражение.
	StringValues int
	// NamingTable — из них называют таблицу счёта.
	NamingTable int
	// Removals — из них тексты с изменяющим словом.
	Removals int
	// ByKeyInPort — из них удаления по ключу в реализации порта.
	ByKeyInPort int
	// ByAgeInSweep — из них удаления по возрасту в уборщике.
	ByAgeInSweep int
}

// failureRowMutationWords — изменяющие слова: любое из них в тексте с таблицей
// делает текст оператором над строками счёта.
var failureRowMutationWords = map[string]bool{"delete": true, "update": true, "merge": true, "truncate": true}

// failureRowDeepMutationRe — изменяющее слово в строке глубже sqlMaxNesting,
// где лексика SQL уже не применяется: лишняя находка возможна, пропуск нет.
var failureRowDeepMutationRe = regexp.MustCompile(`(?i)\b(?:delete|update|merge|truncate)\b`)

// classifyFailureRowText — судьба строк счёта в одном тексте. named=false —
// таблица не названа; kind == "" — текст безвреден: чтение, вставка, имя.
func classifyFailureRowText(text string) (kind FailureRowRemovalKind, named bool) {
	if !SQLNamesRelation(text, FailureRowsTable) {
		return "", false
	}
	toks := sqlTokens(text)
	single := failureRowSingleStatement(toks)
	words := failureRowMutations(toks, 0)
	if words == 0 {
		if single && failureRowOpensWith(toks, "select", "with", "insert") || failureRowNameOnly(toks) {
			return "", true
		}
		return FailureRowsUnclassified, true
	}
	if words != 1 || !single || !failureRowDeletesFromTable(toks) {
		return FailureRowsOther, true
	}
	switch {
	case failureRowCondition(toks, "key", '=', '>'):
		return FailureRowsByKey, true
	case failureRowCondition(toks, "failed_at", '<', '>'):
		return FailureRowsByAge, true
	}
	return FailureRowsOther, true
}

// failureRowIsWord — лексема есть ключевое слово word: имя без кавычек.
func failureRowIsWord(t sqlTok, word string) bool {
	return t.kind == sqlTokName && t.form == SQLFormBare && t.name == word
}

// failureRowMutations — число изменяющих слов в лексемах и в содержимом строк.
func failureRowMutations(toks []sqlTok, depth int) int {
	n := 0
	for _, t := range toks {
		switch {
		case t.kind == sqlTokName && t.form == SQLFormBare && failureRowMutationWords[t.name]:
			n++
		case t.kind == sqlTokString:
			most := 0
			for _, r := range t.readings {
				k := len(failureRowDeepMutationRe.FindAllString(r, -1))
				if depth < sqlMaxNesting {
					k = failureRowMutations(sqlTokens(r), depth+1)
				}
				most = max(most, k)
			}
			n += most
		}
	}
	return n
}

// failureRowSingleStatement — лексемы составляют один оператор: `;` только в
// конце.
func failureRowSingleStatement(toks []sqlTok) bool {
	end := len(toks)
	for end > 0 && toks[end-1].kind == sqlTokOther && toks[end-1].op == ';' {
		end--
	}
	for _, t := range toks[:end] {
		if t.kind == sqlTokOther && t.op == ';' {
			return false
		}
	}
	return true
}

// failureRowOpensWith — оператор открыт одним из слов (скобки перед ним
// пропускаются).
func failureRowOpensWith(toks []sqlTok, words ...string) bool {
	for _, t := range toks {
		if t.kind == sqlTokOther && t.op == '(' {
			continue
		}
		for _, w := range words {
			if failureRowIsWord(t, w) {
				return true
			}
		}
		return false
	}
	return false
}

// failureRowNameOnly — текст есть одно имя таблицы, со схемой либо без.
func failureRowNameOnly(toks []sqlTok) bool {
	isTable := func(t sqlTok) bool { return t.kind == sqlTokName && t.name == FailureRowsTable }
	switch len(toks) {
	case 1:
		return isTable(toks[0])
	case 3:
		return toks[0].kind == sqlTokName && toks[1].kind == sqlTokOther && toks[1].op == '.' && isTable(toks[2])
	}
	return false
}

// failureRowDeletesFromTable — `DELETE FROM [ONLY] [схема.]таблица счёта`.
func failureRowDeletesFromTable(toks []sqlTok) bool {
	for i := 0; i+2 < len(toks); i++ {
		if !failureRowIsWord(toks[i], "delete") || !failureRowIsWord(toks[i+1], "from") {
			continue
		}
		j := i + 2
		if failureRowIsWord(toks[j], "only") {
			j++
		}
		if j+2 < len(toks) && toks[j].kind == sqlTokName && toks[j+1].kind == sqlTokOther && toks[j+1].op == '.' {
			j += 2
		}
		return j < len(toks) && toks[j].kind == sqlTokName && toks[j].name == FailureRowsTable
	}
	return false
}

// failureRowCondition — имя столбца column, за которым стоит знак op, а за
// ним не стоит not (`key =>`, `failed_at <>` условием не являются).
func failureRowCondition(toks []sqlTok, column string, op, not byte) bool {
	for i := 0; i+1 < len(toks); i++ {
		if !failureRowIsWord(toks[i], column) || toks[i+1].kind != sqlTokOther || toks[i+1].op != op {
			continue
		}
		if i+2 < len(toks) && toks[i+2].kind == sqlTokOther && toks[i+2].op == not {
			continue
		}
		return true
	}
	return false
}

// scanFailureRowTexts — тексты над строками счёта в одном файле с функцией, в
// теле которой они стоят. Судится наибольшее свёрнутое выражение: склейка —
// одним текстом, а не по звеньям; не свернулось — судятся звенья.
func scanFailureRowTexts(ix *lvIndex, f *lvFile, census *FailureRowRemovalCensus) []FailureRowRemoval {
	var out []FailureRowRemoval
	var visit func(root ast.Node, fn string, method bool)
	visit = func(root ast.Node, fn string, method bool) {
		ast.Inspect(root, func(n ast.Node) bool {
			if vs, ok := n.(*ast.ValueSpec); ok {
				// Имена объявления — не обращения: судится значение.
				for _, v := range vs.Values {
					visit(v, fn, method)
				}
				return false
			}
			e, ok := n.(ast.Expr)
			if !ok {
				return true
			}
			text, ok := ix.fold(f, e)
			if !ok {
				if sel, isSel := e.(*ast.SelectorExpr); isSel {
					// Хвост селектора — поле либо метод, а не имя пакета.
					visit(sel.X, fn, method)
					return false
				}
				return true
			}
			census.StringValues++
			kind, named := classifyFailureRowText(text)
			if !named {
				return false
			}
			census.NamingTable++
			if kind != "" {
				out = append(out, FailureRowRemoval{
					File: f.rel, Line: f.fset.Position(e.Pos()).Line, Kind: kind,
					Func: fn, Method: method, What: failureRowFirstLine(text),
				})
			}
			return false
		})
	}
	for _, d := range f.file.Decls {
		switch v := d.(type) {
		case *ast.FuncDecl:
			if v.Body != nil {
				visit(v.Body, v.Name.Name, v.Recv != nil)
			}
		case *ast.GenDecl:
			if v.Tok != token.IMPORT {
				visit(v, "", false)
			}
		}
	}
	return out
}

// failureRowFirstLine — начало текста для находки.
func failureRowFirstLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	return s
}

// JudgeFailureRowRemovals — ВЕРДИКТ посылки над корпусом: находки и перепись.
// Положительные половины (удаление по ключу в порту, по возрасту в уборщике)
// перепись называет отдельно: их ноль — «не исполнялось», а не «годно».
func JudgeFailureRowRemovals(corpus TreeCorpus) ([]string, FailureRowRemovalCensus, error) {
	var (
		census   FailureRowRemovalCensus
		findings []string
	)
	ix, files, _, err := newLVIndex(corpus, FailureRowsTable)
	if err != nil {
		return nil, census, err
	}
	for _, f := range files {
		census.Files++
		for _, r := range scanFailureRowTexts(ix, f, &census) {
			if r.Kind != FailureRowsUnclassified {
				census.Removals++
			}
			switch {
			case r.Kind == FailureRowsByKey && r.Method && r.Func == FailureResetPort:
				census.ByKeyInPort++
			case r.Kind == FailureRowsByAge && r.Method && r.Func == FailureRowsSweep:
				census.ByAgeInSweep++
			case r.Kind == FailureRowsByKey:
				findings = append(findings, fmt.Sprintf("%s — строки %s удаляются по ключу мимо реализации порта %s "+
					"(%q): это обнуление счёта, и гейт единственного писателя его не видит",
					r.where(), FailureRowsTable, FailureResetPort, r.What))
			case r.Kind == FailureRowsByAge:
				findings = append(findings, fmt.Sprintf("%s — строки %s удаляются по возрасту мимо уборщика %s (%q)",
					r.where(), FailureRowsTable, FailureRowsSweep, r.What))
			case r.Kind == FailureRowsUnclassified:
				findings = append(findings, fmt.Sprintf("%s — текст называет таблицу %s %s (%q): изменяющего слова в "+
					"нём нет, но это ни один оператор чтения либо вставки, ни имя таблицы; форма, которую разбор не "+
					"узнаёт, — находка, а не молчание", r.where(), FailureRowsTable, r.Kind, r.What))
			default:
				findings = append(findings, fmt.Sprintf("%s — строки %s меняются %s (%q): в тексте изменяющее слово, "+
					"и это не одно удаление ни по ключу в реализации порта, ни по возрасту в уборщике",
					r.where(), FailureRowsTable, r.Kind, r.What))
			}
		}
	}
	sort.Strings(findings)
	return findings, census, nil
}
