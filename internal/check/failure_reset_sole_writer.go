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
// Отсюда две границы, обе названы:
//
//	разбор судит ИМЯ, а не тип приёмника — одноимённый метод чужого типа был бы
//	   сочтён обращением к порту, и гейт покраснел бы на невиновном;
//	обёртка ВНУТРИ дома гейту невидима: он судит координату файла, поэтому
//	   второй безусловный путь, заведённый в самом доме, он не увидит — это
//	   держит таблица решений `completed_login_test.go`, а не он.
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
