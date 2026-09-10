// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// startup_guards_are_judged_test.go — ГЕЙТ КЛАССА: каждый ИМЕНОВАННЫЙ страж
// старта судится пробой боевого профиля, и всякий, кто ею не судится, назван
// поимённо с причиной.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ — НЕ ОДНА ЗАБЫТАЯ СТРОКА ПРОФИЛЯ
//
// Проба боевого профиля (`prod_profile_starts_test.go`) обещает в своей шапке:
// «появится у подъёма новое условие боевого режима — профиль покраснеет, ничего
// здесь не правя». Обещание держалось тем, что проба зовёт САМИ стражи, а не
// выписывает список условий, — и это верно ровно до тех пор, пока стражей она
// перечисляет ПОИМЁННО. Перечисление по именам не знает о стороже, чьё имя в
// него не вписали, и молчит о нём так же, как молчало бы о несуществующем.
//
// Замер, из которого гейт выведен (задача #2476, ревизия `release/kaname-tail`):
// именованных стражей в пакете было ШЕСТЬ, проба звала ТРИ. Из трёх несудимых
// один был условием, отказ которого боевой профиль получал НА КАЖДОМ входе:
// профиль включает свою чеканку и не объявлял режима проверки клиента, которого
// та требует, — то есть посадка была объявлена и неисполнима, а проба профиля
// оставалась зелёной. Одно число («стражей шесть») этот случай СКРЫЛО БЫ: он
// виден только парой «сколько есть · сколько судится».
//
// ─────────────────────────────────────────────────────────────────────────────
// ЕДИНИЦА СЧЁТА — ФУНКЦИЯ-СТРАЖ, УЗНАННАЯ РАЗБОРОМ, А НЕ ПОДСТРОКОЙ
//
// Имя `require…` встречается в этом дереве и комментарием, и в тексте отказа, и
// в имени пробы. Гейт по подстроке краснел бы на собственном объяснении;
// поэтому здесь читается синтаксическое дерево, и стражем считается объявление
// функции верхнего уровня в НЕ-тестовом файле пакета, чьё имя начинается с
// `require` и чей последний результат — `error`. Оба условия несущие: первое
// отделяет стража от помощника, второе — от построителя, который ничего не
// отвергает.
//
// Судимым считается страж, чьё имя ВЫЗЫВАЕТСЯ внутри тела
// `TestProductionProfileSatisfiesTheStartupGuards`. Вызов узнаётся тем же
// разбором: упоминание имени в комментарии пробы вызовом не является.
//
// ─────────────────────────────────────────────────────────────────────────────
// ВЕДОМОСТЬ НЕСУДИМЫХ — САМОИСТЕКАЮЩАЯ, И ЭТО НЕ ПОСЛАБЛЕНИЕ
//
// Страж, чьё условие профилем НЕ ВЫРАЗИМО, существует: он читает материал,
// которого в дереве нет и быть не может (смонтированный лист сертификата).
// Требовать его вызова значило бы требовать от пробы прочитать файл чужого
// кластера — то есть чинить гейт обещанием.
//
// Поэтому у каждой такой записи стоит ПРИЧИНА, и ведомость истекает сама:
// запись, называющая стража, которого в дереве больше нет, — НАХОДКА ровно так
// же, как страж без записи и без вызова. Так снятый страж не оставляет за собой
// прощение, под которое уедет следующий.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ГЕЙТ НЕ УТВЕРЖДАЕТ
//
// Он не говорит, что условий отказа старта ровно столько, сколько именованных
// стражей: условие может жить встроенной ветвью, и именно так жило то, из-за
// которого гейт заведён. ЭТА ПОЛОВИНА НЕ ДЕРЖИТСЯ НИЧЕМ, и это сказано прямо,
// чтобы её наличие не выводил читатель.
//
// Общий предикат «безымянных условий не бывает» был построен и ОТВЕРГНУТ
// замером, а не вкусом. Признак «отказ называет ручку `KANAME_*` в своём
// текстовом литерале» узнаёт не все законные формы: два действующих стража
// подставляют имя ручки ПЕРЕМЕННОЙ (`requireDistinctSurfaceAddrs`,
// `requireHTTPEdgeTLS`), и распознаватель молчал бы о встроенном условии,
// написанном так же. Признак «в подъёме нет отказа, не оборачивающего чужой»
// даёт по дереву ВОСЕМЬ попаданий в теле подъёма, и адъюдикации по ним не
// проводилось: гейт на неадъюдицированной популяции требовал бы от кода
// свойства, о котором никто не решал. Предмет заведён отдельной задачей.
//
// Что осталось от той половины и работает: измеренный экземпляр вынесен в
// именованного стража этим же изменением, поэтому в теле подъёма отказа,
// читающего посадку транспорта, больше нет.
package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// profileProbeName — проба, чей вызов и есть «судится боевым профилем».
const profileProbeName = "TestProductionProfileSatisfiesTheStartupGuards"

// guardsNotJudgedByTheProfile — ведомость стражей, которых проба боевого
// профиля НЕ зовёт, с причиной по каждому.
//
// Причина обязана называть, чего у профиля НЕТ, а не чего не сделал автор:
// «профилем не выразимо» проверяемо, «руки не дошли» — нет.
var guardsNotJudgedByTheProfile = map[string]string{
	"requireOwnFrontHopIdentity": "читает ИМЯ URI из смонтированного листа сертификата " +
		"(KANAME_REST_UPSTREAM_MTLS_CERTFILE) и сверяет его с доменом доверия. Профиль " +
		"называет ПУТЬ к листу, а самого листа в дереве нет и быть не может: он выписан " +
		"удостоверяющим центром чужого кластера. Судить это по объявлению значило бы " +
		"утверждать о файле, которого проба не видела, — то есть завести проверку с формой " +
		"и без предмета. Условие остаётся за подъёмом пода (#2472).",
}

// startupGuardCensus — что гейт узнал о пакете: имена стражей и имена, которые
// проба профиля действительно зовёт.
type startupGuardCensus struct {
	Guards []string
	Judged []string
	// FilesRead — объём осмотренного. «Ноль стражей» обязано быть отличимо от
	// «ноль прочитанных файлов».
	FilesRead int
}

// judgeStartupGuardCoverage — ТЕЛО гейта, вынесенное отдельно, чтобы инъекция
// звала то же, что исполняется на дереве. Своя копия предиката в инъекции
// разошлась бы с настоящим гейтом молча.
//
// Возвращает перепись двумя числами и находки. Находок три вида, и они
// РАЗНЫЕ — общий текст скрыл бы, что именно чинить:
//
//	страж не судится и не назван        → вписать вызов в пробу профиля;
//	запись ведомости без своего стража  → снять запись, её предмет исчез;
//	стражей ноль                        → обход пуст, вердикт беспредметен.
func judgeStartupGuardCoverage(
	c startupGuardCensus, excused map[string]string,
) (guards, judged int, findings []string) {
	judgedSet := map[string]bool{}
	for _, n := range c.Judged {
		judgedSet[n] = true
	}
	guardSet := map[string]bool{}
	for _, n := range c.Guards {
		guardSet[n] = true
	}

	for _, name := range c.Guards {
		if judgedSet[name] {
			judged++
			continue
		}
		if _, ok := excused[name]; ok {
			continue
		}
		findings = append(findings, "страж старта "+name+" не судится пробой боевого профиля "+
			"и не назван в ведомости несудимых: профиль вправе объявить посадку, которую этот "+
			"страж отвергнет при старте, и никто этого не заметит")
	}
	for name := range excused {
		if !guardSet[name] {
			findings = append(findings, "ведомость несудимых называет "+name+
				", а такого стража в пакете нет: запись пережила свой предмет и прощает "+
				"того, кого больше некому судить")
		}
	}
	sort.Strings(findings)
	return len(c.Guards), judged, findings
}

// readStartupGuardCensus — перепись пакета разбором: объявления стражей из
// не-тестовых файлов и имена, вызываемые пробой профиля.
func readStartupGuardCensus(t *testing.T, dir string) startupGuardCensus {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("каталог пакета не читается: %v", err)
	}
	fset := token.NewFileSet()
	census := startupGuardCensus{}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		file, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			t.Fatalf("файл пакета не разбирается (%s): %v", e.Name(), perr)
		}
		census.FilesRead++

		if strings.HasSuffix(e.Name(), "_test.go") {
			census.Judged = append(census.Judged, calledNamesInFunc(file, profileProbeName)...)
			continue
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Name == nil {
				continue
			}
			if !strings.HasPrefix(fn.Name.Name, "require") || !lastResultIsError(fn) {
				continue
			}
			census.Guards = append(census.Guards, fn.Name.Name)
		}
	}
	sort.Strings(census.Guards)
	sort.Strings(census.Judged)
	return census
}

// lastResultIsError — последний результат функции есть `error`.
//
// Именно последний, а не единственный: страж вправе вернуть вместе с отказом и
// то, что он при этом насчитал (`requireHTTPEdgeTLS` возвращает перечень
// объявленных исключений). Требование «ровно один результат» вывело бы такого
// стража из наблюдения молча.
func lastResultIsError(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil || len(fn.Type.Results.List) == 0 {
		return false
	}
	last := fn.Type.Results.List[len(fn.Type.Results.List)-1]
	id, ok := last.Type.(*ast.Ident)
	return ok && id.Name == "error"
}

// calledNamesInFunc — имена функций, ВЫЗЫВАЕМЫЕ внутри тела названной функции.
//
// Разбором, а не подстрокой: имя стража встречается в комментариях пробы и в
// сообщениях её отказов, и оба вызовом не являются.
func calledNamesInFunc(file *ast.File, funcName string) []string {
	var called []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name == nil || fn.Name.Name != funcName || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, isCall := n.(*ast.CallExpr)
			if !isCall {
				return true
			}
			if id, isIdent := call.Fun.(*ast.Ident); isIdent {
				called = append(called, id.Name)
			}
			return true
		})
	}
	return called
}

func TestEveryNamedStartupGuardIsJudgedByTheProductionProfile(t *testing.T) {
	census := readStartupGuardCensus(t, ".")

	// Пустой обход — находка, а не идеал.
	if census.FilesRead == 0 {
		t.Fatal("обход пуст: файлов пакета прочитано 0 — вердикт беспредметен")
	}
	if len(census.Guards) == 0 {
		t.Fatal("обход пуст: именованных стражей старта найдено 0 — вердикт беспредметен")
	}
	if len(census.Judged) == 0 {
		t.Fatalf("обход пуст: проба %s не зовёт ни одного имени — вердикт беспредметен",
			profileProbeName)
	}

	guards, judged, findings := judgeStartupGuardCoverage(census, guardsNotJudgedByTheProfile)

	t.Logf("перепись: файлов пакета прочитано %d · именованных стражей старта %d · "+
		"судимых пробой боевого профиля %d · названо в ведомости несудимых %d",
		census.FilesRead, guards, judged, len(guardsNotJudgedByTheProfile))
	t.Logf("стражи: %s", strings.Join(census.Guards, ", "))

	for _, f := range findings {
		t.Error(f)
	}
	if judged+len(guardsNotJudgedByTheProfile) != guards {
		t.Errorf("перепись не сходится: стражей %d, судимых %d, прощённых %d — "+
			"сумма обязана равняться числу стражей", guards, judged, len(guardsNotJudgedByTheProfile))
	}
}
