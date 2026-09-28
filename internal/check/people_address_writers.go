// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// people_address_writers.go — разбор «кто пишет адрес человека в существующую
// строку» (`kaname.users.email`): часть (б) условия 7 чек-листа поверхности
// подтверждения адреса (приёмка PRO-Robotech/kacho-workspace
// `docs/specs/sub-phase-F6b-console-and-edge-confirmed-address-gate-acceptance.md`,
// край и служба; приёмка службы
// `docs/engineering/acceptance/access-beyond-login-needs-a-verified-address.md`;
// задача PRO-Robotech/kaname#464).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Отметку подтверждения снимает база на смене адреса (триггер
// `users_email_change_drops_verification`, миграция
// `20260915111233_login_methods_live_in_their_own_rows.sql`). Снятие само по себе
// не закрывает того, что уже открыто: перепрос открытых соединений края
// отметку не спрашивает, кеш решений края снятием не сбрасывается. Поэтому
// глагол смены адреса вносится только вместе со своими условиями, и держит это
// гейт: мест, где непроверочный код службы пишет адрес в СУЩЕСТВУЮЩУЮ строку
// человека, — ноль. Появление такого места — находка, и её текст называет, с
// чем вместе глагол вносится (`addressWriterFinding`).
//
// Заведение строки (`INSERT INTO users (…, email, …)`) адреса не меняет — у
// новой строки прежнего адреса нет — и находкой не является; оно считается в
// переписи операторов записи в строки людей.
//
// ─────────────────────────────────────────────────────────────────────────────
// СУДИТСЯ СПИСОК SET ОПЕРАТОРА, А НЕ ПОДСТРОКА
//
// Текст — значение строкового выражения Go, свёрнутое тем же проходом, что у
// гейтов значений строк (`newLVIndex`: литерал, склейка, константа, связанное
// имя пакета), и разобранный общим лексером SQL (`sqlTokens`). Колонка
// читается в голове элемента списка SET; адрес в условии, в цели конфликта
// (`ON CONFLICT (lower(email))`) и в списке колонок вставки записью не является.
// Законные формы записи, каждая доказана инъекцией:
//
//	UPDATE [ONLY] [kaname.]users [[AS] u] SET … email = …        ветвь UPDATE
//	UPDATE users SET (…, email, …) = (…)                          та же ветвь
//	INSERT INTO users … ON CONFLICT … DO UPDATE SET … email = …    ветвь ON CONFLICT
//	MERGE INTO users … WHEN MATCHED THEN UPDATE SET … email = …    ветвь MERGE
//	любая из них внутри CTE, в склейке, в формате fmt.Sprintf, в строке SQL
//
// Имя без кавычек сравнивается без регистра ASCII, в кавычках — побайтово (так
// разрешает база; лексер общий).
//
// ─────────────────────────────────────────────────────────────────────────────
// ФОРМА, КОТОРУЮ РАЗБОР НЕ РЕШАЕТ, — НАХОДКА, А НЕ МОЛЧАНИЕ
//
// Оператор записи в строки людей, чей список SET обрывается на конце текста,
// пуст, несёт в голове элемента подстановку формата (`%s`) либо не ту лексему,
// — и оператор с подстановкой вместо таблицы, пишущий адрес либо колонку из
// подстановки, — находка «не решается разбором». Так же — список SET без
// оператора в том же тексте, называющий адрес. Иначе колонку, собранную во
// время исполнения, гейт пропустил бы молча.
//
// ─────────────────────────────────────────────────────────────────────────────
// ГРАНИЦЫ, НАЗВАННЫЕ ВСЛУХ
//
//  1. Корпус — непроверочный Go дерева (`ProductionGoFile`). Операторы вне Go —
//     миграции, триггеры и функции базы — не судятся: исторический посев
//     названной строки адрес в миграции пишет, и применённая миграция не
//     правится. Новый писатель адреса в миграции этим гейтом не виден.
//  2. Текст, собранный вызовом во время исполнения (`strings.Join`, построитель),
//     судится по звеньям-литералам; звено «UPDATE users SET » краснеет формой
//     «не решается», звено с одним списком колонок без оператора — только если
//     называет адрес.
//  3. Ветвь MERGE в дереве сегодня пуста: её держит инъекция, а не перепись.
package check

import (
	"fmt"
	"go/ast"
	"go/token"
	"sort"
	"strings"
)

const (
	// PeopleRowsTable — таблица строк людей.
	PeopleRowsTable = "users"
	// PeopleAddressColumn — колонка адреса человека.
	PeopleAddressColumn = "email"
	// peopleRowsSchema — схема службы: имя со схемой судится только в ней.
	peopleRowsSchema = "kaname"
)

// Ветви списка SET — ключи переписи.
const (
	SetListUpdate   = "UPDATE … SET"
	SetListConflict = "ON CONFLICT … DO UPDATE SET"
	SetListMerge    = "MERGE … THEN UPDATE SET"
)

// Виды операторов записи в строки людей — ключи переписи.
const (
	PeopleStmtUpdate = "UPDATE"
	PeopleStmtInsert = "INSERT"
	PeopleStmtDelete = "DELETE"
	PeopleStmtMerge  = "MERGE"
)

// PeopleAddressCensus — объём осмотренного.
type PeopleAddressCensus struct {
	// Files — разобранные файлы корпуса.
	Files int
	// StringValues — свёрнутые строковые значения: по одному на наибольшее
	// свёрнутое выражение.
	StringValues int
	// Statements — операторы записи в строки людей по виду.
	Statements map[string]int
	// SetLists — прочитанные списки SET над строками людей по ветви.
	SetLists map[string]int
	// Columns — колонки строк людей, которые пишут прочитанные списки SET.
	Columns map[string]int
	// Writers — координаты записи адреса в существующую строку.
	Writers []string
	// Undecided — координаты операторов, которые разбор не решает.
	Undecided []string
}

// StatementsTotal — всего операторов записи в строки людей.
func (c PeopleAddressCensus) StatementsTotal() int {
	n := 0
	for _, v := range c.Statements {
		n += v
	}
	return n
}

// String — строка переписи для вывода проб.
func (c PeopleAddressCensus) String() string {
	cols := make([]string, 0, len(c.Columns))
	for k, v := range c.Columns {
		cols = append(cols, fmt.Sprintf("%s×%d", k, v))
	}
	sort.Strings(cols)
	return fmt.Sprintf("файлов %d · строковых значений %d · операторов записи в строки людей %d "+
		"(UPDATE %d · INSERT %d · DELETE %d · MERGE %d) · списков SET: %s %d · %s %d · %s %d · "+
		"колонки [%s] · писателей адреса %d · не решается разбором %d",
		c.Files, c.StringValues, c.StatementsTotal(),
		c.Statements[PeopleStmtUpdate], c.Statements[PeopleStmtInsert], c.Statements[PeopleStmtDelete],
		c.Statements[PeopleStmtMerge],
		SetListUpdate, c.SetLists[SetListUpdate], SetListConflict, c.SetLists[SetListConflict],
		SetListMerge, c.SetLists[SetListMerge], strings.Join(cols, " "), len(c.Writers), len(c.Undecided))
}

// addressWriterFinding — текст отказа на месте записи адреса: называет, с чем
// вместе вносится глагол смены адреса.
func addressWriterFinding(where, branch string) string {
	return fmt.Sprintf("%s — оператор пишет адрес человека (kaname.users.email) в существующую строку "+
		"(%s). Глагол смены адреса вносится только вместе с тремя условиями: "+
		"(1) перепрос открытых соединений края — сессии и нашего токена — спрашивает отметку подтверждения "+
		"тем же вопросом, что путь запроса; "+
		"(2) письмо о смене уходит на прежний адрес; "+
		"(3) смене предшествует ступень подтверждения личности. "+
		"Тем же изменением путь смены сбрасывает кеш решений края тем же потоком, что выдачи. "+
		"Источник — часть (б) условия 7 чек-листа поверхности подтверждения адреса (приёмка F6b) "+
		"и приёмка службы access-beyond-login-needs-a-verified-address.md", where, branch)
}

// undecidedFinding — текст отказа на форме, которую разбор не решает.
func undecidedFinding(where, why string) string {
	return fmt.Sprintf("%s — %s: разбор не решает, пишет ли оператор адрес человека (kaname.users.email). "+
		"Список колонок и таблица обязаны сворачиваться при разборе (литерал, склейка, константа); "+
		"форма, которую гейт не решает, — находка, а не молчание", where, why)
}

// peopleTableKind — что стоит на месте таблицы оператора.
type peopleTableKind int

const (
	tableAbsent peopleTableKind = iota // имени нет: текст кончился либо не имя
	tableOther                         // другая таблица
	tablePeople                        // строки людей
	tableHole                          // подстановка формата
)

// peopleMark — место в тексте, о котором говорит находка.
type peopleMark struct {
	at     int
	branch string // у писателя
	why    string // у формы, которую разбор не решает
}

// peopleText — итог разбора одного текста.
type peopleText struct {
	writes, undecided []peopleMark
	stmts, sets       map[string]int
	columns           map[string]int
}

func newPeopleText() *peopleText {
	return &peopleText{stmts: map[string]int{}, sets: map[string]int{}, columns: map[string]int{}}
}

// peopleLockingPrev — слова, после которых UPDATE — не оператор: блокировка
// строк (`FOR [NO KEY] UPDATE`), действие ключа (`ON UPDATE`), событие триггера
// (`BEFORE|AFTER|OR|INSTEAD OF UPDATE`), право (`GRANT|REVOKE UPDATE`).
var peopleLockingPrev = map[string]bool{
	"for": true, "key": true, "on": true, "before": true, "after": true,
	"or": true, "of": true, "grant": true, "revoke": true,
}

// peopleSetEnd — слова, которыми кончается список SET на его глубине.
var peopleSetEnd = map[string]bool{"from": true, "where": true, "returning": true, "when": true}

func isOp(t sqlTok, op byte) bool { return t.kind == sqlTokOther && t.op == op }

// sqlDepths — глубина скобок у каждой лексемы: открывающая и закрывающая скобка
// стоят на глубине объемлющего, содержимое — глубже на один.
func sqlDepths(toks []sqlTok) []int {
	out := make([]int, len(toks))
	d := 0
	for i, t := range toks {
		switch {
		case isOp(t, '(') || isOp(t, '['):
			out[i] = d
			d++
		case isOp(t, ')') || isOp(t, ']'):
			if d > 0 {
				d--
			}
			out[i] = d
		default:
			out[i] = d
		}
	}
	return out
}

// formatHoleEnd — индекс после подстановки формата Go (`%s`, `%[1]v`, `%-8q`),
// начатой в i; -1 — в i не подстановка.
func formatHoleEnd(toks []sqlTok, i int) int {
	if i >= len(toks) || !isOp(toks[i], '%') {
		return -1
	}
	for j := i + 1; j < len(toks); j++ {
		t := toks[j]
		switch {
		case t.kind == sqlTokName && t.form == SQLFormBare:
			return j + 1
		case t.kind == sqlTokOther && strings.IndexByte("[]0123456789.+-# *", t.op) >= 0:
			continue
		default:
			return -1
		}
	}
	return -1
}

// readPeopleTable — имя таблицы в i: `[схема.]имя`. next — индекс после него.
func readPeopleTable(toks []sqlTok, i int) (kind peopleTableKind, next int) {
	if i >= len(toks) {
		return tableAbsent, i
	}
	if end := formatHoleEnd(toks, i); end >= 0 {
		return tableHole, end
	}
	if toks[i].kind != sqlTokName {
		return tableAbsent, i
	}
	first := toks[i]
	if i+2 < len(toks) && isOp(toks[i+1], '.') {
		if end := formatHoleEnd(toks, i+2); end >= 0 {
			return tableHole, end
		}
		if toks[i+2].kind == sqlTokName {
			if first.name == peopleRowsSchema && toks[i+2].name == PeopleRowsTable {
				return tablePeople, i + 3
			}
			return tableOther, i + 3
		}
	}
	if first.name == PeopleRowsTable {
		return tablePeople, i + 1
	}
	return tableOther, i + 1
}

// setColumn — голова элемента списка SET.
type setColumn struct {
	name string
	hole bool
	bad  bool // не имя и не подстановка
}

// setItem — элемент списка SET.
type setItem struct {
	at    int
	cols  []setColumn
	empty bool
}

// readSetItems — элементы списка SET с лексемы s на глубине d. Список кончается
// словом конца на своей глубине вне CASE, `;` либо закрывающей скобкой
// объемлющего.
func readSetItems(toks []sqlTok, dep []int, s, d int) []setItem {
	var (
		items    []setItem
		cur      = setItem{empty: true}
		caseOpen int
		seen     bool
	)
	flush := func() { items = append(items, cur); cur = setItem{empty: true} }
	for k := s; k < len(toks); k++ {
		t := toks[k]
		if dep[k] < d {
			break
		}
		if dep[k] == d {
			switch {
			case failureRowIsWord(t, "case"):
				caseOpen++
			case failureRowIsWord(t, "end") && caseOpen > 0:
				caseOpen--
			}
			if caseOpen == 0 {
				if isOp(t, ';') || t.kind == sqlTokName && t.form == SQLFormBare && peopleSetEnd[t.name] {
					break
				}
				if isOp(t, ',') {
					flush()
					seen = true
					continue
				}
			}
		}
		seen = true
		if !cur.empty {
			continue
		}
		cur.empty, cur.at = false, t.at
		switch {
		case isOp(t, '(') && dep[k] == d:
			cur.cols = readTupleColumns(toks, dep, k+1, d+1)
		case formatHoleEnd(toks, k) >= 0:
			cur.cols = []setColumn{{hole: true}}
		case t.kind == sqlTokName:
			cur.cols = []setColumn{{name: t.name}}
		default:
			cur.cols = []setColumn{{bad: true}}
		}
	}
	if seen {
		flush()
	}
	return items
}

// readTupleColumns — колонки кортежа `(a, b, …)` списка SET на глубине d.
func readTupleColumns(toks []sqlTok, dep []int, s, d int) []setColumn {
	var out []setColumn
	head := true
	for k := s; k < len(toks) && dep[k] >= d; k++ {
		t := toks[k]
		if dep[k] == d && isOp(t, ',') {
			head = true
			continue
		}
		if !head {
			continue
		}
		head = false
		switch {
		case formatHoleEnd(toks, k) >= 0:
			out = append(out, setColumn{hole: true})
		case t.kind == sqlTokName:
			out = append(out, setColumn{name: t.name})
		default:
			out = append(out, setColumn{bad: true})
		}
	}
	if head {
		// Пустой кортеж либо запятая в конце: колонку разбор не видит.
		out = append(out, setColumn{bad: true})
	}
	return out
}

// judgeSetList — список SET с лексемы s на глубине d над таблицей kind.
func (p *peopleText) judgeSetList(toks []sqlTok, dep []int, s, d int, at int, kind peopleTableKind, branch string) {
	if kind == tableOther {
		return
	}
	people := kind == tablePeople
	if people {
		p.sets[branch]++
	}
	items := readSetItems(toks, dep, s, d)
	if len(items) == 0 {
		if people {
			p.undecided = append(p.undecided, peopleMark{at: at, why: "список SET над строками людей пуст либо собирается вне текста (" + branch + ")"})
		}
		return
	}
	for _, it := range items {
		if it.empty {
			if people {
				p.undecided = append(p.undecided, peopleMark{at: at, why: "элемент списка SET над строками людей пуст — колонка собирается вне текста (" + branch + ")"})
			}
			continue
		}
		for _, c := range it.cols {
			switch {
			case c.hole || c.bad:
				p.undecided = append(p.undecided, peopleMark{at: it.at, why: "колонка списка SET — подстановка либо не имя (" + branch + ")"})
			case c.name == PeopleAddressColumn && people:
				p.writes = append(p.writes, peopleMark{at: it.at, branch: branch})
			case c.name == PeopleAddressColumn:
				p.undecided = append(p.undecided, peopleMark{at: it.at, why: "оператор пишет колонку адреса, а таблица — подстановка (" + branch + ")"})
			case people:
				p.columns[c.name]++
			}
		}
	}
}

// enclosingTarget — таблица оператора opener (`insert` либо `merge`), в котором
// стоит действие в i: ищется назад на той же глубине, до `;` либо выхода из
// объемлющей скобки.
func enclosingTarget(toks []sqlTok, dep []int, i int, opener string) peopleTableKind {
	for k := i - 1; k >= 0; k-- {
		if dep[k] < dep[i] || dep[k] == dep[i] && isOp(toks[k], ';') {
			break
		}
		if dep[k] != dep[i] || !failureRowIsWord(toks[k], opener) {
			continue
		}
		if k+1 < len(toks) && failureRowIsWord(toks[k+1], "into") {
			kind, _ := readPeopleTable(toks, k+2)
			if kind == tableAbsent {
				return tableHole
			}
			return kind
		}
		return tableHole
	}
	// Оператор собирается вне текста: таблица не решается.
	return tableHole
}

// judgePeopleText — разбор одного текста SQL на глубине вложенности строк depth.
func judgePeopleText(src string, depth int, p *peopleText) {
	toks := sqlTokens(src)
	dep := sqlDepths(toks)
	consumed := map[int]bool{}
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		switch {
		case t.kind == sqlTokString:
			judgeNestedPeopleText(t, depth, p)
		case failureRowIsWord(t, "update"):
			judgeUpdateAt(toks, dep, i, consumed, p)
		case failureRowIsWord(t, "insert") || failureRowIsWord(t, "merge"):
			if i+1 < len(toks) && failureRowIsWord(toks[i+1], "into") {
				if kind, _ := readPeopleTable(toks, i+2); kind == tablePeople {
					stmt := PeopleStmtInsert
					if t.name == "merge" {
						stmt = PeopleStmtMerge
					}
					p.stmts[stmt]++
				}
			}
		case failureRowIsWord(t, "delete"):
			j := i + 1
			if j < len(toks) && failureRowIsWord(toks[j], "from") {
				j++
				if j < len(toks) && failureRowIsWord(toks[j], "only") {
					j++
				}
				if kind, _ := readPeopleTable(toks, j); kind == tablePeople {
					p.stmts[PeopleStmtDelete]++
				}
			}
		}
	}
	// Список SET без оператора в этом тексте: судится, только если называет
	// адрес, — `SET search_path = …` и прочие настройки сеанса предметом не
	// являются.
	for i, t := range toks {
		if !failureRowIsWord(t, "set") || consumed[i] {
			continue
		}
		for _, it := range readSetItems(toks, dep, i+1, dep[i]) {
			for _, c := range it.cols {
				if c.name == PeopleAddressColumn {
					p.undecided = append(p.undecided, peopleMark{at: it.at, why: "список SET называет колонку адреса, а оператор, которому он принадлежит, собирается вне текста"})
				}
			}
		}
	}
}

// judgeNestedPeopleText — содержимое строки SQL судится как текст SQL ещё раз
// (динамический SQL, тело `DO $$ … $$`); глубже sqlMaxNesting — без грамматики.
func judgeNestedPeopleText(t sqlTok, depth int, p *peopleText) {
	for _, r := range t.readings {
		inner := newPeopleText()
		if depth < sqlMaxNesting {
			judgePeopleText(r, depth+1, inner)
		} else if sqlWordFold(r, PeopleAddressColumn) && sqlWordFold(r, "set") {
			inner.undecided = append(inner.undecided, peopleMark{why: "строка SQL глубже предела вложенности называет колонку адреса и SET"})
		}
		for _, w := range inner.writes {
			p.writes = append(p.writes, peopleMark{at: t.at, branch: w.branch + ", внутри строки SQL"})
		}
		for _, u := range inner.undecided {
			p.undecided = append(p.undecided, peopleMark{at: t.at, why: u.why + ", внутри строки SQL"})
		}
		for k, v := range inner.stmts {
			p.stmts[k] += v
		}
		for k, v := range inner.sets {
			p.sets[k] += v
		}
		for k, v := range inner.columns {
			p.columns[k] += v
		}
		if len(inner.writes)+len(inner.undecided)+len(inner.stmts) > 0 {
			// Второе прочтение той же строки (обратная коса) — то же место.
			return
		}
	}
}

// judgeUpdateAt — слово UPDATE в i: действие конфликта, действие MERGE либо
// оператор.
func judgeUpdateAt(toks []sqlTok, dep []int, i int, consumed map[int]bool, p *peopleText) {
	if i > 0 {
		prev := toks[i-1]
		if failureRowIsWord(prev, "do") || failureRowIsWord(prev, "then") {
			if i+1 >= len(toks) || !failureRowIsWord(toks[i+1], "set") {
				return
			}
			consumed[i+1] = true
			branch, opener := SetListConflict, "insert"
			if prev.name == "then" {
				branch, opener = SetListMerge, "merge"
			}
			kind := enclosingTarget(toks, dep, i, opener)
			p.judgeSetList(toks, dep, i+2, dep[i+1], toks[i].at, kind, branch)
			return
		}
		if isOp(prev, ',') || prev.kind == sqlTokName && prev.form == SQLFormBare && peopleLockingPrev[prev.name] {
			return
		}
	}
	j := i + 1
	if j < len(toks) && failureRowIsWord(toks[j], "only") {
		j++
	}
	kind, j := readPeopleTable(toks, j)
	if kind == tableAbsent {
		return
	}
	if j < len(toks) && isOp(toks[j], '*') {
		j++
	}
	switch {
	case j < len(toks) && failureRowIsWord(toks[j], "as"):
		j += 2
	case j < len(toks) && toks[j].kind == sqlTokName && !failureRowIsWord(toks[j], "set"):
		j++
	}
	if j >= len(toks) || !failureRowIsWord(toks[j], "set") {
		// Не оператор (текст ошибки «update users: …»), если список не
		// обрывается концом текста либо подстановкой.
		if kind == tablePeople && (j >= len(toks) || formatHoleEnd(toks, j) >= 0) {
			p.stmts[PeopleStmtUpdate]++
			p.undecided = append(p.undecided, peopleMark{at: toks[i].at, why: "оператор UPDATE строк людей без списка SET в тексте — список собирается вне него"})
		}
		return
	}
	consumed[j] = true
	if kind == tablePeople {
		p.stmts[PeopleStmtUpdate]++
	}
	p.judgeSetList(toks, dep, j+1, dep[j], toks[j].at, kind, SetListUpdate)
}

// peopleLine — строка исходника для смещения at в свёрнутом значении выражения
// e: у одиночного сырого литерала — точная, у прочих — строка начала выражения.
func peopleLine(f *lvFile, e ast.Expr, text string, at int) int {
	line := f.fset.Position(e.Pos()).Line
	if lit, ok := e.(*ast.BasicLit); ok && strings.HasPrefix(lit.Value, "`") && at <= len(text) {
		line += strings.Count(text[:at], "\n")
	}
	return line
}

// peopleFuncLabel — имя функции для координаты: `тип.метод` либо `функция`.
func peopleFuncLabel(fd *ast.FuncDecl) string {
	if recv, _ := receiverTypeName(fd); recv != "" {
		return recv + "." + fd.Name.Name
	}
	return fd.Name.Name
}

// scanPeopleTexts — свёрнутые строковые значения файла: наибольшее свёрнутое
// выражение судится целиком, не свернулось — судятся звенья.
func scanPeopleTexts(ix *lvIndex, f *lvFile, census *PeopleAddressCensus) {
	var visit func(root ast.Node, fn string)
	visit = func(root ast.Node, fn string) {
		ast.Inspect(root, func(n ast.Node) bool {
			if vs, ok := n.(*ast.ValueSpec); ok {
				for _, v := range vs.Values {
					visit(v, fn)
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
					visit(sel.X, fn)
					return false
				}
				return true
			}
			switch e.(type) {
			case *ast.Ident, *ast.SelectorExpr:
				// Обращение к константе либо связанному имени: его значение судится
				// там, где оно объявлено, — второй суд того же текста удвоил бы и
				// перепись, и находку.
				return false
			}
			census.StringValues++
			p := newPeopleText()
			judgePeopleText(text, 0, p)
			where := func(at int) string {
				loc := fmt.Sprintf("%s:%d", f.rel, peopleLine(f, e, text, at))
				if fn == "" {
					return loc + " вне функции (объявление пакета)"
				}
				return loc + " в " + fn + "()"
			}
			for _, w := range p.writes {
				census.Writers = append(census.Writers, addressWriterFinding(where(w.at), w.branch))
			}
			for _, u := range p.undecided {
				census.Undecided = append(census.Undecided, undecidedFinding(where(u.at), u.why))
			}
			for k, v := range p.stmts {
				census.Statements[k] += v
			}
			for k, v := range p.sets {
				census.SetLists[k] += v
			}
			for k, v := range p.columns {
				census.Columns[k] += v
			}
			return false
		})
	}
	for _, d := range f.file.Decls {
		switch v := d.(type) {
		case *ast.FuncDecl:
			if v.Body != nil {
				visit(v.Body, peopleFuncLabel(v))
			}
		case *ast.GenDecl:
			if v.Tok != token.IMPORT {
				visit(v, "")
			}
		}
	}
}

// JudgePeopleAddressWriters — ВЕРДИКТ над корпусом непроверочного Go: находки
// (места записи адреса, формы, которые разбор не решает, пустой обход) и
// перепись. Корпус приходит параметром: инъекция подаёт синтетику в тот же
// вердикт, что судит дерево.
func JudgePeopleAddressWriters(corpus TreeCorpus) ([]string, PeopleAddressCensus, error) {
	census := PeopleAddressCensus{Statements: map[string]int{}, SetLists: map[string]int{}, Columns: map[string]int{}}
	ix, files, _, err := newLVIndex(corpus, PeopleRowsTable)
	if err != nil {
		return nil, census, err
	}
	for _, f := range files {
		census.Files++
		scanPeopleTexts(ix, f, &census)
	}
	findings := append(append([]string{}, census.Writers...), census.Undecided...)
	switch {
	case census.Files == 0:
		findings = append(findings, "обход пуст — ни одного файла Go не разобрано: «писателей адреса 0» здесь означало бы «прочитано 0»")
	case census.StatementsTotal() == 0:
		findings = append(findings, fmt.Sprintf("операторов записи в строки людей не найдено ни одного (файлов %d, строковых значений %d) — "+
			"распознаватель слеп либо корпус не тот; молчание о писателях адреса сказано ни о чём", census.Files, census.StringValues))
	}
	sort.Strings(findings)
	return findings, census, nil
}
