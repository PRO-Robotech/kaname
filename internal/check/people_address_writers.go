// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// people_address_writers.go — разбор «кто пишет адрес человека в существующую
// строку» (`kaname.users.email`): часть (б) условия 7 чек-листа поверхности
// подтверждения адреса (приёмка PRO-Robotech/kacho-workspace
// `docs/specs/sub-phase-F6b-console-and-edge-confirmed-address-gate-acceptance.md`,
// край и служба; приёмка службы
// `docs/engineering/acceptance/access-beyond-login-needs-a-verified-address.md`;
// задача PRO-Robotech/kaname#464). Половина, судящая миграции, — адрес И
// отметка его подтверждения, формы определения схемы и строки триггера, ведомость
// применённых миграций — в `people_address_writers_migrations.go` (задача
// PRO-Robotech/kaname#471).
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
// Корпус — ДВА вида входа, и оба судит один разбор текста SQL: строковые
// выражения непроверочного Go и тексты миграций. Предмет у них разный: в Go —
// адрес (у отметки подтверждения в Go есть законный писатель — глагол
// подтверждения), в миграции — адрес и отметка (у миграции законного писателя
// отметки нет).
//
// ─────────────────────────────────────────────────────────────────────────────
// СУДИТСЯ СПИСОК SET ОПЕРАТОРА, А НЕ ПОДСТРОКА
//
// Текст — значение строкового выражения Go, свёрнутое тем же проходом, что у
// гейтов значений строк (`newLVIndex`: литерал, склейка, константа, связанное
// имя пакета), и разобранный общим лексером SQL (`sqlTokens`). Склейка, которая
// целиком не свернулась, судится звеньями, и звенья, сворачивающиеся подряд за
// значением времени исполнения (`tbl + " SET " + column + " = $1"`), — одним
// текстом. Колонка читается в голове элемента списка SET; адрес в условии, в
// цели конфликта (`ON CONFLICT (lower(email))`) и в списке колонок вставки
// записью не является.
// Законные формы записи, каждая доказана инъекцией:
//
//	UPDATE [ONLY] [kaname.]users [[AS] u] SET … email = …        ветвь UPDATE
//	UPDATE users SET (…, email, …) = (…)                          та же ветвь
//	IF … THEN UPDATE users SET … · правило DO UPDATE users SET …   та же ветвь
//	INSERT INTO users … ON CONFLICT … DO UPDATE SET … email = …    ветвь ON CONFLICT
//	MERGE INTO users … WHEN MATCHED THEN UPDATE SET … email = …    ветвь MERGE
//	любая из них внутри CTE, в склейке, в формате fmt.Sprintf, в строке SQL
//
// и формы вне списка SET — определение схемы, переписывающее значения строк, и
// присваивание строке триггера (`people_address_writers_migrations.go`).
//
// Имя без кавычек сравнивается без регистра ASCII, в кавычках — побайтово (так
// разрешает база; лексер общий).
//
// ─────────────────────────────────────────────────────────────────────────────
// ФОРМА, КОТОРУЮ РАЗБОР НЕ РЕШАЕТ, — НАХОДКА, А НЕ МОЛЧАНИЕ
//
// «Не решается разбором» — каждая из форм ниже, и каждая доказана инъекцией:
//
//   - список SET над строками людей пуст, несёт пустой элемент, в голове
//     элемента — подстановку формата (`%s`) либо не имя;
//   - UPDATE строк людей без списка SET в тексте;
//   - оператор с подстановкой вместо таблицы (либо вне текста), пишущий адрес
//     либо колонку из подстановки;
//   - список SET без оператора в том же тексте, называющий адрес.
//
// СПИСОК, ПОЛНЫЙ В ЛИТЕРАЛЕ И ПРОДОЛЖЕННЫЙ ВО ВРЕМЯ ИСПОЛНЕНИЯ. Гейт не
// прослеживает значение до исполнителя запроса, поэтому список SET над
// строками людей (либо над таблицей, которую текст не называет, — подстановка
// вместо таблицы либо оператор вне текста), чьи элементы решены и адреса не
// пишут, судится ещё раз:
//
//   - не закрыт в тексте — кончается концом текста, а не WHERE, FROM,
//     RETURNING, `;` либо скобкой: хвост, приставленный склейкой с переменной,
//     `+=`, `strings.Join` либо построителем, дописал бы колонку;
//   - несёт подстановку формата в значении элемента (`labels = %s`):
//     подставленный текст дописал бы колонку.
//
// Закрытый в своём тексте список продолжение колонкой не пополнит — хвост и
// подстановка после закрывающего слова молчат. Полная запись без хвоста тоже
// обязана закрыть список (`RETURNING`, `WHERE` либо `;`): отличить её от
// продолженной гейт не берётся. Пустой список над таблицей, которую текст не
// называет, колонок не несёт — его колонки приставляются звеньями и судятся
// звеньями.
//
// ЗВЕНО-ПРИСВАИВАНИЕ. Текст, начатый списком присваиваний без оператора и без
// SET (`email = $2`, продолжение `, email = $3` либо `%s, email = $3`, кортеж
// `(display_name, email) = (…)`), приставляют к списку SET во время исполнения;
// голова элемента, называющая адрес, — «не решается». Звено условия отбора
// `email = $N` от звена списка SET неотличимо и пишется со своим словом (WHERE,
// AND, OR) либо выражением над колонкой — так пишет дерево
// (`lower(email) = lower($%d)`). Значение константы и имени уровня пакета
// звеном судится в месте обращения, не вошедшем в свёрнутое выражение
// (`q += set`, элемент `[]string{…}`): свёртка подставляет его туда.
//
// Иначе колонку, собранную во время исполнения, гейт пропустил бы молча.
//
// ─────────────────────────────────────────────────────────────────────────────
// ГРАНИЦЫ, НАЗВАННЫЕ ВСЛУХ
//
//  1. Корпус — непроверочный Go дерева и миграции службы (`PeopleAddressInput`).
//     Места в ПРИМЕНЁННЫХ миграциях, которые правке не подлежат (ban #5),
//     названы ведомостью поимённо — точной координатой
//     (`people_address_writers_migrations.go`); у Go ведомости нет.
//  2. Текст, собранный во время исполнения, судится по звеньям, которые
//     сворачиваются (литерал, склейка, константа). Колонка адреса, дошедшая до
//     списка SET не словом свёрнутого текста — из данных либо значением,
//     подставленным в формат (`fmt.Sprintf("%s = $1", column)`), — видна только
//     там, где ей негде встать молча: пустой список, пустой элемент, подстановка
//     в голове либо в значении, список, не закрытый в тексте. Приставленная к
//     списку, чья таблица в тексте не названа (`"UPDATE " + tbl + " SET "`),
//     либо вставленная в закрытый текст заменой (`strings.Replace`), она не
//     видна: адреса нет ни в одном слове, которое разбор читает. Звено с
//     подстановкой в голове (`%s = $%d`) звеном-присваиванием адреса не
//     считается — так же пишется условие любого построителя отбора.
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
	// PeopleMarkColumn — колонка отметки подтверждения адреса человека.
	PeopleMarkColumn = "email_verified_at"
	// peopleRowsSchema — схема службы: имя со схемой судится только в ней.
	peopleRowsSchema = "kaname"
)

// Ветви списка SET — ключи переписи.
const (
	SetListUpdate   = "UPDATE … SET"
	SetListConflict = "ON CONFLICT … DO UPDATE SET"
	SetListMerge    = "MERGE … THEN UPDATE SET"
)

// peopleGoSubject и peopleMigrationSubject — колонки, запись которых судится в
// своём виде входа.
var (
	peopleGoSubject        = map[string]bool{PeopleAddressColumn: true}
	peopleMigrationSubject = map[string]bool{PeopleAddressColumn: true, PeopleMarkColumn: true}
)

// PeopleAddressInput — отбор корпуса гейта: непроверочный Go и миграции
// службы. Объявлен один раз: гейт дерева и его перепись судят один отбор.
func PeopleAddressInput(rel string) bool {
	return ProductionGoFile(rel) || IsMigrationFile(rel)
}

// Виды операторов записи в строки людей — ключи переписи.
const (
	PeopleStmtUpdate = "UPDATE"
	PeopleStmtInsert = "INSERT"
	PeopleStmtDelete = "DELETE"
	PeopleStmtMerge  = "MERGE"
)

// PeopleAddressHalf — объём осмотренного одного вида входа.
type PeopleAddressHalf struct {
	// Files — разобранные файлы.
	Files int
	// Texts — судимые тексты: у Go — свёрнутые строковые значения (по одному на
	// наибольшее свёрнутое выражение), у миграций — файлы.
	Texts int
	// Statements — операторы записи в строки людей по виду.
	Statements map[string]int
	// SetLists — прочитанные списки SET над строками людей по ветви.
	SetLists map[string]int
	// SetListsClosed — из них закрытые в своём тексте (WHERE, FROM, RETURNING,
	// `;`, скобка): продолжение во время исполнения колонки в них не допишет.
	SetListsClosed int
	// AssignmentPieces — звенья: тексты, начатые списком присваиваний без
	// оператора и без SET.
	AssignmentPieces int
	// Columns — колонки строк людей, которые пишут прочитанные списки SET.
	Columns map[string]int
	// TableAlters — операторы ALTER TABLE над строками людей.
	TableAlters int
	// Routines — прочитанные тела подпрограмм (`CREATE FUNCTION … AS строка`).
	Routines int
	// Triggers — прочитанные объявления триггеров; TriggersOverPeople — из них
	// над строками людей.
	Triggers, TriggersOverPeople int
	// RowAssignments — присваивания строке триггера (`NEW.колонка := …`,
	// `NEW := …`, `INTO NEW.колонка`) в телах подпрограмм, любой колонки.
	RowAssignments int
}

func newPeopleAddressHalf() PeopleAddressHalf {
	return PeopleAddressHalf{Statements: map[string]int{}, SetLists: map[string]int{}, Columns: map[string]int{}}
}

// StatementsTotal — всего операторов записи в строки людей.
func (h PeopleAddressHalf) StatementsTotal() int {
	n := 0
	for _, v := range h.Statements {
		n += v
	}
	return n
}

// String — перепись вида входа словами.
func (h PeopleAddressHalf) String() string {
	cols := make([]string, 0, len(h.Columns))
	for k, v := range h.Columns {
		cols = append(cols, fmt.Sprintf("%s×%d", k, v))
	}
	sort.Strings(cols)
	return fmt.Sprintf("операторов записи в строки людей %d "+
		"(UPDATE %d · INSERT %d · DELETE %d · MERGE %d) · списков SET: %s %d · %s %d · %s %d, "+
		"из них закрыто в тексте %d · колонки [%s] · звеньев-присваиваний %d · ALTER TABLE над строками людей %d · "+
		"тел подпрограмм %d · триггеров %d (над строками людей %d) · присваиваний строке триггера %d",
		h.StatementsTotal(),
		h.Statements[PeopleStmtUpdate], h.Statements[PeopleStmtInsert], h.Statements[PeopleStmtDelete],
		h.Statements[PeopleStmtMerge],
		SetListUpdate, h.SetLists[SetListUpdate], SetListConflict, h.SetLists[SetListConflict],
		SetListMerge, h.SetLists[SetListMerge], h.SetListsClosed, strings.Join(cols, " "), h.AssignmentPieces,
		h.TableAlters, h.Routines, h.Triggers, h.TriggersOverPeople, h.RowAssignments)
}

// add — прибавить к переписи вида входа итог разбора одного текста.
func (h *PeopleAddressHalf) add(p *peopleText) {
	for k, v := range p.stmts {
		h.Statements[k] += v
	}
	for k, v := range p.sets {
		h.SetLists[k] += v
	}
	for k, v := range p.columns {
		h.Columns[k] += v
	}
	h.SetListsClosed += p.closed
	h.AssignmentPieces += p.pieces
	h.TableAlters += p.alters
	h.Routines += p.routines
	h.Triggers += len(p.triggers)
	for _, tr := range p.triggers {
		if tr.table == tablePeople {
			h.TriggersOverPeople++
		}
	}
	h.RowAssignments += p.rowAssigns
}

// PeopleAddressCensus — объём осмотренного по обоим видам входа.
type PeopleAddressCensus struct {
	// Go и Migrations — исходники Go и миграции службы.
	Go, Migrations PeopleAddressHalf
	// Writers — координаты записи адреса (в миграции — и отметки) мимо глагола.
	Writers []string
	// Undecided — координаты операторов, которые разбор не решает.
	Undecided []string
	// Applied — места применённых миграций, названные ведомостью: разобраны на
	// этом прогоне, находкой не являются.
	Applied []string
	// LedgerEntries — записей ведомости; LedgerStale — из них без предмета
	// (находка); LedgerOutOfCorpus — о файлах, которых в корпусе нет.
	LedgerEntries, LedgerStale, LedgerOutOfCorpus int
}

// String — строка переписи для вывода проб.
func (c PeopleAddressCensus) String() string {
	return fmt.Sprintf("исходники Go: файлов %d · строковых значений %d · %s; "+
		"миграции: файлов %d · %s; писателей %d · не решается разбором %d · "+
		"названо ведомостью применённых миграций %d (записей %d, без предмета %d, о файлах вне корпуса %d)",
		c.Go.Files, c.Go.Texts, c.Go, c.Migrations.Files, c.Migrations,
		len(c.Writers), len(c.Undecided), len(c.Applied), c.LedgerEntries, c.LedgerStale, c.LedgerOutOfCorpus)
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

// markWriterFinding — текст отказа на месте записи отметки подтверждения.
func markWriterFinding(where, branch string) string {
	return fmt.Sprintf("%s — оператор пишет отметку подтверждения адреса человека (kaname.users.email_verified_at) "+
		"мимо глагола подтверждения (%s). У отметки два писателя, и третьего не заводится: ставит её только "+
		"предъявление кода подтверждения — оператор `markEmailVerifiedSQL` службы, сверяющий адрес в том же "+
		"операторе; снимает — база на смене адреса (триггер users_email_change_drops_verification). "+
		"Источник — приёмка службы access-beyond-login-needs-a-verified-address.md (Р7) и задача kaname#471",
		where, branch)
}

// peopleSubjectWords — предмет вида входа словами находки «не решается».
func peopleSubjectWords(subject map[string]bool) string {
	if subject[PeopleMarkColumn] {
		return "адрес человека либо отметку его подтверждения (kaname.users.email, kaname.users.email_verified_at)"
	}
	return "адрес человека (kaname.users.email)"
}

// undecidedFinding — текст отказа на форме, которую разбор не решает.
func undecidedFinding(where, why, subject string) string {
	return fmt.Sprintf("%s — %s: разбор не решает, пишет ли оператор %s. "+
		"Список колонок и таблица обязаны сворачиваться при разборе (литерал, склейка, константа); "+
		"форма, которую гейт не решает, — находка, а не молчание", where, why, subject)
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
	column string // у писателя: какую колонку предмета он пишет
	branch string // у писателя
	why    string // у формы, которую разбор не решает
}

// peopleText — итог разбора одного текста.
type peopleText struct {
	// subject — колонки, запись которых судится в этом виде входа.
	subject           map[string]bool
	writes, undecided []peopleMark
	stmts, sets       map[string]int
	columns           map[string]int
	// closed — списки SET над строками людей, закрытые в своём тексте.
	closed int
	// pieces — звенья: тексты, начатые списком присваиваний без оператора.
	pieces int
	// noPieces — текст звеном не судится: это значение константы либо имени
	// уровня пакета, которое свёртка подставляет в каждое обращение, и звеном
	// оно судится там, где к нему обращаются.
	noPieces bool
	// routine — подпрограмма, чьё тело этот текст; пусто — текст не тело.
	routine peopleRoutine
	// alters — операторы ALTER TABLE над строками людей; routines — тела
	// подпрограмм; rowAssigns — присваивания строке триггера любой колонки.
	alters, routines, rowAssigns int
	// triggers — объявления триггеров; assigns — присваивания строке триггера
	// колонки предмета либо строки целиком: решаются привязкой по всему корпусу.
	triggers []peopleTrigger
	assigns  []peopleAssign
}

func newPeopleText(subject map[string]bool) *peopleText {
	return &peopleText{subject: subject, stmts: map[string]int{}, sets: map[string]int{}, columns: map[string]int{}}
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
	head  int // индекс лексемы головы
	cols  []setColumn
	empty bool
	// assign — за головой стоит `=`: элемент — присваивание (`a = …`,
	// `(a, b) = …`), а не имя в перечне и не выражение условия.
	assign bool
}

// readSetItems — элементы списка SET с лексемы s на глубине d и индекс лексемы,
// на которой список кончился; end == len(toks) — список кончился концом текста,
// то есть в тексте не закрыт. Закрывает список слово конца на своей глубине вне
// CASE, `;` либо закрывающая скобка объемлющего.
func readSetItems(toks []sqlTok, dep []int, s, d int) (items []setItem, end int) {
	var (
		cur      = setItem{empty: true}
		caseOpen int
		seen     bool
	)
	flush := func() { items = append(items, cur); cur = setItem{empty: true} }
	end = len(toks)
	for k := s; k < len(toks); k++ {
		t := toks[k]
		if dep[k] < d {
			end = k
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
					end = k
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
		cur.empty, cur.at, cur.head = false, t.at, k
		switch {
		case isOp(t, '(') && dep[k] == d:
			cur.cols = readTupleColumns(toks, dep, k+1, d+1)
			cur.assign = tupleAssigned(toks, dep, k, d)
		case formatHoleEnd(toks, k) >= 0:
			cur.cols = []setColumn{{hole: true}}
		case t.kind == sqlTokName:
			cur.cols = []setColumn{{name: t.name}}
			cur.assign = k+1 < len(toks) && isOp(toks[k+1], '=')
		default:
			cur.cols = []setColumn{{bad: true}}
		}
	}
	if seen {
		flush()
	}
	return items, end
}

// tupleAssigned — кортеж, открытый скобкой в k на глубине d, закрыт в тексте, и
// за ним стоит `=`: голова присваивания `(a, b) = (…)`.
func tupleAssigned(toks []sqlTok, dep []int, k, d int) bool {
	for m := k + 1; m < len(toks); m++ {
		if dep[m] == d {
			return isOp(toks[m], ')') && m+1 < len(toks) && isOp(toks[m+1], '=')
		}
	}
	return false
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
//
// Список, каждый элемент которого решён и ни один не пишет адреса, судится ещё
// раз — на продолжение во время исполнения: не закрытый в тексте (кончается
// концом текста) либо несущий подстановку формата в значении — «не решается».
// Гейт не прослеживает значение до исполнителя запроса, поэтому хвост,
// приставленный склейкой, `+=`, `strings.Join` либо построителем, и текст,
// подставленный в значение, неотличимы от колонки, дописанной в список; закрыт
// список в своём тексте — продолжение колонки в него не допишет.
func (p *peopleText) judgeSetList(toks []sqlTok, dep []int, s, d int, at int, kind peopleTableKind, branch string) {
	if kind == tableOther {
		return
	}
	people := kind == tablePeople
	items, end := readSetItems(toks, dep, s, d)
	if people {
		p.sets[branch]++
		if end < len(toks) {
			p.closed++
		}
	}
	marked := len(p.writes) + len(p.undecided)
	if len(items) == 0 && people {
		p.undecided = append(p.undecided, peopleMark{at: at, why: "список SET над строками людей пуст либо собирается вне текста (" + branch + ")"})
	}
	p.judgeSetItems(items, at, people, branch)
	if len(p.writes)+len(p.undecided) > marked {
		// Список уже назвал себя находкой; продолжение ничего к ней не прибавит.
		return
	}
	over := "строками людей"
	if !people {
		over = "таблицей, которую текст не называет"
	}
	// Пустой список над таблицей, которую текст не называет, колонки не несёт:
	// голова оператора, чьи колонки приставляются звеньями, — они судятся
	// звеньями (`judgeAssignmentPiece`). Пустой список над строками людей —
	// находка выше.
	if end == len(toks) && len(items) > 0 {
		p.undecided = append(p.undecided, peopleMark{at: at, why: "список SET над " + over + " не закрыт в тексте — " +
			"кончается концом текста, а не WHERE, FROM, RETURNING, `;` либо скобкой; хвост, приставленный во время " +
			"исполнения (склейка с переменной, +=, strings.Join, построитель), дописал бы в него колонку, а значение до " +
			"исполнителя запроса гейт не прослеживает — список закрывается в своём тексте (" + branch + ")"})
	}
	for k := s; k < end; k++ {
		if formatHoleEnd(toks, k) >= 0 {
			p.undecided = append(p.undecided, peopleMark{at: toks[k].at, why: "подстановка формата в значении списка SET над " +
				over + " — подставленный текст дописал бы в список колонку (" + branch + ")"})
		}
	}
}

// judgeSetItems — головы элементов списка SET: адрес, подстановка, не имя.
func (p *peopleText) judgeSetItems(items []setItem, at int, people bool, branch string) {
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
			case p.subject[c.name] && people:
				p.writes = append(p.writes, peopleMark{at: it.at, column: c.name, branch: branch})
			case p.subject[c.name]:
				p.undecided = append(p.undecided, peopleMark{at: it.at, why: "оператор пишет колонку " + c.name + ", а таблица — подстановка (" + branch + ")"})
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
	// bodies — строки, являющиеся телом подпрограммы, по индексу лексемы;
	// prose — строки-данные, которые база не исполняет никогда (текст
	// комментария объекта, формат сообщения RAISE).
	bodies := map[int]peopleRoutine{}
	prose := peopleProse(toks, dep)
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		switch {
		case t.kind == sqlTokString && prose[i]:
		case t.kind == sqlTokString:
			judgeNestedPeopleText(t, depth, p, bodies[i])
		case failureRowIsWord(t, "alter"):
			p.judgeAlterTableAt(toks, dep, i)
		case failureRowIsWord(t, "create"):
			p.judgeCreateAt(toks, dep, i, bodies)
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
		items, _ := readSetItems(toks, dep, i+1, dep[i])
		for _, it := range items {
			for _, c := range it.cols {
				if p.subject[c.name] {
					p.undecided = append(p.undecided, peopleMark{at: it.at, why: "список SET называет колонку " + c.name + ", а оператор, которому он принадлежит, собирается вне текста"})
				}
			}
		}
	}
	if p.routine.name != "" {
		p.judgeRowAssignments(toks)
	}
	if !p.noPieces {
		p.judgeAssignmentPiece(toks, dep)
	}
}

// judgeAssignmentPiece — звено: текст, начатый списком присваиваний без
// оператора и без SET (`a = …, b = …`, продолжение `, b = …` либо `%s, b = …`,
// кортеж `(a, b) = (…)`). Во время исполнения его приставляют к списку SET,
// собранному вне текста, и к какому оператору — разбор не решает; голова
// элемента, называющая адрес, — находка «не решается». Элемент пустой либо с
// подстановкой в голове — продолжение приставленного текста; первый элемент, не
// являющийся присваиванием (слово оператора, условия, имя в перечне), звено
// кончает.
func (p *peopleText) judgeAssignmentPiece(toks []sqlTok, dep []int) {
	items, _ := readSetItems(toks, dep, 0, 0)
	piece := false
	for _, it := range items {
		if it.empty || formatHoleEnd(toks, it.head) >= 0 {
			continue
		}
		if !it.assign {
			break
		}
		piece = true
		for _, c := range it.cols {
			if p.subject[c.name] {
				p.undecided = append(p.undecided, peopleMark{at: it.at, why: "звено списка присваиваний без оператора и без SET " +
					"называет колонку " + c.name + " в голове элемента — к какому оператору его приставляют во время исполнения, " +
					"разбор не решает; звено условия отбора неотличимо от звена списка SET и пишется со своим словом " +
					"(WHERE, AND, OR) либо выражением над колонкой (`lower(email) = lower($1)`)"})
			}
		}
	}
	if piece {
		p.pieces++
	}
}

// judgeNestedPeopleText — содержимое строки SQL судится как текст SQL ещё раз
// (динамический SQL, тело `DO $$ … $$`, тело подпрограммы routine); глубже
// sqlMaxNesting — без грамматики. Место внутри дословного прочтения называется
// своим смещением в объемлющем тексте, прочие — началом строки.
func judgeNestedPeopleText(t sqlTok, depth int, p *peopleText, routine peopleRoutine) {
	for ri, r := range t.readings {
		inner := newPeopleText(p.subject)
		inner.routine = routine
		if depth < sqlMaxNesting {
			judgePeopleText(r, depth+1, inner)
		} else {
			for _, col := range sortedSubject(p.subject) {
				if sqlWordFold(r, col) && sqlWordFold(r, "set") {
					inner.undecided = append(inner.undecided, peopleMark{why: "строка SQL глубже предела вложенности называет колонку " + col + " и SET"})
				}
			}
		}
		at := func(m int) int {
			if ri == 0 && t.verbatim {
				return t.at + t.bodyOff + m
			}
			return t.at
		}
		for _, w := range inner.writes {
			p.writes = append(p.writes, peopleMark{at: at(w.at), column: w.column, branch: w.branch + ", внутри строки SQL"})
		}
		for _, u := range inner.undecided {
			p.undecided = append(p.undecided, peopleMark{at: at(u.at), why: u.why + ", внутри строки SQL"})
		}
		for _, a := range inner.assigns {
			a.at = at(a.at)
			p.assigns = append(p.assigns, a)
		}
		p.triggers = append(p.triggers, inner.triggers...)
		for k, v := range inner.stmts {
			p.stmts[k] += v
		}
		for k, v := range inner.sets {
			p.sets[k] += v
		}
		for k, v := range inner.columns {
			p.columns[k] += v
		}
		p.closed += inner.closed
		p.pieces += inner.pieces
		p.alters += inner.alters
		p.routines += inner.routines
		p.rowAssigns += inner.rowAssigns
		if len(inner.writes)+len(inner.undecided)+len(inner.stmts)+inner.pieces+inner.alters+
			inner.routines+inner.rowAssigns+len(inner.triggers) > 0 {
			// Второе прочтение той же строки (обратная коса) — то же место.
			return
		}
	}
}

// sortedSubject — колонки предмета в устойчивом порядке.
func sortedSubject(subject map[string]bool) []string {
	out := make([]string, 0, len(subject))
	for col := range subject {
		out = append(out, col)
	}
	sort.Strings(out)
	return out
}

// judgeUpdateAt — слово UPDATE в i: действие конфликта, действие MERGE либо
// оператор.
func judgeUpdateAt(toks []sqlTok, dep []int, i int, consumed map[int]bool, p *peopleText) {
	if i > 0 {
		prev := toks[i-1]
		// За DO и THEN стоит SET — это действие конфликта либо MERGE. Стоит
		// таблица — это оператор: после THEN в PL/pgSQL (`IF … THEN UPDATE
		// users SET …`) и после DO в правиле (`DO UPDATE users SET …`).
		if (failureRowIsWord(prev, "do") || failureRowIsWord(prev, "then")) &&
			i+1 < len(toks) && failureRowIsWord(toks[i+1], "set") {
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

// plusOperands — звенья склейки `a + b + …` по порядку, сквозь скобки: склейка
// строк ассоциативна, а дерево разбора левое, и без выпрямления звенья,
// стоящие подряд за значением времени исполнения, судились бы порознь.
func plusOperands(e ast.Expr) []ast.Expr {
	switch n := e.(type) {
	case *ast.BinaryExpr:
		if n.Op == token.ADD {
			return append(plusOperands(n.X), plusOperands(n.Y)...)
		}
	case *ast.ParenExpr:
		if inner := plusOperands(n.X); len(inner) > 1 {
			return inner
		}
	}
	return []ast.Expr{e}
}

// runLine — строка исходника для смещения at в тексте звеньев run, свёрнутых
// подряд в texts.
func runLine(f *lvFile, run []ast.Expr, texts []string, at int) int {
	off := 0
	for i, e := range run {
		if at < off+len(texts[i]) || i == len(run)-1 {
			return peopleLine(f, e, texts[i], at-off)
		}
		off += len(texts[i])
	}
	return f.fset.Position(run[0].Pos()).Line
}

// scanPeopleTexts — свёрнутые строковые значения файла: наибольшее свёрнутое
// выражение судится целиком; склейка, которая целиком не свернулась, судится
// звеньями, и звенья, сворачивающиеся подряд, — одним текстом.
//
// Значение константы и имени уровня пакета судится там, где объявлено, — но
// звеном не судится: свёртка подставляет его в каждое обращение, и приставляют
// его к оператору там. Обращение, которое не вошло в наибольшее свёрнутое
// выражение (`q += set`, элемент `[]string{…}`, довод вызова), судится звеном в
// месте обращения.
func scanPeopleTexts(ix *lvIndex, f *lvFile, half *PeopleAddressHalf, sc *peopleScan) {
	report := func(p *peopleText, fn string, line func(at int) int) {
		sc.collect(p, half, f.rel, false, func(at int) (int, string) {
			l := line(at)
			loc := fmt.Sprintf("%s:%d", f.rel, l)
			if fn == "" {
				return l, loc + " вне функции (объявление пакета)"
			}
			return l, loc + " в " + fn + "()"
		})
	}
	judge := func(text, fn string, line func(at int) int, pieces bool) {
		half.Texts++
		p := newPeopleText(peopleGoSubject)
		p.noPieces = !pieces
		judgePeopleText(text, 0, p)
		report(p, fn, line)
	}

	var visit func(root ast.Node, fn string, bound ast.Expr)
	// runs — склейка, которая целиком не свернулась.
	runs := func(sum *ast.BinaryExpr, fn string) {
		ops := plusOperands(sum)
		for i := 0; i < len(ops); {
			j := i
			var texts []string
			for j < len(ops) {
				t, ok := ix.fold(f, ops[j])
				if !ok {
					break
				}
				texts = append(texts, t)
				j++
			}
			switch {
			case j == i:
				visit(ops[i], fn, nil)
				i++
				continue
			case j-i == 1:
				visit(ops[i], fn, nil)
			default:
				run := ops[i:j]
				judge(strings.Join(texts, ""), fn, func(at int) int { return runLine(f, run, texts, at) }, true)
			}
			i = j
		}
	}
	visit = func(root ast.Node, fn string, bound ast.Expr) {
		ast.Inspect(root, func(n ast.Node) bool {
			if gd, ok := n.(*ast.GenDecl); ok {
				if gd.Tok == token.IMPORT {
					return false
				}
				for _, s := range gd.Specs {
					vs, ok := s.(*ast.ValueSpec)
					if !ok {
						visit(s, fn, nil)
						continue
					}
					for _, v := range vs.Values {
						// Обращение к константе и к имени уровня пакета свёртка
						// заменяет значением; к локальной переменной — нет.
						var b ast.Expr
						if fn == "" || gd.Tok == token.CONST {
							b = v
						}
						visit(v, fn, b)
					}
				}
				return false
			}
			e, ok := n.(ast.Expr)
			if !ok {
				return true
			}
			text, ok := ix.fold(f, e)
			if !ok {
				switch x := e.(type) {
				case *ast.SelectorExpr:
					visit(x.X, fn, nil)
					return false
				case *ast.BinaryExpr:
					if x.Op == token.ADD {
						runs(x, fn)
						return false
					}
				}
				return true
			}
			line := func(at int) int { return peopleLine(f, e, text, at) }
			switch e.(type) {
			case *ast.Ident, *ast.SelectorExpr:
				// Обращение к константе либо связанному имени: его значение судится
				// там, где оно объявлено, — второй суд того же текста удвоил бы и
				// перепись, и находку. Здесь оно судится только звеном.
				toks := sqlTokens(text)
				p := newPeopleText(peopleGoSubject)
				p.judgeAssignmentPiece(toks, sqlDepths(toks))
				report(p, fn, line)
				return false
			}
			judge(text, fn, line, e != bound)
			return false
		})
	}
	for _, d := range f.file.Decls {
		switch v := d.(type) {
		case *ast.FuncDecl:
			if v.Body != nil {
				visit(v.Body, peopleFuncLabel(v), nil)
			}
		case *ast.GenDecl:
			visit(v, "", nil)
		}
	}
}

// JudgePeopleAddressWriters — ВЕРДИКТ над корпусом непроверочного Go и миграций
// службы: находки (места записи адреса, в миграции — и отметки; формы, которые
// разбор не решает; записи ведомости применённых миграций без предмета; пустой
// обход любого из двух видов входа) и перепись. Корпус приходит параметром:
// инъекция подаёт синтетику в тот же вердикт, что судит дерево. Файл вне обоих
// видов входа — ошибка, а не молчание.
func JudgePeopleAddressWriters(corpus TreeCorpus) ([]string, PeopleAddressCensus, error) {
	return judgePeopleAddressWriters(corpus, peopleAppliedMigrationSites)
}

func judgePeopleAddressWriters(corpus TreeCorpus, ledger []PeopleAppliedSite) ([]string, PeopleAddressCensus, error) {
	census := PeopleAddressCensus{Go: newPeopleAddressHalf(), Migrations: newPeopleAddressHalf(), LedgerEntries: len(ledger)}
	goCorpus, migrations := TreeCorpus{}, TreeCorpus{}
	for _, rel := range corpus.Rels() {
		switch {
		case strings.HasSuffix(rel, ".go"):
			goCorpus[rel] = corpus[rel]
		case IsMigrationFile(rel):
			migrations[rel] = corpus[rel]
		default:
			return nil, census, fmt.Errorf("%s — вне обоих видов входа гейта (исходник Go, миграция каталога %s): "+
				"гейт не вправе судить файл, грамматики которого он не знает", rel, MigrationsDirRel)
		}
	}
	var sc peopleScan
	ix, files, _, err := newLVIndex(goCorpus, PeopleRowsTable)
	if err != nil {
		return nil, census, err
	}
	for _, f := range files {
		census.Go.Files++
		scanPeopleTexts(ix, f, &census.Go, &sc)
	}
	for _, rel := range migrations.Rels() {
		census.Migrations.Files++
		scanPeopleMigration(rel, migrations[rel], &census.Migrations, &sc)
	}
	sc.resolveRowAssignments()

	sites, applied, stale, outside := matchPeopleLedger(sc.sites, ledger, migrations)
	census.Applied, census.LedgerStale, census.LedgerOutOfCorpus = applied, len(stale), outside
	for _, s := range sites {
		if s.kind == siteUndecided {
			census.Undecided = append(census.Undecided, s.finding())
		} else {
			census.Writers = append(census.Writers, s.finding())
		}
	}
	findings := append(append(append([]string{}, census.Writers...), census.Undecided...), stale...)
	switch {
	case census.Go.Files == 0:
		findings = append(findings, "обход пуст — ни одного файла Go не разобрано: «писателей адреса 0» здесь означало бы «прочитано 0»")
	case census.Go.StatementsTotal() == 0:
		findings = append(findings, fmt.Sprintf("операторов записи в строки людей не найдено ни одного (файлов %d, строковых значений %d) — "+
			"распознаватель слеп либо корпус не тот; молчание о писателях адреса сказано ни о чём", census.Go.Files, census.Go.Texts))
	}
	switch {
	case census.Migrations.Files == 0:
		findings = append(findings, "обход миграций пуст — ни одной миграции не прочитано: «писателей адреса и отметки в миграциях 0» "+
			"здесь означало бы «прочитано 0»")
	case census.Migrations.StatementsTotal() == 0:
		findings = append(findings, fmt.Sprintf("в миграциях операторов записи в строки людей не найдено ни одного (миграций %d) — "+
			"распознаватель слеп либо корпус не тот; молчание о писателях адреса и отметки в миграциях сказано ни о чём",
			census.Migrations.Files))
	}
	sort.Strings(findings)
	return findings, census, nil
}
