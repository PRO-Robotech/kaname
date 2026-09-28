// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// people_address_writers_migrations.go — половина гейта писателей адреса людей,
// судящая МИГРАЦИИ службы, и формы записи вне списка SET, которые знает общий
// разбор (задача PRO-Robotech/kaname#471; предмет и разбор списка SET — в шапке
// `people_address_writers.go`, #464).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ В МИГРАЦИИ
//
// Миграция не пишет в строки людей, которых сама не заводит, ни адреса
// (`kaname.users.email`), ни отметки его подтверждения
// (`kaname.users.email_verified_at`). У адреса глагол смены вносится только со
// своими условиями; у отметки писателей два — предъявление кода подтверждения
// ставит её, база на смене адреса снимает, — и миграция третьим не становится.
// Текст миграции судится ТЕМ ЖЕ разбором, что строковые выражения Go: файл —
// один текст SQL, тела `DO $$ … $$`, подпрограмм и динамический SQL — вложенные
// строки, судимые ещё раз. Разделы `-- +goose Up` и `-- +goose Down` судятся
// оба: откат исполняется так же, как накат.
//
// ─────────────────────────────────────────────────────────────────────────────
// ФОРМЫ ЗАПИСИ ВНЕ СПИСКА SET — каждая доказана инъекцией
//
// Определение схемы, пишущее значение колонки в строки, которых оператор не
// заводит (ALTER TABLE над строками людей):
//
//	ADD [COLUMN] [IF NOT EXISTS] колонка … DEFAULT выражение | GENERATED …
//	ALTER [COLUMN] колонка SET DEFAULT выражение     (не NULL: заводимые строки)
//	ALTER [COLUMN] колонка [SET DATA] TYPE … USING выражение
//	ALTER [COLUMN] колонка SET EXPRESSION AS (…)
//	RENAME [COLUMN] другая TO колонка
//	ALTER TABLE [kaname.]другая RENAME TO users     (её строки становятся людьми)
//
// Колонка либо таблица такого определения — подстановка формата (динамический
// SQL, `format('… %I …')`) — «не решается».
//
// Присваивание строке триггера в теле подпрограммы — `NEW.колонка := …`,
// `NEW.колонка = …` в начале оператора, `… INTO [STRICT] NEW.колонка`, строка
// целиком `NEW := …`. Какую таблицу пишет NEW, решает ПРИВЯЗКА: объявление
// `CREATE TRIGGER … ON таблица … EXECUTE FUNCTION|PROCEDURE имя()` где угодно в
// корпусе (функция и триггер бывают в разных миграциях). Привязана к строкам
// людей — писатель (событие не различается: заведённая строка, которую пишет
// триггер, — тоже строка, которой сам триггер не заводил); только к чужим
// таблицам — молчание; к таблице из подстановки либо ни к какой — «не решается».
//
// ─────────────────────────────────────────────────────────────────────────────
// ВЕДОМОСТЬ ПРИМЕНЁННЫХ МИГРАЦИЙ — И ПОЧЕМУ ВЕДОМОСТЬ, А НЕ «ТОЛЬКО ДОБАВЛЕННОЕ»
//
// В применённых миграциях места предмета ЕСТЬ (перепись — в пробе гейта), и
// применённая миграция не правится (ban #5). Соседние гейты миграций судят
// только добавленное относительно ствола; здесь это отвергнуто по трём
// доводам: (1) вердикт — свойство коммита без ствола: судится ВСЁ дерево на
// каждом прогоне, и клон без выборки ствола не уходит в пропуск; (2) места
// неподвижны — применённая миграция не меняется, поэтому ведомость точным числом
// не краснеет на движении к собственной цели; (3) писатель, ДОПИСАННЫЙ в
// применённую миграцию, — находка (обход добавленных файлов его не видит).
//
// Запись ведомости — точная координата (файл, строка, колонка писателя либо
// форма «не решается») и довод. Запись с предметом молчит; запись, чьего места
// на своей строке разбор больше не находит, — находка (ведомость истекает вместе
// с предметом); запись о файле, которого нет в корпусе, считается отдельно
// (`LedgerOutOfCorpus`), и гейт дерева требует её нуля; что каждая запись
// называет ПРИМЕНЁННУЮ и нетронутую миграцию, держит проба гейта дерева по
// стволу.
//
// ─────────────────────────────────────────────────────────────────────────────
// ГРАНИЦЫ, НАЗВАННЫЕ ВСЛУХ
//
//  1. Привязка триггера — по ИМЕНИ подпрограммы, без схемы: база привязывает
//     по идентификатору, и `ALTER FUNCTION … RENAME` привязки не меняет —
//     разбор этого не прослеживает; триггер, снятый позже (`DROP TRIGGER`),
//     привязку не отзывает — лишняя находка, не пропуск.
//  2. Подпрограмма, которую миграция ЗОВЁТ, судится там, где объявлено её тело;
//     тело, объявленное вне корпуса, не видно.
//  3. Запись через представление, правило над представлением и подмена
//     подпрограммы-снимателя отметки (`CREATE OR REPLACE` без присваивания,
//     снятие её триггера) — не формы записи колонки и этим разбором не
//     судятся: снятие отметки на смене адреса и неподтверждённость новой строки
//     держит интеграционная проба схемы на накатанной цепочке
//     (`TestIntegration_AddressVerificationIsBoundToTheValue`,
//     `internal/migrations/login_method_schema_integration_test.go`).
//  4. Заведение строки с отметкой (`INSERT INTO users (…, email_verified_at)`)
//     — заведение, а не запись в строку, которой оператор не заводил.
package check

import (
	"fmt"
	"strings"
)

// peopleRoutine — подпрограмма, чьё тело судится: имя без схемы (ключ
// привязки) и написание для находки.
type peopleRoutine struct {
	name, label string
}

// peopleTrigger — объявление триггера: какую подпрограмму зовёт и над чем.
type peopleTrigger struct {
	function string
	table    peopleTableKind
}

// peopleAssign — присваивание строке триггера колонки предмета; column пусто —
// строка целиком.
type peopleAssign struct {
	routine peopleRoutine
	column  string
	at      int
}

func (a peopleAssign) target() string {
	if a.column == "" {
		return "NEW целиком"
	}
	return "NEW." + a.column
}

// peopleSiteKind — род места: писатель либо форма, которую разбор не решает.
type peopleSiteKind int

const (
	siteWriter peopleSiteKind = iota
	siteUndecided
)

// peopleSite — место находки с координатой.
type peopleSite struct {
	kind      peopleSiteKind
	rel       string
	line      int
	where     string
	column    string // у писателя
	branch    string // у писателя
	why       string // у «не решается»
	subject   string // предмет вида входа словами
	migration bool
}

func (s peopleSite) finding() string {
	switch {
	case s.kind == siteUndecided:
		return undecidedFinding(s.where, s.why, s.subject)
	case s.column == PeopleMarkColumn:
		return markWriterFinding(s.where, s.branch)
	}
	return addressWriterFinding(s.where, s.branch)
}

// peoplePendingAssign — присваивание строке триггера, ждущее привязки.
type peoplePendingAssign struct {
	peopleAssign
	site peopleSite
}

// peopleScan — места, присваивания и триггеры по всему корпусу.
type peopleScan struct {
	sites    []peopleSite
	assigns  []peoplePendingAssign
	triggers []peopleTrigger
}

// collect — итог разбора одного текста: места с координатой и перепись.
func (sc *peopleScan) collect(p *peopleText, half *PeopleAddressHalf, rel string, migration bool, locate func(at int) (int, string)) {
	subject := peopleSubjectWords(p.subject)
	site := func(at int) peopleSite {
		line, where := locate(at)
		return peopleSite{rel: rel, line: line, where: where, subject: subject, migration: migration}
	}
	for _, w := range p.writes {
		s := site(w.at)
		s.kind, s.column, s.branch = siteWriter, w.column, w.branch
		sc.sites = append(sc.sites, s)
	}
	for _, u := range p.undecided {
		s := site(u.at)
		s.kind, s.why = siteUndecided, u.why
		sc.sites = append(sc.sites, s)
	}
	for _, a := range p.assigns {
		sc.assigns = append(sc.assigns, peoplePendingAssign{peopleAssign: a, site: site(a.at)})
	}
	sc.triggers = append(sc.triggers, p.triggers...)
	half.add(p)
}

// resolveRowAssignments — присваивания строке триггера по привязке во всём
// корпусе: к строкам людей — писатель; к таблице из подстановки либо ни к какой
// — «не решается»; только к чужим таблицам — молчание.
func (sc *peopleScan) resolveRowAssignments() {
	byFunction := map[string][]peopleTableKind{}
	for _, tr := range sc.triggers {
		byFunction[tr.function] = append(byFunction[tr.function], tr.table)
	}
	for _, a := range sc.assigns {
		var people, hole bool
		for _, k := range byFunction[a.routine.name] {
			people = people || k == tablePeople
			hole = hole || k == tableHole
		}
		s := a.site
		switch {
		case len(byFunction[a.routine.name]) == 0:
			s.kind, s.why = siteUndecided, fmt.Sprintf("подпрограмма %s присваивает строке триггера (%s), а триггера, "+
				"который её зовёт, в корпусе нет — к какой таблице она привязана, разбор не решает", a.routine.label, a.target())
		case people && a.column == "":
			s.kind, s.why = siteUndecided, fmt.Sprintf("подпрограмма %s, которую зовёт триггер над строками людей, "+
				"присваивает строку триггера целиком — какие колонки она пишет, разбор не решает", a.routine.label)
		case people:
			s.kind, s.column = siteWriter, a.column
			s.branch = fmt.Sprintf("присваивание строке триггера %s в подпрограмме %s, которую зовёт триггер над строками людей",
				a.target(), a.routine.label)
		case hole:
			s.kind, s.why = siteUndecided, fmt.Sprintf("подпрограмму %s, присваивающую строке триггера (%s), зовёт триггер "+
				"над таблицей из подстановки", a.routine.label, a.target())
		default:
			continue
		}
		sc.sites = append(sc.sites, s)
	}
}

// scanPeopleMigration — текст миграции: один текст SQL, место — строка файла.
func scanPeopleMigration(rel, src string, half *PeopleAddressHalf, sc *peopleScan) {
	half.Texts++
	p := newPeopleText(peopleMigrationSubject)
	// Звено — осколок, который приставляют во время исполнения; файл миграции
	// осколком не бывает. Вложенные строки (динамический SQL) звеньями судятся.
	p.noPieces = true
	judgePeopleText(src, 0, p)
	sc.collect(p, half, rel, true, func(at int) (int, string) {
		if at > len(src) {
			at = len(src)
		}
		line := 1 + strings.Count(src[:at], "\n")
		return line, fmt.Sprintf("%s:%d (миграция)", rel, line)
	})
}

// isWordAt — в k стоит слово word без кавычек.
func isWordAt(toks []sqlTok, k int, word string) bool {
	return k >= 0 && k < len(toks) && failureRowIsWord(toks[k], word)
}

// readRoutineName — имя подпрограммы в k: `[схема.]имя`; ok — имя прочитано.
func readRoutineName(toks []sqlTok, k int) (routine peopleRoutine, next int, ok bool) {
	if k >= len(toks) || toks[k].kind != sqlTokName {
		return peopleRoutine{}, k, false
	}
	if k+2 < len(toks) && isOp(toks[k+1], '.') && toks[k+2].kind == sqlTokName {
		return peopleRoutine{name: toks[k+2].name, label: toks[k].name + "." + toks[k+2].name}, k + 3, true
	}
	return peopleRoutine{name: toks[k].name, label: toks[k].name}, k + 1, true
}

// judgeCreateAt — слово CREATE в i: тело подпрограммы (`CREATE [OR REPLACE]
// FUNCTION|PROCEDURE имя … AS строка`) отмечается для разбора присваиваний
// строке триггера; объявление триггера записывается для привязки.
func (p *peopleText) judgeCreateAt(toks []sqlTok, dep []int, i int, bodies map[int]peopleRoutine) {
	j := i + 1
	if isWordAt(toks, j, "or") && isWordAt(toks, j+1, "replace") {
		j += 2
	}
	d := dep[i]
	switch {
	case isWordAt(toks, j, "function") || isWordAt(toks, j, "procedure"):
		routine, k, ok := readRoutineName(toks, j+1)
		if !ok {
			return
		}
		for ; k < len(toks) && dep[k] >= d; k++ {
			if dep[k] != d {
				continue
			}
			if isOp(toks[k], ';') {
				return
			}
			if isWordAt(toks, k, "as") && k+1 < len(toks) && toks[k+1].kind == sqlTokString {
				bodies[k+1] = routine
				p.routines++
				return
			}
		}
	case isWordAt(toks, j, "trigger") || isWordAt(toks, j, "constraint") && isWordAt(toks, j+1, "trigger"):
		k := j + 1
		if isWordAt(toks, j, "constraint") {
			k++
		}
		table := peopleTableKind(-1)
		for ; k < len(toks) && dep[k] >= d; k++ {
			if dep[k] != d {
				continue
			}
			if isOp(toks[k], ';') {
				return
			}
			if isWordAt(toks, k, "on") {
				table, k = readPeopleTable(toks, k+1)
				if table == tableAbsent {
					// Таблица собирается вне текста.
					table = tableHole
				}
				break
			}
		}
		if table < 0 {
			return
		}
		for ; k < len(toks) && dep[k] >= d; k++ {
			if dep[k] != d {
				continue
			}
			if isOp(toks[k], ';') {
				return
			}
			if isWordAt(toks, k, "execute") && (isWordAt(toks, k+1, "function") || isWordAt(toks, k+1, "procedure")) {
				if routine, _, ok := readRoutineName(toks, k+2); ok {
					p.triggers = append(p.triggers, peopleTrigger{function: routine.name, table: table})
				}
				return
			}
		}
	}
}

// peopleRaiseLevels — уровни RAISE, после которых стоит формат сообщения.
var peopleRaiseLevels = map[string]bool{
	"debug": true, "log": true, "info": true, "notice": true, "warning": true, "exception": true,
}

// peopleProse — строки-данные, которые база не исполняет никогда, и поэтому
// текстом SQL не судятся: текст комментария объекта (`COMMENT ON … IS 'текст'`)
// и формат сообщения (`RAISE [уровень] 'формат'`). Прочие строки судятся как
// текст SQL: исполнит ли их база, разбор не решает.
func peopleProse(toks []sqlTok, dep []int) map[int]bool {
	out := map[int]bool{}
	for i := range toks {
		switch {
		case isWordAt(toks, i, "comment") && isWordAt(toks, i+1, "on"):
			for k := i + 2; k < len(toks) && dep[k] >= dep[i]; k++ {
				if dep[k] != dep[i] {
					continue
				}
				if isOp(toks[k], ';') {
					break
				}
				if isWordAt(toks, k, "is") {
					if k+1 < len(toks) && toks[k+1].kind == sqlTokString {
						out[k+1] = true
					}
					break
				}
			}
		case isWordAt(toks, i, "raise"):
			k := i + 1
			if k < len(toks) && toks[k].kind == sqlTokName && toks[k].form == SQLFormBare && peopleRaiseLevels[toks[k].name] {
				k++
			}
			if k < len(toks) && toks[k].kind == sqlTokString {
				out[k] = true
			}
		}
	}
	return out
}

// peopleStatementStart — лексема k начинает оператор PL/pgSQL.
func peopleStatementStart(toks []sqlTok, k int) bool {
	if k == 0 || isOp(toks[k-1], ';') {
		return true
	}
	prev := toks[k-1]
	return prev.kind == sqlTokName && prev.form == SQLFormBare &&
		(prev.name == "begin" || prev.name == "then" || prev.name == "else" || prev.name == "loop")
}

// assignAt — в k стоит знак присваивания PL/pgSQL (`:=` либо `=`).
func assignAt(toks []sqlTok, k int) bool {
	if k >= len(toks) {
		return false
	}
	return isOp(toks[k], '=') || isOp(toks[k], ':') && k+1 < len(toks) && isOp(toks[k+1], '=')
}

// recordAssign — присваивание строке триггера: считается всякое, ждёт привязки
// — колонки предмета и строки целиком.
func (p *peopleText) recordAssign(column string, at int) {
	p.rowAssigns++
	if column == "" || p.subject[column] {
		p.assigns = append(p.assigns, peopleAssign{routine: p.routine, column: column, at: at})
	}
}

// judgeRowAssignments — присваивания строке триггера в теле подпрограммы:
// `NEW.колонка := …` и `NEW := …` в начале оператора, цели `INTO`.
func (p *peopleText) judgeRowAssignments(toks []sqlTok) {
	for k := 0; k < len(toks); k++ {
		if isWordAt(toks, k, "into") {
			p.judgeIntoTargets(toks, k+1)
			continue
		}
		if !isWordAt(toks, k, "new") || !peopleStatementStart(toks, k) {
			continue
		}
		switch {
		case k+2 < len(toks) && isOp(toks[k+1], '.') && toks[k+2].kind == sqlTokName && assignAt(toks, k+3):
			p.recordAssign(toks[k+2].name, toks[k].at)
		case assignAt(toks, k+1):
			p.recordAssign("", toks[k].at)
		}
	}
}

// judgeIntoTargets — цели `INTO [STRICT] цель[, цель…]` с лексемы j: цель
// `NEW.колонка` — присваивание колонке, `NEW` — строке целиком.
func (p *peopleText) judgeIntoTargets(toks []sqlTok, j int) {
	if isWordAt(toks, j, "strict") {
		j++
	}
	for j < len(toks) {
		switch {
		case isWordAt(toks, j, "new") && j+2 < len(toks) && isOp(toks[j+1], '.') && toks[j+2].kind == sqlTokName:
			p.recordAssign(toks[j+2].name, toks[j].at)
			j += 3
		case isWordAt(toks, j, "new"):
			p.recordAssign("", toks[j].at)
			j++
		case toks[j].kind == sqlTokName:
			j++
			if j+1 < len(toks) && isOp(toks[j], '.') && toks[j+1].kind == sqlTokName {
				j += 2
			}
		default:
			return
		}
		if j >= len(toks) || !isOp(toks[j], ',') {
			return
		}
		j++
	}
}

// peopleAddNotColumn — слова после ADD, начинающие не колонку.
var peopleAddNotColumn = map[string]bool{
	"constraint": true, "primary": true, "unique": true, "check": true, "foreign": true, "exclude": true,
}

// Ветви определения схемы — слова находки.
const (
	schemaAddColumn     = "ALTER TABLE … ADD COLUMN … DEFAULT либо GENERATED"
	schemaSetDefault    = "ALTER TABLE … ALTER COLUMN … SET DEFAULT — умолчание пишет колонку в заводимые строки"
	schemaTypeUsing     = "ALTER TABLE … ALTER COLUMN … TYPE … USING"
	schemaSetExpression = "ALTER TABLE … ALTER COLUMN … SET EXPRESSION"
	schemaRenameColumn  = "ALTER TABLE … RENAME COLUMN … TO"
	// Слова ветви не складываются в оператор: гейт судит и собственные строки.
	schemaRenameTable = "чужая таблица переименована в строки людей (ALTER TABLE … RENAME TO), её строки становятся строками людей"
)

// judgeAlterTableAt — слово ALTER в i: `ALTER TABLE [IF EXISTS] [ONLY] таблица
// [*] действие[, действие…]`.
func (p *peopleText) judgeAlterTableAt(toks []sqlTok, dep []int, i int) {
	if !isWordAt(toks, i+1, "table") {
		return
	}
	j := i + 2
	if isWordAt(toks, j, "if") && isWordAt(toks, j+1, "exists") {
		j += 2
	}
	if isWordAt(toks, j, "only") {
		j++
	}
	schema := ""
	if j+1 < len(toks) && toks[j].kind == sqlTokName && isOp(toks[j+1], '.') {
		schema = toks[j].name
	}
	kind, j := readPeopleTable(toks, j)
	if kind == tableAbsent {
		return
	}
	if j < len(toks) && isOp(toks[j], '*') {
		j++
	}
	if kind == tablePeople {
		p.alters++
	}
	d := dep[i]
	for j < len(toks) && dep[j] >= d {
		end := j
		for end < len(toks) && dep[end] >= d && (dep[end] != d || !isOp(toks[end], ',') && !isOp(toks[end], ';')) {
			end++
		}
		p.judgeAlterAction(toks, dep, j, end, d, kind, schema)
		if end >= len(toks) || dep[end] < d || !isOp(toks[end], ',') {
			return
		}
		j = end + 1
	}
}

// columnEnd — индекс после имени колонки либо подстановки в k.
func columnEnd(toks []sqlTok, k int) int {
	if end := formatHoleEnd(toks, k); end >= 0 {
		return end
	}
	return k + 1
}

// wordInAction — слово word стоит в действии [s, b) на его глубине d.
func wordInAction(toks []sqlTok, dep []int, s, b, d int, word string) bool {
	for k := s; k < b; k++ {
		if dep[k] == d && failureRowIsWord(toks[k], word) {
			return true
		}
	}
	return false
}

// judgeAlterAction — одно действие ALTER TABLE [a, b) на глубине d.
func (p *peopleText) judgeAlterAction(toks []sqlTok, dep []int, a, b, d int, kind peopleTableKind, schema string) {
	w := func(k int, word string) bool { return k < b && isWordAt(toks, k, word) }
	switch {
	case w(a, "add"):
		k := a + 1
		if w(k, "column") {
			k++
		}
		if w(k, "if") && w(k+1, "not") && w(k+2, "exists") {
			k += 3
		}
		if k >= b || toks[k].kind == sqlTokName && toks[k].form == SQLFormBare && peopleAddNotColumn[toks[k].name] {
			return
		}
		writes := false
		for m := columnEnd(toks, k); m < b; m++ {
			if dep[m] != d {
				continue
			}
			if failureRowIsWord(toks[m], "generated") ||
				failureRowIsWord(toks[m], "default") && !isWordAt(toks, m+1, "null") {
				writes = true
			}
		}
		if writes {
			p.judgeSchemaColumn(toks, k, kind, schemaAddColumn)
		}
	case w(a, "alter"):
		k := a + 1
		if w(k, "column") {
			k++
		}
		if k >= b {
			return
		}
		c, after := k, columnEnd(toks, k)
		switch {
		case w(after, "set") && w(after+1, "default"):
			if w(after+2, "null") && after+3 == b {
				return
			}
			p.judgeSchemaColumn(toks, c, kind, schemaSetDefault)
		case w(after, "set") && w(after+1, "expression"):
			p.judgeSchemaColumn(toks, c, kind, schemaSetExpression)
		case (w(after, "type") || w(after, "set") && w(after+1, "data") && w(after+2, "type")) &&
			wordInAction(toks, dep, after, b, d, "using"):
			p.judgeSchemaColumn(toks, c, kind, schemaTypeUsing)
		}
	case w(a, "rename"):
		k := a + 1
		switch {
		case w(k, "to"):
			p.judgeTableRename(toks, k+1, kind, schema)
		case w(k, "constraint"):
		default:
			if w(k, "column") {
				k++
			}
			if after := columnEnd(toks, k); w(after, "to") && after+1 < b {
				p.judgeSchemaColumn(toks, after+1, kind, schemaRenameColumn)
			}
		}
	}
}

// judgeSchemaColumn — колонка в k, которую определение схемы над таблицей kind
// пишет в строки, которых не заводит.
func (p *peopleText) judgeSchemaColumn(toks []sqlTok, k int, kind peopleTableKind, branch string) {
	hole := formatHoleEnd(toks, k) >= 0
	named := !hole && toks[k].kind == sqlTokName
	at := toks[k].at
	switch kind {
	case tablePeople:
		switch {
		case !named:
			p.undecided = append(p.undecided, peopleMark{at: at, why: "колонка определения схемы над строками людей — " +
				"подстановка либо не имя (" + branch + ")"})
		case p.subject[toks[k].name]:
			p.writes = append(p.writes, peopleMark{at: at, column: toks[k].name, branch: branch})
		}
	case tableHole:
		if !named || p.subject[toks[k].name] {
			p.undecided = append(p.undecided, peopleMark{at: at, why: "определение схемы над таблицей из подстановки " +
				"пишет колонку предмета либо колонку из подстановки (" + branch + ")"})
		}
	}
}

// judgeTableRename — `ALTER TABLE таблица RENAME TO новое` с именем в k:
// чужая таблица схемы службы, ставшая строками людей, пишет их адреса.
func (p *peopleText) judgeTableRename(toks []sqlTok, k int, kind peopleTableKind, schema string) {
	if k >= len(toks) || kind == tablePeople {
		return
	}
	at := toks[k].at
	hole := formatHoleEnd(toks, k) >= 0
	toPeople := !hole && toks[k].kind == sqlTokName && toks[k].name == PeopleRowsTable
	inSchema := schema == "" || schema == peopleRowsSchema
	switch {
	case kind == tableOther && toPeople && inSchema:
		p.writes = append(p.writes, peopleMark{at: at, column: PeopleAddressColumn, branch: schemaRenameTable})
	case kind == tableHole && toPeople, kind == tableOther && hole && inSchema:
		p.undecided = append(p.undecided, peopleMark{at: at, why: "переименование таблицы, где имя либо таблица — подстановка, " +
			"может сделать строки таблицы строками людей (" + schemaRenameTable + ")"})
	}
}

// PeopleAppliedSite — место предмета в ПРИМЕНЁННОЙ миграции, названное
// ведомостью: точная координата и довод.
type PeopleAppliedSite struct {
	// Rel и Line — файл миграции и строка места.
	Rel  string
	Line int
	// Column — колонка писателя; пусто — место формы «не решается».
	Column string
	// Why — почему место законно и почему правке не подлежит.
	Why string
}

func (e PeopleAppliedSite) what() string {
	if e.Column == "" {
		return "формы «не решается»"
	}
	return "писателя колонки " + e.Column
}

// peopleAppliedMigrationSites — ведомость мест предмета в применённых
// миграциях. Пополняется только местом, которое УЖЕ стоит в применённой
// миграции; новая миграция места предмета не несёт вовсе.
var peopleAppliedMigrationSites = []PeopleAppliedSite{
	{
		Rel: "internal/migrations/20260906085136_cluster_anchor_gets_a_way_back.sql", Line: 392,
		Why: "переписчик написания якоря кластера kaname.rename_cluster_anchor обходит текстовые колонки схемы по " +
			"каталогу (таблица и колонка — подстановки format) и пишет только значения, равные прежнему написанию " +
			"якоря; таблицу и колонку разбор не решает",
	},
	{
		Rel: "internal/migrations/20260906085136_cluster_anchor_gets_a_way_back.sql", Line: 414,
		Why: "тот же переписчик по колонкам jsonb (тип выбирает каталог: `data_type = 'jsonb'`); адрес (text) и " +
			"отметка (timestamptz) в этот обход не входят",
	},
	{
		Rel: "internal/migrations/20260906085136_cluster_anchor_gets_a_way_back.sql", Line: 452,
		Why: "тот же переписчик возвращает умолчания колонок, называвшие прежнее написание якоря; у адреса и " +
			"отметки умолчания нет",
	},
	{
		Rel: "internal/migrations/20260913144108_seed_identity_leaves_the_platform_brand.sql", Line: 145,
		Column: PeopleAddressColumn,
		Why: "перевод адреса посевной строки владельца системного аккаунта (usr1a18042d81fb438d6) на " +
			"`system@system.invalid` (задача kacho#2554): строка заведена сводом, значение — не почтовый ящик (RFC 6761)",
	},
	{
		Rel: "internal/migrations/20260913144108_seed_identity_leaves_the_platform_brand.sql", Line: 195,
		Column: PeopleAddressColumn,
		Why:    "обратный ход того же перевода посевной строки",
	},
	{
		Rel: "internal/migrations/20260915111233_login_methods_live_in_their_own_rows.sql", Line: 105,
		Column: PeopleMarkColumn,
		Why: "снятие отметки базой на смене адреса — триггер users_email_change_drops_verification, второй " +
			"законный писатель отметки",
	},
}

// PeopleAppliedMigrationRels — файлы, которые называет ведомость, без
// повторов: по ним проба гейта дерева сверяет, что каждый ПРИМЕНЁН и не тронут.
func PeopleAppliedMigrationRels() []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range peopleAppliedMigrationSites {
		if !seen[e.Rel] {
			seen[e.Rel] = true
			out = append(out, e.Rel)
		}
	}
	return out
}

// matchPeopleLedger — места корпуса против ведомости: запись с предметом
// поглощает ровно одно место миграции на своей строке; запись без предмета —
// находка; запись о файле вне корпуса считается отдельно.
func matchPeopleLedger(sites []peopleSite, ledger []PeopleAppliedSite, migrations TreeCorpus) (rest []peopleSite, applied, stale []string, outside int) {
	used := make([]bool, len(sites))
	for _, e := range ledger {
		if !IsMigrationFile(e.Rel) {
			stale = append(stale, fmt.Sprintf("%s:%d — запись ведомости применённых миграций называет не миграцию каталога %s: "+
				"у исходников Go ведомости нет", e.Rel, e.Line, MigrationsDirRel))
			continue
		}
		if _, ok := migrations[e.Rel]; !ok {
			outside++
			continue
		}
		found := false
		for i, s := range sites {
			if used[i] || !s.migration || s.rel != e.Rel || s.line != e.Line {
				continue
			}
			if e.Column == "" && s.kind == siteUndecided || e.Column != "" && s.kind == siteWriter && s.column == e.Column {
				used[i], found = true, true
				applied = append(applied, fmt.Sprintf("%s:%d %s — %s", e.Rel, e.Line, e.what(), e.Why))
				break
			}
		}
		if !found {
			stale = append(stale, fmt.Sprintf("%s:%d — запись ведомости применённых миграций без предмета: разбор больше "+
				"не находит на этой строке %s (%s). Применённая миграция не правится (ban #5), поэтому исчезнувшее место "+
				"означает правку применённой миграции либо слепоту разбора; ведомость истекает вместе с предметом — "+
				"запись снимается тем же изменением, что сняло место", e.Rel, e.Line, e.what(), e.Why))
		}
	}
	for i, s := range sites {
		if !used[i] {
			rest = append(rest, s)
		}
	}
	return rest, applied, stale, outside
}
