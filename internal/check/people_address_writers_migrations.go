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
// Запись строки триггера в теле подпрограммы на PL/pgSQL. База пишет ту
// строку, которую подпрограмма триггера ВЕРНУЛА, поэтому судятся две вещи.
//
//   - Цель присваивания, называющая строку триггера. Строку называют NEW, OLD,
//     их псевдонимы (`имя ALIAS FOR new`, псевдоним псевдонима) и любое из них
//     под меткой блока (`метка.new.колонка`; внешний блок помечен именем
//     подпрограммы). Цели — все, какие есть в грамматике PL/pgSQL: начало
//     оператора (`цель := …`, `цель = …`, с индексом `[…]`), `INTO [STRICT]
//     цель[, …]`, `GET [CURRENT|STACKED] DIAGNOSTICS цель = …`, `FOR цель[, …]
//     IN` (и под меткой цикла `<<метка>>`), `FOREACH цель … IN ARRAY`, аргумент
//     `CALL` целиком (позиционный либо `имя =>`: выходной параметр процедуры
//     пишет в него). Колонка названа — присваивание колонке; нет — строке
//     целиком.
//   - RETURN в подпрограмме, объявленной `RETURNS trigger`: законно вернуть саму
//     строку триггера (NEW, OLD, псевдоним, под меткой, в скобках), NULL, ничего
//     и CASE, каждая ветвь которого законна. Прочее (`RETURN r` после `r :=
//     NEW; r.колонка := …`, `RETURN jsonb_populate_record(NEW, …)`) — строка,
//     которая не строка триггера: база пишет её целиком.
//
// Тело подпрограммы триггера на языке, отличном от PL/pgSQL, разбор не читает —
// оно пишет строку целиком. Какую таблицу пишет подпрограмма, решает
// ПРИВЯЗКА: объявление `CREATE TRIGGER … ON таблица … EXECUTE
// FUNCTION|PROCEDURE имя()` где угодно в корпусе (функция и триггер бывают в
// разных миграциях). Привязана к строкам людей — писатель, если колонка
// названа, и «не решается», если строка пишется целиком (событие не
// различается: заведённая строка, которую пишет триггер, — тоже строка, которой
// сам триггер не заводил); только к чужим таблицам — молчание; к таблице из
// подстановки либо ни к какой — «не решается». Триггер над строками людей
// либо над таблицей из подстановки, чья подпрограмма тела в корпусе не имеет
// (подпрограмма расширения пишет колонку, названную аргументом триггера), —
// «не решается» с координатой объявления триггера.
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
//     тело, объявленное вне корпуса, не видно (у подпрограммы триггера над
//     строками людей это не молчание, а «не решается» — выше).
//     Момент и уровень триггера не различаются: присваивание в подпрограмме
//     триггера AFTER либо FOR EACH STATEMENT (возвращённая строка не пишется) и
//     присваивание OLD в подпрограмме, возвращающей NEW, — лишняя находка, не
//     пропуск.
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

// peoplePLpgSQL — язык тел, которые разбор читает как PL/pgSQL.
const peoplePLpgSQL = "plpgsql"

// peopleRoutine — подпрограмма, чьё тело судится: имя без схемы (ключ
// привязки), написание для находки, возвращает ли она строку триггера
// (`RETURNS trigger`) и язык тела.
type peopleRoutine struct {
	name, label string
	trigger     bool
	lang        string
}

// peopleTrigger — объявление триггера: какую подпрограмму зовёт, над чем и где
// стоит.
type peopleTrigger struct {
	function, label string
	table           peopleTableKind
	at              int
}

// peopleAssignForm — чем подпрограмма пишет строку триггера.
type peopleAssignForm int

const (
	// assignTarget — строка триггера либо её колонка — цель присваивания.
	assignTarget peopleAssignForm = iota
	// assignReturned — подпрограмма триггера возвращает строку, которая не
	// строка триггера: база пишет её целиком.
	assignReturned
	// assignUnread — тело подпрограммы триггера на языке, которого разбор не
	// читает.
	assignUnread
)

// peopleAssign — запись строки триггера: колонка предмета (column) либо
// строка целиком (column пусто).
type peopleAssign struct {
	routine peopleRoutine
	column  string
	at      int
	form    peopleAssignForm
}

// act — что подпрограмма делает со строкой триггера, словами находки.
func (a peopleAssign) act() string {
	switch {
	case a.form == assignReturned:
		return "возвращает строку, которая не строка триггера (RETURN не NEW, не OLD и не NULL), — база пишет возвращённую строку"
	case a.form == assignUnread:
		lang := a.routine.lang
		if lang == "" {
			lang = "без объявления языка"
		}
		return "возвращает строку триггера из тела на языке " + lang + ", которого разбор не читает"
	case a.column == "":
		return "присваивает строке триггера целиком"
	}
	return "присваивает колонке строки триггера " + a.column
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

// peoplePendingAssign — запись строки триггера, ждущая привязки.
type peoplePendingAssign struct {
	peopleAssign
	site peopleSite
}

// peoplePendingTrigger — объявление триггера с местом.
type peoplePendingTrigger struct {
	peopleTrigger
	site peopleSite
}

// peopleScan — места, записи строки триггера, триггеры и тела подпрограмм по
// всему корпусу.
type peopleScan struct {
	sites    []peopleSite
	assigns  []peoplePendingAssign
	triggers []peoplePendingTrigger
	declared map[string]bool
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
	for _, tr := range p.triggers {
		sc.triggers = append(sc.triggers, peoplePendingTrigger{peopleTrigger: tr, site: site(tr.at)})
	}
	if sc.declared == nil {
		sc.declared = map[string]bool{}
	}
	for _, name := range p.declared {
		sc.declared[name] = true
	}
	half.add(p)
}

// resolveRowAssignments — записи строки триггера по привязке во всём корпусе:
// к строкам людей — писатель (колонка названа) либо «не решается» (строка
// целиком); к таблице из подстановки либо ни к какой — «не решается»; только к
// чужим таблицам — молчание. Триггер над строками людей либо над таблицей из
// подстановки, чья подпрограмма не имеет тела в корпусе, — «не решается»: какую
// строку она возвращает, разбор не видит.
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
			s.kind, s.why = siteUndecided, fmt.Sprintf("подпрограмма %s %s, а триггера, который её зовёт, в корпусе нет — "+
				"к какой таблице она привязана, разбор не решает", a.routine.label, a.act())
		case people && a.column == "":
			s.kind, s.why = siteUndecided, fmt.Sprintf("подпрограмма %s, которую зовёт триггер над строками людей, %s — "+
				"какие колонки она пишет, разбор не решает", a.routine.label, a.act())
		case people:
			s.kind, s.column = siteWriter, a.column
			s.branch = fmt.Sprintf("подпрограмма %s, которую зовёт триггер над строками людей, %s",
				a.routine.label, a.act())
		case hole:
			s.kind, s.why = siteUndecided, fmt.Sprintf("подпрограмма %s %s, и зовёт её триггер над таблицей из подстановки",
				a.routine.label, a.act())
		default:
			continue
		}
		sc.sites = append(sc.sites, s)
	}
	for _, tr := range sc.triggers {
		if sc.declared[tr.function] || tr.table != tablePeople && tr.table != tableHole {
			continue
		}
		over := "над строками людей"
		if tr.table == tableHole {
			over = "над таблицей из подстановки"
		}
		s := tr.site
		s.kind, s.why = siteUndecided, fmt.Sprintf("триггер %s зовёт подпрограмму %s, тела которой в корпусе нет (подпрограмма "+
			"расширения пишет колонку, названную аргументом триггера), — какую строку она возвращает, разбор не решает",
			over, tr.label)
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
// FUNCTION|PROCEDURE имя … AS строка`) отмечается для разбора записи строки
// триггера вместе с тем, возвращает ли подпрограмма строку триггера и на каком
// языке тело; объявление триггера записывается для привязки.
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
		body := -1
		for ; k < len(toks) && dep[k] >= d && (dep[k] != d || !isOp(toks[k], ';')); k++ {
			switch {
			case dep[k] != d:
			case isWordAt(toks, k, "returns"):
				if ret, _, ok := readRoutineName(toks, k+1); ok && ret.name == "trigger" {
					routine.trigger = true
				}
			case isWordAt(toks, k, "language") && k+1 < len(toks):
				routine.lang = routineLanguage(toks[k+1])
			case isWordAt(toks, k, "as") && body < 0 && k+1 < len(toks) && toks[k+1].kind == sqlTokString:
				body = k + 1
			}
		}
		if body < 0 {
			return
		}
		bodies[body] = routine
		p.routines++
		p.declared = append(p.declared, routine.name)
		if routine.trigger && routine.lang != peoplePLpgSQL {
			p.assigns = append(p.assigns, peopleAssign{routine: routine, at: toks[i].at, form: assignUnread})
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
					p.triggers = append(p.triggers, peopleTrigger{function: routine.name, label: routine.label, table: table, at: toks[i].at})
				}
				return
			}
		}
	}
}

// routineLanguage — язык тела по лексеме после LANGUAGE: имя либо строка.
func routineLanguage(t sqlTok) string {
	switch {
	case t.kind == sqlTokName:
		return t.name
	case t.kind == sqlTokString && len(t.readings) > 0:
		return strings.ToLower(t.readings[0])
	}
	return ""
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

// peopleStatementStart — лексема k начинает оператор PL/pgSQL: после `;`, после
// слов, за которыми начинается оператор, и после метки `<<метка>>`.
func peopleStatementStart(toks []sqlTok, k int) bool {
	if k == 0 || isOp(toks[k-1], ';') {
		return true
	}
	if k >= 2 && isOp(toks[k-1], '>') && isOp(toks[k-2], '>') {
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
		p.assigns = append(p.assigns, peopleAssign{routine: p.routine, column: column, at: at, form: assignTarget})
	}
}

// triggerRowNames — имена, которыми тело называет строку триггера: NEW, OLD и
// их псевдонимы (`имя ALIAS FOR new`, псевдоним псевдонима — тоже).
func triggerRowNames(toks []sqlTok) map[string]bool {
	rows := map[string]bool{"new": true, "old": true}
	for grown := true; grown; {
		grown = false
		for k := 0; k+3 < len(toks); k++ {
			if toks[k].kind != sqlTokName || rows[toks[k].name] || !isWordAt(toks, k+1, "alias") || !isWordAt(toks, k+2, "for") {
				continue
			}
			if column, _, ok := triggerRowRef(toks, k+3, rows); ok && column == "" {
				rows[toks[k].name], grown = true, true
			}
		}
	}
	return rows
}

// triggerRowRef — ссылка на строку триггера в k: `строка[.колонка]` либо
// `метка.строка[.колонка]` (имя тела квалифицируется меткой блока, внешний блок
// помечен именем подпрограммы). ok — ссылка называет строку триггера; column
// пусто — строку целиком; next — индекс после составного имени.
func triggerRowRef(toks []sqlTok, k int, rows map[string]bool) (column string, next int, ok bool) {
	var parts []string
	next = k
	for next < len(toks) && toks[next].kind == sqlTokName {
		parts = append(parts, toks[next].name)
		next++
		if next+1 >= len(toks) || !isOp(toks[next], '.') || toks[next+1].kind != sqlTokName {
			break
		}
		next++
	}
	for i := 0; i < len(parts) && i < 2; i++ {
		if rows[parts[i]] {
			if i+1 < len(parts) {
				column = parts[i+1]
			}
			return column, next, true
		}
	}
	return "", next, false
}

// skipSubscripts — индекс после индексов элемента `[…]`, начатых в k.
func skipSubscripts(toks []sqlTok, dep []int, k int) int {
	for k < len(toks) && isOp(toks[k], '[') {
		d := dep[k]
		for k++; k < len(toks) && (!isOp(toks[k], ']') || dep[k] != d); k++ {
		}
		if k < len(toks) {
			k++
		}
	}
	return k
}

// judgeRowAssignments — запись строки триггера в теле подпрограммы на
// PL/pgSQL. Цели присваивания — все, какие есть в грамматике PL/pgSQL: начало
// оператора (`цель := …`, `цель = …`), `INTO [STRICT] цель[, …]`, `GET
// [CURRENT|STACKED] DIAGNOSTICS цель = …`, `FOR цель[, …] IN`, `FOREACH цель …
// IN ARRAY`, аргумент `CALL` (выходной параметр процедуры пишет в него). В
// подпрограмме триггера судится и RETURN: база пишет ту строку, которую
// подпрограмма вернула.
func (p *peopleText) judgeRowAssignments(toks []sqlTok, dep []int) {
	rows := triggerRowNames(toks)
	for k := 0; k < len(toks); k++ {
		if isWordAt(toks, k, "into") {
			p.judgeTargets(toks, dep, k+1, rows)
			continue
		}
		if !peopleStatementStart(toks, k) {
			continue
		}
		switch {
		case isWordAt(toks, k, "get"):
			p.judgeDiagnosticsTargets(toks, dep, k+1, rows)
		case isWordAt(toks, k, "for") || isWordAt(toks, k, "foreach"):
			p.judgeTargets(toks, dep, k+1, rows)
		case isWordAt(toks, k, "call"):
			p.judgeCallArguments(toks, dep, k+1, rows)
		case isWordAt(toks, k, "return"):
			if p.routine.trigger {
				p.judgeTriggerReturn(toks, dep, k, rows)
			}
		default:
			if column, next, ok := triggerRowRef(toks, k, rows); ok && assignAt(toks, skipSubscripts(toks, dep, next)) {
				p.recordAssign(column, toks[k].at)
			}
		}
	}
}

// judgeTargets — список целей с лексемы j: `[STRICT] цель[, цель…]` (INTO, FOR,
// FOREACH): цель, называющая строку триггера, — присваивание ей.
func (p *peopleText) judgeTargets(toks []sqlTok, dep []int, j int, rows map[string]bool) {
	if isWordAt(toks, j, "strict") {
		j++
	}
	for j < len(toks) && toks[j].kind == sqlTokName {
		column, next, ok := triggerRowRef(toks, j, rows)
		if ok {
			p.recordAssign(column, toks[j].at)
		}
		j = skipSubscripts(toks, dep, next)
		if j >= len(toks) || !isOp(toks[j], ',') {
			return
		}
		j++
	}
}

// judgeDiagnosticsTargets — `[CURRENT|STACKED] DIAGNOSTICS цель = элемент[, …]`
// с лексемы j.
func (p *peopleText) judgeDiagnosticsTargets(toks []sqlTok, dep []int, j int, rows map[string]bool) {
	if isWordAt(toks, j, "current") || isWordAt(toks, j, "stacked") {
		j++
	}
	if !isWordAt(toks, j, "diagnostics") {
		return
	}
	d := dep[j]
	for j++; j < len(toks); j++ {
		if column, next, ok := triggerRowRef(toks, j, rows); ok && assignAt(toks, skipSubscripts(toks, dep, next)) {
			p.recordAssign(column, toks[j].at)
		}
		for j < len(toks) && (dep[j] != d || !isOp(toks[j], ',') && !isOp(toks[j], ';')) {
			j++
		}
		if j >= len(toks) || !isOp(toks[j], ',') {
			return
		}
	}
}

// judgeCallArguments — `CALL имя(аргумент[, …])` с имени в j: аргумент, который
// целиком называет строку триггера либо её колонку (позиционно либо `имя =>`),
// — присваивание: выходной параметр процедуры пишет в него.
func (p *peopleText) judgeCallArguments(toks []sqlTok, dep []int, j int, rows map[string]bool) {
	_, j, ok := readRoutineName(toks, j)
	if !ok || j >= len(toks) || !isOp(toks[j], '(') {
		return
	}
	d := dep[j] + 1
	s := j + 1
	for k := s; k < len(toks); k++ {
		if dep[k] > d || dep[k] == d && !isOp(toks[k], ',') {
			continue
		}
		a := s
		if a+2 < k && toks[a].kind == sqlTokName &&
			(isOp(toks[a+1], '=') && isOp(toks[a+2], '>') || isOp(toks[a+1], ':') && isOp(toks[a+2], '=')) {
			a += 3
		}
		if column, next, ok := triggerRowRef(toks, a, rows); ok && skipSubscripts(toks, dep, next) == k {
			p.recordAssign(column, toks[a].at)
		}
		if dep[k] < d {
			return
		}
		s = k + 1
	}
}

// judgeTriggerReturn — оператор RETURN в k: законно вернуть саму строку
// триггера (NEW, OLD, их псевдоним, в скобках, под меткой), NULL, ничего и CASE,
// каждая ветвь которого законна; прочее — строка, которая не строка триггера.
func (p *peopleText) judgeTriggerReturn(toks []sqlTok, dep []int, k int, rows map[string]bool) {
	p.returns++
	e := k + 1
	for e < len(toks) && dep[e] >= dep[k] && (dep[e] != dep[k] || !isOp(toks[e], ';')) {
		e++
	}
	if !lawfulTriggerReturn(toks, dep, k+1, e, rows) {
		p.assigns = append(p.assigns, peopleAssign{routine: p.routine, at: toks[k].at, form: assignReturned})
	}
}

// lawfulTriggerReturn — выражение [s, e) возвращает саму строку триггера либо
// ничего.
func lawfulTriggerReturn(toks []sqlTok, dep []int, s, e int, rows map[string]bool) bool {
	for wrapsGroup(toks, dep, s, e) {
		s, e = s+1, e-1
	}
	switch {
	case s >= e:
		return true
	case e == s+1 && isWordAt(toks, s, "null"):
		return true
	case isWordAt(toks, s, "case") && isWordAt(toks, e-1, "end"):
		return lawfulCaseResults(toks, dep, s, e, rows)
	}
	column, next, ok := triggerRowRef(toks, s, rows)
	return ok && column == "" && next == e
}

// wrapsGroup — [s, e) целиком — одна группа в скобках.
func wrapsGroup(toks []sqlTok, dep []int, s, e int) bool {
	if e-s < 2 || !isOp(toks[s], '(') || !isOp(toks[e-1], ')') {
		return false
	}
	for k := s + 1; k < e-1; k++ {
		if dep[k] <= dep[s] {
			return false
		}
	}
	return true
}

// lawfulCaseResults — каждая ветвь результата CASE [s, e) законна; CASE без
// ELSE возвращает NULL.
func lawfulCaseResults(toks []sqlTok, dep []int, s, e int, rows map[string]bool) bool {
	d, nest, start := dep[s], 0, -1
	for k := s + 1; k < e-1; k++ {
		if dep[k] != d {
			continue
		}
		switch {
		case isWordAt(toks, k, "case"):
			nest++
		case isWordAt(toks, k, "end"):
			nest--
		case nest == 0 && (isWordAt(toks, k, "when") || isWordAt(toks, k, "else")):
			if start >= 0 && !lawfulTriggerReturn(toks, dep, start, k, rows) {
				return false
			}
			start = -1
			if isWordAt(toks, k, "else") {
				start = k + 1
			}
		case nest == 0 && isWordAt(toks, k, "then"):
			start = k + 1
		}
	}
	return start < 0 || lawfulTriggerReturn(toks, dep, start, e-1, rows)
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
				"у исходников Go ведомости нет — законного писателя Go называет перечень people_address_lawful_writers.go", e.Rel, e.Line, MigrationsDirRel))
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
