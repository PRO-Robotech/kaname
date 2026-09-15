// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// sql_relation_name.go — ОБЩИЙ распознаватель имени отношения в тексте SQL. По
// нему судят оба гейта материала способа входа: гейт дерева Go — значения
// строковых литералов и их склеек (`login_verifier_containment.go`), гейт
// схемы — тексты подпрограмм базы (`internal/repo/kaname/pg`
// `TestLoginVerifierStaysInsideTheSchema`). Разбор ОДИН: вторая копия
// разошлась бы с первой молча, и расхождение пришлось бы ровно на то
// написание, которое знает только одна из копий.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ — ГРАММАТИКА, А НЕ ПОДСТРОКА
//
// Прежде оба гейта искали имя таблицы образцом «целое слово, регистр как
// есть». Базе регистр имени без кавычек безразличен: `KANAME.USER_LOGIN_METHODS`
// она разрешает в ту же таблицу, и триггер соседней таблицы, читавший материал
// так, проходил мимо гейта схемы с «называющих таблицу 0». Ошибался образец и в
// обратную сторону: `user_login_methods$x` и `user_login_methodsé` для базы —
// другие имена, а образец считал их упоминанием.
//
// Перечень написаний выведен из лексической структуры Postgres 16 (раздел 4.1
// документации: идентификаторы, строковые константы, комментарии), а не из
// памяти:
//
//	ИМЯ
//	  без кавычек          [A-Za-z_\x80-\xff][A-Za-z0-9_$\x80-\xff]*; регистр
//	                       приводится к нижнему ТОЛЬКО у ASCII — база в UTF8
//	                       прочих букв не приводит
//	  в кавычках           "…", `""` внутри — кавычка; сравнение побайтовое
//	  Юникодное            U&"…" и u&"…": \XXXX, \+XXXXXX, `\\`, суррогатная
//	                       пара — один знак; UESCAPE 'c' после имени меняет знак
//	                       экранирования
//	  длиннее 63 байт      база усекает до 63 (NAMEDATALEN-1) по границе знака —
//	                       усекается и здесь
//	  со схемой и без неё  `схема.имя` и имя через путь поиска; `ONLY имя`,
//	                       `имя AS m`, `имя m`, `имя%ROWTYPE` — судится само имя
//
//	ИМЯ ВНУТРИ СТРОКИ — содержимое строки судится как текст SQL ещё раз: так
//	живут динамический SQL (`EXECUTE '…'`), разбор имени (`'…'::regclass`,
//	`to_regclass('…')`) и аргумент `format`
//	  '…' и N'…'           `''` — кавычка; содержимое судится и как есть, и с
//	                       раскрытой обратной косой (на случай посадки с
//	                       standard_conforming_strings = off)
//	  E'…'                 \b \f \n \r \t, \o…\ooo, \xh…\xhh, \uXXXX,
//	                       \UXXXXXXXX, `\c` — сам знак c
//	  U&'…'                как U&"…", с UESCAPE
//	  $метка$…$метка$      содержимое как есть
//	  продолжение          строки, разделённые пробелами с переводом строки
//	                       (и строчными комментариями после него), — одна строка
//	  склейка ||           цепочка строковых констант через `||` судится и
//	                       целиком, и по звеньям — как склейка у гейта Go
//	  B'…', X'…'           битовые строки: имени не несут и не судятся
//
//	КОММЕНТАРИИ — не судятся: `--` до конца строки и `/* */` с вложением.
//
// ─────────────────────────────────────────────────────────────────────────────
// ГРАНИЦЫ, НАЗВАННЫЕ ВСЛУХ
//
//  1. ИМЯ, СОБРАННОЕ ВО ВРЕМЯ ИСПОЛНЕНИЯ, НЕ УЗНАЁТСЯ: склейка с переменной,
//     `lower('USER_…')`, имя из каталога по oid — это поток данных, а не лексика.
//  2. АРГУМЕНТ `format('%I', …)` СУДИТСЯ КАК ТЕКСТ SQL. `%I` берёт имя в
//     кавычки, и `format('%I', 'USER_LOGIN_METHODS')` называет ДРУГОЕ
//     отношение, — распознаватель найдёт в нём таблицу. Ошибка в сторону лишней
//     находки, не пропуска.
//  3. СТРОКИ, ВЛОЖЕННЫЕ ГЛУБЖЕ sqlMaxNesting, судятся без грамматики: имя
//     ищется без учёта регистра и кавычек — лишняя находка возможна, пропуск нет.
//  4. ОСКОЛОК ТЕКСТА (литерал Go, который склеивают во время исполнения):
//     незакрытые строка и имя в кавычках судятся как текст SQL до конца осколка
//     — они могли открыться в соседнем осколке. Комментарий, открытый в
//     осколке, судится как комментарий.
//  5. ТЕКСТ НЕ НА SQL — подпрограмма на языке, чью грамматику распознаватель
//     не знает: `SQLRoutineNamesRelation` судит его без грамматики, как в
//     границе 3.
package check

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// Формы записи имени — ключи переписи у вызывающих.
const (
	SQLFormBare      = "без кавычек"
	SQLFormQuoted    = "в кавычках"
	SQLFormUnicode   = "U&\"…\""
	SQLFormInString  = "внутри строки"
	SQLFormNoGrammar = "без грамматики"
)

// sqlNameMax — предел длины имени: длиннее база усекает (NAMEDATALEN-1).
const sqlNameMax = 63

// sqlMaxNesting — предел вложенности строк; глубже текст судится без грамматики.
const sqlMaxNesting = 6

// SQLNamesRelation — называет ли текст SQL отношение relation хоть раз.
// relation — имя, каким его хранит каталог базы.
func SQLNamesRelation(src, relation string) bool {
	return len(SQLRelationNamings(src, relation)) > 0
}

// SQLRelationNamings — формы, которыми текст называет отношение: по записи на
// упоминание. Упоминание внутри строки записывается формой SQLFormInString, как
// бы оно ни было написано внутри неё.
func SQLRelationNamings(src, relation string) []string {
	var out []string
	sqlJudge(src, relation, 0, func(form string) { out = append(out, form) })
	return out
}

// SQLRoutineNamesRelation — называет ли текст подпрограммы отношение и судился ли
// он грамматикой SQL. Язык решает, какой: `sql` и `plpgsql` — лексикой SQL
// (PL/pgSQL передаёт свои операторы разбору SQL как есть); текст на прочих
// языках — без грамматики (граница 5).
func SQLRoutineNamesRelation(language, src, relation string) (names, grammar bool) {
	switch language {
	case "sql", "plpgsql":
		return SQLNamesRelation(src, relation), true
	}
	return sqlWordFold(src, relation), false
}

// ─────────────────────────────────────────────────────────────────────────────
// лексемы

type sqlTokKind int

const (
	sqlTokOther sqlTokKind = iota
	sqlTokName
	sqlTokString
	sqlTokConcat
)

type sqlTok struct {
	kind sqlTokKind
	// name и form — у имени: имя, каким его разрешит база, и форма записи.
	name, form string
	// readings — у строки: прочтения содержимого (одно либо два).
	readings []string
}

// sqlStrKind — вид строковой константы: от него зависит раскрытие содержимого.
type sqlStrKind int

const (
	sqlStrPlain   sqlStrKind = iota // '…' и N'…'
	sqlStrEscape                    // E'…'
	sqlStrUnicode                   // U&'…'
)

func isSQLSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}

func isSQLIdentStart(c byte) bool {
	return c == '_' || c >= 0x80 || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isSQLIdentCont(c byte) bool {
	return isSQLIdentStart(c) || c == '$' || (c >= '0' && c <= '9')
}

// sqlTokens — лексемы текста; пробелы и комментарии не порождают ничего.
func sqlTokens(src string) []sqlTok {
	var toks []sqlTok
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case isSQLSpace(c):
			i++
		case strings.HasPrefix(src[i:], "--"):
			i = sqlLineEnd(src, i)
		case strings.HasPrefix(src[i:], "/*"):
			i = sqlBlockCommentEnd(src, i)
		case c == '\'':
			tok, next := sqlString(src, i, sqlStrPlain)
			toks, i = append(toks, tok), next
		case c == '"':
			tok, next := sqlQuotedName(src, i, SQLFormQuoted, false)
			toks, i = append(toks, tok), next
		case c == '$':
			tag := sqlDollarTag(src[i:])
			if tag == "" {
				// `$1` — параметр, а не начало строки в долларах.
				toks, i = append(toks, sqlTok{kind: sqlTokOther}), i+1
				continue
			}
			body := src[i+len(tag):]
			end := strings.Index(body, tag)
			if end < 0 {
				toks, i = append(toks, sqlTok{kind: sqlTokString, readings: []string{body}}), len(src)
				continue
			}
			toks = append(toks, sqlTok{kind: sqlTokString, readings: []string{body[:end]}})
			i += len(tag) + end + len(tag)
		case isSQLIdentStart(c):
			j := i + 1
			for j < len(src) && isSQLIdentCont(src[j]) {
				j++
			}
			if j == i+1 && j < len(src) {
				// Однобуквенное слово вплотную к кавычке — приставка константы.
				switch {
				case (c == 'U' || c == 'u') && strings.HasPrefix(src[j:], `&"`):
					tok, next := sqlQuotedName(src, j+1, SQLFormUnicode, true)
					toks, i = append(toks, tok), next
					continue
				case (c == 'U' || c == 'u') && strings.HasPrefix(src[j:], `&'`):
					tok, next := sqlString(src, j+1, sqlStrUnicode)
					toks, i = append(toks, tok), next
					continue
				case src[j] == '\'' && (c == 'E' || c == 'e'):
					tok, next := sqlString(src, j, sqlStrEscape)
					toks, i = append(toks, tok), next
					continue
				case src[j] == '\'' && (c == 'N' || c == 'n'):
					tok, next := sqlString(src, j, sqlStrPlain)
					toks, i = append(toks, tok), next
					continue
				case src[j] == '\'' && (c == 'B' || c == 'b' || c == 'X' || c == 'x'):
					// Битовая строка: содержимое — цифры, имени не несёт.
					_, next, _ := sqlScanSingleQuoted(src, j, false)
					toks, i = append(toks, sqlTok{kind: sqlTokOther}), next
					continue
				}
			}
			toks = append(toks, sqlTok{kind: sqlTokName, name: sqlTruncate(sqlFoldASCII(src[i:j])), form: SQLFormBare})
			i = j
		case c == '|' && strings.HasPrefix(src[i:], "||"):
			toks, i = append(toks, sqlTok{kind: sqlTokConcat}), i+2
		default:
			toks, i = append(toks, sqlTok{kind: sqlTokOther}), i+1
		}
	}
	return toks
}

// sqlLineEnd — позиция перевода строки, завершающего строчный комментарий.
func sqlLineEnd(src string, i int) int {
	if nl := strings.IndexByte(src[i:], '\n'); nl >= 0 {
		return i + nl
	}
	return len(src)
}

// sqlBlockCommentEnd — позиция после блочного комментария с вложением.
func sqlBlockCommentEnd(src string, i int) int {
	depth := 0
	for i < len(src) {
		switch {
		case strings.HasPrefix(src[i:], "/*"):
			depth++
			i += 2
		case strings.HasPrefix(src[i:], "*/"):
			depth--
			i += 2
			if depth == 0 {
				return i
			}
		default:
			i++
		}
	}
	return len(src)
}

// sqlDollarTag — метка строки в долларах в начале s: `$$` либо `$метка$`, где
// метка начинается не с цифры и `$` не содержит. Пусто — не метка.
func sqlDollarTag(s string) string {
	if len(s) < 2 || s[0] != '$' {
		return ""
	}
	i := 1
	if s[i] != '$' {
		if !isSQLIdentStart(s[i]) {
			return ""
		}
		for i < len(s) && s[i] != '$' {
			if !isSQLIdentStart(s[i]) && (s[i] < '0' || s[i] > '9') {
				return ""
			}
			i++
		}
		if i == len(s) {
			return ""
		}
	}
	return s[:i+1]
}

// sqlScanSingleQuoted — содержимое строки в одинарных кавычках, открытой в
// позиции at, с продолжениями; удвоенная кавычка — кавычка. backslash — обратная коса
// экранирует следующий знак (E-строка). closed — строка закрыта.
func sqlScanSingleQuoted(src string, at int, backslash bool) (raw string, next int, closed bool) {
	var b strings.Builder
	i := at + 1
	for i < len(src) {
		c := src[i]
		switch {
		case backslash && c == '\\' && i+1 < len(src):
			b.WriteByte(c)
			b.WriteByte(src[i+1])
			i += 2
		case c == '\'' && i+1 < len(src) && src[i+1] == '\'':
			b.WriteByte('\'')
			i += 2
		case c == '\'':
			if cont := sqlContinuation(src, i+1); cont >= 0 {
				i = cont + 1
				continue
			}
			return b.String(), i + 1, true
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String(), len(src), false
}

// sqlContinuation — позиция кавычки, продолжающей строку, закрытую перед i:
// пробелы с переводом строки, после него — пробелы и строчные комментарии. -1 —
// не продолжение.
func sqlContinuation(src string, i int) int {
	newline := false
	for i < len(src) {
		c := src[i]
		switch {
		case c == '\n':
			newline = true
			i++
		case isSQLSpace(c):
			i++
		case newline && strings.HasPrefix(src[i:], "--"):
			i = sqlLineEnd(src, i)
		case newline && c == '\'':
			return i
		default:
			return -1
		}
	}
	return -1
}

// sqlString — строковая константа вида kind, чья открывающая кавычка в at.
func sqlString(src string, at int, kind sqlStrKind) (sqlTok, int) {
	raw, next, _ := sqlScanSingleQuoted(src, at, kind == sqlStrEscape)
	var readings []string
	switch kind {
	case sqlStrEscape:
		readings = []string{sqlUnbackslash(raw)}
	case sqlStrUnicode:
		esc, after := sqlUEscape(src, next)
		readings, next = []string{sqlUnicodeUnescape(raw, esc)}, after
	default:
		readings = []string{raw}
		if alt := sqlUnbackslash(raw); alt != raw {
			readings = append(readings, alt)
		}
	}
	return sqlTok{kind: sqlTokString, readings: readings}, next
}

// sqlQuotedName — имя в кавычках, открытое в at; unicode — имя U&"…". Незакрытое
// имя судится как текст (граница 4).
func sqlQuotedName(src string, at int, form string, unicode bool) (sqlTok, int) {
	var b strings.Builder
	i := at + 1
	for i < len(src) {
		c := src[i]
		if c == '"' {
			if i+1 < len(src) && src[i+1] == '"' {
				b.WriteByte('"')
				i += 2
				continue
			}
			name, next := b.String(), i+1
			if unicode {
				var esc byte
				esc, next = sqlUEscape(src, next)
				name = sqlUnicodeUnescape(name, esc)
			}
			return sqlTok{kind: sqlTokName, name: sqlTruncate(name), form: form}, next
		}
		b.WriteByte(c)
		i++
	}
	return sqlTok{kind: sqlTokString, readings: []string{b.String()}}, len(src)
}

// sqlUEscape — знак экранирования из `UESCAPE 'c'` после константы U&, и
// позиция после него; без предложения — обратная коса и позиция from.
func sqlUEscape(src string, from int) (byte, int) {
	i := sqlSkipSpaceAndComments(src, from)
	const kw = "uescape"
	if len(src)-i < len(kw) || !strings.EqualFold(src[i:i+len(kw)], kw) ||
		(i+len(kw) < len(src) && isSQLIdentCont(src[i+len(kw)])) {
		return '\\', from
	}
	i = sqlSkipSpaceAndComments(src, i+len(kw))
	if i+2 < len(src) && src[i] == '\'' && src[i+2] == '\'' {
		return src[i+1], i + 3
	}
	return '\\', from
}

func sqlSkipSpaceAndComments(src string, i int) int {
	for i < len(src) {
		switch {
		case isSQLSpace(src[i]):
			i++
		case strings.HasPrefix(src[i:], "--"):
			i = sqlLineEnd(src, i)
		case strings.HasPrefix(src[i:], "/*"):
			i = sqlBlockCommentEnd(src, i)
		default:
			return i
		}
	}
	return i
}

// sqlUnbackslash — раскрытие экранирования E-строки.
func sqlUnbackslash(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 == len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch c := s[i]; {
		case c == 'b':
			b.WriteByte('\b')
		case c == 'f':
			b.WriteByte('\f')
		case c == 'n':
			b.WriteByte('\n')
		case c == 'r':
			b.WriteByte('\r')
		case c == 't':
			b.WriteByte('\t')
		case c == 'x':
			n := sqlDigits(s[i+1:], 2, 16)
			if n == 0 {
				b.WriteByte(c)
				continue
			}
			v, _ := strconv.ParseUint(s[i+1:i+1+n], 16, 8)
			b.WriteByte(byte(v))
			i += n
		case c == 'u' || c == 'U':
			want := 4
			if c == 'U' {
				want = 8
			}
			if sqlDigits(s[i+1:], want, 16) != want {
				b.WriteByte(c)
				continue
			}
			v, _ := strconv.ParseUint(s[i+1:i+1+want], 16, 32)
			b.WriteRune(rune(v))
			i += want
		case c >= '0' && c <= '7':
			n := 1 + sqlDigits(s[i+1:], 2, 8)
			v, _ := strconv.ParseUint(s[i:i+n], 8, 16)
			b.WriteByte(byte(v))
			i += n - 1
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// sqlUnicodeUnescape — раскрытие экранирования константы U& знаком esc.
func sqlUnicodeUnescape(s string, esc byte) string {
	if strings.IndexByte(s, esc) < 0 {
		return s
	}
	var b strings.Builder
	var high rune
	for i := 0; i < len(s); i++ {
		if s[i] != esc || i+1 == len(s) {
			b.WriteByte(s[i])
			continue
		}
		if s[i+1] == esc {
			b.WriteByte(esc)
			i++
			continue
		}
		start, want := i+1, 4
		if s[i+1] == '+' {
			start, want = i+2, 6
		}
		if sqlDigits(s[start:], want, 16) != want {
			b.WriteByte(s[i])
			continue
		}
		v, _ := strconv.ParseUint(s[start:start+want], 16, 32)
		r := rune(v)
		i = start + want - 1
		switch {
		case r >= 0xD800 && r <= 0xDBFF:
			high = r
			continue
		case r >= 0xDC00 && r <= 0xDFFF && high != 0:
			r = 0x10000 + (high-0xD800)<<10 + (r - 0xDC00)
		}
		high = 0
		b.WriteRune(r)
	}
	return b.String()
}

// sqlDigits — сколько подряд цифр основания base (не больше limit) в начале s.
func sqlDigits(s string, limit, base int) int {
	n := 0
	for n < limit && n < len(s) {
		c := s[n]
		ok := (c >= '0' && c <= '7') || (base >= 10 && (c == '8' || c == '9')) ||
			(base == 16 && ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
		if !ok {
			break
		}
		n++
	}
	return n
}

// sqlFoldASCII — приведение имени без кавычек: только ASCII, как у базы в UTF8.
func sqlFoldASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// sqlTruncate — усечение имени до sqlNameMax байт по границе знака.
func sqlTruncate(s string) string {
	if len(s) <= sqlNameMax {
		return s
	}
	n := sqlNameMax
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// sqlJudge — упоминания отношения в тексте на глубине вложенности depth.
func sqlJudge(src, relation string, depth int, emit func(string)) {
	if depth > sqlMaxNesting {
		if sqlWordFold(src, relation) {
			emit(SQLFormNoGrammar)
		}
		return
	}
	inner := func(readings ...string) {
		for _, r := range readings {
			found := false
			sqlJudge(r, relation, depth+1, func(string) { found = true })
			if found {
				emit(SQLFormInString)
				return
			}
		}
	}
	toks := sqlTokens(src)
	for i, t := range toks {
		switch t.kind {
		case sqlTokName:
			if t.name == relation {
				emit(t.form)
			}
		case sqlTokString:
			inner(t.readings...)
			// Начало цепочки `||`: звено, перед которым нет `строка ||`.
			if i >= 2 && toks[i-1].kind == sqlTokConcat && toks[i-2].kind == sqlTokString {
				continue
			}
			first, last := t.readings[0], t.readings[len(t.readings)-1]
			j := i
			for j+2 < len(toks) && toks[j+1].kind == sqlTokConcat && toks[j+2].kind == sqlTokString {
				r := toks[j+2].readings
				first, last = first+r[0], last+r[len(r)-1]
				j += 2
			}
			if j > i {
				inner(first, last)
			}
		}
	}
}

// sqlWordFold — имя как целое слово без учёта регистра ASCII, кавычек и
// комментариев: суд без грамматики (границы 3 и 5). Ошибается только в
// сторону лишней находки.
func sqlWordFold(src, relation string) bool {
	hay, needle := sqlFoldASCII(src), sqlFoldASCII(relation)
	for from := 0; ; {
		k := strings.Index(hay[from:], needle)
		if k < 0 {
			return false
		}
		k += from
		end := k + len(needle)
		if (k == 0 || !isSQLIdentCont(hay[k-1])) && (end == len(hay) || !isSQLIdentCont(hay[end])) {
			return true
		}
		from = k + 1
	}
}
