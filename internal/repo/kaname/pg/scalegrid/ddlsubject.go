// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package scalegrid

import (
	"regexp"
	"strings"
)

// СУБЪЕКТ ОПЕРАТОРА ОПРЕДЕЛЕНИЯ — «что оператор МЕНЯЕТ», а не «что он НАЗЫВАЕТ»
//
// # Что было неверно
//
// Прежний отбор миграций под отпечаток брал оператор, если имя измеряемой
// таблицы встречалось в нём ГДЕ УГОДНО, лишь бы рядом стоял глагол CREATE /
// ALTER / DROP. Самый частый вид такого попадания — раздел ссылок ЧУЖОГО
// определения:
//
//	CREATE TABLE kaname.human_sessions (
//	    user_id text NOT NULL,
//	    CONSTRAINT … FOREIGN KEY (user_id) REFERENCES kaname.users(id) …
//	);
//
// DDL здесь идёт над `human_sessions`; `users` названа лишь как адресат ключа.
// Плана ЧТЕНИЯ `users` это не меняет: ни колонки, ни индекса, ни статистики у
// неё не прибавилось. Отчёт о стоимости вердикта от такой миграции ложным не
// становится — а гейт свежести объявлял его несвежим и требовал пересъёмки,
// каждая около двух часов на поднятой базе.
//
// Замер по истории этого дерева (шесть пересъёмок отчёта R7-1 за 16–17 сентября,
// каждая вызвана РОВНО ОДНОЙ новой миграцией):
//
//	20260915111233_login_methods…      ALTER TABLE kaname.users ADD COLUMN   субъект
//	20260916012708_invite_row…         ALTER TABLE kaname.users ADD COLUMN   субъект
//	20260916190000_human_session…      REFERENCES kaname.users(id)           ССЫЛКА
//	20260917015400_recovery_code…      REFERENCES kaname.users(id)           ССЫЛКА
//	20260917210000_memberships_cursor  CREATE INDEX ON kaname.memberships    субъект
//	20260917221000_access_keys…        REFERENCES kaname.users(id)           ССЫЛКА
//
// Планы чтения при этом сдвинулись РОВНО У ОДНОЙ из шести — у той, что завела
// индекс на измеряемой таблице (`Index Only Scan→memberships` стал
// `Index Scan→memberships`). Три пересъёмки из шести оплачены ссылкой в чужом
// определении.
//
// # Почему РАЗБОР, а не подстрока
//
// Сужение, сделанное ещё одним выражением по тексту («имя не после слова
// REFERENCES»), повторило бы прежний дефект в другой форме: оно отвечало бы на
// вопрос «как записано», а не «что оператор меняет». Поэтому оператор
// РАЗБИРАЕТСЯ: у него опознаётся глагол, вид объекта и СУБЪЕКТ — имя, стоящее в
// грамматически определённой позиции. Позиция выводится из грамматики команды,
// а не из того, в каком месте текста имя оказалось.
//
// Граница разбора названа честно в `ddlStatementOf`: разбирается ГОЛОВА
// оператора, а не всё его тело. Головы хватает, потому что субъект в SQL стоит
// именно в голове; тело читается лишь на предмет раздела ссылок и исполняемого
// динамического DDL.
//
// # СОРАЗМЕРЕН ЛИ РАЗБОР ПРЕДМЕТУ — ЗАМЕР, А НЕ ВПЕЧАТЛЕНИЕ
//
// ## Путь, который здесь НЕ рассматривался, и это надо сказать прямо
//
// Сравнивались два пути: разбирать текст своим распознавателем и разбирать
// чужим (`pg_query_go` поверх парсера сервера — требует cgo, а модуль собирается
// `CGO_ENABLED=0`; чистый Go даёт сотню тысяч строк чужого диалекта). Третий
// путь — НЕ РАЗБИРАТЬ ТЕКСТ ВОВСЕ — не рассматривался ни разу, хотя отвечает на
// тот же вопрос прямее: «изменилась ли структура измеряемых таблиц» читается по
// РЕЗУЛЬТИРУЮЩЕЙ СХЕМЕ, и сравнение двух снимков схемы уместилось бы в десятки
// строк. Он не бесплатен — снимка схемы в дереве сегодня нет, его надо снимать
// на поднятой базе и держать свежим, — но он НЕ БЫЛ ОТВЕРГНУТ, он просто не
// пришёл в голову. Записано здесь именно так, а не как «взвешен и отклонён».
//
// ## Выгода распределена НЕРАВНОМЕРНО, и дорогая треть сегодня не купила ничего
//
// Замер по каталогу миграций (32 файла, 1201 оператор), файлы считаются
// СОБСТВЕННЫЕ — те, которых не берёт никакой другой механизм:
//
//	разрез операторов + разбор головы + раздел ссылок   133 оператора   6 файлов
//	замыкание по динамическому DDL                        2 оператора   1 файл
//	словарь именованных объектов (218 записей)            1 оператор    0 файлов
//	ветка схемы                                           2 оператора   0 файлов
//
// То есть ответ «девять миграций вместо семи» покупает ПЕРВАЯ строка. Замыкание
// по динамическому случаю покупает ровно один файл — и он настоящий, прежним
// предикатом не виденный. А словарь именованных объектов и ветка схемы не
// купили СЕГОДНЯ ни одного файла: оба их срабатывания приходятся на файлы, уже
// взятые разбором головы, и оба — в разделе ОТКАТА, который в работе не
// исполняется вовсе.
//
// Около ста девяноста строк, таким образом, оправданы БУДУЩИМИ формами, а не
// сегодняшним предметом. Называть их «закрытыми слепыми зонами» — приписывать
// себе чужую заслугу: слепая зона у них есть, предмета у неё сегодня нет.
// Оставлены они потому, что цена ошибки несимметрична (пропущенное изменение
// даёт ложное число, лишний файл — лишний прогон), а не потому, что что-то
// поймали.

// ddlScope — ЧЕМУ оператор способен навредить: у приборов этого каталога
// измеряемые величины РАЗНЫЕ, и одна и та же форма значима для одного и
// безразлична другому.
type ddlScope int

const (
	// scopeReadPlan — план ЧТЕНИЯ измеряемой таблицы. Триггер и входящий
	// внешний ключ его не меняют: и то и другое исполняется на ЗАПИСИ.
	scopeReadPlan ddlScope = iota
	// scopeWriteCost — стоимость ЗАПИСИ и УДАЛЕНИЯ строки измеряемой таблицы.
	// Здесь триггер на таблице и входящий ключ с действием значимы: они
	// исполняются ровно на том пути, который этот прибор и меряет.
	scopeWriteCost
)

// qname — имя объекта: схема (может быть пустой) и собственное имя.
type qname struct {
	schema string
	name   string
}

// matches — совпадает ли имя с ИСКОМЫМ. У искомого схема может быть не названа
// (так их пишут пробы) — тогда схема не сужает.
//
// Имя, СОДЕРЖАЩЕЕ подстановку, совпадает с любым искомым: оно и означает «какое
// именно — выяснится при исполнении». Осторожность здесь наступает ПОФАЙЛОВО, в
// том поле, где подстановка стоит, а не на всём операторе: у динамического
// `CREATE TRIGGER` неизвестна таблица-хозяин, и прибору ЧТЕНИЯ это по-прежнему
// безразлично, а прибору ЗАПИСИ — нет.
func (q qname) matches(want qname) bool {
	if strings.Contains(q.name, dynamicPlaceholder) || strings.Contains(q.schema, dynamicPlaceholder) {
		return true
	}
	if q.name != want.name {
		return false
	}
	return want.schema == "" || q.schema == "" || q.schema == want.schema
}

// ddlStatement — разобранная ГОЛОВА одного оператора.
type ddlStatement struct {
	// subjects — таблицы и представления, которые оператор ИЗМЕНЯЕТ.
	subjects []qname
	// schemas — схемы, изменяемые целиком (CREATE/DROP/ALTER SCHEMA): всякая
	// измеряемая таблица такой схемы меняется вместе с ней.
	schemas []string
	// indexes — индексы, названные по имени. Таблицу-хозяйку из текста вывести
	// нельзя: имя индекса её не содержит by construction.
	indexes []qname
	// stats — расширенные статистики, названные по имени. Та же беда, что у
	// индекса, и та же цена ошибки: менять план — их единственное назначение.
	stats []qname
	// triggersOn — таблицы, на которых заводится или снимается триггер.
	triggersOn []qname
	// refs — таблицы, НА КОТОРЫЕ оператор ссылается внешним ключом.
	refs []qname
	// opaque — оператор исполняет DDL, чей субъект подставляется во время
	// выполнения. Статически он не выводится НИКАКИМ разбором.
	opaque bool
	// unknownObject — глагол определения опознан, вид объекта — нет. Пустое
	// значит «голова разобрана целиком».
	unknownObject string
}

// corpusIndex — то, что из ОДНОГО файла не выводится и берётся у всего каталога.
//
// Два таких сведения, и оба нужны, чтобы не промолчать:
//
//	indexOwner       имя индекса и имя расширенной статистики таблицы не
//	                 содержат by construction, а снятие каждого из них план
//	                 чтения меняет наверняка;
//	dynamicDDLFuncs  функция, исполняющая DDL через EXECUTE, ОПРЕДЕЛЯЕТСЯ одной
//	                 миграцией, а ИСПОЛНЯЕТСЯ другой — и структуру меняет вторая.
//
// Оба словаря ВЫВОДЯТСЯ обходом, а не выписываются: выписанный не двигался бы
// от нового индекса и от новой функции.
type corpusIndex struct {
	indexOwner      map[qname]qname
	statsOwner      map[qname]qname
	dynamicDDLFuncs map[string]bool
}

// touchesAnyOf — задевает ли разобранный оператор хоть одну из искомых таблиц.
//
// Индекс, которого в словаре нет, судится осторожно: «задевает». Молчание на
// неизвестном имени было бы слепотой.
func (s ddlStatement) touchesAnyOf(want []qname, scope ddlScope, corpus corpusIndex) bool {
	if s.opaque || s.unknownObject != "" {
		return true
	}
	hit := func(names []qname) bool {
		for _, n := range names {
			for _, w := range want {
				if n.matches(w) {
					return true
				}
			}
		}
		return false
	}
	if hit(s.subjects) {
		return true
	}
	for _, sch := range s.schemas {
		if sch == anySchema || strings.Contains(sch, dynamicPlaceholder) {
			return len(want) > 0
		}
		for _, w := range want {
			if w.schema == "" || w.schema == sch {
				return true
			}
		}
	}
	for _, named := range []struct {
		names []qname
		owner map[qname]qname
	}{{s.indexes, corpus.indexOwner}, {s.stats, corpus.statsOwner}} {
		for _, n := range named.names {
			owner, known := named.owner[n]
			if !known {
				// Имя ни одним объявлением этого каталога не связано с
				// таблицей: связать нечем, и осторожный исход — единственный,
				// не вносящий слепоты.
				return true
			}
			if hit([]qname{owner}) {
				return true
			}
		}
	}
	if scope == scopeWriteCost {
		// Триггер на таблице и входящий ключ исполняются на ЗАПИСИ — ровно на
		// том пути, который этот прибор и меряет.
		if hit(s.triggersOn) || hit(s.refs) {
			return true
		}
	}
	return false
}

// migrationTouchesStructure — меняет ли миграция то, ЧЕМ мерили: структуру
// измеряемой таблицы, от которой зависит план её чтения.
//
// Оболочка над `migrationTouches` для прибора ЧТЕНИЯ: словарь индексов у неё
// пуст, поэтому индекс, названный по имени, судится осторожно. Полный словарь
// собирает обход каталога миграций (`migrationsNaming`).
func migrationTouchesStructure(src string, tables []string) bool {
	return migrationTouches(src, tables, scopeReadPlan, corpusIndex{})
}

// migrationTouches — общий предикат обоих приборов.
func migrationTouches(src string, tables []string, scope ddlScope, corpus corpusIndex) bool {
	want := make([]qname, 0, len(tables))
	for _, t := range tables {
		want = append(want, parseQName(t))
	}
	for _, stmt := range sqlStatements(src) {
		if ddlStatementOf(stmt, corpus).touchesAnyOf(want, scope, corpus) {
			return true
		}
	}
	return false
}

// buildCorpusIndex — оба словаря по ВСЕМУ каталогу миграций.
//
// Множество функций с динамическим DDL замыкается до неподвижной точки: тело,
// зовущее такую функцию, исполняет её DDL так же, как если бы писало его само.
func buildCorpusIndex(bodies map[string]string) corpusIndex {
	c := corpusIndex{
		indexOwner:      map[qname]qname{},
		statsOwner:      map[qname]qname{},
		dynamicDDLFuncs: map[string]bool{},
	}
	for _, body := range bodies {
		namedOwnersIn(body, c.indexOwner, c.statsOwner)
	}
	defs := map[string]string{} // имя функции → её тело
	for _, body := range bodies {
		functionBodiesIn(body, defs)
	}
	for moved := true; moved; {
		moved = false
		for name, body := range defs {
			if c.dynamicDDLFuncs[name] {
				continue
			}
			if !bodyExecutesDDL(body, c.dynamicDDLFuncs) {
				continue
			}
			c.dynamicDDLFuncs[name] = true
			if i := strings.LastIndex(name, "."); i >= 0 {
				c.dynamicDDLFuncs[name[i+1:]] = true
			}
			moved = true
		}
	}
	return c
}

// namedOwnersIn — словари «индекс → его таблица» и «расширенная статистика →
// её таблица», выведенные из текста.
//
// Выводятся, а не выписываются: выписанный перечень не двигался бы от нового
// объявления и продолжал бы знать снятые.
func namedOwnersIn(src string, indexes, stats map[qname]qname) {
	for _, stmt := range sqlStatements(src) {
		toks := sqlTokens(stmt)
		if len(toks) < 3 || toks[0].word != "create" {
			continue
		}
		if toks[1].word == "statistics" {
			name, next := qnameAt(toks, skipWords(toks, 2, "if", "not", "exists"))
			from := findWordAtDepth(toks, next, "from")
			if name.name == "" || from < 0 {
				continue
			}
			if owner, _ := qnameAt(toks, from+1); owner.name != "" {
				rememberOwner(stats, name, owner)
			}
			continue
		}
		i := 1
		for i < len(toks) && (toks[i].word == "unique" || toks[i].word == "concurrently") {
			i++
		}
		if i >= len(toks) || toks[i].word != "index" {
			continue
		}
		i++
		for i < len(toks) && (toks[i].word == "concurrently" || toks[i].word == "if" ||
			toks[i].word == "not" || toks[i].word == "exists") {
			i++
		}
		if i >= len(toks) || toks[i].word == "on" {
			continue // индекс без имени — связывать нечего
		}
		idx, next := qnameAt(toks, i)
		onIdx := findWordAtDepth(toks, next, "on")
		if onIdx < 0 {
			continue
		}
		j := onIdx + 1
		if j < len(toks) && toks[j].word == "only" {
			j++
		}
		owner, _ := qnameAt(toks, j)
		if owner.name == "" {
			continue
		}
		rememberOwner(indexes, idx, owner)
	}
}

// rememberOwner — имя объекта пишут и со схемой, и без неё; в словарь идут обе
// формы, потому что `DROP INDEX`/`DROP STATISTICS` встречаются в обеих.
func rememberOwner(into map[qname]qname, name, owner qname) {
	if name.schema == "" {
		name.schema = owner.schema
	}
	into[name] = owner
	into[qname{name: name.name}] = owner
}

// ── РАЗБОР ГОЛОВЫ ОПЕРАТОРА ────────────────────────────────────────────────

// ИСПОЛНЯЕМЫЙ SQL РАЗБИРАЕТСЯ ТЕМ ЖЕ РАЗБОРОМ — ВТОРОГО СЛОВАРЯ НЕТ
//
// Прежде признак динамического случая был ПАРНЫМ: слово `EXECUTE` и совпадение
// с отдельным перечнем глаголов. Перечень знал формы, заведённые к тому дню, и
// не рос вместе с разбором: статистика, политика, триггер, правило, внешняя
// таблица, перестроение — всё, что разбор научился судить позже, — в
// динамическом виде МОЛЧАЛО. Замер зондом: семь новых форм молчат, старая
// краснеет. Шапки четырёх отчётов при этом обещали обратное — что такие случаи
// судятся осторожно.
//
// Двум спискам об одном предмете расходиться свойственно, и разойдутся они
// снова при следующей форме. Поэтому список ОДИН, и он же разбор: содержимое
// исполняемого литерала разбирается `ddlStatementOf` — той самой функцией, что
// разбирает оператор в файле. Что она умеет судить, то и в динамическом виде
// судится, BY CONSTRUCTION.
//
// # Подстановка отличается от полного имени, и исходы у них РАЗНЫЕ
//
//	EXECUTE format('ALTER TABLE kaname.%I …', r.t)   субъект НЕИЗВЕСТЕН → осторожно
//	EXECUTE 'ALTER TABLE kaname.limits …'            субъект известен  → судится точно
//
// Осторожность наступает В ТОМ ПОЛЕ, где стоит подстановка, а не на всём
// операторе: у динамического `CREATE TRIGGER … ON kaname.%I` неизвестна
// таблица-хозяин, и прибору ЧТЕНИЯ это безразлично по-прежнему, а прибору
// ЗАПИСИ — нет. Прежняя непрозрачность красила оператор целиком и обоим.
//
// Прежний признак не различал их вовсе: любой исполняемый DDL делал оператор
// непрозрачным, то есть задевающим ЛЮБУЮ измеряемую таблицу. Полностью
// выписанный оператор над ЧУЖОЙ таблицей краснел зря.
var (
	dynamicExecute = regexp.MustCompile(`(?i)\bEXECUTE\b`)

	// formatPlaceholder — подстановка `format`. После неё имя субъекта из
	// текста не выводится, и это единственный случай осторожного исхода.
	formatPlaceholder = regexp.MustCompile(`%[IsLdq]`)
)

// dynamicPlaceholder — чем подстановка заменяется перед разбором. Слово, а не
// знак: разбору нужна законная лексема имени, иначе субъект не выделится вовсе
// и оператор пройдёт за «ничего не меняет».
const dynamicPlaceholder = "dynsubjectplaceholder"

// planRelevant — разобранный оператор говорит о структуре хоть чего-нибудь.
func (s ddlStatement) planRelevant() bool {
	return len(s.subjects) > 0 || len(s.stats) > 0 || len(s.indexes) > 0 ||
		len(s.schemas) > 0 || len(s.triggersOn) > 0 || s.unknownObject != ""
}

// merge — предметы вложенного оператора становятся предметами внешнего.
//
// Переносятся ВСЕ поля, включая триггеры и раздел ссылок: их читает прибор
// ЗАПИСИ, и перенести только субъекты значило бы сделать исполняемый оператор
// слепым ровно там, где он видим у оператора в файле.
func (s *ddlStatement) merge(inner ddlStatement) {
	s.subjects = append(s.subjects, inner.subjects...)
	s.stats = append(s.stats, inner.stats...)
	s.indexes = append(s.indexes, inner.indexes...)
	s.schemas = append(s.schemas, inner.schemas...)
	s.triggersOn = append(s.triggersOn, inner.triggersOn...)
	s.refs = append(s.refs, inner.refs...)
	if inner.unknownObject != "" && s.unknownObject == "" {
		s.unknownObject = inner.unknownObject
	}
}

// namingHeads — головы операторов, которые объект НАЗЫВАЮТ, но не исполняют:
// `COMMENT ON FUNCTION`, `DROP FUNCTION`, `GRANT … ON FUNCTION`, определение
// функции. Перечень нужен затем, что определитель динамической функции и её
// исполнитель — разные миграции, и спутать их значит взять не ту.
var namingHeads = map[string]bool{
	"comment": true, "grant": true, "revoke": true, "drop": true, "alter": true,
	"create": true, "set": true, "reset": true, "lock": true, "begin": true,
	"commit": true, "rollback": true, "savepoint": true,
}

// executedDDL — предметы SQL, который оператор ИСПОЛНЯЕТ, а не содержит.
func executedDDL(stmt string, toks []sqlToken, corpus corpusIndex, out *ddlStatement) {
	if len(toks) == 0 || namingHeads[toks[0].word] {
		return
	}
	// Зов функции, которая сама исполняет DDL: её предмет тем более неизвестен.
	if namesAnyOf(stmt, corpus.dynamicDDLFuncs) {
		out.opaque = true
		return
	}
	if !dynamicExecute.MatchString(stmt) {
		return
	}
	for _, lit := range executedLiterals(stmt) {
		inner := parseStatementHead(formatPlaceholder.ReplaceAllString(lit, dynamicPlaceholder))
		if !inner.planRelevant() {
			continue
		}
		out.merge(inner)
	}
}

// executedLiterals — содержимое строковых литералов и тел в долларовых
// кавычках НА ВСЕХ УРОВНЯХ: ровно то, что может быть отдано серверу как SQL.
//
// Уровней именно несколько, и это не запас: исполняемый оператор живёт внутри
// тела функции или `DO`-блока, то есть литералом ВНУТРИ литерала. Разбор в один
// уровень видит тело целиком (`DECLARE … BEGIN …`), головы определения в нём
// нет, и он молчит — так первая редакция этой починки и промолчала по всем
// формам сразу.
//
// Спуск конечен по построению: каждый следующий уровень строго короче
// предыдущего. Предел глубины назван всё равно — на случай текста, устроенного
// так, что наш собственный пропуск литералов не сдвинется.
func executedLiterals(stmt string) []string {
	return literalsAtDepth(stmt, 0)
}

// literalsAtDepth — литералы одного уровня и всё, что лежит внутри них.
func literalsAtDepth(src string, depth int) []string {
	const maxLiteralDepth = 4
	if depth > maxLiteralDepth {
		return nil
	}
	var out []string
	for i := 0; i < len(src); {
		var body string
		switch {
		case src[i] == '\'':
			j := skipSingleQuoted(src, i, escapedStringPrefix(src, i))
			if j-1 > i+1 {
				body = src[i+1 : j-1]
			}
			i = j
		case src[i] == '$':
			end, ok := dollarQuoteEnd(src, i)
			if !ok {
				i++
				continue
			}
			body = dollarQuotedBodyOf(src[i:end])
			i = end
		default:
			i++
			continue
		}
		if body == "" {
			continue
		}
		out = append(out, body)
		out = append(out, literalsAtDepth(body, depth+1)...)
	}
	return out
}

// bodyExecutesDDL — тело функции исполняет DDL прямо или через другую такую же.
func bodyExecutesDDL(body string, dynamic map[string]bool) bool {
	if namesAnyOf(body, dynamic) {
		return true
	}
	if !dynamicExecute.MatchString(body) {
		return false
	}
	for _, lit := range executedLiterals(body) {
		if parseStatementHead(formatPlaceholder.ReplaceAllString(lit, dynamicPlaceholder)).planRelevant() {
			return true
		}
	}
	return false
}

// namesAnyOf — встречается ли в тексте хоть одно из имён ЦЕЛЫМ СЛОВОМ.
//
// Ищется по СЫРОМУ тексту, а не по лексемам: вызов живёт внутри тела в
// долларовых кавычках, а лексема тела — одна метка.
func namesAnyOf(src string, names map[string]bool) bool {
	if len(names) == 0 {
		return false
	}
	lower := strings.ToLower(src)
	for name := range names {
		for i := 0; ; {
			j := strings.Index(lower[i:], name)
			if j < 0 {
				break
			}
			at := i + j
			before := at == 0 || !identPart(lower[at-1])
			after := at+len(name) >= len(lower) || !identPart(lower[at+len(name)])
			if before && after {
				return true
			}
			i = at + len(name)
		}
	}
	return false
}

// functionBodiesIn — тела функций, определённых в тексте, по их именам.
func functionBodiesIn(src string, into map[string]string) {
	for _, stmt := range sqlStatements(src) {
		toks := sqlTokens(stmt)
		if len(toks) == 0 || toks[0].word != "create" {
			continue
		}
		i := skipWords(toks, 1, "or", "replace")
		if i >= len(toks) || (toks[i].word != "function" && toks[i].word != "procedure") {
			continue
		}
		name, _ := qnameAt(toks, i+1)
		if name.name == "" {
			continue
		}
		body := dollarQuotedBodyOf(stmt)
		if body == "" {
			continue
		}
		full := name.name
		if name.schema != "" {
			full = name.schema + "." + name.name
		}
		into[full] += "\n" + body
	}
}

// dollarQuotedBodyOf — содержимое ПЕРВОГО тела в долларовых кавычках.
func dollarQuotedBodyOf(stmt string) string {
	for i := 0; i < len(stmt); i++ {
		if stmt[i] != '$' {
			continue
		}
		end, ok := dollarQuoteEnd(stmt, i)
		if !ok {
			continue
		}
		j := i + 1
		for j < len(stmt) && stmt[j] != '$' {
			j++
		}
		tag := stmt[i : j+1]
		if end-len(tag) > j+1 {
			return stmt[j+1 : end-len(tag)]
		}
		return ""
	}
	return ""
}

// objectKindOf — ВИД ОБЪЕКТА, как его читает разбор.
//
// Один дом на три читателя: разбор, перепись форм и проба доказательства
// безвредности. Каждый, кто выводил вид по-своему, выводил его иначе — перепись
// считала слово в позиции 1..3 и ловила «function» в `ALTER TABLE … DROP
// CONSTRAINT … FUNCTION`, а проба не проверяла вида вовсе.
//
// Короткий оператор даёт ВЕРДИКТ, а не срез за границей: раньше здесь стоял
// `toks[1:4]`, и оператор из двух лексем ронял бы весь прогон. В корпусе такого
// не случилось — но не по построению, а потому, что ёмкость среза оказывалась
// достаточной.
func objectKindOf(toks []sqlToken) string {
	if len(toks) == 0 {
		return ""
	}
	at := func(i int) string {
		if i < 0 || i >= len(toks) {
			return ""
		}
		return toks[i].word
	}
	switch toks[0].word {
	case "analyze", "analyse", "reindex", "cluster", "vacuum":
		return toks[0].word
	case "create":
		i := skipWords(toks, 1, "or", "replace", "global", "local", "temp", "temporary",
			"unlogged", "unique", "concurrently", "recursive")
		return twoWordKind(at(i), at(i+1))
	case "alter", "drop":
		return twoWordKind(at(1), at(2))
	}
	return ""
}

// twoWordKind — виды, чьё имя состоит из двух слов, называются целиком: иначе
// `MATERIALIZED VIEW` и `FOREIGN TABLE` неотличимы от `MATERIALIZED` и
// `FOREIGN`, а `CONSTRAINT TRIGGER` — от ограничения.
func twoWordKind(first, second string) string {
	switch first {
	case "materialized", "constraint", "foreign":
		if second != "" {
			return first + " " + second
		}
	}
	return first
}

// ddlStatementOf — разбор головы ОДНОГО оператора.
//
// # Что разбирается, а что нет
//
// Разбирается ГОЛОВА: глагол, вид объекта и имена в грамматически определённых
// позициях. Тело читается на два признака — раздел ссылок (`REFERENCES …`) и
// исполняемый динамический DDL. Полной грамматики PostgreSQL здесь нет, и это
// названо честно: голова — то место, где стоит субъект, и её грамматика
// перечислима; тело содержит выражения, литералы и тела функций, разбирать
// которые пришлось бы настоящим разборщиком сервера.
//
// Глагол определения, чей ВИД ОБЪЕКТА распознавателю неизвестен, даёт
// `unknownObject` и осторожный исход «задевает»: молчание на незнакомой форме
// было бы слепотой. Что корпус миграций сегодня такой формы не содержит —
// отдельное утверждение, и его держит проба переписи.
func ddlStatementOf(stmt string, corpus corpusIndex) ddlStatement {
	out := parseStatementHead(stmt)
	// ОПРЕДЕЛЕНИЕ функции НЕ ИСПОЛНЯЕТ её тело: структуры оно не меняет, даже
	// если тело сплошь состоит из динамического DDL. Меняет её тот оператор,
	// который функцию ЗОВЁТ, — и он, как правило, живёт в ДРУГОЙ миграции.
	executedDDL(stmt, sqlTokens(stmt), corpus, &out)
	return out
}

// parseStatementHead — разбор ОДНОГО оператора без учёта исполняемого им SQL.
//
// Отделено от `ddlStatementOf` затем, что исполняемый литерал разбирается ЭТОЙ
// же функцией: рекурсия здесь кончается по построению, а не по счётчику.
func parseStatementHead(stmt string) ddlStatement {
	var out ddlStatement
	toks := sqlTokens(stmt)
	if len(toks) == 0 {
		return out
	}

	// Раздел ссылок читается во ВСЁМ операторе: он стоит и в определении
	// колонки, и в отдельном ограничении.
	for i := 0; i < len(toks); i++ {
		if toks[i].word == "references" {
			if ref, _ := qnameAt(toks, i+1); ref.name != "" {
				out.refs = append(out.refs, ref)
			}
		}
	}

	switch toks[0].word {
	case "create":
		parseCreate(toks, &out)
	case "alter":
		parseAlter(toks, &out)
	case "drop":
		parseDrop(toks, &out)
	case "analyze", "analyse", "reindex", "cluster", "vacuum":
		parseMaintenance(toks, &out)
	}
	return out
}

// judgedHeads — головы операторов, которые разбор РАЗБИРАЕТ.
//
// Один источник на разбор и на перепись: перепись, знающая меньше разбора,
// печатает число о другом предмете, и именно так у одного вывода получились
// три разных числа форм.
var judgedHeads = map[string]bool{
	"create": true, "alter": true, "drop": true,
	"analyze": true, "analyse": true, "reindex": true, "cluster": true, "vacuum": true,
}

// ПЕРЕСТРОЕНИЕ И СБОР СТАТИСТИКИ МЕНЯЮТ ПЛАН, НЕ БУДУЧИ ОПРЕДЕЛЕНИЕМ
//
// У этих команд своя голова, и разбор до них не доходил вовсе — а план чтения
// они меняют прямее, чем иное определение:
//
//	ANALYZE   переписывает статистику планировщика
//	REINDEX   перестраивает индексы таблицы
//	CLUSTER   перекладывает строки по индексу, меняя корреляцию
//	VACUUM    двигает оценки числа строк и страниц
//
// Команда БЕЗ имени таблицы (`VACUUM;`, `ANALYZE;`) относится ко всей базе,
// значит и к измеряемым таблицам: она берётся как правка схемы целиком.
func parseMaintenance(toks []sqlToken, out *ddlStatement) {
	i := skipWords(toks, 1, "verbose", "full", "freeze", "analyze", "analyse",
		"concurrently", "force")
	i = skipParenGroup(toks, i)
	i = skipWords(toks, i, "verbose", "full", "freeze", "analyze", "analyse", "concurrently")

	if toks[0].word == "reindex" {
		switch {
		case i < len(toks) && toks[i].word == "index":
			out.indexes = append(out.indexes, qnameList(toks, skipWords(toks, i+1, "concurrently"))...)
			return
		case i < len(toks) && (toks[i].word == "schema" || toks[i].word == "database" ||
			toks[i].word == "system"):
			j := skipWords(toks, i+1, "concurrently")
			if j < len(toks) && toks[j].ident {
				out.schemas = append(out.schemas, toks[j].word)
			} else {
				out.schemas = append(out.schemas, anySchema)
			}
			return
		case i < len(toks) && toks[i].word == "table":
			i = skipWords(toks, i+1, "concurrently")
		}
	}

	names := qnameList(toks, i)
	if len(names) == 0 {
		// Имени нет — команда относится ко ВСЕЙ базе, то есть и к измеряемым
		// таблицам. Молчание здесь было бы слепотой на самой широкой форме.
		out.schemas = append(out.schemas, anySchema)
		return
	}
	out.subjects = append(out.subjects, names...)
}

// anySchema — метка «схема любая»: так записывается команда по всей базе.
const anySchema = "*"

// skipParenGroup — индекс за группой в скобках, если она стоит на месте i.
func skipParenGroup(toks []sqlToken, i int) int {
	if i >= len(toks) || toks[i].word != "(" {
		return i
	}
	for i < len(toks) && toks[i].word != ")" {
		i++
	}
	if i < len(toks) {
		i++
	}
	return i
}

// БЕЗВРЕДНОСТЬ ВИДА ОБЪЕКТА ДОКАЗЫВАЕТСЯ, А НЕ ОБЪЯВЛЯЕТСЯ
//
// Первая редакция этого словаря была ПЕРЕЧНЕМ СЛОВ: вид, попавший в него,
// покупал молчание одним своим присутствием. Через эту дверь класс и вошёл —
// `statistics` и `policy` лежали там без единой инъекции, а менять план чтения
// таблицы есть ЕДИНСТВЕННОЕ назначение расширенной статистики и прямое
// следствие политики построчной безопасности.
//
// Хуже того, слепоту нельзя было увидеть переписью форм: вид, объявленный
// знакомым, ею не ищется ПО ПОСТРОЕНИЮ — «незнакомых ноль» было верно и не
// значило ничего.
//
// Поэтому запись несёт ТРИ оператора, и проба прогоняет каждый:
//
//	naming   этот вид, НАЗЫВАЮЩИЙ измеряемую таблицу        обязан молчать
//	foreign  тот же вид над НЕИЗМЕРЯЕМОЙ                     обязан молчать так же
//	control  иная форма, меняющая план ТОЙ ЖЕ измеряемой     обязана краснеть
//
// Первые два вместе показывают, что исход есть решение о ВИДЕ, а не совпадение
// имени; третий — что имя распознавателю ВИДНО, иначе «молчит» было бы
// неотличимо от «не видит». Записи без всех трёх безвредности не покупают:
// `proven` возвращает ложь, и вид уходит в осторожный исход наравне с
// незнакомым.
//
// Перечень СУЖЕН до видов, которые в каталоге миграций сегодня встречаются.
// Запись, которой нечего исключать, — находка: она переживает свой предмет и
// молча покрывает пустоту.
type harmlessObject struct {
	why     string
	naming  string
	foreign string
	control string
}

// proven — запись несёт все три половины доказательства.
func (h harmlessObject) proven() bool {
	return h.naming != "" && h.foreign != "" && h.control != ""
}

// objectsWithoutTableSubject — виды объектов, чьё определение плана чтения
// измеряемой таблицы не меняет. Вид вне словаря — осторожный исход.
var objectsWithoutTableSubject = map[string]harmlessObject{
	"function": {
		why: "функция ЧИТАЕТ таблицу, а не меняет её: ни столбца, ни индекса, " +
			"ни статистики у таблицы от объявления функции не прибавляется",
		naming: "CREATE FUNCTION kaname.ab_count() RETURNS bigint LANGUAGE sql AS $$" +
			" SELECT count(*) FROM kaname.access_bindings; $$;",
		foreign: "CREATE FUNCTION kaname.lim_count() RETURNS bigint LANGUAGE sql AS $$" +
			" SELECT count(*) FROM kaname.limits; $$;",
		control: "ALTER TABLE kaname.access_bindings ADD COLUMN note text;",
	},
	"sequence": {
		why: "последовательность живёт своим объектом; привязка её к столбцу " +
			"таблицы плана чтения этой таблицы не меняет",
		naming:  "ALTER SEQUENCE kaname.ab_seq OWNED BY kaname.access_bindings.id;",
		foreign: "ALTER SEQUENCE kaname.lim_seq OWNED BY kaname.limits.id;",
		control: "ALTER TABLE kaname.access_bindings ALTER COLUMN id SET DEFAULT 0;",
	},
}

// harmless — вид объекта, безвредность которого ДОКАЗАНА. Объявленная, но не
// доказанная безвредность молчания не покупает.
func harmless(word string) bool {
	h, ok := objectsWithoutTableSubject[word]
	return ok && h.proven()
}

func parseCreate(toks []sqlToken, out *ddlStatement) {
	i := 1
	for i < len(toks) && (toks[i].word == "or" || toks[i].word == "replace" ||
		toks[i].word == "global" || toks[i].word == "local" ||
		toks[i].word == "temp" || toks[i].word == "temporary" || toks[i].word == "unlogged") {
		i++
	}
	if i >= len(toks) {
		return
	}
	switch toks[i].word {
	case "table":
		i = skipWords(toks, i+1, "if", "not", "exists")
		name, next := qnameAt(toks, i)
		if name.name != "" {
			out.subjects = append(out.subjects, name)
		}
		// Секция меняет и план чтения РОДИТЕЛЯ.
		if p := findSeqAtDepth(toks, next, "partition", "of"); p >= 0 {
			if parent, _ := qnameAt(toks, p+2); parent.name != "" {
				out.subjects = append(out.subjects, parent)
			}
		}
		// Наследование — то же самое другими словами: после него чтение
		// РОДИТЕЛЯ обходит и потомка. Имена стоят в скобках, поэтому берутся
		// перечнем. `LIKE` сюда не относится: он копирует описание столбцов
		// один раз и связи не заводит.
		out.subjects = append(out.subjects, inheritedParents(toks, next)...)
	case "view":
		if name, _ := qnameAt(toks, i+1); name.name != "" {
			out.subjects = append(out.subjects, name)
		}
	case "materialized":
		j := skipWords(toks, i+2, "if", "not", "exists") // materialized view …
		if name, _ := qnameAt(toks, j); name.name != "" {
			out.subjects = append(out.subjects, name)
		}
	case "unique", "index":
		parseIndexHead(toks, i, out)
	case "statistics":
		// `CREATE STATISTICS <имя> [(виды)] ON <столбцы> FROM <таблица>` —
		// субъект стоит в хвосте `FROM`. Менять план чтения этой таблицы —
		// ЕДИНСТВЕННОЕ назначение расширенной статистики.
		if from := findWordAtDepth(toks, i, "from"); from >= 0 {
			if tbl, _ := qnameAt(toks, from+1); tbl.name != "" {
				out.subjects = append(out.subjects, tbl)
			}
		}
	case "policy":
		// `CREATE POLICY <имя> ON <таблица> …` — условие политики подставляется
		// в КАЖДЫЙ запрос к таблице, то есть в её план чтения.
		if on := findWordAtDepth(toks, i, "on"); on >= 0 {
			if tbl, _ := qnameAt(toks, on+1); tbl.name != "" {
				out.subjects = append(out.subjects, tbl)
			}
		}
	case "schema":
		j := skipWords(toks, i+1, "if", "not", "exists")
		if j < len(toks) && toks[j].ident {
			out.schemas = append(out.schemas, toks[j].word)
		}
	case "foreign":
		// `CREATE FOREIGN TABLE <имя>` — ТАБЛИЦА: она носит имя в той же схеме и
		// тем же именем читается запросом вердикта. Оговорка «внешняя» говорит,
		// ГДЕ лежат данные, а не чьё имя стоит субъектом.
		// `CREATE FOREIGN DATA WRAPPER` таблицей не является — и безвредным
		// видом тоже не объявлен, поэтому судится ОСТОРОЖНО, а не молча.
		if names := foreignTableName(toks, i); len(names) > 0 {
			out.subjects = append(out.subjects, names...)
		} else {
			out.unknownObject = foreignKindName(toks, i)
		}
	case "trigger", "constraint":
		// CREATE TRIGGER … ON <таблица> и CREATE CONSTRAINT TRIGGER … ON <…>.
		if on := findWordAtDepth(toks, i, "on"); on >= 0 {
			if t, _ := qnameAt(toks, on+1); t.name != "" {
				out.triggersOn = append(out.triggersOn, t)
			}
		}
	case "rule":
		// Правило переписывает и ЧТЕНИЕ: `CREATE RULE … AS ON SELECT TO <таблица>`.
		if to := findWordAtDepth(toks, i, "to"); to >= 0 {
			if t, _ := qnameAt(toks, to+1); t.name != "" {
				out.subjects = append(out.subjects, t)
			}
		}
	default:
		if !harmless(toks[i].word) {
			out.unknownObject = toks[i].word
		}
	}
}

// foreignTableName — имена из `FOREIGN TABLE <имя>[, …]`; у прочих объектов с
// оговоркой `FOREIGN` (обёртка данных, сервер) имени таблицы нет.
func foreignTableName(toks []sqlToken, at int) []qname {
	if at+1 >= len(toks) || toks[at+1].word != "table" {
		return nil
	}
	return qnameList(toks, skipWords(toks, at+2, "if", "not", "exists"))
}

// foreignKindName — вид объекта с оговоркой `FOREIGN`, для текста находки.
func foreignKindName(toks []sqlToken, at int) string {
	if at+1 < len(toks) {
		return "foreign " + toks[at+1].word
	}
	return "foreign"
}

// inheritedParents — родители из оговорки `INHERITS (a, b)`.
func inheritedParents(toks []sqlToken, from int) []qname {
	h := findWordAtDepth(toks, from, "inherits")
	if h < 0 || h+1 >= len(toks) || toks[h+1].word != "(" {
		return nil
	}
	var out []qname
	for i := h + 2; i < len(toks) && toks[i].word != ")"; {
		name, next := qnameAt(toks, i)
		if name.name == "" {
			i++
			continue
		}
		out = append(out, name)
		i = next
		if i < len(toks) && toks[i].word == "," {
			i++
		}
	}
	return out
}

// parseIndexHead — `[UNIQUE] INDEX [CONCURRENTLY] [IF NOT EXISTS] [имя] ON [ONLY] <таблица>`.
func parseIndexHead(toks []sqlToken, i int, out *ddlStatement) {
	for i < len(toks) && toks[i].word != "index" {
		i++
	}
	on := findWordAtDepth(toks, i, "on")
	if on < 0 {
		return
	}
	j := on + 1
	if j < len(toks) && toks[j].word == "only" {
		j++
	}
	if t, _ := qnameAt(toks, j); t.name != "" {
		out.subjects = append(out.subjects, t)
	}
}

func parseAlter(toks []sqlToken, out *ddlStatement) {
	if len(toks) < 2 {
		return
	}
	switch toks[1].word {
	case "table":
		i := skipWords(toks, 2, "if", "exists", "only")
		name, next := qnameAt(toks, i)
		if name.name == "" {
			return
		}
		out.subjects = append(out.subjects, name)
		// `RENAME TO` соседней парой — это переименование САМОЙ таблицы; у
		// колонки и ограничения между словами стоит их вид, и пара не смыкается.
		if r := findSeqAtDepth(toks, next, "rename", "to"); r >= 0 && r+2 < len(toks) {
			out.subjects = append(out.subjects, qname{schema: name.schema, name: toks[r+2].word})
		}
		// `INHERIT <родитель>` и `NO INHERIT <родитель>` меняют план чтения
		// РОДИТЕЛЯ, а субъектом оператора стоит потомок.
		if h := findWordAtDepth(toks, next, "inherit"); h >= 0 {
			if parent, _ := qnameAt(toks, h+1); parent.name != "" {
				out.subjects = append(out.subjects, parent)
			}
		}
	case "foreign":
		if names := foreignTableName(toks, 1); len(names) > 0 {
			out.subjects = append(out.subjects, names...)
		} else {
			out.unknownObject = foreignKindName(toks, 1)
		}
	case "statistics":
		i := skipWords(toks, 2, "if", "exists")
		if st, _ := qnameAt(toks, i); st.name != "" {
			out.stats = append(out.stats, st)
		}
	case "policy":
		if on := findWordAtDepth(toks, 2, "on"); on >= 0 {
			if tbl, _ := qnameAt(toks, on+1); tbl.name != "" {
				out.subjects = append(out.subjects, tbl)
			}
		}
	case "view", "materialized":
		i := 2
		if toks[1].word == "materialized" {
			i = 3
		}
		i = skipWords(toks, i, "if", "exists")
		name, next := qnameAt(toks, i)
		if name.name == "" {
			return
		}
		out.subjects = append(out.subjects, name)
		if r := findSeqAtDepth(toks, next, "rename", "to"); r >= 0 && r+2 < len(toks) {
			out.subjects = append(out.subjects, qname{schema: name.schema, name: toks[r+2].word})
		}
	case "index":
		i := skipWords(toks, 2, "if", "exists")
		if idx, _ := qnameAt(toks, i); idx.name != "" {
			out.indexes = append(out.indexes, idx)
		}
	case "schema":
		i := skipWords(toks, 2, "if", "exists")
		if i < len(toks) && toks[i].ident {
			out.schemas = append(out.schemas, toks[i].word)
		}
	default:
		if !harmless(toks[1].word) {
			out.unknownObject = toks[1].word
		}
	}
}

func parseDrop(toks []sqlToken, out *ddlStatement) {
	if len(toks) < 2 {
		return
	}
	switch toks[1].word {
	case "table":
		out.subjects = append(out.subjects, qnameList(toks, skipWords(toks, 2, "if", "exists"))...)
	case "view":
		out.subjects = append(out.subjects, qnameList(toks, skipWords(toks, 2, "if", "exists"))...)
	case "materialized":
		out.subjects = append(out.subjects, qnameList(toks, skipWords(toks, 3, "if", "exists"))...)
	case "index":
		out.indexes = append(out.indexes, qnameList(toks, skipWords(toks, 2, "concurrently", "if", "exists"))...)
	case "foreign":
		if names := foreignTableName(toks, 1); len(names) > 0 {
			out.subjects = append(out.subjects, names...)
		} else {
			out.unknownObject = foreignKindName(toks, 1)
		}
	case "statistics":
		out.stats = append(out.stats, qnameList(toks, skipWords(toks, 2, "if", "exists"))...)
	case "policy":
		if on := findWordAtDepth(toks, 2, "on"); on >= 0 {
			if tbl, _ := qnameAt(toks, on+1); tbl.name != "" {
				out.subjects = append(out.subjects, tbl)
			}
		}
	case "schema":
		for _, q := range qnameList(toks, skipWords(toks, 2, "if", "exists")) {
			out.schemas = append(out.schemas, q.name)
		}
	case "trigger", "rule":
		if on := findWordAtDepth(toks, 2, "on"); on >= 0 {
			if t, _ := qnameAt(toks, on+1); t.name != "" {
				out.triggersOn = append(out.triggersOn, t)
			}
		}
	default:
		if !harmless(toks[1].word) {
			out.unknownObject = toks[1].word
		}
	}
}

// ── ИМЕНА И ЛЕКСЕМЫ ────────────────────────────────────────────────────────

// sqlToken — лексема оператора. `ident` отличает имя от знака препинания и от
// литерала: литерал в лексему не превращается вовсе, он заменяется меткой.
type sqlToken struct {
	word  string // имя — в нижнем регистре; знак препинания — сам собой
	ident bool
	depth int // глубина вложенности скобок НА момент лексемы
}

var identStart = func(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80
}
var identPart = func(c byte) bool {
	return identStart(c) || (c >= '0' && c <= '9') || c == '$'
}

// sqlTokens — лексемы ОДНОГО оператора. Литералы заменяются меткой `'`: их
// содержимое на субъект не влияет, а вот скобки и точки с запятой внутри них
// сбили бы счёт глубины.
func sqlTokens(stmt string) []sqlToken {
	var out []sqlToken
	depth := 0
	for i := 0; i < len(stmt); {
		c := stmt[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(':
			out = append(out, sqlToken{word: "(", depth: depth})
			depth++
			i++
		case c == ')':
			if depth > 0 {
				depth--
			}
			out = append(out, sqlToken{word: ")", depth: depth})
			i++
		case c == '\'':
			i = skipSingleQuoted(stmt, i, escapedStringPrefix(stmt, i))
			out = append(out, sqlToken{word: "'", depth: depth})
		case c == '"':
			j := i + 1
			var b strings.Builder
			for j < len(stmt) {
				if stmt[j] == '"' {
					if j+1 < len(stmt) && stmt[j+1] == '"' {
						b.WriteByte('"')
						j += 2
						continue
					}
					j++
					break
				}
				b.WriteByte(stmt[j])
				j++
			}
			// Имя в кавычках регистрозависимо; сравнение идёт в нижнем регистре,
			// потому что весь этот корпус пишет имена строчными.
			out = append(out, sqlToken{word: strings.ToLower(b.String()), ident: true, depth: depth})
			i = j
		case c == '$':
			if end, tag := dollarQuoteEnd(stmt, i); tag {
				out = append(out, sqlToken{word: "'", depth: depth})
				i = end
				continue
			}
			out = append(out, sqlToken{word: "$", depth: depth})
			i++
		case identStart(c):
			j := i
			for j < len(stmt) && identPart(stmt[j]) {
				j++
			}
			out = append(out, sqlToken{word: strings.ToLower(stmt[i:j]), ident: true, depth: depth})
			i = j
		default:
			out = append(out, sqlToken{word: string(c), depth: depth})
			i++
		}
	}
	return out
}

// qnameAt — имя объекта, начинающееся с лексемы i. Возвращает имя и индекс
// ПЕРВОЙ лексемы за ним.
func qnameAt(toks []sqlToken, i int) (qname, int) {
	if i >= len(toks) || !toks[i].ident {
		return qname{}, i
	}
	parts := []string{toks[i].word}
	j := i + 1
	for j+1 < len(toks) && toks[j].word == "." && toks[j+1].ident {
		parts = append(parts, toks[j+1].word)
		j += 2
	}
	switch len(parts) {
	case 1:
		return qname{name: parts[0]}, j
	default:
		// `база.схема.таблица` — берутся два последних сегмента.
		return qname{schema: parts[len(parts)-2], name: parts[len(parts)-1]}, j
	}
}

// qnameList — перечень имён через запятую (форма `DROP TABLE a, b, c`).
func qnameList(toks []sqlToken, i int) []qname {
	var out []qname
	for i < len(toks) {
		name, next := qnameAt(toks, i)
		if name.name == "" {
			break
		}
		out = append(out, name)
		i = next
		if i < len(toks) && toks[i].word == "," {
			i++
			continue
		}
		break
	}
	return out
}

// parseQName — искомое имя таблицы из строки вида `kaname.users` или `users`.
func parseQName(s string) qname {
	if i := strings.LastIndex(s, "."); i >= 0 {
		return qname{schema: strings.ToLower(s[:i]), name: strings.ToLower(s[i+1:])}
	}
	return qname{name: strings.ToLower(s)}
}

func skipWords(toks []sqlToken, i int, words ...string) int {
	for i < len(toks) {
		matched := false
		for _, w := range words {
			if toks[i].word == w {
				i++
				matched = true
				break
			}
		}
		if !matched {
			return i
		}
	}
	return i
}

// findWordAtDepth — первая лексема `word` на ВЕРХНЕМ уровне скобок.
func findWordAtDepth(toks []sqlToken, from int, word string) int {
	for i := from; i < len(toks); i++ {
		if toks[i].depth == 0 && toks[i].ident && toks[i].word == word {
			return i
		}
	}
	return -1
}

// findSeqAtDepth — первая пара смежных лексем на верхнем уровне скобок.
func findSeqAtDepth(toks []sqlToken, from int, first, second string) int {
	for i := from; i+1 < len(toks); i++ {
		if toks[i].depth == 0 && toks[i].word == first && toks[i+1].word == second {
			return i
		}
	}
	return -1
}

// ── ГРАНИЦЫ ОПЕРАТОРОВ ─────────────────────────────────────────────────────

// sqlStatements — текст миграции, разбитый на ОПЕРАТОРЫ.
//
// Разделитель ищется только на верхнем уровне: точка с запятой внутри литерала,
// внутри имени в кавычках и внутри тела в долларовых кавычках оператором не
// кончает. Прежний разбор резал текст по каждой точке с запятой — и тело
// функции распадалось на обрывки, у которых головы не было вовсе. Пока предикат
// искал имя ГДЕ УГОДНО, это было безразлично; распознавателю СУБЪЕКТА обрывок
// без головы стоил бы пропущенного оператора.
//
// Комментарии снимаются здесь же и тем же проходом: снимать их отдельным
// выражением по тексту значило бы съедать `--` внутри литерала.
func sqlStatements(src string) []string {
	var out []string
	var b strings.Builder
	flush := func() {
		if s := strings.TrimSpace(b.String()); s != "" {
			out = append(out, s)
		}
		b.Reset()
	}
	for i := 0; i < len(src); {
		switch {
		case src[i] == '-' && i+1 < len(src) && src[i+1] == '-':
			for i < len(src) && src[i] != '\n' {
				i++
			}
			b.WriteByte(' ')
		case src[i] == '/' && i+1 < len(src) && src[i+1] == '*':
			depth, j := 1, i+2
			for j < len(src) && depth > 0 {
				switch {
				case src[j] == '/' && j+1 < len(src) && src[j+1] == '*':
					depth++
					j += 2
				case src[j] == '*' && j+1 < len(src) && src[j+1] == '/':
					depth--
					j += 2
				default:
					j++
				}
			}
			i = j
			b.WriteByte(' ')
		case src[i] == '\'':
			j := skipSingleQuoted(src, i, escapedStringPrefix(src, i))
			b.WriteString(src[i:j])
			i = j
		case src[i] == '"':
			j := i + 1
			for j < len(src) {
				if src[j] == '"' {
					if j+1 < len(src) && src[j+1] == '"' {
						j += 2
						continue
					}
					j++
					break
				}
				j++
			}
			b.WriteString(src[i:j])
			i = j
		case src[i] == '$':
			if end, ok := dollarQuoteEnd(src, i); ok {
				b.WriteString(src[i:end])
				i = end
				continue
			}
			b.WriteByte(src[i])
			i++
		case src[i] == ';':
			flush()
			i++
		default:
			b.WriteByte(src[i])
			i++
		}
	}
	flush()
	return out
}

// skipSingleQuoted — индекс за закрывающей кавычкой литерала.
//
// Форм литерала ДВЕ, и различаются они приставкой:
//
//	'…'    обычная. Кавычку вносит только УДВОЕНИЕ; обратный слэш — обычный
//	       знак (standard_conforming_strings=on, умолчание с Postgres 9.1).
//	E'…'   с экранированием. Обратный слэш экранирует ВСЁ, включая кавычку.
//
// Пропуск, не знающий второй формы, кончает литерал на `\'` и дальше читает
// как код то, что кодом не является, — а следующая настоящая кавычка открывает
// литерал, который тянется ДО КОНЦА ФАЙЛА. Теряется поэтому не один оператор, а
// весь оставшийся текст: замер на трёх операторах дал один.
//
// `escaped` говорит, какая это форма; устанавливает его вызывающий, потому что
// приставка стоит ПЕРЕД кавычкой и в кавычку не входит.
func skipSingleQuoted(src string, i int, escaped bool) int {
	j := i + 1
	for j < len(src) {
		if escaped && src[j] == '\\' {
			// Экранируется СЛЕДУЮЩИЙ знак, каким бы он ни был: `\\` — это слэш,
			// и кавычка за ним литерал закрывает.
			j += 2
			continue
		}
		if src[j] == '\'' {
			if j+1 < len(src) && src[j+1] == '\'' {
				j += 2
				continue
			}
			return j + 1
		}
		j++
	}
	return len(src)
}

// escapedStringPrefix — стоит ли перед кавычкой приставка `E`/`e`, делающая
// литерал экранируемым.
//
// Приставкой она является только ОТДЕЛЬНЫМ словом: у `kaname.some_e'x'` буква
// `e` — хвост имени, и литерал за ней обычный.
func escapedStringPrefix(src string, quote int) bool {
	if quote == 0 || (src[quote-1] != 'E' && src[quote-1] != 'e') {
		return false
	}
	return quote == 1 || !identPart(src[quote-2])
}

// dollarQuoteEnd — индекс за закрывающей долларовой кавычкой и признак того,
// что она вообще открывалась. Метка может быть пустой (`$$`) и именованной
// (`$body$`); `$1` меткой не является.
func dollarQuoteEnd(src string, i int) (int, bool) {
	j := i + 1
	for j < len(src) && identPart(src[j]) && src[j] != '$' {
		j++
	}
	if j >= len(src) || src[j] != '$' {
		return i, false
	}
	tag := src[i : j+1]
	if end := strings.Index(src[j+1:], tag); end >= 0 {
		return j + 1 + end + len(tag), true
	}
	return len(src), true
}
