// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// catalog_seed_parity.go — ЯДРО двух гейтов каталога модуля, отделённое от корня
// дерева НАМЕРЕННО: инъекция обязана прогнать его на синтетическом входе, а не
// на этом дереве.
//
// # Почему пакет сервиса, а не internal/repohygiene
//
// Гейт обязан сверяться с ЛИТЕРАЛОМ, а не с его текстом (чтение чужого исходника
// как текста — отдельный класс дефекта проверки). Литерал живёт в
// `internal/authzmap`, и корневой `internal/repohygiene` импортировать
// его НЕ МОЖЕТ: правило внутренних пакетов Go допускает импорт
// `internal/...` только из поддерева `services/iam/`. Прогнано и
// получено: «use of internal package … not allowed». Поэтому гейт живёт рядом со
// вторым гейтом того же предмета (`retired_block_storage_test.go`), а не рядом с
// прочими гейтами дерева.
//
// Гейт первый — ПАРИТЕТ: строки, которые сеет миграция каталога, обязаны быть
// ровно тем множеством, которое даёт литерал `authzmap`. Расхождение здесь
// невидимо ничем другим: применённую миграцию не правят (запрет #5), а литерал
// правится свободно.
//
// # Форм записи посева ДВЕ, и распознаватель обязан знать обе
//
// Рука пишет один оператор на много кортежей, перечисляя лишь те колонки, что
// отличаются от умолчания:
//
//	INSERT INTO kaname.catalog_verb (module, resource, verb) VALUES
//	  ('alpha', 'thing', 'get'),
//	  ('beta', 'other', 'list');
//
// `pg_dump --column-inserts` — по оператору на строку, ВСЕ колонки, готовые
// значения:
//
//	INSERT INTO kaname.catalog_verb (module, resource, verb, retired_at,
//	  retired_reason, live, per_object) VALUES ('compute', 'instance', 'get',
//	  NULL, NULL, true, true);
//
// Прежняя редакция знала только первую: она искала ЛИТЕРАЛЬНЫЙ префикс вместе с
// перечнем колонок (`… catalog_verb (module, resource, verb) VALUES`). После
// свода 171 миграции в одну первичную, собранную дампом, все четыре префикса
// давали ноль попаданий — то есть гейт краснел «оператор посева не найден», а не
// сверял. Поэтому разбор ведётся ПО КОЛОНКАМ: оператор читается как пара
// «перечень колонок × кортежи», и обе формы становятся одним входом.
//
// # Половины словаря различаются ЗНАЧЕНИЕМ, а не оператором
//
// До свода пообъектную и ярусную половины сеяли РАЗНЫЕ миграции, и гейты
// различали их по тексту оператора. Дамп кладёт обе половины в одну таблицу
// одним перечнем колонок, а различает `per_object`. Так же и снятые строки
// ресурса: они отличаются от живых не оператором, а `live`. Разбор по колонкам
// берёт именно это — значение дискриминатора, — поэтому переживает обе формы.
//
// Гейт второй — ФОРМА КЛЮЧА: `RESTRICT` рядом с `DEFERRABLE` принимается DDL и
// молча инертен (измерено на PostgreSQL 16.15, приёмка §0.2 Н2, проба C4), а
// ключи проекции правила обязаны быть `DEFERRABLE INITIALLY IMMEDIATE` — форма и
// есть производитель текста трёх сценариев отказа.

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// catalogSeedCensus — объём осмотренного. Печатается всегда: «ноль расхождений»
// обязано быть отличимо от «ноль прочитанного».
type catalogSeedCensus struct {
	// ПРОЧИТАНО — сколько строк разбор вынул из оператора.
	ReadModuleRows   int
	ReadResourceRows int
	ReadVerbRows     int

	// КЛАССИФИЦИРОВАНО — сколько из прочитанного попало в каждую половину.
	// Числа печатаются ПАРОЙ с прочитанным: расширяя распознаватель, обязан
	// двигаться объём осмотренного, а не только число находок; одно число
	// скрывает ровно тот случай, ради которого перепись и заведена.
	SeededModules   int
	SeededResources int
	SeededVerbs     int
	RetiredSeeded   int
	TierOnlyVerbs   int

	// СВОД ЦЕПОЧКИ. Обе величины печатаются рядом с прочитанным: расширение
	// охвата обязано двигать объём осмотренного, и без пары «миграций прочитано
	// N · снято поздним оператором M» прибавка охвата неотличима от прибавки
	// находок.
	MigrationsRead int
	RetiredLater   int
}

// splitTupleFields — поля одного кортежа, разрезанные по ВЕРХНЕУРОВНЕВОЙ запятой.
//
// Наивное `strings.Split(",")` здесь неверно, и это не край: строка снятого
// ресурса несёт и вызов `now()`, и причину снятия ЗАПЯТЫМИ внутри кавычек.
// Первая редакция гейта резала по каждой запятой и объявила кортеж «короче семи
// полей» — то есть находка была бы о разборе, а не о дереве.
func splitTupleFields(inner string) []string {
	var out []string
	var cur strings.Builder
	depth := 0
	inQuote := false
	for i := 0; i < len(inner); i++ {
		ch := inner[i]
		switch {
		case ch == '\'':
			// Удвоенная кавычка внутри литерала — экранированная, не конец.
			if inQuote && i+1 < len(inner) && inner[i+1] == '\'' {
				cur.WriteByte(ch)
				cur.WriteByte(inner[i+1])
				i++
				continue
			}
			inQuote = !inQuote
			cur.WriteByte(ch)
		case inQuote:
			cur.WriteByte(ch)
		case ch == '(':
			depth++
			cur.WriteByte(ch)
		case ch == ')':
			depth--
			cur.WriteByte(ch)
		case ch == ',' && depth == 0:
			out = append(out, strings.Trim(strings.TrimSpace(cur.String()), "'"))
			cur.Reset()
		default:
			cur.WriteByte(ch)
		}
	}
	if strings.TrimSpace(cur.String()) != "" {
		out = append(out, strings.Trim(strings.TrimSpace(cur.String()), "'"))
	}
	return out
}

// insertRow — одна строка оператора INSERT: перечень колонок, кортеж значений и
// доступ по имени колонки.
//
// Кортеж и перечень хранятся ОБА, а не только карта: их несовпадение по длине —
// самостоятельная находка, и по карте её не увидеть (лишнее значение просто не
// получит имени, а недостающее — молча станет отсутствующим).
type insertRow struct {
	cols   []string
	vals   []string
	byName map[string]string
}

// has — колонка НАЗВАНА оператором. Отличать от «значение пусто» обязательно:
// колонка, оператором не названная, приходит из умолчания схемы.
func (r insertRow) has(col string) bool {
	_, ok := r.byName[col]
	return ok
}

// get — значение названной колонки; для неназванной — пустая строка.
func (r insertRow) get(col string) string { return r.byName[col] }

// boolOrDefault — значение булевой колонки с УМОЛЧАНИЕМ СХЕМЫ.
//
// Колонка, не названная оператором, значения не теряет: её ставит `DEFAULT` из
// `CREATE TABLE` того же файла — `live boolean DEFAULT true NOT NULL` и
// `per_object boolean DEFAULT true NOT NULL`. Рукописный посев на это умолчание
// и опирается (живая строка колонки `live` не несёт вовсе), дамп же печатает
// значение всегда. Разбор обязан читать обе формы одинаково, иначе рукописная
// живая строка была бы прочитана как «значение не задано».
func (r insertRow) boolOrDefault(col string) bool {
	if !r.has(col) {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(r.get(col)), "true")
}

// isNull — SQL-овый NULL, а не пустая строка. Дамп пишет отсутствие преемника
// словом `NULL`; рукописный посев мог не назвать колонку вовсе. Оба означают
// «преемника нет», и путать их с пустой строкой нельзя: пустая строка была бы
// именем ресурса, которого не существует.
func isNull(v string) bool {
	t := strings.TrimSpace(v)
	return t == "" || strings.EqualFold(t, "null")
}

func isSpaceByte(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

func skipSpace(s string, i int) int {
	for i < len(s) && isSpaceByte(s[i]) {
		i++
	}
	return i
}

// readParenGroup — содержимое сбалансированной скобочной группы, начинающейся в
// позиции i, и позиция сразу за её закрывающей скобкой.
//
// Скобки внутри строкового литерала не считаются, и это не край: причина снятия
// ресурса — русская проза, которая скобки и запятые содержит свободно.
func readParenGroup(s string, i int) (inner string, next int, ok bool) {
	if i >= len(s) || s[i] != '(' {
		return "", i, false
	}
	depth := 0
	inQuote := false
	start := i + 1
	for ; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '\'':
			// Удвоенная кавычка внутри литерала — экранированная, не конец.
			if inQuote && i+1 < len(s) && s[i+1] == '\'' {
				i++
				continue
			}
			inQuote = !inQuote
		case inQuote:
			// внутри литерала скобки — текст
		case ch == '(':
			depth++
		case ch == ')':
			depth--
			if depth == 0 {
				return s[start:i], i + 1, true
			}
		}
	}
	return "", i, false
}

// parseInsertRows — строки, вставляемые в названную таблицу, ЛЮБОЙ из двух форм
// записи (см. шапку файла).
//
// Читается ИСПОЛНЯЕМАЯ часть: комментарий, объясняющий посев, за посев не
// считается — иначе гейт зеленел бы на собственном объяснении.
//
// Отказов ДВА, и они разные: оператора нет вовсе (таблицу не сеют, либо имя
// разошлось) и оператор есть, а кортежей ноль. Второй — тот самый случай, ради
// которого отказ и заведён: «расхождений нет» обязано быть отличимо от «ничего
// не прочитано».
func parseInsertRows(body, table string) ([]insertRow, error) {
	exec := stripSQLComments(body)
	prefix := "INSERT INTO " + table

	statements := 0
	var out []insertRow
	for off := 0; off < len(exec); {
		j := strings.Index(exec[off:], prefix)
		if j < 0 {
			break
		}
		p := off + j + len(prefix)
		off = p
		// Соседняя таблица, чьё имя ПРОДОЛЖАЕТ искомое (`catalog_verb_history`),
		// отсекается требованием ниже: за именем обязан идти перечень колонок, то
		// есть пробелы и `(`. На `_history (` пробелы позиции не сдвигают, а `_`
		// скобкой не является — оператор не читается вовсе.
		//
		// Отдельная проверка границы имени здесь СТОЯЛА и снята: её снятие не
		// меняло исхода ни на одном входе, включая инъекцию границы, — то есть
		// она документировала контракт, который держит другой код. Свойство при
		// этом проверяется: TestIAMCT114_Injection_TableNameBoundaryIsRespected.
		p = skipSpace(exec, p)
		colsInner, afterCols, ok := readParenGroup(exec, p)
		if !ok {
			continue
		}
		cols := splitTupleFields(colsInner)
		p = skipSpace(exec, afterCols)
		if !strings.HasPrefix(exec[p:], "VALUES") {
			continue
		}
		p = skipSpace(exec, p+len("VALUES"))
		statements++
		for {
			inner, afterTuple, okTuple := readParenGroup(exec, p)
			if !okTuple {
				break
			}
			vals := splitTupleFields(inner)
			row := insertRow{cols: cols, vals: vals, byName: make(map[string]string, len(cols))}
			for k, c := range cols {
				if k < len(vals) {
					row.byName[c] = vals[k]
				}
			}
			out = append(out, row)
			p = skipSpace(exec, afterTuple)
			if p < len(exec) && exec[p] == ',' {
				p = skipSpace(exec, p+1)
				continue
			}
			break
		}
		off = p
	}

	if statements == 0 {
		return nil, fmt.Errorf("оператор посева не найден: INSERT INTO %s", table)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("оператор INSERT INTO %s не дал ни одного кортежа — обход пуст, "+
			"и «расхождений нет» неотличимо от «ничего не прочитано»", table)
	}
	return out, nil
}

// arityFindings — кортежи, не сходящиеся с перечнем колонок СВОЕГО оператора.
//
// Прежняя редакция сверяла длину кортежа с ЧИСЛОМ (три поля, семь полей) —
// утверждение о форме, верное ровно для той записи, под которую гейт писался.
// Сверка с перечнем колонок того же оператора верна для обеих форм и не требует
// знать наперёд, сколько колонок автор назовёт.
func arityFindings(kind string, rows []insertRow) []string {
	var out []string
	for _, r := range rows {
		if len(r.vals) != len(r.cols) {
			out = append(out, fmt.Sprintf(
				"посев %s: кортеж из %d значений при %d названных колонках: %s",
				kind, len(r.vals), len(r.cols), strings.Join(r.vals, "|")))
		}
	}
	return out
}

// auditCatalogSeed — сверка посева миграции с литералом, в ОБЕ стороны.
// wantModules/wantResources/wantVerbs приходят от вызывающего: гейт дерева
// подаёт настоящий литерал, инъекция — синтетический.
//
// Глаголы сверяются ПООБЪЕКТНЫЕ: ярусную половину той же таблицы судит
// `auditTierOnlyVerbSeed`. Половины разведены не по операторам (дамп кладёт их
// одним), а по значению `per_object` — и вместе две сверки покрывают таблицу
// целиком в обе стороны, дыры между ними нет.
func auditCatalogSeed(corpus []catalogSeedMigration, wantModules, wantResources, wantVerbs []string) (catalogSeedCensus, []string, error) {
	var c catalogSeedCensus

	body, retiredLater, findings := catalogCorpus(corpus)
	c.MigrationsRead = len(corpus)
	c.RetiredLater = len(retiredLater)

	mods, err := parseInsertRows(body, "kaname.catalog_module")
	if err != nil {
		return c, nil, err
	}
	res, err := parseInsertRows(body, "kaname.catalog_resource")
	if err != nil {
		return c, nil, err
	}
	verbs, err := parseInsertRows(body, "kaname.catalog_verb")
	if err != nil {
		return c, nil, err
	}
	c.ReadModuleRows, c.ReadResourceRows, c.ReadVerbRows = len(mods), len(res), len(verbs)

	findings = append(findings, arityFindings("модуля", mods)...)
	findings = append(findings, arityFindings("ресурса", res)...)
	findings = append(findings, arityFindings("глагола", verbs)...)

	gotMod := map[string]bool{}
	for _, r := range mods {
		if !r.boolOrDefault("live") {
			continue // снятый модуль живым ключом каталога не является
		}
		gotMod[r.get("module")] = true
	}

	gotRes := map[string]bool{}
	var retired []insertRow
	for _, r := range res {
		module, resource, dotted := r.get("module"), r.get("resource"), r.get("dotted")
		// Производная форма обязана согласоваться с парой ЗДЕСЬ, а не только
		// проверкой в схеме: расхождение написаний — прямой путь к классу 513001.
		// Проверяется у ВСЯКОЙ строки, живой и снятой: третье написание в снятой
		// строке уводит преемника ровно так же.
		if dotted != module+"."+resource {
			findings = append(findings, fmt.Sprintf(
				"посев ресурса: точечная форма %q не выводится из пары (%s, %s)", dotted, module, resource))
		}
		if r.boolOrDefault("live") {
			gotRes[dotted] = true
			continue
		}
		retired = append(retired, r)
	}

	gotVerb := map[string]bool{}
	seededAlive := map[string]bool{}
	for _, r := range verbs {
		if !r.boolOrDefault("live") {
			continue // снятый глагол живым ключом каталога не является
		}
		key := r.get("module") + "." + r.get("resource") + "." + r.get("verb")
		seededAlive[key] = true
		if !r.boolOrDefault("per_object") {
			continue // ярусная половина — предмет auditTierOnlyVerbSeed
		}
		if retiredLater[key] {
			// Строку посеяла базовая миграция живой, а поздняя пометила снятой.
			// Живым ключом каталога она не является — ровно так же, как строка,
			// посеянная снятой сразу.
			continue
		}
		gotVerb[key] = true
	}

	// Снятие, которому нечего снимать, — находка того же рода, что исключение,
	// пережившее свой предмет: оператор стоит в цепочке, выглядит работающим и
	// не меняет ничего.
	for key := range retiredLater {
		if !seededAlive[key] {
			findings = append(findings,
				"снятие глагола "+key+": цепочка снимает строку, которой посев не сеет живой — "+
					"оператор пережил свой предмет")
		}
	}

	c.SeededModules, c.SeededResources, c.SeededVerbs = len(gotMod), len(gotRes), len(gotVerb)
	c.RetiredSeeded = len(retired)

	findings = append(findings, symmetricDiff("модуль", setOf(wantModules), gotMod)...)
	findings = append(findings, symmetricDiff("ресурс", setOf(wantResources), gotRes)...)
	findings = append(findings, symmetricDiff("глагол", setOf(wantVerbs), gotVerb)...)

	// Снятые строки обязаны нести преемника, и преемник обязан быть ЖИВЫМ ключом
	// каталога. Преемник, указывающий на снятое, восстанавливает клиенту шаг,
	// которого не существует.
	for _, r := range retired {
		successor := r.get("superseded_by")
		if isNull(successor) {
			findings = append(findings, "посев снятого: строка "+r.get("dotted")+" не несёт преемника")
			continue
		}
		if !gotRes[successor] {
			findings = append(findings, "посев снятого: преемник "+successor+" строки "+r.get("dotted")+
				" не является живым ключом каталога")
		}
	}
	return c, findings, nil
}

func setOf(xs []string) map[string]bool {
	out := make(map[string]bool, len(xs))
	for _, x := range xs {
		out[x] = true
	}
	return out
}

// symmetricDiff — расхождение в ОБЕ стороны. Одностороннее сравнение молчало бы
// на строке, посеянной сверх литерала: она даёт правилу референт, по которому оно
// резолвится, а проекция глаголов — нет.
func symmetricDiff(kind string, want, got map[string]bool) []string {
	var out []string
	for k := range want {
		if !got[k] {
			out = append(out, kind+" "+k+": есть в литерале, не посеян миграцией")
		}
	}
	for k := range got {
		if !want[k] {
			out = append(out, kind+" "+k+": посеян миграцией, нет в литерале")
		}
	}
	sort.Strings(out)
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// форма ключа

var (
	// reRestrictDeferrable — `RESTRICT` и `DEFERRABLE` в одном объявлении ключа.
	// Объявление тянется через несколько строк, поэтому режется по `;`.
	reRestrictDeferrable = regexp.MustCompile(`(?s)RESTRICT.*?DEFERRABLE|DEFERRABLE.*?RESTRICT`)
	// reInitiallyDeferred — отложенность ПО УМОЛЧАНИЮ на ключе проекции правила.
	reInitiallyDeferred = regexp.MustCompile(`DEFERRABLE\s+INITIALLY\s+DEFERRED`)
)

// auditKeyForm — форма ключей, объявленных телом миграции.
//
// Проверяются ДВА свойства, и они разные: `RESTRICT … DEFERRABLE` запрещён у
// всякого объявления тела, кроме поимённо названных вызывающим, а
// `INITIALLY DEFERRED` запрещён ТОЛЬКО на ключах, названных вызывающим.
//
// # Охват ВЫРОС с семи объявлений до сорока двух — и предпосылку пришлось
// перемерить
//
// До свода тело гейта было одной миграцией, объявлявшей семь ключей, и запрет
// `RESTRICT … DEFERRABLE` был записан как «ВЕЗДЕ в этом дереве». Это утверждение
// никогда не проверялось на дереве: гейт видел свою миграцию и только её. Свод
// сделал телом всю схему (замер: объявлений ключа 42), и предпосылка упала —
// дерево несёт ДВА объявления этой формы, и оба намеренные.
//
// Узкая популяция предпосылку не подтверждает, она её СКРЫВАЕТ; расширяя охват,
// перемеряют предпосылку, а не только новые элементы.
//
// # Почему ведомость, а не сужение запрета обратно до трёх ключей
//
// Сужение вернуло бы охват к семи объявлениям и снова спрятало бы остальные 35.
// Ведомость сохраняет охват и НАЗЫВАЕТ то, что прежде было невидимо: третье
// объявление этой формы — находка, а запись, которой нечего исключать, — тоже
// находка (послабление обязано истекать само).
func auditKeyForm(body string, immediateOnly, restrictDeferrableExempt []string) (scanned int, findings []string) {
	exemptAll := stripSQLComments(body)
	// Самоистечение: запись, у которой в теле нет предмета, — находка. Без этого
	// ведомость пережила бы снятие ключа и осталась бы слепой зоной, выданной
	// вперёд следующему объявлению того же имени.
	for _, name := range restrictDeferrableExempt {
		if !strings.Contains(exemptAll, "ADD CONSTRAINT "+name) {
			findings = append(findings, "послабление на RESTRICT рядом с DEFERRABLE названо для ключа "+
				name+", а такого объявления в теле нет: исключению нечего исключать, и "+
				"следующее объявление того же имени уехало бы под него незамеченным")
		}
	}

	for _, stmt := range strings.Split(body, ";") {
		if !strings.Contains(stmt, "FOREIGN KEY") && !strings.Contains(stmt, "REFERENCES") {
			continue
		}
		scanned++
		exec := stripSQLComments(stmt)
		if reRestrictDeferrable.MatchString(exec) && !namesAnyOf(exec, restrictDeferrableExempt) {
			findings = append(findings, "объявление ключа несёт RESTRICT рядом с DEFERRABLE: "+
				"форма принимается DDL и молча инертна — проверка остаётся немедленной "+
				"(измерено, приёмка rule-segments-have-a-referent §0.2 Н2)")
		}
		for _, name := range immediateOnly {
			if strings.Contains(exec, name) && reInitiallyDeferred.MatchString(exec) {
				findings = append(findings, "ключ "+name+" объявлен INITIALLY DEFERRED: "+
					"отказ всплывёт на коммите, где подсказка одна на транзакцию, а сегментов "+
					"в правиле много — сценарии отказа теряют своего производителя")
			}
		}
	}
	return scanned, findings
}

func namesAnyOf(stmt string, names []string) bool {
	for _, n := range names {
		if strings.Contains(stmt, n) {
			return true
		}
	}
	return false
}

// stripSQLComments — снять строчные комментарии. Гейт судит ИСПОЛНЯЕМОЕ: слово
// `RESTRICT`, сказанное в объяснении, ключом не является, и без этой строки гейт
// краснел бы на собственном комментарии.
func stripSQLComments(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// ─────────────────────────────────────────────────────────────────────────────
// ЯРУСНАЯ ПОЛОВИНА СЛОВАРЯ (задача #1863)
//
// Половин у словаря глаголов две, и посеяны они РАЗНЫМИ миграциями: пообъектная
// — 20260901113757, ярусная — 20260902062000. Иначе быть не могло: первая
// применена и правке не подлежит (запрет #5).
//
// Отсюда и гейтов два, а не один расширенный: каждый сверяет СВОЙ текст со СВОЕЙ
// половиной перечня, а перечень у обоих один — `authzmap.CatalogSeedVerbs()`.
// Свести их в один значило бы склеить два тела и потерять ответ на вопрос
// «какая миграция разошлась».

// auditTierOnlyVerbSeed — сверка ярусного посева с литералом, в ОБЕ стороны.
//
// Проверяются ДВЕ вещи, и вторая не выводится из первой: множество троек и
// ЗНАЧЕНИЕ признака у каждой. Кортеж с `true` прошёл бы сверку множеств и означал
// бы ровно обратное тому, ради чего заведён.
//
// # Признак словаря судится у троек, НАЗВАННЫХ литералом
//
// До свода ярусную половину сеяла отдельная миграция, и всякая строка её тела
// была ярусной по построению — поэтому прежняя редакция требовала `false` от
// КАЖДОГО прочитанного кортежа. Дамп кладёт обе половины одной таблицей, и то же
// требование объявило бы находкой все 109 пообъектных строк, не нарушивших
// ничего. Требование сохранено там, где у него есть предмет: у тройки, которую
// литерал объявил ярусной, признак обязан быть `false`. Пообъектные строки судит
// `auditCatalogSeed` — вместе две сверки покрывают таблицу целиком.
func auditTierOnlyVerbSeed(corpus []catalogSeedMigration, want []string) (seeded int, findings []string, err error) {
	body, retiredLater, corpusFindings := catalogCorpus(corpus)
	findings = append(findings, corpusFindings...)
	rows, err := parseInsertRows(body, "kaname.catalog_verb")
	if err != nil {
		return 0, nil, err
	}
	findings = append(findings, arityFindings("ярусного глагола", rows)...)

	wantSet := setOf(want)
	got := map[string]bool{}
	for _, r := range rows {
		if !r.boolOrDefault("live") {
			continue // снятый глагол ярусной половиной не является
		}
		key := r.get("module") + "." + r.get("resource") + "." + r.get("verb")
		if retiredLater[key] {
			continue // снято поздним оператором цепочки
		}
		if r.boolOrDefault("per_object") {
			if wantSet[key] {
				findings = append(findings, fmt.Sprintf(
					"посев ярусного глагола %s: признак словаря %q, а не false — "+
						"пообъектная строка вернула бы материализацию снятого отношения",
					key, r.get("per_object")))
			}
			continue
		}
		got[key] = true
	}
	findings = append(findings, symmetricDiff("ярусный глагол", wantSet, got)...)
	return len(got), findings, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// СВОД ЦЕПОЧКИ: посев читается ВСЕМ каталогом миграций, а не одной базовой

// catalogSeedMigration — одна миграция корпуса. Порядок в срезе есть порядок
// ПРИМЕНЕНИЯ (у goose он лексикографический по имени файла).
//
// # Почему свод, а не одна базовая миграция
//
// Гейт судит, что цепочка ОСТАВЛЯЕТ в каталоге, и до задачи kacho#1922 читал
// ровно один файл — базовую миграцию. Пока строк каталога не трогала ни одна
// последующая, разницы не было; в тот день, когда её тронули, односоставный
// разбор дал бы вердикт о состоянии, которого в базе нет ни секунды.
//
// Класс назван на месте, а не ссылкой: форма записи, о которой распознаватель
// не знает, даёт не красное и не зелёное — она МОЛЧИТ, и отличить такое
// молчание от чистоты нечем. Отсюда устройство ниже: всякий оператор над
// таблицей каталога, не опознанный как посев либо как снятие в признанной
// форме, есть НАХОДКА, а не пропущенная строка.
//
// Расширение охвата ничего не меняет на дереве, где поздних операторов нет, —
// и это ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ, а не довод против: перепись печатает «миграций
// прочитано N», поэтому прибавка объёма видна отдельно от прибавки находок.
type catalogSeedMigration struct {
	Name string
	Body string
}

// oneMigration — корпус из одного тела. Форма для инъекции: у неё вход
// синтетический, и цепочки у него нет.
func oneMigration(body string) []catalogSeedMigration {
	return []catalogSeedMigration{{Name: "0001_initial.sql", Body: body}}
}

// reDollarQuoted — блок, ограниченный долларовыми кавычками (`$$ … $$`,
// `$tag$ … $tag$`). Его тело — ТЕКСТ ДЛЯ СЕРВЕРА, а не оператор внешнего
// уровня: точка с запятой внутри границей оператора не является.
var reDollarQuoted = regexp.MustCompile(`(?s)\$([A-Za-z_][A-Za-z_0-9]*)?\$.*?\$([A-Za-z_][A-Za-z_0-9]*)?\$`)

// reCatalogDML — запись в таблицу каталога. Служит ДВУМ разным вопросам:
// «оператор внешнего уровня пишет в каталог» и «в долларовом блоке спрятана
// запись, которой разбор не увидит».
var reCatalogDML = regexp.MustCompile(
	`(?is)\b(UPDATE|DELETE\s+FROM|INSERT\s+INTO)\s+kaname\.(catalog_module|catalog_resource|catalog_verb)\b`)

// reRetireVerb — ЕДИНСТВЕННАЯ признанная форма снятия строки словаря глаголов.
//
// Форма узкая НАМЕРЕННО: всякий иной оператор над таблицей каталога уходит в
// находку «форма, неизвестная разбору», а не в молчание. Так новая форма
// обязана быть ОБЪЯВЛЕНА разбору прежде, чем она пройдёт, — иначе свод считал
// бы живой строку, которую цепочка снимает.
var reRetireVerb = regexp.MustCompile(
	`(?is)^UPDATE\s+kaname\.catalog_verb\s+SET\s+(.+?)\s+WHERE\s+(.+)$`)

// reRetireWhere — отбор ОДНОЙ строки словаря по её первичному ключу.
var reRetireWhere = regexp.MustCompile(
	`(?is)^module\s*=\s*'([^']*)'\s+AND\s+resource\s*=\s*'([^']*)'\s+AND\s+verb\s*=\s*'([^']*)'\s+AND\s+live$`)

// splitSQLStatements — операторы внешнего уровня, разрезанные по `;`.
//
// Одинарная кавычка учитывается: точка с запятой внутри литерала границей не
// является, а причина снятия — литерал, который её содержать вправе.
func splitSQLStatements(s string) []string {
	var (
		out     []string
		cur     strings.Builder
		inQuote bool
	)
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '\'':
			if inQuote && i+1 < len(s) && s[i+1] == '\'' {
				cur.WriteByte(ch)
				cur.WriteByte(s[i+1])
				i++
				continue
			}
			inQuote = !inQuote
			cur.WriteByte(ch)
		case ch == ';' && !inQuote:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(ch)
		}
	}
	out = append(out, cur.String())
	return out
}

// normalizeSpace — пробельные последовательности в один пробел, края обрезаны.
func normalizeSpace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// catalogCorpus — свод цепочки: что читать как посев и что цепочка сняла ПОСЛЕ
// него.
//
// Возвращает: склеенный в порядке применения исполняемый текст (вход разбора
// вставок), множество снятых поздним оператором глаголов в форме
// `модуль.ресурс.глагол`, находки и объём осмотренного.
func catalogCorpus(corpus []catalogSeedMigration) (seedBody string, retired map[string]bool, findings []string) {
	retired = map[string]bool{}
	var body strings.Builder
	for _, m := range corpus {
		// Половина, которая ПРИМЕНЯЕТСЯ, и только она: откат `20260914120000`
		// оживляет ту же строку каталога (`live = true`), и разбор, читающий файл
		// целиком, свёл бы снятие с его собственным откатом в ноль — то есть
		// молча вернул бы прежний вердикт.
		//
		// Разрез берётся у ЕДИНСТВЕННОГО владельца разбора. Здесь стояла своя
		// копия, и она расходилась с каноном ровно там, где расхождение не
		// видно: файл БЕЗ маркера `-- +goose Up`, но С маркером отката, она
		// отдавала ЦЕЛИКОМ — вместе с откатом. Сегодня оба маркера есть у всех
		// семнадцати миграций, поэтому копия молчала; премиса держалась
		// совпадением, а не устройством.
		//
		// Тело без разметки goose по-прежнему читается ЦЕЛИКОМ: у синтетического
		// входа инъекции разметки нет, и требовать её значило бы судить форму
		// фикстуры, а не предмет.
		exec := stripSQLComments(migrations.MigrationUpSection(m.Body))

		// Долларовый блок маскируется, а не читается: его точка с запятой
		// оператора не заканчивает. Но запись в каталог, спрятанная внутри,
		// обязана быть НАЗВАНА — иначе маска стала бы слепой зоной.
		for _, blk := range reDollarQuoted.FindAllString(exec, -1) {
			if loc := reCatalogDML.FindString(blk); loc != "" {
				findings = append(findings, fmt.Sprintf(
					"%s: запись в каталог внутри долларового блока (%s) — разбор такой формы "+
						"не читает, и свод цепочки был бы неполон молча",
					m.Name, normalizeSpace(loc)))
			}
		}
		exec = reDollarQuoted.ReplaceAllStringFunc(exec, func(b string) string {
			return strings.Repeat(" ", len(b))
		})

		body.WriteString(exec)
		body.WriteString("\n")

		for _, raw := range splitSQLStatements(exec) {
			st := normalizeSpace(raw)
			if st == "" || !reCatalogDML.MatchString(st) {
				continue
			}
			if strings.HasPrefix(strings.ToUpper(st), "INSERT INTO KANAME.CATALOG_") {
				continue // посев — предмет разбора вставок
			}
			key, ok := retiredVerbOf(st)
			if !ok {
				findings = append(findings, fmt.Sprintf(
					"%s: оператор над каталогом, форма которого разбору НЕИЗВЕСТНА: %s. "+
						"Свод цепочки обязан знать всякую форму записи: непрочитанный оператор "+
						"не даёт ни красного, ни зелёного — он молчит, и посев расходится с "+
						"литералом незамеченным", m.Name, firstRunes(st, 160)))
				continue
			}
			retired[key] = true
		}
	}
	return body.String(), retired, findings
}

// retiredVerbOf — снимает ли оператор ровно одну строку словаря глаголов.
//
// Требуются ВСЕ признаки сразу: пометка неживой, отметка времени снятия,
// непустая причина и отбор по полному первичному ключу живой строки. Оператор,
// у которого недостаёт хоть одного, формой снятия НЕ является — он либо правит
// что-то ещё, либо снимает больше одной строки, и в обоих случаях свод по нему
// неверен.
func retiredVerbOf(statement string) (string, bool) {
	m := reRetireVerb.FindStringSubmatch(statement)
	if m == nil {
		return "", false
	}
	set := normalizeSpace(m[1])
	if !strings.Contains(set, "live = false") ||
		!strings.Contains(set, "retired_at = now()") ||
		!regexp.MustCompile(`retired_reason\s*=\s*'[^']+'`).MatchString(set) {
		return "", false
	}
	w := reRetireWhere.FindStringSubmatch(normalizeSpace(m[2]))
	if w == nil {
		return "", false
	}
	return w[1] + "." + w[2] + "." + w[3], true
}

// firstRunes — начало оператора для текста находки, обрезанное по РУНЕ.
// Обрезание по байту разрубило бы кириллическую причину снятия посередине.
func firstRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
