// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package check

// catalog_seed_parity.go — ЯДРО двух гейтов каталога модуля, отделённое от корня
// дерева НАМЕРЕННО: инъекция обязана прогнать его на синтетическом входе, а не
// на этом дереве.
//
// # Почему пакет сервиса, а не internal/repohygiene
//
// Гейт обязан сверяться с ЛИТЕРАЛОМ, а не с его текстом (чтение чужого исходника
// как текста — отдельный класс дефекта проверки). Литерал живёт в
// `services/iam/internal/authzmap`, и корневой `internal/repohygiene` импортировать
// его НЕ МОЖЕТ: правило внутренних пакетов Go допускает импорт
// `services/iam/internal/...` только из поддерева `services/iam/`. Прогнано и
// получено: «use of internal package … not allowed». Поэтому гейт живёт рядом со
// вторым гейтом того же предмета (`retired_block_storage_test.go`), а не рядом с
// прочими гейтами дерева.
//
// Гейт первый — ПАРИТЕТ: строки, которые сеет миграция 20260901113757, обязаны быть
// ровно тем множеством, которое даёт литерал `authzmap`. Расхождение здесь
// невидимо ничем другим: миграция применена и правке не подлежит (запрет #5), а
// литерал правится свободно.
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
)

// catalogSeedCensus — объём осмотренного. Печатается всегда: «ноль расхождений»
// обязано быть отличимо от «ноль прочитанного».
type catalogSeedCensus struct {
	SeededModules   int
	SeededResources int
	SeededVerbs     int
	RetiredSeeded   int
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

// parseSeedBlock — кортежи ОДНОГО оператора INSERT, начиная со строки, на
// которой этот оператор объявлен. Читается ИСПОЛНЯЕМАЯ часть: строка,
// начинающаяся с `--`, кортежем не является, и комментарий, объясняющий посев,
// не может быть засчитан за него.
//
// Кортеж может занимать НЕСКОЛЬКО строк (строка снятого ресурса занимает три),
// поэтому накопление идёт до баланса скобок, а не по строке.
func parseSeedBlock(body, insertPrefix string) ([][]string, error) {
	i := strings.Index(body, insertPrefix)
	if i < 0 {
		return nil, fmt.Errorf("оператор посева не найден: %q", insertPrefix)
	}
	rest := body[i+len(insertPrefix):]

	var out [][]string
	var buf strings.Builder
	depth := 0
	for _, line := range strings.Split(rest, "\n") {
		if idx := strings.Index(line, "--"); idx >= 0 && depth == 0 {
			line = line[:idx]
		}
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if depth == 0 && !strings.HasPrefix(t, "(") {
			break // оператор кончился
		}
		for _, ch := range t {
			switch ch {
			case '(':
				depth++
			case ')':
				depth--
			}
		}
		buf.WriteString(t)
		if depth > 0 {
			buf.WriteByte(' ')
			continue
		}
		tuple := strings.TrimSpace(buf.String())
		buf.Reset()
		done := strings.HasSuffix(tuple, ";")
		tuple = strings.TrimRight(tuple, ";,")
		tuple = strings.TrimSpace(tuple)
		tuple = strings.TrimPrefix(tuple, "(")
		tuple = strings.TrimSuffix(tuple, ")")
		out = append(out, splitTupleFields(tuple))
		if done {
			break
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("оператор %q не дал ни одного кортежа — обход пуст, "+
			"и «расхождений нет» неотличимо от «ничего не прочитано»", insertPrefix)
	}
	return out, nil
}

// auditCatalogSeed — сверка посева миграции с литералом, в ОБЕ стороны.
// wantModules/wantResources/wantVerbs приходят от вызывающего: гейт дерева
// подаёт настоящий литерал, инъекция — синтетический.
func auditCatalogSeed(body string, wantModules, wantResources, wantVerbs []string) (catalogSeedCensus, []string, error) {
	var c catalogSeedCensus
	var findings []string

	mods, err := parseSeedBlock(body, "INSERT INTO kacho_iam.catalog_module (module) VALUES")
	if err != nil {
		return c, nil, err
	}
	res, err := parseSeedBlock(body, "INSERT INTO kacho_iam.catalog_resource (module, resource, dotted) VALUES")
	if err != nil {
		return c, nil, err
	}
	verbs, err := parseSeedBlock(body, "INSERT INTO kacho_iam.catalog_verb (module, resource, verb) VALUES")
	if err != nil {
		return c, nil, err
	}
	retired, err := parseSeedBlock(body,
		"(module, resource, dotted, retired_at, retired_reason, superseded_by, live) VALUES")
	if err != nil {
		return c, nil, err
	}

	gotMod := map[string]bool{}
	for _, r := range mods {
		if len(r) != 1 {
			findings = append(findings, "посев модуля: кортеж не из одного поля: "+strings.Join(r, "|"))
			continue
		}
		gotMod[r[0]] = true
	}
	gotRes := map[string]bool{}
	for _, r := range res {
		if len(r) != 3 {
			findings = append(findings, "посев ресурса: кортеж не из трёх полей: "+strings.Join(r, "|"))
			continue
		}
		// Производная форма обязана согласоваться с парой ЗДЕСЬ, а не только
		// проверкой в схеме: расхождение написаний — прямой путь к классу 513001.
		if r[2] != r[0]+"."+r[1] {
			findings = append(findings, fmt.Sprintf(
				"посев ресурса: точечная форма %q не выводится из пары (%s, %s)", r[2], r[0], r[1]))
		}
		gotRes[r[2]] = true
	}
	gotVerb := map[string]bool{}
	for _, r := range verbs {
		if len(r) != 3 {
			findings = append(findings, "посев глагола: кортеж не из трёх полей: "+strings.Join(r, "|"))
			continue
		}
		gotVerb[r[0]+"."+r[1]+"."+r[2]] = true
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
		if len(r) < 7 {
			findings = append(findings, "посев снятого: кортеж короче семи полей: "+strings.Join(r, "|"))
			continue
		}
		successor := r[5]
		if successor == "" {
			findings = append(findings, "посев снятого: строка "+r[2]+" не несёт преемника")
			continue
		}
		if !gotRes[successor] {
			findings = append(findings, "посев снятого: преемник "+successor+" строки "+r[2]+
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
// Проверяются ДВА свойства, и они разные: `RESTRICT … DEFERRABLE` запрещён
// ВЕЗДЕ в этом дереве (форма принимается DDL и молча инертна), а
// `INITIALLY DEFERRED` запрещён ТОЛЬКО на ключах, названных вызывающим, —
// одиннадцать существующих объявлений дерева этой проверкой не пересматриваются.
func auditKeyForm(body string, immediateOnly []string) (scanned int, findings []string) {
	for _, stmt := range strings.Split(body, ";") {
		if !strings.Contains(stmt, "FOREIGN KEY") && !strings.Contains(stmt, "REFERENCES") {
			continue
		}
		scanned++
		exec := stripSQLComments(stmt)
		if reRestrictDeferrable.MatchString(exec) {
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

// tierOnlyVerbSeedPrefix — оператор посева ярусной половины. Форма кортежа у
// него ЧЕТЫРЁХПОЛЬНАЯ: признак словаря стоит значением, а не умолчанием, —
// строка, положенная умолчанием `true`, была бы пообъектной и вернула бы
// материализацию снятого отношения.
const tierOnlyVerbSeedPrefix = "INSERT INTO kacho_iam.catalog_verb (module, resource, verb, per_object) VALUES"

// auditTierOnlyVerbSeed — сверка ярусного посева с литералом, в ОБЕ стороны.
//
// Проверяются ДВЕ вещи, и вторая не выводится из первой: множество троек и
// ЗНАЧЕНИЕ признака у каждой. Кортеж с `true` прошёл бы сверку множеств и означал
// бы ровно обратное тому, ради чего заведён.
func auditTierOnlyVerbSeed(body string, want []string) (seeded int, findings []string, err error) {
	rows, err := parseSeedBlock(body, tierOnlyVerbSeedPrefix)
	if err != nil {
		return 0, nil, err
	}
	got := map[string]bool{}
	for _, r := range rows {
		if len(r) != 4 {
			findings = append(findings, "посев ярусного глагола: кортеж не из четырёх полей: "+
				strings.Join(r, "|"))
			continue
		}
		if r[3] != "false" {
			findings = append(findings, fmt.Sprintf(
				"посев ярусного глагола %s.%s.%s: признак словаря %q, а не false — "+
					"пообъектная строка вернула бы материализацию снятого отношения",
				r[0], r[1], r[2], r[3]))
			continue
		}
		got[r[0]+"."+r[1]+"."+r[2]] = true
	}
	findings = append(findings, symmetricDiff("ярусный глагол", setOf(want), got)...)
	return len(got), findings, nil
}
