// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// role_page_wildcard_agrees_test.go — гейт того же класса, что и сосед по
// каталогу, но НАД ДРУГОЙ ПОВЕРХНОСТЬЮ: заявление СТРАНИЦЫ АРЕНДАТОРА о
// подстановке `"*"` обязано сходиться с тем, что домен делает (задача #2046).
//
// # Почему отдельный гейт, а не расширение соседнего
//
// `TestRuleWildcardContractAgreesWithTheDomain` судит КОНТРАКТ: там заявление
// привязано к полю ОБЪЯВЛЕНИЕМ — комментарий стоит непосредственно над
// `string module = 1;`, и признак привязки даётся разбором. На странице
// арендатора привязки-объявления нет вовсе: заявление сделано ПРОЗОЙ, поля
// названы внутри предложения, а одно предложение говорит сразу о двух полях.
// Наивный перенос распознавателя дал бы гейт, который либо не видит ни одного
// заявления, либо краснеет на законной фразе.
//
// Страница при этом ПЕРВИЧНЕЕ контракта: её читают вместо proto.
//
// # Признак привязки, выбранный здесь
//
// ЗАЯВЛЕНИЕ = пара «поле × полярность», взятая из ОДНОГО ПРЕДЛОЖЕНИЯ, которое
// лежит в ОБЛАСТИ ПОДСТАНОВКИ. Три части, и каждая нужна:
//
//	область   — абзац несёт литерал подстановки ЛИБО стоит во врезке, чей
//	            заголовок его несёт. Второе обязательно: несущее предложение
//	            страницы («Ярусом роли ограничена подстановка в `module` и
//	            `resources`…») литерала не содержит и без области было бы
//	            невидимо;
//	поле      — код-спан, чьё имя совпадает с полем `Rule` (принимаются оба
//	            написания: змеиное контракта и верблюжье JSON, потому что на
//	            странице арендатора законны оба);
//	полярность— «ограничена ЯРУСОМ» против «НЕ ограничена». Ось ровно та же,
//	            что у соседа: политикозависимость, а не «отвергается ли».
//
// # Граница названа, а не подразумевается
//
// Предложение БЕЗ маркера полярности заявлением не считается и молчит — «запрет
// всегда» (`resourceNames`) этой осью не выражается, и требовать по нему
// вердикта значило бы краснеть на верном тексте. Обе величины печатаются
// переписью: предложений в области прочитано · заявлений распознано. Прибавка
// распознавателя, не изменившая второе число, — холостая.
//
// # Самопротиворечие — ОТДЕЛЬНАЯ находка, и это форма наблюдавшегося дефекта
//
// Здесь уже жила неправда, у которой обе половины стояли в двух строках друг от
// друга: заголовок объявлял подстановку системной для трёх полей, а фраза ниже
// говорила о глаголах обратное. Такой текст противоречит себе ДО всякого
// обращения к домену, поэтому и судится до него: иначе вердикт зависел бы от
// того, какая из двух половин совпала с поведением.
package domain_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// polarity — что предложение утверждает об ЯРУСЕ.
type polarity int

const (
	polarityNone polarity = iota
	// polarityTierBound — подстановка ограничена ярусом роли: арендаторская
	// отвергает, платформенная принимает.
	polarityTierBound
	// polarityTierFree — подстановка ярусом НЕ ограничена.
	polarityTierFree
	// polarityBoth — предложение несёт ОБА маркера. Заявлением оно не считается,
	// и это решение, а не пропуск: одно предложение вправе законно сказать о
	// РАЗНЫХ полях разное («глагол грантабелен, но модуль/ресурс system-only»),
	// а какому полю какая половина принадлежит, признак не решает. Приписать
	// обе полярности всем названным полям значило бы краснеть на верном тексте;
	// выбрать первую — судить по порядку слов. Поэтому такое предложение
	// считается НЕРАЗОБРАННЫМ и печатается отдельной величиной переписи.
	polarityBoth
)

func (p polarity) String() string {
	switch p {
	case polarityTierBound:
		return "ограничена ярусом"
	case polarityTierFree:
		return "ярусом не ограничена"
	case polarityBoth:
		return "оба маркера сразу"
	}
	return "нет маркера"
}

var (
	// reTierBound / reTierFree — маркеры полярности. Обе половины двуязычного
	// корпуса: страница арендатора русская, но несёт англоязычные имена ярусов
	// (`system-роль`, `custom-роль`), и предикат на одном языке недобирал бы
	// молча (`testing.md` §«Предикат по ДВУЯЗЫЧНОМУ корпусу»).
	//
	// Порядок проверки не важен — спрашиваются ОБА, и совпадение обоих есть
	// самостоятельная находка, а не повод выбрать первый.
	reTierBound = regexp.MustCompile(
		`(?i)ярусом роли ограничена|ограничена ярусом|ограничен ярусом|` +
			`в system-роли законн|только в system-рол|лишь в system-рол|` +
			`только для system-рол|лишь для system-рол|только системной роли|system-only`)
	reTierFree = regexp.MustCompile(
		`(?i)не ограничен|грантабел|в custom-роли тоже|законна и в custom-роли`)
	// reCodeSpan — код-спан страницы: имя поля арендатор читает именно так.
	reCodeSpan = regexp.MustCompile("`([^`]+)`")
	// proseFieldStems — ПРОЗАИЧЕСКИЕ имена полей. Страница вправе назвать поле
	// словом, а не код-спаном («глагол-`*`», «модуль/ресурс-`*`»), и историческая
	// редакция врезки делала именно так — распознаватель, знающий только
	// код-спаны, не увидел бы там НИ ОДНОГО заявления.
	//
	// Привязка узкая намеренно: стем засчитывается, только если он стоит
	// НЕПОСРЕДСТВЕННО ПЕРЕД литералом подстановки (окно `proseWindow`). Слово
	// «глагол» встречается на странице десятки раз в прозе о правилах, и без
	// окна оно означало бы другое.
	proseFieldStems = map[string]string{
		"модул":  "module",
		"ресурс": "resources",
		"глагол": "verbs",
	}
	// reAdmonition — открытие/закрытие врезки Docusaurus.
	reAdmonition = regexp.MustCompile(`^:::`)
)

// pageFieldSpellings — написания поля, законные на странице арендатора.
// Ключ — написание, значение — имя поля В КОНТРАКТЕ, чтобы вердикт шёл по той
// же координате, что у соседнего гейта и у производителя поведения.
//
// Набор берётся из КОНТРАКТА, а не из производителей поведения, и различие
// несущее: поле, о подстановке в котором страница заявляет, а производителя у
// него нет, обязано стать НАХОДКОЙ («заявление некому проверить»). Строй словарь
// по производителям — и такое заявление не распозналось бы вовсе, то есть ветвь
// находки была бы мёртвой. Проверено инъекцией: `matchLabels`.
func pageFieldSpellings(contractFields []string) map[string]string {
	out := map[string]string{}
	for _, field := range contractFields {
		out[field] = field
		out[snakeToCamel(field)] = field
	}
	return out
}

func snakeToCamel(s string) string {
	parts := strings.Split(s, "_")
	for i := 1; i < len(parts); i++ {
		if parts[i] == "" {
			continue
		}
		parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
	}
	return strings.Join(parts, "")
}

type rolePageCensus struct {
	Paragraphs int // абзацев прочитано
	Scoped     int // из них в области подстановки
	Sentences  int // предложений области прочитано
	Ambiguous  int // предложений с обоими маркерами — не разобрано
	Claims     int // заявлений распознано (поле × полярность)
	Fields     int // различных полей, о которых есть заявление
	Probed     int // из них с производителем поведения
	Dependent  int // из пробованных — политикозависимых по факту
}

func (c rolePageCensus) String() string {
	return fmt.Sprintf("абзацев прочитано %d · в области подстановки %d · "+
		"предложений области %d · с обоими маркерами (не разобрано) %d · "+
		"заявлений распознано %d · полей заявлено %d · "+
		"с производителем поведения %d · политикозависимых по факту %d",
		c.Paragraphs, c.Scoped, c.Sentences, c.Ambiguous, c.Claims, c.Fields,
		c.Probed, c.Dependent)
}

// pageClaim — одно заявление страницы, с координатой.
type pageClaim struct {
	field string
	pol   polarity
	line  int
}

// auditRolePageWildcardClaims выносит вердикт по ТЕКСТУ страницы и ПОВЕДЕНИЮ
// домена. Текст принимается параметром, чтобы инъекция подавала синтетику, не
// трогая дерево.
func auditRolePageWildcardClaims(
	pageText string, probes map[string]wildcardProbe, contractFields []string,
) ([]string, rolePageCensus, error) {
	var (
		findings []string
		census   rolePageCensus
		claims   []pageClaim
	)
	spellings := pageFieldSpellings(contractFields)

	for _, par := range splitParagraphs(pageText) {
		census.Paragraphs++
		if !par.inWildcardScope {
			continue
		}
		census.Scoped++
		for _, sent := range splitSentences(par.text) {
			census.Sentences++
			pol := sentencePolarity(sent)
			if pol == polarityBoth {
				census.Ambiguous++
				continue
			}
			if pol == polarityNone {
				continue
			}
			fields := fieldsNamed(sent, spellings)
			if len(fields) == 0 {
				// Полярность без поля — не заявление о поле: страница вправе
				// говорить о подстановке вообще. Считается прочитанным и молчит.
				continue
			}
			for _, f := range fields {
				census.Claims++
				claims = append(claims, pageClaim{field: f, pol: pol, line: par.line})
			}
		}
	}

	// Самопротиворечие судится ДО обращения к домену: текст, говорящий о поле
	// обе вещи сразу, неверен при любом поведении.
	byField := map[string][]pageClaim{}
	var order []string
	for _, c := range claims {
		if _, seen := byField[c.field]; !seen {
			order = append(order, c.field)
		}
		byField[c.field] = append(byField[c.field], c)
	}
	census.Fields = len(order)

	for _, field := range order {
		fieldClaims := byField[field]
		seen := map[polarity]int{}
		for _, c := range fieldClaims {
			seen[c.pol] = c.line
		}
		if seen[polarityTierBound] != 0 && seen[polarityTierFree] != 0 {
			findings = append(findings, fmt.Sprintf(
				"поле %s: страница заявляет о нём обе полярности — «%s» (строка %d) "+
					"против «%s» (строка %d)", field,
				polarityTierBound, seen[polarityTierBound],
				polarityTierFree, seen[polarityTierFree]))
		}

		probe, ok := probes[field]
		if !ok {
			findings = append(findings, fmt.Sprintf(
				"строка %d, поле %s: страница заявляет о подстановке, а производителя "+
					"поведения у поля нет — заявление некому проверить",
				fieldClaims[0].line, field))
			continue
		}
		census.Probed++
		tenantErr := probe(domain.TenantPolicy())
		platformErr := probe(domain.PolicyOfRole(true, ""))
		dependent := tenantErr != nil && platformErr == nil
		if dependent {
			census.Dependent++
		}
		for _, c := range fieldClaims {
			switch {
			case c.pol == polarityTierBound && !dependent:
				findings = append(findings, fmt.Sprintf(
					"строка %d, поле %s: страница заявляет подстановку ограниченной ярусом, "+
						"а домен её так не судит (арендаторская политика: %v; платформенная: %v)",
					c.line, field, tenantErr, platformErr))
			case c.pol == polarityTierFree && dependent:
				findings = append(findings, fmt.Sprintf(
					"строка %d, поле %s: страница заявляет подстановку не ограниченной ярусом, "+
						"а домен ограничивает (арендаторская политика: %v)", c.line, field, tenantErr))
			}
		}
	}
	return findings, census, nil
}

// paragraph — абзац страницы с координатой и признаком области.
type paragraph struct {
	text            string
	line            int
	inWildcardScope bool
}

// splitParagraphs режет страницу на абзацы и помечает те, что лежат в области
// подстановки: сам абзац несёт литерал ЛИБО стоит во врезке, чей заголовок его
// несёт.
func splitParagraphs(pageText string) []paragraph {
	var (
		out      []paragraph
		cur      []string
		curLine  int
		inAdmon  bool
		admonWld bool
	)
	flush := func() {
		if len(cur) == 0 {
			return
		}
		text := strings.Join(cur, " ")
		out = append(out, paragraph{
			text:            text,
			line:            curLine,
			inWildcardScope: reWildcardLiteral.MatchString(text) || (inAdmon && admonWld),
		})
		cur = nil
	}
	for i, line := range strings.Split(pageText, "\n") {
		if reAdmonition.MatchString(strings.TrimSpace(line)) {
			flush()
			if inAdmon {
				inAdmon, admonWld = false, false
			} else {
				inAdmon = true
				admonWld = reWildcardLiteral.MatchString(line)
			}
			continue
		}
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if len(cur) == 0 {
			curLine = i + 1
		}
		cur = append(cur, strings.TrimSpace(line))
	}
	flush()
	return out
}

// reSentenceEnd — граница предложения. Точка внутри координат (`v1.`) и внутри
// подстановки (`*.*`) границей не является: за ней нет пробела.
var reSentenceEnd = regexp.MustCompile(`\.\s+`)

func splitSentences(text string) []string {
	var out []string
	for _, s := range reSentenceEnd.Split(text, -1) {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

// sentencePolarity — что предложение утверждает об ярусе. Выделение снимается
// (`**не** ограничена` → `не ограничена`): иначе маркер отрицания разорвался бы
// разметкой. Одинарная звёздочка НЕ снимается — она и есть предмет.
//
// # Отрицание СИЛЬНЕЕ голого маркера, и это не тонкость
//
// «НЕ ограничена ярусом» несёт внутри себя подстроку «ограничена ярусом».
// Спрошенные независимо, оба маркера совпали бы, предложение ушло бы в
// неразобранные — и совершенно законная фраза оказалась бы вне наблюдения
// МОЛЧА. Поэтому маркеры отрицания сперва ВЫРЕЗАЮТСЯ, и утвердительный
// спрашивается у остатка.
//
// Найдено собственной инъекцией, а не замыслом: на живой странице две половины
// написаны так, что не сталкиваются («Ярусом роли ограничена…» против «…— не
// ограничена»), и по ней одной дефект был бы невидим.
func sentencePolarity(sentence string) polarity {
	plain := strings.ReplaceAll(sentence, "**", "")
	free := reTierFree.MatchString(plain)
	bound := reTierBound.MatchString(reTierFree.ReplaceAllString(plain, " "))
	switch {
	case bound && free:
		return polarityBoth
	case bound:
		return polarityTierBound
	case free:
		return polarityTierFree
	}
	return polarityNone
}

// proseWindow — сколько рун перед литералом подстановки просматривается на
// прозаическое имя поля. Величина взята по самой длинной живой форме
// («модуль/ресурс-`*`» — 14 рун от начала стема до литерала) с запасом.
const proseWindow = 40

// fieldsNamed — поля `Rule`, названные предложением: код-спанами и прозой
// вплотную к литералу. Порядок появления, без повторов.
func fieldsNamed(sentence string, spellings map[string]string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(field string) {
		if field == "" || seen[field] {
			return
		}
		seen[field] = true
		out = append(out, field)
	}
	for _, m := range reCodeSpan.FindAllStringSubmatch(sentence, -1) {
		add(spellings[strings.TrimSpace(m[1])])
	}
	for _, loc := range reWildcardLiteral.FindAllStringIndex(sentence, -1) {
		runes := []rune(sentence[:loc[0]])
		if len(runes) > proseWindow {
			runes = runes[len(runes)-proseWindow:]
		}
		window := strings.ToLower(string(runes))
		for stem, field := range proseFieldStems {
			if strings.Contains(window, stem) {
				add(field)
			}
		}
	}
	return out
}

// TestRolePageWildcardClaimAgreesWithTheDomain — вердикт о НАСТОЯЩЕЙ странице.
//
// Способность падать доказывает не этот прогон, а инъекция
// (`role_page_wildcard_agrees_injection_test.go`).
func TestRolePageWildcardClaimAgreesWithTheDomain(t *testing.T) {
	text := readRolePage(t)
	findings, census, err := auditRolePageWildcardClaims(
		text, ruleWildcardProbes(), ruleContractFields(t))
	if err != nil {
		t.Fatalf("разбор страницы не отработал: %v", err)
	}
	t.Logf("объём осмотренного: %s", census)

	// Премисы: «ноль находок» обязано быть отличимо от «ноль прочитанного», и
	// каждая закрывает СВОЙ способ получить пустой вердикт.
	if census.Paragraphs == 0 {
		t.Fatal("абзацев прочитано 0 — обход пуст, вердикт беспредметен")
	}
	if census.Scoped == 0 {
		t.Fatal("ни один абзац не попал в область подстановки — страница о предмете " +
			"не говорит либо признак области негоден")
	}
	if census.Claims == 0 {
		t.Fatal("заявлений распознано 0 — сверять не с чем: распознаватель не видит " +
			"ни одной формы, в которой страница делает заявление")
	}
	if census.Probed == 0 {
		t.Fatal("ни одно заявленное поле не спрошено у домена — сверка не состоялась")
	}
	if census.Dependent == 0 {
		t.Fatal("политикозависимых подстановок по факту 0 — производители поведения " +
			"негодны: ярус роли не различается ни на одном поле")
	}

	for _, f := range findings {
		t.Errorf("НАХОДКА: %s", f)
	}
}

// ruleContractFields — имена полей `message Rule` ИЗ КОНТРАКТА.
//
// Разбор переиспользует `reRuleField` соседнего гейта: второй распознаватель
// объявления поля разошёлся бы с первым молча.
func ruleContractFields(t *testing.T) []string {
	t.Helper()
	var (
		fields []string
		inRule bool
	)
	for _, line := range strings.Split(readRoleContract(t), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case !inRule:
			if strings.HasPrefix(trimmed, "message Rule ") || trimmed == "message Rule{" {
				inRule = true
			}
		case trimmed == "}":
			inRule = false
		default:
			if m := reRuleField.FindStringSubmatch(line); m != nil {
				fields = append(fields, m[1])
			}
		}
	}
	if len(fields) == 0 {
		t.Fatal("полей message Rule в контракте не найдено — словарь написаний пуст, " +
			"страница осталась бы вне наблюдения целиком")
	}
	return fields
}

// readRolePage читает страницу арендатора о роли.
//
// Координата объявлена ЗДЕСЬ и одна. Страница живёт В МОДУЛЕ сервиса (в отличие
// от контракта, который остаётся в корне), поэтому подъём до ближайшего
// `go.mod` даёт её и в монорепо, и при выносе iam отдельным репозиторием.
func readRolePage(t *testing.T) string {
	t.Helper()
	path := filepath.Join(moduleRootDir(t), "docs", "content", "api", "role.mdx")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("страница роли не прочитана (%s): %v", path, err)
	}
	return string(b)
}
