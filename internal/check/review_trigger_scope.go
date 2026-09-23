// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// review_trigger_scope.go — РАЗБОР ТРИГГЕРОВ процессов: запрос в ветку ЛИНИИ
// (волны, эпика) идёт тем же конвейером, что запрос в ствол, а `push` судит
// только ствол (задача PRO-Robotech/kaname#394).
//
// # ПРЕДМЕТ
//
// Правило 2026-09-22 (PRO-Robotech/kacho-workspace#770): волна вливается
// запросом в ветку эпика, и конвейер гоняется на запросе в ветку-номер. Процессы
// службы были сужены до `main` и по `push`, и по `pull_request`, поэтому запрос
// в ветку-номер приходил БЕЗ ЕДИНОГО контекста: PR #326 влит в `358` с пустым
// перечнем проверок на голове. Это не выдавало себя ничем — у такого запроса
// нет красного, потому что нет прогона, а «нет прогона» на странице запроса
// выглядит так же, как «проверять нечего».
//
// # ЧЕТЫРЕ ОСИ, И КАЖДАЯ ЛОМАЕТСЯ СВОИМ СПОСОБОМ, МОЛЧА
//
//  1. БАЗЫ ЗАПРОСА. `on.pull_request.branches` КАЖДОГО процесса, идущего на
//     запросе, РАВЕН множеству ReviewBaseBranches: ни уже (запрос в линию без
//     вердикта), ни шире (прогон на запросе в ветку полосы, ревью, спасения —
//     тот расход, ради которого фильтр и заведён). Сверяется РАВЕНСТВО, а не
//     вхождение: вхождение молчало бы на `'**'`;
//  2. СТВОЛ ПО `push`. `on.push.branches` равен {main}: вердикт линии даёт её
//     ЗАПРОС, а не каждая отправка в неё. Держатель `trunkverdict` сужен по
//     стволу своим условием и судится своим гейтом (trunk_verdict_holder.go),
//     здесь это не повторяется;
//  3. ПУТИ НЕ СУЖАЮТ ЗАПРОС. Защита ствола требует контексты ПОИМЁННО, а
//     контекст, который не начался, остаётся «ожидается» — ни зелёного, ни
//     красного, и слияние стоит;
//  4. ЗАДАНИЕ НЕ РАЗЛИЧАЕТ БАЗУ. Условие `if:` задания или шага, читающее базу
//     запроса, даёт запросу в линию ДРУГОЙ состав заданий при том же триггере —
//     ровно то, что запрещает ось 1, этажом ниже. Как это распознаётся — в
//     разделе «ОСЬ 4: СУДИТСЯ ЗВЕНО, А НЕ ПУТЬ».
//
// # ОСЬ 4: СУДИТСЯ ЗВЕНО, А НЕ ПУТЬ
//
// У провайдера обращение к полю — всегда одно из трёх: `.имя`, фильтр `.*` или
// `[*]`, индекс `[выражение]`. Применяется оно к ЛЮБОМУ значению слева: к корню
// контекста, к другому обращению, к группе `(…)`, к вызову функции
// (actions/languageservices, expressions/src/parser.ts:184 @656a821a: `index()`
// принимает `Grouping`, `FunctionCall` и `ContextAccess`). Имя поля несёт само
// обращение, и только оно; левая часть даёт значение, но поля не называет.
// Круг 1 искал подстроку, круг 2 разбирал путь от корня — и оба слепли на
// записи ЛЕВОЙ части: сначала на индексе, затем на группе и вызове. Поэтому
// разбор идёт по лексемам (conditionReadsBase) и судит каждое обращение, не
// спрашивая, что стоит слева, — и новая запись левой части слепоты не даёт:
//
//   - звено, НАЗВАННОЕ в тексте, — имя после точки или литерал в `[ ]`, —
//     читает базу, если среди его слов есть слово `base` (namesBase): `base`,
//     `base_ref`, `base_sha`, `GITHUB_BASE_REF`, `baseRef`, `pr-base`. Слово, а
//     не подстрока: `database` и `DATABASE_REF` — другое слово, `head` и
//     `head_ref` — тоже;
//   - звено, НЕ названное в тексте, — фильтр или индекс выражением, — может
//     оказаться любым полем своего объекта. Оно считается чтением базы у
//     ЛЮБОГО объекта, кроме закрытого перечня silentOwners — тех, у кого
//     выбранное звено базой быть не может: корень `needs` и корень `steps`
//     (звено выбирает итог задания или шага, а не значение; выход под ним
//     судится своим звеном) и поле `labels` (у метки поля базы нет). Объект
//     слева неизвестен — результат `)`, другое неизвестное звено, — тоже
//     чтение базы. Перечень держит МОЛЧАЩИХ, а не краснеющих: объект, о
//     котором разбор не знает (`changes`, `outputs`, `inputs`, `event`, поле
//     формы из `fromJSON`), даёт красное, и неполнота перечня стоит красного,
//     а не слепоты.
//
// Строковый литерал вне `[ ]` звеном не является: `'pull_request.base'` — то, с
// чем сравнивают. Лексемы различаются так же, как у провайдера (lexer.ts того
// же среза): литерал в одинарных кавычках, удвоенная кавычка внутри его не
// закрывает; точка после имени, `]`, `)` или `*` — обращение, иначе — начало
// числа.
//
// Цена надаппроксимации — красное на имени, чьё слово `base` к базе запроса
// отношения не имеет (задание `base`, переменная `BASE_IMAGE`), и на
// неизвестном звене у объекта вне перечня молчащих, даже если поля базы у
// него нет (`….requested_reviewers.*`). Такое условие переписывается
// поимённым полем, либо объект входит в перечень со своей причиной: молчание
// дороже.
//
// # YAML: ПСЕВДОНИМ РАЗРЕШАЕТСЯ ДО СУЖДЕНИЯ
//
// Провайдер разрешает псевдоним `*имя` в узел якоря `&имя` в ЛЮБОМ месте
// объявления (actions/languageservices, workflow-parser yaml-object-reader.ts,
// ветка isAlias; замер @actions/workflow-parser 0.3.61): `if: *якорь`, задание,
// `steps` и шаг под псевдонимом исполняются так же, как записанные на месте.
// Узел yaml.v3 хранит у псевдонима имя якоря, а не значение, и разбор,
// читающий узел как есть, судил бы имя. Поэтому КАЖДЫЙ псевдоним документа
// разрешается до всех четырёх осей (resolveAliases), а их число стоит в
// переписи. Три записи провайдер не принимает — тот же замер: ключ слияния
// `<<` (`Unexpected value '<<'`), ключ-псевдоним (`Unexpected value
// 'undefined'`), псевдоним внутрь собственного якоря (`Expected mapping
// end`), — и разбор на них отказывает, а не молчит. Так же отказывает ось 4
// на `jobs`, задании, `steps`, шаге и условии, записанных формой, которой
// провайдер не принимает.
//
// # ПОЧЕМУ РАЗБОР УЗЛОВ, А НЕ ПОИСК ПО ПОДСТРОКЕ
//
// Образец `[0-9]+` и слово `main` стоят и в комментариях — там, где фильтр
// объяснён. Проверка по подстроке зеленела бы на собственном объяснении.
// Здесь читается разобранный YAML, и все ЗАКОННЫЕ записи события различаются:
// `on: pull_request` (скаляр), `on: [push, pull_request]` (последовательность),
// `pull_request:` без тела и с телом, `branches` списком блоком, списком в
// строку и одиночным скаляром. Первые три — «любая база», то есть находка оси 1.
//
// # ЧЕГО ЭТОТ РАЗБОР НЕ СУДИТ — СКАЗАНО ПРЯМО
//
// Тела `run:`: база, прочитанная оболочкой из окружения, разбору условий не
// видна. Настройки защиты ветки: перечень обязательных контекстов живёт вне
// дерева (`.github/TRUNK-VERDICT.md`). И СЕМАНТИКУ глоба у провайдера: разбор
// сверяет ЗАПИСЬ фильтра с объявленной, а что запись захватывает на origin —
// замер переписью веток (шапка `on:` в `ci.yml`), то есть свойство вне дерева.
//
// По оси 4 граница такая — этого ось НЕ судит, и её зелёное об этом ничего
// не говорит. Судится только `if:` заданий и шагов в объявлениях каталога
// `.github/workflows`. Не осматриваются: многоразовый процесс — `with:`, которым
// задание `uses:` отдаёт базу вызываемому, и чужой процесс по `владелец/репо`;
// составные действия — `.github/actions/**` и чужие `uses:` шага — с их `if:`;
// тела `run:`; выражения вне `if:` — `strategy.matrix`, `continue-on-error`,
// `with:`, `env:`, `outputs`, `runs-on`, `concurrency`, `environment`, — хотя
// каждое из них способно дать запросу в линию другой состав или исход; и
// данные, приходящие в условие не записью YAML. Последних два вида: база,
// переложенная оболочкой, выходом, входом `inputs` или `fromJSON` в значение
// под именем без слова `base` (`env.ONLY_MAIN`, `inputs.target`), — и объект
// выше базы, потреблённый функцией ЦЕЛИКОМ
// (`contains(toJSON(github.event.pull_request), 'main')`): звена `base` в
// условии нет — есть объект, внутри которого она лежит.

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

// LineBranchPattern — форма имени ветки ЛИНИИ (волны, эпика): одна или больше
// цифр, и ничего больше.
//
// Синтаксис фильтра провайдера: класс `[0-9]` — одна цифра, `+` — «один или
// больше предыдущего знака», и образец сопоставляется со ВСЕМ именем ветки.
// `'[0-9]*'` НЕ равносилен ему: `*` берёт любой хвост без косой черты, и ветка
// `2564-line-b` стала бы линией.
const LineBranchPattern = "[0-9]+"

// ReviewBaseBranches — базы запроса, на которых процесс ОБЯЗАН идти, и только
// они. Одно объявление в дереве Go: процессы несут его копиями (иначе фильтр
// провайдеру не объявить), и разойтись копиям не даёт этот разбор.
func ReviewBaseBranches() []string {
	return []string{TrunkBranch, LineBranchPattern}
}

// reviewEvent — событие запроса. `pull_request_target` сюда НЕ входит: у него
// другой контекст исполнения (права базы на чужой голове), и объявление его
// ради вердикта линии было бы расширением поверхности, а не триггера.
const reviewEvent = "pull_request"

// ownerPlace — где объект перечня молчащих обязан стоять, чтобы молчать:
// корнем выражения или полем другого объекта. Имя вне своего места — другой
// объект (`fromJSON(…).steps` — поле произвольной формы, а не контекст шагов).
type ownerPlace int

const (
	asContext ownerPlace = iota + 1
	asField
)

// silentOwners — ЗАКРЫТЫЙ перечень объектов, у которых неизвестное звено
// базой запроса оказаться не может; у всякого другого — может (шапка, «ОСЬ 4:
// СУДИТСЯ ЗВЕНО, А НЕ ПУТЬ»). Каждая запись несёт причину. Имена в нижнем
// регистре: провайдер регистра имён не различает.
var silentOwners = map[string]ownerPlace{
	// Ключи — имена заданий из `needs:`, значение — {outputs, result}: звено
	// выбирает ИТОГ задания, а не значение. Выход под ним судится своим
	// звеном: `outputs` в перечень не входит.
	"needs": asContext,
	// Ключи — `id` шагов, значение — {outputs, outcome, conclusion}: то же.
	"steps": asContext,
	// Метки запроса: у метки поля id, node_id, url, name, description, color,
	// default — поля базы нет.
	"labels": asField,
}

// ownerIsSilent — молчит ли неизвестное звено у названного объекта.
func ownerIsSilent(on linkOwner) bool {
	place, ok := silentOwners[strings.ToLower(on.named)]
	if !ok {
		return false
	}
	return (place == asContext) == on.root
}

// namesBase — есть ли среди слов звена слово `base`.
//
// Слова разделены любым знаком, кроме буквы и цифры; вторым разбором — ещё и
// сменой строчной буквы заглавной (`baseRef`). Регистр снят: `bAse` у
// провайдера то же поле, что `base`. Слово, а не подстрока: `database` и
// `DATABASE_REF` базой не являются.
func namesBase(link string) bool {
	for _, camel := range []bool{false, true} {
		var word []rune
		prevLower := false
		for _, r := range link + " " {
			alnum := unicode.IsLetter(r) || unicode.IsDigit(r)
			if !alnum || (camel && prevLower && unicode.IsUpper(r)) {
				if strings.EqualFold(string(word), "base") {
					return true
				}
				word = word[:0]
			}
			if alnum {
				word = append(word, r)
			}
			prevLower = unicode.IsLower(r)
		}
	}
	return false
}

// linkOwner — объект, к которому применяется следующее обращение: названный
// (имя, как записано; root — стоит корнем выражения), неизвестный (чем именно
// — для находки) или никакой (перед этим стоял оператор, литерал, запятая).
type linkOwner struct {
	named   string
	root    bool
	unknown string
}

// bracketFrame — открытый индекс-выражение: у какого объекта и где начат.
type bracketFrame struct {
	owner linkOwner
	at    int
}

// conditionReadsBase — читает ли условие базу запроса, и какими звеньями —
// ВСЕМИ, через «; », в порядке разбора (пусто — не читает); второе — сколько
// звеньев прочитано, для переписи.
//
// Разбор идёт по ЛЕКСЕМАМ провайдера и судит каждое обращение отдельно, не
// спрашивая, что стоит слева (шапка, «ОСЬ 4: СУДИТСЯ ЗВЕНО, А НЕ ПУТЬ»).
func conditionReadsBase(expr string) (reading string, links int) {
	var (
		owner linkOwner
		// Точка — обращение, если перед ней имя, `]`, `)` или `*`; иначе это
		// начало числа (lexer.ts провайдера, та же развилка).
		access   bool
		open     []bracketFrame
		readings []string
	)
	found := func(desc string) { readings = append(readings, desc) }
	named := func(link string) {
		links++
		if namesBase(link) {
			found(fmt.Sprintf("звено `%s`", link))
		}
	}
	unknownAt := func(on linkOwner, link string) {
		links++
		switch {
		case on.unknown != "":
			found(fmt.Sprintf("неизвестное звено `%s` у %s", link, on.unknown))
		case on.named != "" && !ownerIsSilent(on):
			found(fmt.Sprintf("неизвестное звено `%s` у `%s`", link, on.named))
		}
	}
	unknownLink := linkOwner{unknown: "неизвестного звена"}

	for i := 0; i < len(expr); {
		c := expr[i]
		switch {
		case isExprSpace(c):
			i++ // пробел лексемой не является и прежней не отменяет
		case c == '\'':
			_, i = scanStringLiteral(expr, i)
			owner, access = linkOwner{}, false
		case c == '.' && access:
			k := skipExprSpaces(expr, i+1)
			switch {
			case k < len(expr) && expr[k] == '*':
				unknownAt(owner, "*")
				owner, access, i = unknownLink, true, k+1
			case k < len(expr) && isIdentStart(expr[k]):
				j := scanIdentChars(expr, k)
				named(expr[k:j])
				owner, access, i = linkOwner{named: expr[k:j]}, true, j
			default:
				owner, access, i = linkOwner{}, false, k
			}
		case c == '[':
			k := skipExprSpaces(expr, i+1)
			if k < len(expr) && expr[k] == '\'' {
				lit, e := scanStringLiteral(expr, k)
				if e = skipExprSpaces(expr, e); e < len(expr) && expr[e] == ']' {
					named(lit)
					owner, access, i = linkOwner{named: lit}, true, e+1
					continue
				}
			}
			if k < len(expr) && expr[k] == '*' {
				if e := skipExprSpaces(expr, k+1); e < len(expr) && expr[e] == ']' {
					unknownAt(owner, "[*]")
					owner, access, i = unknownLink, true, e+1
					continue
				}
			}
			if k < len(expr) && (isDigit(expr[k]) || expr[k] == '-' || expr[k] == '+') {
				if e := skipExprSpaces(expr, scanNumber(expr, k+1)); e < len(expr) && expr[e] == ']' {
					// Элемент списка судится по имени списка: у элемента
					// `pull_requests` поле базы есть, у элемента меток — нет.
					links++
					access, i = true, e+1
					continue
				}
			}
			open = append(open, bracketFrame{owner: owner, at: i})
			owner, access, i = linkOwner{}, false, i+1
		case c == ']':
			if n := len(open); n > 0 {
				unknownAt(open[n-1].owner, expr[open[n-1].at:i+1])
				open = open[:n-1]
			}
			owner, access, i = unknownLink, true, i+1
		case c == ')':
			owner, access, i = linkOwner{unknown: "результата группы или вызова"}, true, i+1
		case isIdentStart(c):
			j := scanIdentChars(expr, i)
			if k := skipExprSpaces(expr, j); k < len(expr) && expr[k] == '(' {
				// Имя функции звеном не является; её аргументы разбираются дальше.
				owner, access, i = linkOwner{}, false, j
				continue
			}
			named(expr[i:j])
			owner, access, i = linkOwner{named: expr[i:j], root: true}, true, j
		case isDigit(c) || c == '.' || c == '-' || c == '+':
			owner, access, i = linkOwner{}, false, scanNumber(expr, i+1)
		default:
			owner, access, i = linkOwner{}, false, i+1
		}
	}
	return strings.Join(readings, "; "), links
}

// scanStringLiteral — литерал в одинарных кавычках (удвоенная кавычка внутри —
// одна кавычка текста): его текст и позиция за ним. Незакрытый литерал
// тянется до конца выражения.
func scanStringLiteral(s string, i int) (string, int) {
	var b strings.Builder
	for j := i + 1; j < len(s); j++ {
		if s[j] != '\'' {
			b.WriteByte(s[j])
			continue
		}
		if j+1 < len(s) && s[j+1] == '\'' {
			b.WriteByte('\'')
			j++
			continue
		}
		return b.String(), j + 1
	}
	return b.String(), len(s)
}

func scanIdentChars(s string, i int) int {
	for i < len(s) && isIdentChar(s[i]) {
		i++
	}
	return i
}

func scanNumber(s string, i int) int {
	for i < len(s) && (isIdentChar(s[i]) || s[i] == '.') {
		i++
	}
	return i
}

func skipExprSpaces(s string, i int) int {
	for i < len(s) && isExprSpace(s[i]) {
		i++
	}
	return i
}

func isExprSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }
func isDigit(c byte) bool     { return c >= '0' && c <= '9' }
func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
func isIdentChar(c byte) bool { return isIdentStart(c) || isDigit(c) || c == '-' }

// ReviewTriggerCensus — объём осмотренного.
type ReviewTriggerCensus struct {
	// Files — объявлений прочитано; OnReview — из них идущих на запросе;
	// ReviewAtLine — из идущих на запросе тех, чей фильтр баз РАВЕН объявленному.
	Files        int
	OnReview     int
	ReviewAtLine int
	// OnBranchPush — идущих по `push` в ветки (не только в метки).
	OnBranchPush int
	// Conditions — условий `if:` осмотрено (заданий и шагов вместе);
	// ConditionLinks — звеньев в них прочитано. Условия есть, а звеньев ноль —
	// разбор лексем ослеп, и молчание оси 4 сказано ни о чём.
	Conditions     int
	ConditionLinks int
	// Aliases — псевдонимов YAML разрешено до суждения (шапка, «YAML:
	// ПСЕВДОНИМ РАЗРЕШАЕТСЯ ДО СУЖДЕНИЯ»).
	Aliases int
}

// String — перепись одной строкой. «Ноль находок» обязано быть отличимо от
// «ноль прочитанного», поэтому печатаются все величины.
func (c ReviewTriggerCensus) String() string {
	return fmt.Sprintf("объявлений процессов %d · идут на запросе %d · из них с базами {%s} %d · "+
		"идут по push в ветки %d · условий if: осмотрено %d · звеньев в них прочитано %d · "+
		"псевдонимов YAML разрешено %d",
		c.Files, c.OnReview, strings.Join(ReviewBaseBranches(), ", "), c.ReviewAtLine,
		c.OnBranchPush, c.Conditions, c.ConditionLinks, c.Aliases)
}

// eventFilter — фильтр одного события в той форме, в какой он записан.
type eventFilter struct {
	// Bare — событие названо без тела (скаляром, в последовательности, `~`).
	Bare     bool
	Keys     map[string]bool
	Branches []string
}

// AuditReviewTriggers — вердикт о триггерах КОРПУСА процессов.
//
// Вход — имя объявления → его текст. Чистая функция от корпуса затем, чтобы
// способность упасть доказывалась подачей входа, а не правкой дерева.
func AuditReviewTriggers(corpus map[string]string) ([]string, ReviewTriggerCensus, error) {
	census := ReviewTriggerCensus{Files: len(corpus)}
	if census.Files == 0 {
		return nil, census, fmt.Errorf("объявлений процессов прочитано ноль — вердикт беспредметен")
	}

	names := make([]string, 0, len(corpus))
	for n := range corpus {
		names = append(names, n)
	}
	sort.Strings(names)

	var findings []string
	for _, name := range names {
		perFile, title, err := auditOneProcess(corpus[name], &census)
		if err != nil {
			return nil, census, fmt.Errorf("%s: %w", name, err)
		}
		for _, f := range perFile {
			findings = append(findings, fmt.Sprintf("%s (процесс %q): %s", name, title, f))
		}
	}

	if census.OnReview == 0 {
		return nil, census, fmt.Errorf(
			"процессов, идущих на запросе (%s), не найдено ни одного: детектор события "+
				"молчит, и его ноль означает «не искали», а не «их нет»", reviewEvent)
	}
	return findings, census, nil
}

func auditOneProcess(raw string, census *ReviewTriggerCensus) ([]string, string, error) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(raw), &root); err != nil {
		return nil, "", fmt.Errorf("объявление процесса не разобрано: %w", err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return nil, "", fmt.Errorf("объявление процесса не является отображением верхнего уровня")
	}
	doc := root.Content[0]
	aliases, err := resolveAliases(doc)
	if err != nil {
		return nil, "", err
	}
	census.Aliases += aliases

	title := scalarOf(mappingValue(doc, "name"))
	// Ключ `on` в YAML 1.1 — булево true; узел хранит исходную запись, поэтому
	// сверяется значение узла, а не его разрешённый тип.
	onNode := mappingValue(doc, "on")
	if onNode == nil {
		return nil, title, fmt.Errorf("в объявлении нет `on:` — процесс не запускается ничем, " +
			"и молчание разбора было бы вердиктом о пустом")
	}
	events, err := eventsOf(onNode)
	if err != nil {
		return nil, title, err
	}

	var findings []string

	// (1) и (3) — БАЗЫ ЗАПРОСА И ПУТИ.
	if pr, ok := events[reviewEvent]; ok {
		census.OnReview++
		fs, atLine := auditReviewFilter(pr)
		if atLine {
			census.ReviewAtLine++
		}
		findings = append(findings, fs...)
	}

	// (2) — СТВОЛ ПО `push`.
	if push, ok := events["push"]; ok {
		fs, onBranches := auditPushFilter(push)
		if onBranches {
			census.OnBranchPush++
		}
		findings = append(findings, fs...)
	}

	// (4) — ЗАДАНИЕ НЕ РАЗЛИЧАЕТ БАЗУ.
	fs, err := auditBaseReadingConditions(mappingValue(doc, "jobs"), census)
	if err != nil {
		return nil, title, err
	}
	findings = append(findings, fs...)
	return findings, title, nil
}

// resolveAliases — заменяет КАЖДЫЙ псевдоним документа узлом его якоря, так
// же, как это делает провайдер, и возвращает, сколько псевдонимов разрешено.
//
// Узлы якорей общие у всех псевдонимов, и каждый разрешается один раз
// (done): псевдоним на псевдонимы не множит обход. Три записи — отказ, а не
// молчание (шапка, «YAML: ПСЕВДОНИМ РАЗРЕШАЕТСЯ ДО СУЖДЕНИЯ»).
func resolveAliases(doc *yaml.Node) (int, error) {
	var (
		count  int
		onPath = map[*yaml.Node]bool{}
		done   = map[*yaml.Node]bool{}
		walk   func(n *yaml.Node) (*yaml.Node, error)
	)
	walk = func(n *yaml.Node) (*yaml.Node, error) {
		if n.Kind == yaml.AliasNode {
			if n.Alias == nil {
				return nil, fmt.Errorf("псевдоним `*%s` без якоря (строка %d)", n.Value, n.Line)
			}
			count++
			if onPath[n.Alias] {
				return nil, fmt.Errorf("псевдоним `*%s` (строка %d) ведёт внутрь собственного якоря: "+
					"провайдер такое объявление не принимает, а разбор не судит бесконечный узел",
					n.Value, n.Line)
			}
			return walk(n.Alias)
		}
		if done[n] {
			return n, nil
		}
		onPath[n] = true
		for i, c := range n.Content {
			if n.Kind == yaml.MappingNode && i%2 == 0 {
				switch {
				case c.Kind == yaml.AliasNode:
					return nil, fmt.Errorf("ключ отображения записан псевдонимом `*%s` (строка %d): "+
						"провайдер ключа-псевдонима не разрешает, и разбор не знает, какой ключ судить",
						c.Value, c.Line)
				case c.Kind == yaml.ScalarNode && c.Tag == "!!merge":
					return nil, fmt.Errorf("ключ слияния `<<` (строка %d): провайдер слияния не "+
						"применяет и объявление не принимает, а разбор не знает, чьи ключи судить", c.Line)
				}
			}
			r, err := walk(c)
			if err != nil {
				return nil, err
			}
			n.Content[i] = r
		}
		delete(onPath, n)
		done[n] = true
		return n, nil
	}
	_, err := walk(doc)
	return count, err
}

// eventsOf — события триггера во ВСЕХ законных записях.
func eventsOf(on *yaml.Node) (map[string]eventFilter, error) {
	out := map[string]eventFilter{}
	switch on.Kind {
	case yaml.ScalarNode:
		out[on.Value] = eventFilter{Bare: true}
	case yaml.SequenceNode:
		for _, n := range on.Content {
			if n.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("элемент последовательности `on:` не скаляр (строка %d)", n.Line)
			}
			out[n.Value] = eventFilter{Bare: true}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(on.Content); i += 2 {
			key, body := on.Content[i], on.Content[i+1]
			f, err := filterOf(body)
			if err != nil {
				return nil, fmt.Errorf("событие %q: %w", key.Value, err)
			}
			out[key.Value] = f
		}
	default:
		return nil, fmt.Errorf("`on:` записан формой, которую разбор не знает (строка %d)", on.Line)
	}
	return out, nil
}

// filterOf — тело события: без тела, либо отображение фильтров.
func filterOf(body *yaml.Node) (eventFilter, error) {
	if body == nil || (body.Kind == yaml.ScalarNode && body.Tag == "!!null") {
		return eventFilter{Bare: true}, nil
	}
	if body.Kind != yaml.MappingNode {
		return eventFilter{}, fmt.Errorf("тело события не отображение (строка %d)", body.Line)
	}
	f := eventFilter{Keys: map[string]bool{}}
	for i := 0; i+1 < len(body.Content); i += 2 {
		key, val := body.Content[i].Value, body.Content[i+1]
		f.Keys[key] = true
		if key != "branches" {
			continue
		}
		switch val.Kind {
		case yaml.ScalarNode:
			f.Branches = []string{val.Value}
		case yaml.SequenceNode:
			for _, b := range val.Content {
				if b.Kind != yaml.ScalarNode {
					return eventFilter{}, fmt.Errorf("элемент `branches` не скаляр (строка %d)", b.Line)
				}
				f.Branches = append(f.Branches, b.Value)
			}
		default:
			return eventFilter{}, fmt.Errorf("`branches` записан формой, которую разбор не знает (строка %d)", val.Line)
		}
	}
	return f, nil
}

// auditReviewFilter — ось 1 и ось 3. Второе значение — равен ли фильтр баз
// объявленному.
func auditReviewFilter(f eventFilter) ([]string, bool) {
	var findings []string
	if f.Keys["branches-ignore"] {
		findings = append(findings, "фильтр баз запроса записан ИСКЛЮЧЕНИЕМ (`branches-ignore`): "+
			"всякая новая форма ветки идёт на запросе по умолчанию, и расход растёт без правки "+
			"этого файла — нужен `branches` со множеством {"+strings.Join(ReviewBaseBranches(), ", ")+"}")
	}
	for _, k := range []string{"paths", "paths-ignore"} {
		if f.Keys[k] {
			findings = append(findings, fmt.Sprintf("запрос сужен по путям (`%s`): защита ствола требует "+
				"контексты ПОИМЁННО, а контекст, который не начался, остаётся «ожидается» — ни "+
				"зелёного, ни красного, и слияние стоит", k))
		}
	}

	if f.Bare || !f.Keys["branches"] {
		if !f.Keys["branches-ignore"] {
			findings = append(findings, "запрос не сужен по базе: процесс идёт на запросе в ЛЮБУЮ "+
				"ветку — полосы, ревью, спасения, — хотя вердикт нужен только стволу и линии {"+
				strings.Join(ReviewBaseBranches(), ", ")+"}")
		}
		return findings, false
	}

	missing, extra := setDiff(f.Branches, ReviewBaseBranches())
	if len(missing) == 0 && len(extra) == 0 {
		return findings, true
	}
	var why []string
	if len(missing) > 0 {
		why = append(why, fmt.Sprintf("недостаёт %s — запрос туда приходит БЕЗ ЕДИНОГО контекста, "+
			"и отсутствие прогона на странице запроса неотличимо от «проверять нечего»",
			quoteAll(missing)))
	}
	if len(extra) > 0 {
		why = append(why, fmt.Sprintf("лишние %s — они захватывают ветки, которые не ствол и не "+
			"линия, и каждый запрос туда оплачивается полным прогоном", quoteAll(extra)))
	}
	findings = append(findings, fmt.Sprintf("базы запроса %s ≠ {%s}: %s",
		quoteAll(f.Branches), strings.Join(ReviewBaseBranches(), ", "), strings.Join(why, "; ")))
	return findings, false
}

// auditPushFilter — ось 2. Второе значение — идёт ли процесс по push в ветки.
func auditPushFilter(f eventFilter) ([]string, bool) {
	if f.Keys["branches-ignore"] {
		return []string{"`push` сужен ИСКЛЮЧЕНИЕМ (`branches-ignore`): каждая ветка вне перечня " +
			"идёт по отправке, а вердикт линии даёт её ЗАПРОС — нужен `branches: [main]`"}, true
	}
	// Тело с одними метками — процесс идёт по push ТОЛЬКО в метки: так провайдер
	// читает `push:` без `branches`, если названы `tags`. Это законная форма.
	if !f.Bare && !f.Keys["branches"] && (f.Keys["tags"] || f.Keys["tags-ignore"]) {
		return nil, false
	}
	if f.Bare || !f.Keys["branches"] {
		return []string{"`push` не сужен по ветке: процесс идёт на КАЖДУЮ отправку в каждую " +
			"ветку, хотя по push судится только ствол — нужен `branches: [main]`"}, true
	}
	missing, extra := setDiff(f.Branches, []string{TrunkBranch})
	var findings []string
	if len(extra) > 0 {
		findings = append(findings, fmt.Sprintf("`push` расширен за ствол: %s — вердикт линии даёт "+
			"её ЗАПРОС, а отправка в неё оплачивалась бы вторым полным прогоном того же дерева",
			quoteAll(extra)))
	}
	if len(missing) > 0 {
		findings = append(findings, fmt.Sprintf("`push` не идёт в ствол %q: вердикт посаженного "+
			"состояния выносить не о чем", TrunkBranch))
	}
	return findings, true
}

// auditBaseReadingConditions — ось 4: условия `if:` заданий и их шагов.
//
// Псевдонимы к этому моменту разрешены (resolveAliases), и узел, записанный
// формой, которой провайдер не принимает, — отказ, а не пропуск: пропуск
// молчал бы о задании, которое провайдер исполнит, если форма ему известна
// лучше, чем разбору.
func auditBaseReadingConditions(jobs *yaml.Node, census *ReviewTriggerCensus) ([]string, error) {
	if jobs == nil {
		return nil, nil
	}
	if jobs.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("`jobs:` не отображение (строка %d): ось 4 не знает, где задания", jobs.Line)
	}
	var findings []string
	judge := func(where string, cond *yaml.Node) error {
		if cond.Kind != yaml.ScalarNode {
			return fmt.Errorf("%s: условие `if:` не скаляр (строка %d) — провайдер такого не "+
				"принимает, а разбор не знает, что судить", where, cond.Line)
		}
		census.Conditions++
		reading, links := conditionReadsBase(cond.Value)
		census.ConditionLinks += links
		if reading != "" {
			findings = append(findings, fmt.Sprintf("%s: условие %q читает БАЗУ запроса (%s) — "+
				"на запросе в линию состав заданий другой, чем на запросе в ствол, при том же "+
				"триггере", where, strings.TrimSpace(cond.Value), reading))
		}
		return nil
	}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		jobName, job := jobs.Content[i].Value, jobs.Content[i+1]
		where := fmt.Sprintf("задание %s", jobName)
		if job.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("%s не отображение (строка %d): ось 4 не знает, где его условие",
				where, job.Line)
		}
		if cond := mappingValue(job, "if"); cond != nil {
			if err := judge(where, cond); err != nil {
				return nil, err
			}
		}
		steps := mappingValue(job, "steps")
		if steps == nil {
			continue // задание `uses:` шагов не несёт
		}
		if steps.Kind != yaml.SequenceNode {
			return nil, fmt.Errorf("%s: `steps` не последовательность (строка %d): ось 4 не знает, "+
				"где условия шагов", where, steps.Line)
		}
		for si, st := range steps.Content {
			stepWhere := fmt.Sprintf("%s, шаг %d", where, si+1)
			if st.Kind != yaml.MappingNode {
				return nil, fmt.Errorf("%s не отображение (строка %d): ось 4 не знает, где его условие",
					stepWhere, st.Line)
			}
			if cond := mappingValue(st, "if"); cond != nil {
				if err := judge(stepWhere, cond); err != nil {
					return nil, err
				}
			}
		}
	}
	return findings, nil
}

// mappingValue — значение ключа отображения, либо nil.
func mappingValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func scalarOf(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

// setDiff — чего из want нет в got, и что в got сверх want. Повтор в got
// лишним не считается: фильтр провайдера — множество.
func setDiff(got, want []string) (missing, extra []string) {
	g := map[string]bool{}
	for _, x := range got {
		g[x] = true
	}
	w := map[string]bool{}
	for _, x := range want {
		w[x] = true
		if !g[x] {
			missing = append(missing, x)
		}
	}
	for x := range g {
		if !w[x] {
			extra = append(extra, x)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return missing, extra
}

func quoteAll(xs []string) string {
	q := make([]string, len(xs))
	for i, x := range xs {
		q[i] = "`" + x + "`"
	}
	return "{" + strings.Join(q, ", ") + "}"
}
