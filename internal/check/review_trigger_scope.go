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
//     ровно то, что запрещает ось 1, этажом ниже.
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

import (
	"fmt"
	"sort"
	"strings"

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

// baseReadingMarkers — чем условие `if:` читает базу запроса. Сравнение без
// учёта регистра: переменная окружения того же смысла пишется `GITHUB_BASE_REF`.
var baseReadingMarkers = []string{"base_ref", "pull_request.base"}

// ReviewTriggerCensus — объём осмотренного.
type ReviewTriggerCensus struct {
	// Files — объявлений прочитано; OnReview — из них идущих на запросе;
	// ReviewAtLine — из идущих на запросе тех, чей фильтр баз РАВЕН объявленному.
	Files        int
	OnReview     int
	ReviewAtLine int
	// OnBranchPush — идущих по `push` в ветки (не только в метки).
	OnBranchPush int
	// Conditions — условий `if:` осмотрено (заданий и шагов вместе).
	Conditions int
}

// String — перепись одной строкой. «Ноль находок» обязано быть отличимо от
// «ноль прочитанного», поэтому печатаются все величины.
func (c ReviewTriggerCensus) String() string {
	return fmt.Sprintf("объявлений процессов %d · идут на запросе %d · из них с базами {%s} %d · "+
		"идут по push в ветки %d · условий if: осмотрено %d",
		c.Files, c.OnReview, strings.Join(ReviewBaseBranches(), ", "), c.ReviewAtLine,
		c.OnBranchPush, c.Conditions)
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
	findings = append(findings, auditBaseReadingConditions(mappingValue(doc, "jobs"), census)...)
	return findings, title, nil
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
func auditBaseReadingConditions(jobs *yaml.Node, census *ReviewTriggerCensus) []string {
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return nil
	}
	var findings []string
	judge := func(where, cond string) {
		census.Conditions++
		low := strings.ToLower(cond)
		for _, m := range baseReadingMarkers {
			if strings.Contains(low, m) {
				findings = append(findings, fmt.Sprintf("%s: условие %q читает БАЗУ запроса — на "+
					"запросе в линию состав заданий другой, чем на запросе в ствол, при том же "+
					"триггере", where, strings.TrimSpace(cond)))
				return
			}
		}
	}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		jobName, job := jobs.Content[i].Value, jobs.Content[i+1]
		if job.Kind != yaml.MappingNode {
			continue
		}
		if cond := mappingValue(job, "if"); cond != nil {
			judge(fmt.Sprintf("задание %s", jobName), cond.Value)
		}
		steps := mappingValue(job, "steps")
		if steps == nil || steps.Kind != yaml.SequenceNode {
			continue
		}
		for si, st := range steps.Content {
			if st.Kind != yaml.MappingNode {
				continue
			}
			if cond := mappingValue(st, "if"); cond != nil {
				judge(fmt.Sprintf("задание %s, шаг %d", jobName, si+1), cond.Value)
			}
		}
	}
	return findings
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
