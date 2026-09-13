// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// quality_tool_invocation_test.go — инструмент качества зовётся ОДИНАКОВО
// ЗНАЧАЩИМ способом из рецепта и из конвейера.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Две проверки об одном предмете давали РАЗНЫЕ вердикты, и ни одна об этом не
// знала. Цель `lint` рецепта звала линтер БЕЗ `--config`, задание конвейера — с
// `--config=.github/golangci.yml`. Корневого `.golangci.yml` в дереве нет, поэтому
// цель уходила на умолчания инструмента: свой набор правил и ни одного из
// объявленных исключений.
//
// Цена измерена (ствол `4c3ad523`, пин v2.12.2, то же дерево, различие только в
// `--config`): БЕЗ конфигурации — 64 находки и код 2, С ней — «0 issues» и код 0.
// Все 64 покрыты объявленными исключениями (48 в `_test.go`, 11 в слоях,
// зеркалящих proto-имена, 5 — закрытие ресурса в `defer`), то есть красным было
// не дерево, а СПОСОБ СПРОСИТЬ. Разработчик, прогнавший цель локально, получал
// 64 находки на нетронутом дереве — и переставал её звать (#54).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ГЕЙТ, А НЕ ОДНА ПРАВКА РЕЦЕПТА
//
// Правка закрывает экземпляр. Класс — «вердикт выбирается неявно» — вернётся
// молча: `--config` снимут как лишний, конвейер переведут на другой файл, пин
// поднимут с одной стороны. Ни одно из трёх не даёт красного САМО: расхождение
// обнаруживается только тогда, когда кто-то сличит два вердикта вручную, а
// сличать их некому. Правило без механизма есть пожелание.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ИМЕННО УТВЕРЖДАЕТСЯ — пять осей, каждая закрывает свой отказ
//
//  1. ЯВНОСТЬ. Каждое обращение называет `--config` ЗНАЧЕНИЕМ. Поиск по умолчанию
//     идёт от текущего каталога вверх, поэтому его исход зависит от того, откуда
//     позвали и что лежит у соседей, — вердикт перестаёт быть свойством дерева.
//     Это и есть исходный дефект.
//  2. СОГЛАСИЕ. Все названные конфигурации — ОДНА. Два разных набора правил дают
//     два законных вердикта об одном дереве, и спорить между ними нечем.
//  3. СУЩЕСТВОВАНИЕ. Названный файл в дереве ЕСТЬ. Координата, пережившая свой
//     предмет, читается как действующая; здесь она к тому же ломает прогон у
//     всякого, кто цель позовёт.
//  4. ОБЛАСТЬ. Обход у обеих сторон один. Пустой перечень позиционных доводов —
//     это `./...` по умолчанию инструмента, поэтому сравниваются НОРМАЛИЗОВАННЫЕ
//     области: иначе «то же самое, записанное иначе» читалось бы расхождением.
//  5. ПИН. Версия, объявленная рецептом, равна версии, которую ставит конвейер.
//     Набор правил и их реализация едут ВМЕСТЕ с версией: расхождение пина есть
//     расхождение вердикта, и оно тише прочих — обе стороны выглядят согласными.
//
// ─────────────────────────────────────────────────────────────────────────────
// ГЕЙТ СУДИТ ИСПОЛНЯЕМУЮ ЧАСТЬ, А НЕ ТЕКСТ
//
// Предмет — ОБРАЩЕНИЕ, а не слово. В рецепте читаются только строки рецепта
// (начинаются с табуляции), в объявлении процесса — только скаляры `run:`
// разобранного YAML. Комментарий рецепта, комментарий YAML и подпись `name:`
// (а она здесь несёт слово «пин» со своим числом) под запрет НЕ подпадают: гейт,
// краснеющий на собственном объяснении, — тот самый класс, который корпус ловит.
//
// Обращением считается токен `golangci-lint` с подкомандой `run` следом.
// `golangci-lint version` в проверке пина обращением НЕ является и молчит —
// предмет оси в том, каким набором правил СУДЯТ, а не в том, что имя инструмента
// встретилось.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ЭТА ПРОВЕРКА НЕ ЗАКРЫВАЕТ — сказано прямо
//
//   - Она судит ОБЪЯВЛЕНИЕ, а не исход: что два прогона дали одинаковые числа,
//     доказывается прогоном, а не чтением.
//   - Флаги, НЕ определяющие вердикт (`--timeout`, форма вывода, многословность),
//     не сравниваются намеренно. Требование побайтового равенства командных строк
//     краснело бы на законной правке одной стороны, а гейт, краснеющий на верном
//     коде, отключают первым.
//   - Обращение, спрятанное за переменной make или за вызовом скрипта, гейту
//     невидимо: он не разворачивает подстановки и не входит внутрь `bash x.sh`.
//     Сегодня таких в дереве нет (перепись ниже печатает число найденных); заведут
//     — это отдельный предмет со своим замером, и здесь он назван, а не умолчан.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// qualityToolBinary — имя инструмента качества, чьи обращения сверяются.
const qualityToolBinary = "golangci-lint"

// qualityToolSubcommand — подкоманда, которая ВЫНОСИТ ВЕРДИКТ. Обращения с любой
// другой подкомандой (`version`, `help`, `linters`) предметом оси не являются:
// они ничего не судят, и требовать от них набор правил было бы требованием формы.
const qualityToolSubcommand = "run"

// qualityMakefile — рецепт службы относительно её корня.
const qualityMakefile = "Makefile"

// qualityWorkflowDir — каталог объявлений процессов. Перечень объявлений
// ВЫВОДИТСЯ обходом этого каталога, а не выписывается: выписанный не знал бы о
// заведённом завтра объявлении, и то линтовало бы своим набором правил молча.
const qualityWorkflowDir = ".github/workflows"

// qualityPinVariable — имя переменной рецепта, несущей пин инструмента.
const qualityPinVariable = "GOLANGCI_LINT_VERSION"

// qualityDefaultScope — область обхода, которую инструмент берёт, когда
// позиционных доводов не дано. Нормализация к ней нужна, чтобы «то же самое,
// записанное иначе» не читалось расхождением: конвейер доводов не даёт, рецепт
// пишет `./...`, и области у них ОДНА.
var qualityDefaultScope = []string{"./..."}

// qualityPinInInstall — пин в установочном обращении конвейера
// (`…/cmd/golangci-lint@v2.12.2`).
var qualityPinInInstall = regexp.MustCompile(qualityToolBinary + `@(v?[0-9][^\s"']*)`)

// qualityMakeAssignment — присваивание переменной рецепта в любой из трёх форм.
var qualityMakeAssignment = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\s*(?::=|\?=|=)\s*(.*?)\s*$`)

// qualityInvocation — одно ОБРАЩЕНИЕ к инструменту качества.
type qualityInvocation struct {
	// Where — координата, по которой читатель находку откроет. Находка,
	// называющая симптом вместо места, посылает искать не там.
	Where string
	// Config — значение `--config`; пусто означает, что конфигурация не названа
	// и будет ОТЫСКАНА инструментом. Это и есть ось 1.
	Config string
	// Scope — позиционные доводы, уже нормализованные.
	Scope []string
}

// qualityPin — объявление версии инструмента одной из сторон.
type qualityPin struct {
	Where   string
	Version string
}

// qualityCensus — объём осмотренного. «Ноль находок» обязано быть отличимо от
// «ноль прочитанного», а «ноль обращений» — от «обход не дошёл до рецепта».
type qualityCensus struct {
	makefileRecipeLines int
	workflowFiles       int
	workflowsParsed     int
	runSteps            int
	fromMakefile        int
	fromWorkflows       int
	pins                int
}

// scanQualityToolInvocations — разбор над ПРОИЗВОЛЬНЫМ корнем. Вынесено из пробы
// затем, чтобы способность гейта упасть доказывалась подачей входа, а не чтением.
func scanQualityToolInvocations(root string) (qualityCensus, []qualityInvocation, []qualityPin, []string) {
	var census qualityCensus
	var invocations []qualityInvocation
	var pins []qualityPin
	var findings []string

	// ── рецепт ───────────────────────────────────────────────────────────────
	if raw, err := os.ReadFile(filepath.Join(root, qualityMakefile)); err != nil {
		findings = append(findings, qualityMakefile+": не прочитан: "+err.Error()+
			" — о рецепте не сказано ничего, и зелёное здесь означало бы «не читали»")
	} else {
		lines := strings.Split(string(raw), "\n")
		for i := 0; i < len(lines); i++ {
			line := lines[i]

			// Присваивание пина — строка НЕ рецепта: значение объявлено деревом,
			// а не исполняется шеллом.
			if !strings.HasPrefix(line, "\t") {
				if m := qualityMakeAssignment.FindStringSubmatch(line); m != nil && m[1] == qualityPinVariable {
					pins = append(pins, qualityPin{
						Where:   qualityMakefile + ":" + strconv.Itoa(i+1),
						Version: strings.TrimSpace(m[2]),
					})
				}
				continue
			}

			// Строка рецепта: склеиваем продолжения, чтобы обращение, разорванное
			// обратной косой, не осталось непрочитанным.
			start := i
			logical := strings.TrimPrefix(line, "\t")
			for strings.HasSuffix(strings.TrimRight(logical, " \t"), "\\") && i+1 < len(lines) {
				logical = strings.TrimSuffix(strings.TrimRight(logical, " \t"), "\\")
				i++
				logical += " " + strings.TrimPrefix(lines[i], "\t")
			}
			census.makefileRecipeLines++

			for _, inv := range qualityInvocationsIn(logical) {
				inv.Where = qualityMakefile + ":" + strconv.Itoa(start+1)
				invocations = append(invocations, inv)
				census.fromMakefile++
			}
		}
	}

	// ── объявления процессов ─────────────────────────────────────────────────
	entries, err := os.ReadDir(filepath.Join(root, qualityWorkflowDir))
	if err != nil {
		findings = append(findings, qualityWorkflowDir+": каталог объявлений не прочитан: "+err.Error()+
			" — вторая сторона сверки отсутствует, сравнивать не с чем")
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if ext := filepath.Ext(e.Name()); ext != ".yml" && ext != ".yaml" {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		rel := qualityWorkflowDir + "/" + name
		census.workflowFiles++

		raw, rerr := os.ReadFile(filepath.Join(root, rel))
		if rerr != nil {
			findings = append(findings, rel+": не прочитан: "+rerr.Error())
			continue
		}
		var doc yaml.Node
		if uerr := yaml.Unmarshal(raw, &doc); uerr != nil {
			findings = append(findings, rel+": не разобран YAML: "+uerr.Error()+
				" — объявление НЕ проверено, а его обращения остались невидимыми")
			continue
		}
		body := &doc
		if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
			body = doc.Content[0]
		}
		jobs := pipelineMappingValue(body, "jobs")
		if jobs == nil || jobs.Kind != yaml.MappingNode {
			census.workflowsParsed++
			continue
		}
		census.workflowsParsed++

		for i := 0; i+1 < len(jobs.Content); i += 2 {
			jobKey, job := jobs.Content[i], jobs.Content[i+1]
			steps := pipelineMappingValue(job, "steps")
			if steps == nil || steps.Kind != yaml.SequenceNode {
				continue
			}
			for _, step := range steps.Content {
				if step.Kind != yaml.MappingNode {
					continue
				}
				// Читается ТОЛЬКО `run:` — исполняемая часть. Подпись `name:` и
				// комментарии YAML сюда не попадают by construction.
				run := pipelineMappingValue(step, "run")
				if run == nil || run.Kind != yaml.ScalarNode {
					continue
				}
				census.runSteps++
				where := rel + ":" + strconv.Itoa(run.Line) + " (задание `" + jobKey.Value + "`)"

				for _, logical := range qualityLogicalLines(run.Value) {
					for _, inv := range qualityInvocationsIn(logical) {
						inv.Where = where
						invocations = append(invocations, inv)
						census.fromWorkflows++
					}
					if m := qualityPinInInstall.FindStringSubmatch(qualityStripComment(logical)); m != nil {
						pins = append(pins, qualityPin{Where: where, Version: m[1]})
					}
				}
			}
		}
	}
	census.pins = len(pins)

	findings = append(findings, qualityJudge(root, invocations, pins)...)
	sort.Strings(findings)
	return census, invocations, pins, findings
}

// qualityJudge — пять осей над уже собранными обращениями.
func qualityJudge(root string, invocations []qualityInvocation, pins []qualityPin) []string {
	var findings []string

	// Ось 1: явность.
	for _, inv := range invocations {
		if inv.Config != "" {
			continue
		}
		findings = append(findings, inv.Where+": обращение к `"+qualityToolBinary+" "+qualityToolSubcommand+
			"` не называет `--config` — набор правил будет ОТЫСКАН инструментом от текущего каталога вверх "+
			"по дереву, то есть вердикт станет зависеть от того, откуда позвали. Назови конфигурацию "+
			"значением: прогон без неё и прогон с ней об одном дереве отвечают по-разному, и спорить "+
			"между ними нечем (#54)")
	}

	// Ось 2: согласие. Сравнивается с ПЕРВЫМ названным, а не с выписанной
	// константой: гейт судит согласие сторон, а не соблюдение своего мнения о том,
	// как файл обязан называться.
	var anchor *qualityInvocation
	for i := range invocations {
		if invocations[i].Config != "" {
			anchor = &invocations[i]
			break
		}
	}
	if anchor != nil {
		for _, inv := range invocations {
			if inv.Config == "" || inv.Config == anchor.Config {
				continue
			}
			findings = append(findings, inv.Where+": названа конфигурация `"+inv.Config+
				"`, а "+anchor.Where+" называет `"+anchor.Config+
				"` — два набора правил дают два законных вердикта об одном дереве")
		}

		// Ось 3: существование.
		seen := map[string]bool{}
		for _, inv := range invocations {
			if inv.Config == "" || seen[inv.Config] {
				continue
			}
			seen[inv.Config] = true
			if _, err := os.Stat(filepath.Join(root, inv.Config)); err != nil {
				findings = append(findings, inv.Where+": названной конфигурации `"+inv.Config+
					"` в дереве НЕТ — координата пережила свой предмет, и прогон отказывает у всякого, "+
					"кто обращение повторит")
			}
		}

		// Ось 4: область.
		for _, inv := range invocations {
			if qualityScopeEqual(inv.Scope, anchor.Scope) {
				continue
			}
			findings = append(findings, inv.Where+": область обхода `"+strings.Join(inv.Scope, " ")+
				"`, а "+anchor.Where+" обходит `"+strings.Join(anchor.Scope, " ")+
				"` — стороны судят РАЗНЫЕ множества пакетов, и совпадение их вердиктов было бы случайностью")
		}
	}

	// Ось 5: пин.
	if len(pins) > 1 {
		want := qualityNormalizeVersion(pins[0].Version)
		for _, p := range pins[1:] {
			if qualityNormalizeVersion(p.Version) == want {
				continue
			}
			findings = append(findings, p.Where+": объявлена версия `"+p.Version+
				"`, а "+pins[0].Where+" объявляет `"+pins[0].Version+
				"` — набор правил и их реализация едут вместе с версией, поэтому расхождение пина есть "+
				"расхождение вердикта, и оно тише прочих: обе стороны на вид согласны")
		}
	}

	return findings
}

// qualityNormalizeVersion — `v2.12.2` и `2.12.2` суть одна версия: конвейер
// ставит с приставкой, инструмент о себе сообщает без неё.
func qualityNormalizeVersion(v string) string { return strings.TrimPrefix(v, "v") }

// qualityScopeEqual — сравнение уже нормализованных областей.
func qualityScopeEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// qualityLogicalLines — строки скаляра `run:` со склеенными продолжениями.
func qualityLogicalLines(run string) []string {
	var out []string
	raw := strings.Split(run, "\n")
	for i := 0; i < len(raw); i++ {
		logical := raw[i]
		for strings.HasSuffix(strings.TrimRight(logical, " \t"), "\\") && i+1 < len(raw) {
			logical = strings.TrimSuffix(strings.TrimRight(logical, " \t"), "\\")
			i++
			logical += " " + raw[i]
		}
		out = append(out, logical)
	}
	return out
}

// qualityStripComment — отсечение комментария шелла. `#` внутри кавычек
// комментария не открывает, поэтому состояние кавычек отслеживается: иначе
// объяснение, положенное рядом, читалось бы как код, а строка с `#` внутри
// кавычек обрывалась бы посередине.
func qualityStripComment(line string) string {
	var inSingle, inDouble bool
	for i, r := range line {
		switch {
		case r == '\'' && !inDouble:
			inSingle = !inSingle
		case r == '"' && !inSingle:
			inDouble = !inDouble
		case r == '#' && !inSingle && !inDouble:
			// Комментарий открывает только `#`, стоящий в начале токена.
			if i == 0 || line[i-1] == ' ' || line[i-1] == '\t' {
				return line[:i]
			}
		}
	}
	return line
}

// qualityFields — разбиение на токены с уважением к кавычкам и со снятием их
// самих: `--config='x'` и `--config=x` называют одно.
func qualityFields(line string) []string {
	var out []string
	var cur strings.Builder
	var inSingle, inDouble, started bool
	flush := func() {
		if started {
			out = append(out, cur.String())
			cur.Reset()
			started = false
		}
	}
	for _, r := range line {
		switch {
		case r == '\'' && !inDouble:
			inSingle = !inSingle
			started = true
		case r == '"' && !inSingle:
			inDouble = !inDouble
			started = true
		case (r == ' ' || r == '\t') && !inSingle && !inDouble:
			flush()
		default:
			cur.WriteRune(r)
			started = true
		}
	}
	flush()
	return out
}

// qualityInvocationsIn — обращения к инструменту в ОДНОЙ логической строке.
//
// Обращением считается токен, чьё базовое имя есть имя инструмента, со следующим
// за ним токеном-подкомандой. Приставка пути (`bin/golangci-lint`) обращением
// быть не мешает; приставка версии (`…/golangci-lint@v2.12.2` в установочной
// строке) — мешает, и это верно: там инструмент СТАВЯТ, а не зовут.
func qualityInvocationsIn(line string) []qualityInvocation {
	fields := qualityFields(qualityStripComment(line))
	var out []qualityInvocation

	for i := 0; i+1 < len(fields); i++ {
		if filepath.Base(fields[i]) != qualityToolBinary || fields[i+1] != qualityToolSubcommand {
			continue
		}
		inv := qualityInvocation{}
		args := fields[i+2:]
		for j := 0; j < len(args); j++ {
			a := args[j]
			switch {
			case strings.HasPrefix(a, "--config="):
				inv.Config = strings.TrimPrefix(a, "--config=")
			case a == "--config" || a == "-c":
				if j+1 < len(args) {
					j++
					inv.Config = args[j]
				}
			case strings.HasPrefix(a, "-"):
				// Прочие флаги вердикта не определяют — см. шапку, «чего не закрывает».
				continue
			case a == "&&" || a == "||" || a == ";" || a == "|":
				// Конец обращения: дальше уже другая команда.
				j = len(args)
			default:
				inv.Scope = append(inv.Scope, a)
			}
		}
		if len(inv.Scope) == 0 {
			inv.Scope = append([]string(nil), qualityDefaultScope...)
		}
		out = append(out, inv)
	}
	return out
}

func TestQualityToolIsInvokedTheSameWayEverywhere(t *testing.T) {
	t.Parallel()

	census, invocations, _, findings := scanQualityToolInvocations(serviceRoot)

	t.Logf("перепись: строк рецепта осмотрено %d · объявлений процессов %d · из них разобрано %d · "+
		"шагов с `run:` %d · обращений к инструменту %d (рецепт %d · конвейер %d) · объявлений пина %d · находок %d",
		census.makefileRecipeLines, census.workflowFiles, census.workflowsParsed, census.runSteps,
		len(invocations), census.fromMakefile, census.fromWorkflows, census.pins, len(findings))

	// Пустой обход — поломка гейта, а не чистота дерева.
	if census.makefileRecipeLines == 0 {
		t.Fatal("строк рецепта прочитано ноль — обход беспредметен, и зелёное здесь означало бы " +
			"«ноль прочитанного», а не «ноль находок»")
	}
	if census.workflowFiles == 0 {
		t.Fatal("объявлений процессов не прочитано ни одного — вторая сторона сверки отсутствует")
	}

	for _, f := range findings {
		t.Error(f)
	}

	// Отдельно от находок: обе стороны обязаны ПРИСУТСТВОВАТЬ. Сверка, у которой
	// один операнд пуст, проходит тривиально — ровно тот вакуумный зелёный, ради
	// которого гейт и заведён.
	if census.fromMakefile == 0 {
		t.Error("в рецепте не найдено ни одного обращения к `" + qualityToolBinary + " " + qualityToolSubcommand +
			"` — сверять конвейер не с чем, и вердикт о согласии сторон беспредметен")
	}
	if census.fromWorkflows == 0 {
		t.Error("в объявлениях процессов не найдено ни одного обращения к `" + qualityToolBinary + " " +
			qualityToolSubcommand + "` — сверять рецепт не с чем, и вердикт о согласии сторон беспредметен")
	}
	if census.pins < 2 {
		t.Errorf("объявлений пина найдено %d — ось версии сверяет сторону саму с собой; "+
			"пин обязан быть назван И рецептом (переменная %s), И установочным шагом конвейера",
			census.pins, qualityPinVariable)
	}
}
