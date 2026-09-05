// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// schema_mechanism_precedes_the_service_test.go — у поставки ОБЯЗАН быть механизм
// создания схемы, и он обязан быть исполнимым и стоять раньше службы.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Чарт службы, вынесенной отдельным продуктом, ставит оператор ЧУЖОГО облака: у
// него нет ни зонтичного чарта, ни нашего рецепта стенда, ни шага `make`. Всё,
// что создаёт схему, обязано ехать В САМОМ ЧАРТЕ — иначе установка в пустой
// кластер даёт службу без базы, то есть продукт, который не поднимается.
//
// Механизм в дереве ЕСТЬ: init-контейнер, исполняющий отдельный binary
// `kacho-migrator`. Предмет этой пробы — не завести его, а УДЕРЖАТЬ: сегодня его
// не держит ничто. Снятие init-контейнера проходит молча — `helm template` и
// `helm lint` остаются зелёными, ни одна проба дерева не краснеет, а отказ
// приходит только в чужом кластере и только на первом обращении к таблице.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ОБЪЯВЛЕНИЕ, А НЕ РЕНДЕР
//
// Рендер требует `helm` на машине и `helm dep build` для чартов с зависимостями;
// проба, которой нужен инструмент, пропускается ровно там, где она нужна. Здесь
// читается ТЕКСТ ШАБЛОНА — то, что чарт объявляет.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ИСПОЛНИМАЯ ЧАСТЬ, А НЕ ПОДСТРОКА
//
// Шаблон iam называет binary ДВАЖДЫ: один раз в комментарии, объясняющем
// механизм, и один раз в `command:`. Проверка по подстроке осталась бы зелёной на
// чарте, где от механизма остался ОДИН КОММЕНТАРИЙ, — то есть краснела бы на
// собственном объяснении и молчала на снятой защите. Поэтому строки-комментарии
// отбрасываются до разбора, а судятся только значения ключей `command:`/`args:`.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ИМЕННО УТВЕРЖДАЕТСЯ, по каждому чарту службы с базой
//
//  1. МЕХАНИЗМ ЕСТЬ — в блоке `initContainers:` есть контейнер, чья пара
//     `command`+`args` называет путь мигратора;
//  2. ОН ИСПОЛНИМ — названный путь лежит среди назначений `COPY --from=…`
//     собственного Dockerfile службы. Ручка, называющая файл, которого образ не
//     несёт, есть объявленная и неисполнимая возможность: под уходит в
//     перезапуск, а профиль читается как настроенный;
//  3. ПОРЯДОК «СХЕМА РАНЬШЕ СЛУЖБЫ» ОБЪЯВЛЕН — мигратор стоит в `initContainers`,
//     а не среди `containers`. Это сильнейшая из доступных форм порядка: её
//     держит kubelet by construction, а не наше объявление;
//  4. ОБРАЗ МИГРАТОРА ПРОИЗВОДИТСЯ ЧАРТОМ — выражение образа несёт подстановку
//     (`{{ … }}`), а не прибитый литерал. Литерал увёл бы механизм на образ, в
//     котором мигратора нет, и снова молча;
//  5. МЕХАНИЗМ ВКЛЮЧЁН ПО УМОЛЧАНИЮ — если он обёрнут ручкой, ручка обязана
//     умалчивать `true`. Установка с умолчаниями в пустой кластер обязана
//     создавать схему; ручка, умалчивающая «выключено», даёт службу без схемы
//     тому, кто её values не читал.
//
// Пункт 5 НЕ запрещает саму ручку: накат схемы отдельным процессом под контролем
// администратора базы — законный производственный уклад. Запрещено умолчание,
// при котором поставка молча приезжает без схемы.
//
// ─────────────────────────────────────────────────────────────────────────────
// ГРАНИЦА ПРЕДМЕТА, НАЗВАННАЯ ЧЕСТНО
//
//   - Проверяется ОБЪЯВЛЕНИЕ, а не подъём. Что мигратор действительно применит
//     цепочку к живой базе, эта проба не утверждает и утверждать не может: базы
//     у неё нет и быть не должно.
//   - Не проверяется, что образ СОБРАН, — только что Dockerfile кладёт по
//     названному пути. Сборку держит конвейер.
//   - Не проверяется совместимость запущенного образа с применённой версией
//     схемы: такого стража в продукте нет. Это остаток, а не обещание, и он
//     назван здесь, чтобы «проба есть» не читалось как «предмет закрыт».
package deploy_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// migratorBinaryPath — путь, по которому чарт зовёт накат схемы. Одна величина на
// обе стороны сверки: и для поиска в объявлении чарта, и для сверки с
// назначениями Dockerfile.
const migratorBinaryPath = "/usr/local/bin/kacho-migrator"

// chartUnderTest — служба, чей чарт эта проба ОБЯЗАНА осмотреть. Проверка
// собственной предпосылки: обход, потерявший iam, дал бы зелёное о чужих чартах
// и молчание о том единственном, ради которого проба заведена.
const chartUnderTest = "iam"

// templateLine — строка шаблона вместе с её отступом и признаком комментария.
// Комментарий хранится, а не выбрасывается: перепись обязана назвать, сколько
// строк прочитано, включая те, что судить нельзя.
type templateLine struct {
	number    int
	indent    int
	text      string
	isComment bool
	isBlank   bool
}

// containerDecl — один объявленный контейнер: его имя, выражение образа и слитая
// пара `command`+`args`. Слитая намеренно: подкоманду наката один чарт держит в
// `command`, другой — в `args`, и распознаватель, знающий одну форму, объявил бы
// второй чарт лишённым механизма, ничего в нём не сломав.
type containerDecl struct {
	name       string
	image      string
	invocation []string
	line       int
}

// chartAudit — что осмотрено в одном чарте. Величины печатаются переписью: «ноль
// находок» обязано быть отличимо от «ноль прочитанного».
type chartAudit struct {
	service        string
	templateLines  int
	initItems      int
	serviceItems   int
	dockerfileDest int
}

// finding — находка с координатой. Координата обязательна: находка, называющая
// симптом без места, посылает читателя искать не там.
type finding struct {
	service string
	where   string
	what    string
}

func (f finding) String() string {
	return fmt.Sprintf("%s: %s — %s", f.service, f.where, f.what)
}

var (
	// reQuoted вынимает элементы объявленного массива `["a", "b"]`.
	reQuoted = regexp.MustCompile(`"([^"]*)"`)
	// reCopyFrom читает назначение слоевого копирования. Источник намеренно не
	// связан: один Dockerfile кладёт binary из корня, другой — из промежуточного
	// каталога, и оба законны. Ключ выравнивают пробелами — их тоже не связываем.
	reCopyFrom = regexp.MustCompile(`^\s*COPY\s+--from=\S+\s+(\S+)\s+(\S+)\s*$`)
	// reGuard читает ручку, которой обёрнут механизм.
	reGuard = regexp.MustCompile(`\{\{-?\s*if\s+\.Values\.([A-Za-z0-9_.]+)\s*-?\}\}`)
)

// readTemplateLines размечает шаблон по строкам. Строка считается комментарием,
// когда её первый непробельный знак — решётка: судить её нельзя, считать нужно.
func readTemplateLines(raw string) []templateLine {
	out := []templateLine{}
	for i, s := range strings.Split(raw, "\n") {
		trimmed := strings.TrimLeft(s, " ")
		line := templateLine{
			number:    i + 1,
			indent:    len(s) - len(trimmed),
			text:      s,
			isComment: strings.HasPrefix(trimmed, "#"),
			isBlank:   strings.TrimSpace(s) == "",
		}
		out = append(out, line)
	}
	return out
}

// blockBody возвращает тело блока с названным ключом: строки, лежащие глубже
// самого ключа. Строки управления шаблоном на уровне ключа тело закрывают — так
// же, как их видит helm.
func blockBody(lines []templateLine, key string) ([]templateLine, int, bool) {
	want := key + ":"
	for i, l := range lines {
		if l.isComment || l.isBlank || strings.TrimSpace(l.text) != want {
			continue
		}
		body := []templateLine{}
		for _, b := range lines[i+1:] {
			if b.isBlank || b.isComment {
				body = append(body, b)
				continue
			}
			if b.indent <= l.indent {
				break
			}
			body = append(body, b)
		}
		return body, l.number, true
	}
	return nil, 0, false
}

// splitContainers режет тело блока на объявленные контейнеры. Элементом считается
// строка `- name:` на наименьшем встреченном отступе: имена внутри `env:` и
// `volumeMounts:` лежат глубже и элементами не становятся.
func splitContainers(body []templateLine) []containerDecl {
	itemIndent := -1
	for _, l := range body {
		if l.isBlank || l.isComment {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(l.text), "- name:") {
			if itemIndent == -1 || l.indent < itemIndent {
				itemIndent = l.indent
			}
		}
	}
	if itemIndent == -1 {
		return nil
	}

	out := []containerDecl{}
	var cur *containerDecl
	flush := func() {
		if cur != nil {
			out = append(out, *cur)
			cur = nil
		}
	}
	for _, l := range body {
		if l.isBlank || l.isComment {
			continue
		}
		trimmed := strings.TrimSpace(l.text)
		if l.indent == itemIndent && strings.HasPrefix(trimmed, "- name:") {
			flush()
			cur = &containerDecl{
				name: strings.TrimSpace(strings.TrimPrefix(trimmed, "- name:")),
				line: l.number,
			}
			continue
		}
		if cur == nil || l.indent <= itemIndent {
			continue
		}
		switch {
		case strings.HasPrefix(trimmed, "image:"):
			if cur.image == "" {
				cur.image = strings.TrimSpace(strings.TrimPrefix(trimmed, "image:"))
			}
		case strings.HasPrefix(trimmed, "command:"), strings.HasPrefix(trimmed, "args:"):
			for _, m := range reQuoted.FindAllStringSubmatch(trimmed, -1) {
				cur.invocation = append(cur.invocation, m[1])
			}
		}
	}
	flush()
	return out
}

// namesMigrator отвечает, зовёт ли объявленный контейнер накат схемы.
func namesMigrator(c containerDecl) bool {
	for _, a := range c.invocation {
		if a == migratorBinaryPath {
			return true
		}
	}
	return false
}

// dockerfileDestinations собирает пути, по которым образ службы что-либо кладёт.
func dockerfileDestinations(raw string) []string {
	out := []string{}
	for _, s := range strings.Split(raw, "\n") {
		if m := reCopyFrom.FindStringSubmatch(s); m != nil {
			out = append(out, m[2])
		}
	}
	return out
}

// guardAbove ищет ручку, которой обёрнут блок: до трёх значащих строк выше него.
func guardAbove(lines []templateLine, blockLine int) (string, bool) {
	seen := 0
	for i := blockLine - 2; i >= 0 && seen < 3; i-- {
		l := lines[i]
		if l.isBlank || l.isComment {
			continue
		}
		seen++
		if m := reGuard.FindStringSubmatch(l.text); m != nil {
			return m[1], true
		}
	}
	return "", false
}

// valueIsTrue разрешает точечный путь в values.yaml и отвечает, умалчивает ли он
// истину.
func valueIsTrue(values map[string]any, path string) bool {
	var cur any = values
	for _, seg := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return false
		}
		cur, ok = m[seg]
		if !ok {
			return false
		}
	}
	b, ok := cur.(bool)
	return ok && b
}

// auditSchemaMechanism осматривает все чарты служб под названным корнем. Корень
// параметр, а не константа: тем же кодом судит и настоящее дерево, и внесённый
// дефект во временной копии — иначе доказательство способности упасть проверяло
// бы не то, что исполняется.
func auditSchemaMechanism(root string) ([]chartAudit, []finding, error) {
	valuePaths, err := filepath.Glob(filepath.Join(root, "services", "*", "deploy", "values.yaml"))
	if err != nil {
		return nil, nil, err
	}
	sort.Strings(valuePaths)

	audits := []chartAudit{}
	findings := []finding{}

	for _, vp := range valuePaths {
		chartDir := filepath.Dir(vp)
		service := filepath.Base(filepath.Dir(chartDir))

		rawValues, err := os.ReadFile(vp)
		if err != nil {
			return nil, nil, err
		}
		var values map[string]any
		if err := yaml.Unmarshal(rawValues, &values); err != nil {
			return nil, nil, fmt.Errorf("%s: values.yaml не разбирается: %w", service, err)
		}
		// Чарт без базы механизма наката не требует: требовать его значило бы
		// заводить находку там, где предмета нет.
		if _, hasDB := values["db"]; !hasDB {
			continue
		}

		audit := chartAudit{service: service}
		tmplPath := filepath.Join(chartDir, "templates", "deployment.yaml")
		rawTmpl, err := os.ReadFile(tmplPath)
		if err != nil {
			findings = append(findings, finding{
				service: service,
				where:   tmplPath,
				what:    "чарт объявляет базу, но шаблона развёртывания не несёт — механизму наката негде быть",
			})
			audits = append(audits, audit)
			continue
		}

		lines := readTemplateLines(string(rawTmpl))
		audit.templateLines = len(lines)

		dfPath := filepath.Join(root, "services", service, "Dockerfile")
		rawDF, err := os.ReadFile(dfPath)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: Dockerfile не прочитан: %w", service, err)
		}
		dests := dockerfileDestinations(string(rawDF))
		audit.dockerfileDest = len(dests)

		initBody, initLine, hasInit := blockBody(lines, "initContainers")
		serviceBody, _, hasService := blockBody(lines, "containers")
		initItems := splitContainers(initBody)
		serviceItems := splitContainers(serviceBody)
		audit.initItems = len(initItems)
		audit.serviceItems = len(serviceItems)
		audits = append(audits, audit)

		// (3) Порядок: накат, попавший в служебные контейнеры, исполняется
		// ОДНОВРЕМЕННО со службой, а не раньше неё.
		for _, c := range serviceItems {
			if namesMigrator(c) {
				findings = append(findings, finding{
					service: service,
					where:   fmt.Sprintf("%s:%d", tmplPath, c.line),
					what:    "накат схемы объявлен среди containers — порядок «схема раньше службы» не объявлен: контейнеры пода стартуют одновременно",
				})
			}
		}

		if !hasInit {
			findings = append(findings, finding{
				service: service,
				where:   tmplPath,
				what:    "блока initContainers нет — механизма создания схемы у поставки не осталось",
			})
			continue
		}
		if !hasService {
			findings = append(findings, finding{
				service: service,
				where:   tmplPath,
				what:    "блока containers нет — шаблон не объявляет служебного контейнера",
			})
		}

		// (1) Механизм есть — судится исполнимая часть, не проза.
		var migrator *containerDecl
		for i := range initItems {
			if namesMigrator(initItems[i]) {
				migrator = &initItems[i]
				break
			}
		}
		if migrator == nil {
			findings = append(findings, finding{
				service: service,
				where:   fmt.Sprintf("%s:%d", tmplPath, initLine),
				what: fmt.Sprintf("ни один init-контейнер не зовёт %s — механизма создания схемы нет "+
					"(упоминание в комментарии механизмом не является)", migratorBinaryPath),
			})
			continue
		}

		// (2) Он исполним — путь производится собственным образом службы.
		produced := false
		for _, d := range dests {
			if d == migratorBinaryPath {
				produced = true
				break
			}
		}
		if !produced {
			findings = append(findings, finding{
				service: service,
				where:   fmt.Sprintf("%s:%d", tmplPath, migrator.line),
				what: fmt.Sprintf("чарт зовёт %s, а %s по этому пути ничего не кладёт (назначений прочитано %d) — "+
					"объявленная и неисполнимая возможность", migratorBinaryPath, dfPath, len(dests)),
			})
		}

		// (4) Образ производится чартом, а не прибит литералом.
		if !strings.Contains(migrator.image, "{{") {
			shown := strings.Trim(migrator.image, `"`)
			findings = append(findings, finding{
				service: service,
				where:   fmt.Sprintf("%s:%d", tmplPath, migrator.line),
				what: fmt.Sprintf("образ наката задан литералом %q — механизм уведён с образа службы, "+
					"и мигратора в нём может не быть", shown),
			})
		}

		// (5) Механизм включён по умолчанию.
		if key, wrapped := guardAbove(lines, initLine); wrapped && !valueIsTrue(values, key) {
			findings = append(findings, finding{
				service: service,
				where:   fmt.Sprintf("%s:%d", tmplPath, initLine),
				what: fmt.Sprintf("механизм обёрнут ручкой .Values.%s, а она не умалчивает true — "+
					"установка с умолчаниями даёт службу без схемы", key),
			})
		}
	}

	return audits, findings, nil
}

func TestSchemaMechanismPrecedesTheService(t *testing.T) {
	root := filepath.Join("..", "..", "..")

	audits, findings, err := auditSchemaMechanism(root)
	if err != nil {
		t.Fatalf("обход не состоялся: %v", err)
	}

	// Пустой обход — не зелёное. Проба, ничего не прочитавшая, обязана падать:
	// иначе «ноль находок» неотличимо от «ноль прочитанного».
	if len(audits) == 0 {
		t.Fatalf("осмотрено 0 чартов служб с базой — обход беспредметен, вердикт недействителен")
	}

	// Проверка собственной предпосылки: обход, потерявший чарт, ради которого
	// проба заведена, дал бы зелёное о чужих чартах.
	sawChartUnderTest := false
	for _, a := range audits {
		if a.service == chartUnderTest {
			sawChartUnderTest = true
		}
	}
	if !sawChartUnderTest {
		t.Fatalf("чарта %q среди осмотренных нет — предпосылка пробы не выполнена", chartUnderTest)
	}

	totalLines, totalInit, totalService, totalDest := 0, 0, 0, 0
	for _, a := range audits {
		totalLines += a.templateLines
		totalInit += a.initItems
		totalService += a.serviceItems
		totalDest += a.dockerfileDest
		t.Logf("осмотрено: %s — строк шаблона %d, init-контейнеров %d, служебных контейнеров %d, назначений Dockerfile %d",
			a.service, a.templateLines, a.initItems, a.serviceItems, a.dockerfileDest)
	}
	t.Logf("перепись: чартов с базой %d, строк шаблонов %d, init-контейнеров %d, служебных контейнеров %d, назначений Dockerfile %d, находок %d",
		len(audits), totalLines, totalInit, totalService, totalDest, len(findings))

	if len(findings) > 0 {
		msgs := make([]string, 0, len(findings))
		for _, f := range findings {
			msgs = append(msgs, f.String())
		}
		sort.Strings(msgs)
		t.Fatalf("механизм создания схемы не удержан, находок %d:\n  %s",
			len(findings), strings.Join(msgs, "\n  "))
	}
}
