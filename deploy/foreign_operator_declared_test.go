// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// foreign_operator_declared_test.go — ЧАРТ НЕ СОЗДАЁТ У АРЕНДАТОРА НИ ОДНОГО
// ОБЪЕКТА, О КОТОРОМ НЕ СКАЗАНО НА СТРАНИЦЕ УСТАНОВКИ; а объект, чей вид
// заводит ЧУЖОЙ оператор, назван вместе с оператором, ручкой и умолчанием.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Чарт везёт `PrometheusRule` — вид ЧУЖОГО оператора, и умолчание ручки —
// включено. В кластере, где оператора нет, схема отвергает объект и отвергает
// вместе с ним ВСЮ установку, а не одну тревогу:
//
//	Error: INSTALLATION FAILED: unable to build kubernetes objects from release
//	manifest: resource mapping not found for name: "kaname" ... no matches for
//	kind "PrometheusRule" in version "monitoring.coreos.com/v1"
//	ensure CRDs are installed first
//
// Отказ приходит от БИБЛИОТЕКИ: он не называет ни ручки, которой это
// выключается, ни того, что надо поставить, — то есть НЕ ВОССТАНАВЛИВАЕТ
// следующий шаг. Требование при этом стояло на странице наблюдаемости, куда
// ставящий продукт не заходит, а таблица зависимостей страницы установки
// перечисляла четыре зависимости и оператора среди них НЕ НАЗЫВАЛА.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ОТКАЗ ПРОДУКТА ВМЕСТО ОТКАЗА СХЕМЫ ОТВЕРГНУТ — ЗАМЕРОМ, А НЕ ВКУСОМ
//
// Единственное, что исполняется РАНЬШЕ отказа схемы, — рендер шаблона: сам
// текст отказа выше есть обёртка helm вокруг сборки манифеста, а хуки, поды и
// страж старта живут ПОСЛЕ неё. Значит отказ продукта выразим только через
// `.Capabilities.APIVersions.Has` + `fail`, и цена этого измерена здесь же
// (helm v4.2.4, пробный чарт, `TestCapabilitiesCannotTellAbsenceFromNoCluster`):
//
//	`helm template` без кластера            → `false` ВСЕГДА
//	`helm template --api-versions <группа>` → `true`
//
// То есть отказ сработал бы у КАЖДОГО, кто рендерит без кластера, — и у нас, и у
// арендатора, читающего свой релиз `helm template` либо собирающего его
// конвейером GitOps. Мы утверждали бы про ЕГО кластер то, чего не спрашивали.
// Отличить «оператора нет» от «спросить не у кого» шаблону НЕЧЕМ: `KubeVersion`
// вне кластера отдаёт вшитое в helm значение, неотличимое от настоящего
// кластера той же версии.
//
// Своя цена измерена своим предикатом, а не взята у соседа: файлов этого
// каталога, рендерящих чарт БЕЗ кластера, — 17 (2026-09-10,
// `grep -l -E 'renderStandaloneChart\(|renderChartAt' services/iam/deploy/*_test.go | wc -l`).
// Число ОРИЕНТИР: оно растёт с каждой новой пробой рендера и стареет молча —
// поэтому рядом стоит предикат, а не память.
//
// Ложный отказ на верной установке хуже истинного отказа библиотеки, поэтому
// выбран исход «сказать словами» — и сказанное СВЯЗАНО с деревом этим гейтом.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ УТВЕРЖДАЕТСЯ
//
//	Р1  чарт рендерится и объекты у него есть — иначе «необъявленных 0»
//	    означало бы «прочитано 0»;
//	Р2  КАЖДЫЙ объект рендера назван в таблице страницы, и назван с тем же
//	    `apiVersion`, что у него в рендере;
//	Р3  у КАЖДОЙ строки таблицы есть ПРЕДМЕТ — объект, который чарт правда
//	    везёт. Строка, которой больше нечего описывать, — находка: она
//	    унаследует следующую слепую зону;
//	Р4  умолчание ручки, НАЗВАННОЕ страницей, равно умолчанию в профиле —
//	    два места об одном предмете иначе разъедутся молча;
//	Р5  СРЕДСТВО, которое страница даёт, РАБОТАЕТ: названная ручка с названным
//	    значением убирает объект из рендера. Средство, не помогающее, хуже
//	    отсутствующего — по нему арендатор решит, что дело не в операторе.
//	    Положительный контроль к этому отрицанию даёт Р3: строка без объекта в
//	    рендере уже находка, значит «объекта нет» здесь не может зеленеть на
//	    чарте, где его нет вовсе;
//	Р6  оператор, названный в таблице объектов, назван и в таблице зависимостей
//	    рантайма — там, куда ставящий продукт смотрит ПЕРВЫМ делом;
//	Р7  перепись печатается числами, и пустой обход роняет прогон.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ЭТА ПРОВЕРКА НЕ РАЗЛИЧАЕТ — сказано прямо
//
// Кластера у неё нет. Она НЕ утверждает, что установка в кластере без оператора
// отказывает именно этим текстом, что оператор по названному имени существует и
// что его определение принимает наши выражения, — это решает живой прогон
// полосы кластера, и только он. Она судит СОГЛАСИЕ трёх мест дерева: рендера
// чарта, профиля и опубликованной страницы.
//
// Классификатор «свой вид / чужой» она НЕ содержит намеренно: перечень
// встроенных групп был бы вторым местом об одном предмете рядом с
// `deploy/iam_chart_foreign_kinds_established_test.go` модуля платформы.
// Разделение объявляет САМА страница, и потому оно проверяемо: объект,
// не названный ни своим, ни чужим, — находка.
package deploy_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kaname/tools/surfaceroster"
)

// installPageRel — ОПУБЛИКОВАННАЯ страница установки относительно корня службы.
// Именно опубликованная: инженерные страницы сайт не служит, и у того, кто
// ставит продукт, их нет.
const installPageRel = "docs/content/install/deploy.mdx"

// objectsTableHeader — шапка таблицы объектов. Якорь берётся по шапке, а не по
// заголовку раздела: заголовок правят ради читаемости, шапка же есть контракт
// между страницей и этим гейтом.
const objectsTableHeader = "| Объект | `apiVersion` | Вид заводит | Выключается |"

// clusterServesItself — отметка строки, чей вид кластер служит САМ.
const clusterServesItself = "кластер сам"

// runtimeDependenciesHeading — раздел, куда смотрит ставящий продукт первым.
const runtimeDependenciesHeading = "## Зависимости рантайма"

// noKnobCell — содержимое колонки «Выключается» у строки своего вида.
const noKnobCell = "—"

// switchCellRe — колонка «Выключается» строки ЧУЖОГО вида: ручка со значением,
// которым объект снимается, и умолчание этой ручки.
var switchCellRe = regexp.MustCompile("^`([A-Za-z0-9_.]+)=([A-Za-z0-9]+)` \\(умолчание — `([A-Za-z0-9]+)`\\)$")

// backtickedRe — содержимое первых обратных кавычек ячейки.
var backtickedRe = regexp.MustCompile("`([^`]+)`")

// chartObject — объект, который чарт создаёт у арендатора.
type chartObject struct {
	Kind       string
	APIVersion string
}

// pageRow — строка таблицы объектов страницы установки.
type pageRow struct {
	Kind        string
	APIVersion  string
	Provider    string
	Foreign     bool
	Knob        string
	RemedyValue string
	Default     string
}

// installPageText — текст опубликованной страницы установки.
func installPageText(t *testing.T, root string) string {
	t.Helper()
	path := filepath.Join(root, installPageRel)
	raw, err := os.ReadFile(path) // #nosec G304 -- путь из корня службы
	require.NoErrorf(t, err, "опубликованная страница установки не читается: %s", path)
	return string(raw)
}

// firstBackticked — содержимое первых обратных кавычек ячейки.
func firstBackticked(cell string) string {
	m := backtickedRe.FindStringSubmatch(cell)
	if m == nil {
		return ""
	}
	return m[1]
}

// plainCell — ячейка без разметки выделения.
func plainCell(cell string) string {
	return strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(cell, "**", ""), "`", ""))
}

// splitRow — ячейки строки таблицы.
func splitRow(line string) []string {
	parts := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// installPageRows разбирает таблицу объектов страницы установки.
//
// Возвращает и findings: строка, разобранная не до конца, — находка, а не
// пропуск. Молча пропущенная строка вывела бы объект из-под наблюдения, и
// «необъявленных 0» стало бы означать «не разобрано».
func installPageRows(page string) (rows []pageRow, findings []string) {
	lines := strings.Split(page, "\n")
	start := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == objectsTableHeader {
			start = i
			break
		}
	}
	if start < 0 {
		return nil, []string{fmt.Sprintf(
			"на странице установки НЕТ таблицы объектов: ожидалась шапка\n  %s\n"+
				"Без неё арендатор не знает, что появится в его пространстве имён и что "+
				"из этого требует чужого оператора", objectsTableHeader)}
	}

	for _, l := range lines[start+2:] {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "|") {
			break
		}
		cells := splitRow(l)
		if len(cells) != 4 {
			findings = append(findings, fmt.Sprintf(
				"строка таблицы объектов разобрана в %d ячейки вместо четырёх: %q", len(cells), l))
			continue
		}
		row := pageRow{
			Kind:       firstBackticked(cells[0]),
			APIVersion: firstBackticked(cells[1]),
			Provider:   plainCell(cells[2]),
		}
		if row.Kind == "" || row.APIVersion == "" || row.Provider == "" {
			findings = append(findings, fmt.Sprintf(
				"строка таблицы объектов не называет вида, apiVersion либо того, кто вид заводит: %q", l))
			continue
		}
		row.Foreign = row.Provider != clusterServesItself
		switch {
		case !row.Foreign:
			if cells[3] != noKnobCell {
				findings = append(findings, fmt.Sprintf(
					"вид %s служит кластер сам, а колонка «Выключается» несёт %q вместо %q: "+
						"ручка у встроенного вида обещает выбор, которого нет",
					row.Kind, cells[3], noKnobCell))
				continue
			}
		default:
			m := switchCellRe.FindStringSubmatch(cells[3])
			if m == nil {
				findings = append(findings, fmt.Sprintf(
					"вид %s заводит %s, а колонка «Выключается» не называет ручки со значением и "+
						"умолчанием: %q. Ожидается форма `ручка=значение` (умолчание — `значение`) — "+
						"без неё арендатору нечего сделать, прочитав требование",
					row.Kind, row.Provider, cells[3]))
				continue
			}
			row.Knob, row.RemedyValue, row.Default = m[1], m[2], m[3]
		}
		rows = append(rows, row)
	}
	return rows, findings
}

// renderedChartObjects — объекты, которые чарт создаёт у арендатора.
func renderedChartObjects(t *testing.T, rendered string) []chartObject {
	t.Helper()
	var out []chartObject
	seen := map[chartObject]bool{}
	forEachDoc(t, rendered, func(doc map[string]any) {
		kind, _ := doc["kind"].(string)
		api, _ := doc["apiVersion"].(string)
		if kind == "" || api == "" {
			return
		}
		o := chartObject{Kind: kind, APIVersion: api}
		if seen[o] {
			return
		}
		seen[o] = true
		out = append(out, o)
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Kind < out[j].Kind })
	return out
}

// judgeDeclaration — само суждение, в ОБЕ стороны: объект без строки и строка
// без объекта одинаково находки.
func judgeDeclaration(rows []pageRow, objects []chartObject) []string {
	var findings []string

	byKind := map[string]pageRow{}
	for _, r := range rows {
		byKind[r.Kind] = r
	}
	rendered := map[string]string{}
	for _, o := range objects {
		rendered[o.Kind] = o.APIVersion
	}

	var undeclared []string
	for _, o := range objects {
		r, ok := byKind[o.Kind]
		if !ok {
			undeclared = append(undeclared, fmt.Sprintf("%s (%s)", o.Kind, o.APIVersion))
			continue
		}
		if r.APIVersion != o.APIVersion {
			findings = append(findings, fmt.Sprintf(
				"страница называет вид %s как %s, а чарт создаёт его как %s: "+
					"группа вида решает, кто его заводит, и по неверной арендатор поставит не то",
				o.Kind, r.APIVersion, o.APIVersion))
		}
	}
	sort.Strings(undeclared)
	if len(undeclared) > 0 {
		findings = append(findings, fmt.Sprintf(
			"чарт создаёт объекты, которых страница установки НЕ НАЗЫВАЕТ: %s.\n"+
				"Ставящий продукт не узнает ни что появится в его пространстве имён, ни того, "+
				"что вид чужой: без определения вида схема отвергает ВСЮ установку, а её отказ "+
				"не называет ни ручки, ни того, что надо поставить",
			strings.Join(undeclared, ", ")))
	}

	var stale []string
	for _, r := range rows {
		if _, ok := rendered[r.Kind]; !ok {
			stale = append(stale, r.Kind)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		findings = append(findings, fmt.Sprintf(
			"страница называет объекты, которых чарт БОЛЬШЕ НЕ СОЗДАЁТ: %s — "+
				"строке нечего описывать, и она унаследует следующую слепую зону",
			strings.Join(stale, ", ")))
	}
	return findings
}

// knobDefaultInProfile — умолчание ручки в профиле, по точечному пути.
func knobDefaultInProfile(valuesBody, dotted string) (string, bool, error) {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(valuesBody), &doc); err != nil {
		return "", false, fmt.Errorf("профиль не разбирается как YAML: %w", err)
	}

	var cur any = doc
	for _, seg := range strings.Split(dotted, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", false, nil
		}
		cur, ok = m[seg]
		if !ok {
			return "", false, nil
		}
	}
	return fmt.Sprintf("%v", cur), true, nil
}

// judgeForeignRow — суждение о строке ЧУЖОГО вида: оператор назван там, куда
// ставящий смотрит первым; ручка есть в профиле; умолчание страницы равно
// умолчанию профиля.
//
// Отдельной функцией, а не строками теста: доказательство способности гейта
// упасть зовёт её же, и подать ей вход настоящим деревом нельзя, не внеся
// дефект в поставку.
func judgeForeignRow(r pageRow, deps, valuesBody string) []string {
	var findings []string
	if !strings.Contains(deps, r.Provider) {
		findings = append(findings, fmt.Sprintf(
			"вид %s заводит %s, и в таблице зависимостей рантайма этого оператора НЕТ.\n"+
				"Ставящий продукт читает зависимости, а не таблицу объектов ниже: требование, "+
				"названное только там, он увидит уже после отказа установки",
			r.Kind, r.Provider))
	}
	got, ok, err := knobDefaultInProfile(valuesBody, r.Knob)
	switch {
	case err != nil:
		findings = append(findings, err.Error())
	case !ok:
		findings = append(findings, fmt.Sprintf(
			"страница называет ручку %s, которой в профиле НЕТ: арендатор выполнит "+
				"средство и не получит ничего", r.Knob))
	case got != r.Default:
		findings = append(findings, fmt.Sprintf(
			"страница называет умолчанием ручки %s значение %q, а профиль несёт %q — "+
				"два места об одном предмете разошлись, и разошлось то, которое читает арендатор",
			r.Knob, r.Default, got))
	}
	return findings
}

// judgeRemedyWorks — СРЕДСТВО, которое страница даёт, обязано работать: ручка с
// названным значением убирает объект из рендера.
//
// Средство, не помогающее, хуже отсутствующего: по нему арендатор решит, что
// дело не в операторе, и пойдёт искать причину не там.
func judgeRemedyWorks(r pageRow, off []chartObject) []string {
	var findings []string
	for _, o := range off {
		if o.Kind != r.Kind {
			continue
		}
		findings = append(findings, fmt.Sprintf(
			"страница советует %s=%s, чтобы снять %s, — и объект ОСТАЁТСЯ в рендере: "+
				"арендатор выполнит совет, получит тот же отказ схемы и решит, "+
				"что дело не в операторе",
			r.Knob, r.RemedyValue, r.Kind))
	}
	return findings
}

// sectionText — текст раздела страницы от его заголовка до следующего.
func sectionText(page, heading string) string {
	i := strings.Index(page, heading)
	if i < 0 {
		return ""
	}
	rest := page[i+len(heading):]
	if j := strings.Index(rest, "\n## "); j >= 0 {
		return rest[:j]
	}
	return rest
}

func TestEveryObjectTheChartCreatesIsDeclaredOnTheInstallPage(t *testing.T) {
	root, err := surfaceroster.IAMRoot(".")
	require.NoError(t, err, "корень дерева службы")

	page := installPageText(t, root)
	rows, parseFindings := installPageRows(page)
	require.Emptyf(t, parseFindings, "таблица объектов страницы установки не разобрана:\n  - %s",
		strings.Join(parseFindings, "\n  - "))
	require.NotEmpty(t, rows, "таблица объектов страницы установки ПУСТА — "+
		"сверять нечего, и «необъявленных 0» означало бы «прочитано 0»")

	valuesBody, err := os.ReadFile("values.yaml")
	require.NoError(t, err, "профиль умолчаний чарта")

	// Раздел, куда ставящий продукт смотрит первым, читается ДО следующего
	// заголовка: иначе «оператор назван в зависимостях» зеленело бы от той самой
	// таблицы ниже, расхождение с которой Р6 и стережёт.
	deps := sectionText(page, runtimeDependenciesHeading)
	require.NotEmpty(t, deps, "на странице установки нет раздела %q — "+
		"требование чужого оператора некуда положить", runtimeDependenciesHeading)

	// ── Р4 и Р6: оператор назван в зависимостях, умолчание сходится ─────────
	foreign := 0
	var profileFindings []string
	for _, r := range rows {
		if !r.Foreign {
			continue
		}
		foreign++
		profileFindings = append(profileFindings, judgeForeignRow(r, deps, string(valuesBody))...)
	}
	require.Emptyf(t, profileFindings, "страница установки и профиль расходятся, находок %d:\n  - %s",
		len(profileFindings), strings.Join(profileFindings, "\n  - "))

	for _, profile := range []string{"values.prod.yaml", "values.dev.yaml"} {
		t.Run(profile, func(t *testing.T) {
			profiles := []string{"values.yaml", profile}
			rendered := renderStandaloneChart(t, profiles)
			objects := renderedChartObjects(t, rendered)

			// ── Р1: обход непуст ────────────────────────────────────────────
			require.NotEmpty(t, objects, "чарт не создал НИ ОДНОГО объекта — "+
				"обход пуст, и вердикт беспредметен")

			findings := judgeDeclaration(rows, objects)

			// ── Р5: средство страницы РАБОТАЕТ ──────────────────────────────
			for _, r := range rows {
				if !r.Foreign {
					continue
				}
				off := renderStandaloneChart(t, profiles, r.Knob+"="+r.RemedyValue)
				findings = append(findings, judgeRemedyWorks(r, renderedChartObjects(t, off))...)
			}

			// ── Р7: перепись ────────────────────────────────────────────────
			t.Logf("ПЕРЕПИСЬ объектов поставки (%s):\n"+
				"  объектов рендера %d · строк страницы %d · из них чужих видов %d · находок %d",
				profile, len(objects), len(rows), foreign, len(findings))

			require.Emptyf(t, findings, "страница установки и чарт расходятся, находок %d:\n  - %s",
				len(findings), strings.Join(findings, "\n  - "))
		})
	}
}
