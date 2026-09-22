// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// alert_rules_delivered_test.go — правила тревоги ПОСТАВЛЯЮТСЯ ОБЪЕКТОМ, и
// объект не расходится с опубликованной страницей.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Восемь правил существовали ТЕКСТОМ страницы: тот, кто ставит продукт, их
// видел, а переносить в свою систему мониторинга должен был руками. Разница
// между «видит» и «действует» здесь не стилистическая: правило, которое надо
// перепечатать, не перепечатает никто, — и первым не сработает то, ради чего
// замер и делался. `KanameIdentityLedgerUnsampled` звонит на ОТСУТСТВИЕ
// события: там, где симптома ждать неоткуда, ручной перенос не случится
// никогда.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ОБЪЕКТ ВЫКЛЮЧАЕМ
//
// `PrometheusRule` — вид ЧУЖОГО оператора. В установке, где оператора
// Prometheus нет, объект отвергнет схема кластера, и отвергнет она ВСЮ
// установку, а не одну тревогу. Выключатель здесь не удобство: без него чарт
// перестал бы ставиться там, где ставился.
//
// Умолчание при этом `true`, и это осознанно обратное решение к «пусто — не
// сужаем»: правило, поставленное молча, звонит; правило, не поставленное молча,
// молчит — а молчание неотличимо от исправности.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ УТВЕРЖДАЕТСЯ
//
//	Р1  объект есть в рендере, и в нём есть правила — иначе поставка обещает
//	    то, чего не везёт;
//	Р2  набор объекта и набор страницы СОВПАДАЮТ, и сверяется это В ОБЕ
//	    СТОРОНЫ: два места об одном предмете разъезжаются молча, и разъезжается
//	    обычно то, которое читают чаще;
//	Р3  объект выключается ручкой, и выключенный НЕ ОСТАВЛЯЕТ СЛЕДА в рендере;
//	Р4  перепись печатается числами, и пустой обход роняет прогон.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ЭТА ПРОВЕРКА НЕ ЗАКРЫВАЕТ — сказано прямо
//
// Она судит СОВПАДЕНИЕ объекта со страницей, а не верность самих выражений.
// Что каждый названный ряд имеет производителя, держит соседняя проба
// (`TestObservabilityPagePromisesOnlyWhatTheServiceProduces`); что отбор внутри
// ряда называет живой контракт — `TestAlertSelectorsNameAContractTheTreeProduces`.
// Объект попадает в ИХ популяцию ЧЕРЕЗ совпадение, доказанное здесь: страница
// осмотрена обеими, а объект ей равен. Цепочка держится, пока зелены все три —
// и рвётся заметно, потому что рвётся она красным.
package deploy_test

import (
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

// publishedObservabilityPage — опубликованная страница относительно корня
// службы. Именно опубликованная: инженерные страницы сайт не служит, и у того,
// кто ставит продукт, их нет.
const publishedObservabilityPage = "docs/content/advanced/observability.mdx"

// alertRulesToggle — ручка, выключающая объект правил.
const alertRulesToggle = "alertRules.enabled"

// pageAlertBlockRe — блок кода страницы с правилами. Берётся блок, а не строки:
// имя `alert:` встречается и в прозе вокруг. Первая группа — ПОМЕТКА ПОСАДКИ
// на строке перед блоком (`<!-- posture: own -->`), вторая — тело блока.
//
// Пометка машинно читаемая намеренно: заголовок прозой распознаватель судил бы
// словом, а слово «own» стоит на странице и там, где посадка не при чём.
var pageAlertBlockRe = regexp.MustCompile("(?s)(?:<!-- posture: ([a-z]+) -->\n)?```yaml\n(.*?)```")

// posturedRules — правила страницы, разложенные по посадке: пустой ключ —
// правила, действующие на ЛЮБОЙ посадке.
type posturedRules map[string][]alertRule

// forPosture — что страница обещает установке названной посадки: общие
// правила плюс правила её полосы. Правила чужой посадки в обещание НЕ входят.
func (p posturedRules) forPosture(posture string) []alertRule {
	out := append([]alertRule{}, p[""]...)
	if posture != "" {
		out = append(out, p[posture]...)
	}
	return out
}

// alertRule — правило в том виде, в каком его сверяют две стороны.
type alertRule struct {
	Alert       string            `yaml:"alert"`
	Expr        string            `yaml:"expr"`
	For         string            `yaml:"for"`
	Annotations map[string]string `yaml:"annotations"`
}

// key — предмет сверки: имя, выражение, выдержка и текст для дежурного.
//
// Выражение нормализуется по пробелам НАМЕРЕННО: страница несёт его блочным
// скаляром с переносом и отступом, объект — тем же скаляром, но отступ у него
// свой. Различие отступа не является различием правила, а различие ТЕКСТА —
// является, и оно остаётся видимым.
func (r alertRule) key() string {
	return r.Alert + "\x00" + strings.Join(strings.Fields(r.Expr), " ") +
		"\x00" + r.For + "\x00" + r.Annotations["summary"]
}

// parseAlertRules разбирает последовательность правил из текста YAML.
func parseAlertRules(text string) ([]alertRule, error) {
	var out []alertRule
	if err := yaml.Unmarshal([]byte(text), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// pageAlertRules — правила, обещанные опубликованной страницей, по посадке.
func pageAlertRules(t *testing.T, root string) posturedRules {
	t.Helper()
	path := filepath.Join(root, publishedObservabilityPage)
	raw, err := os.ReadFile(path) // #nosec G304 -- путь из корня службы
	require.NoErrorf(t, err, "опубликованная страница не читается: %s", path)

	rules := posturedRules{}
	for _, m := range pageAlertBlockRe.FindAllStringSubmatch(string(raw), -1) {
		if !strings.Contains(m[2], "- alert:") {
			continue
		}
		parsed, perr := parseAlertRules(m[2])
		require.NoErrorf(t, perr, "блок правил страницы не разбирается как YAML: %s", path)
		rules[m[1]] = append(rules[m[1]], parsed...)
	}
	return rules
}

// identityPostureSet — ручка чарта, выбирающая посадку личности.
const identityPostureSet = "authn.identityProvider"

// postureOfProfiles — посадка, которую объявляет цепочка профилей; пусто —
// профиль посадки не объявляет.
func postureOfProfiles(t *testing.T, chain []string) string {
	t.Helper()
	v, _ := at(mergeChartProfiles(t, chain), "authn", "identityProvider").(string)
	return v
}

// alertRenders — что рендерится и под какой посадкой. ОБЕ полосы личности
// рендерятся явно, а не только та, что стоит в поставляемом профиле: правило
// чужой полосы, уехавшее не под свой выключатель, видно только на второй.
type alertRender struct {
	name    string
	chain   []string
	sets    []string
	posture string
}

func alertRenders(t *testing.T) []alertRender {
	t.Helper()
	prod := []string{"values.yaml", "values.prod.yaml"}
	dev := []string{"values.yaml", "values.dev.yaml"}
	return []alertRender{
		{name: "values.prod.yaml", chain: prod, posture: postureOfProfiles(t, prod)},
		{name: "values.dev.yaml", chain: dev, posture: postureOfProfiles(t, dev)},
		{name: "values.prod.yaml+own", chain: prod, sets: []string{identityPostureSet + "=own"}, posture: "own"},
		{name: "values.prod.yaml+external", chain: prod, sets: []string{identityPostureSet + "=external"}, posture: "external"},
	}
}

// chartAlertRules — правила, которые везёт объект, плюс сколько объектов найдено.
func chartAlertRules(t *testing.T, rendered string) (rules []alertRule, objects int) {
	t.Helper()
	dec := yaml.NewDecoder(strings.NewReader(rendered))
	for {
		var doc map[string]any
		if err := dec.Decode(&doc); err != nil {
			break
		}
		if doc == nil {
			continue
		}
		if kind, _ := doc["kind"].(string); kind != "PrometheusRule" {
			continue
		}
		objects++

		// Пересборка через YAML, а не ручной обход карт: форма правила
		// объявлена типом, и разбирать её вторым способом значило бы завести
		// второй разбор одного предмета.
		spec, _ := doc["spec"].(map[string]any)
		groups, _ := spec["groups"].([]any)
		for _, g := range groups {
			gm, _ := g.(map[string]any)
			raw, err := yaml.Marshal(gm["rules"])
			require.NoError(t, err, "правила объекта не пересобираются")
			parsed, perr := parseAlertRules(string(raw))
			require.NoError(t, perr, "правила объекта не разбираются")
			rules = append(rules, parsed...)
		}
	}
	return rules, objects
}

// diffRuleSets — что есть у одной стороны и нет у другой, в обе стороны.
func diffRuleSets(page, chart []alertRule) (onlyPage, onlyChart []string) {
	inChart := map[string]bool{}
	for _, r := range chart {
		inChart[r.key()] = true
	}
	inPage := map[string]bool{}
	for _, r := range page {
		inPage[r.key()] = true
	}
	for _, r := range page {
		if !inChart[r.key()] {
			onlyPage = append(onlyPage, r.Alert)
		}
	}
	for _, r := range chart {
		if !inPage[r.key()] {
			onlyChart = append(onlyChart, r.Alert)
		}
	}
	sort.Strings(onlyPage)
	sort.Strings(onlyChart)
	return onlyPage, onlyChart
}

// TestDeliveredAlertRulesMatchThePublishedPage — Р2 ПО ПОСАДКАМ (задача #210).
//
// Правило о хуках поставщика личности под посадкой `own` звонило бы вечно:
// хуков поставщика там нет by construction, тишина на них штатна, а порог,
// срабатывающий на штатном состоянии, перестают читать — и вместе с ним
// теряют настоящую тревогу под `external`. Поэтому набор правил ЗАВИСИТ от
// посадки: общие правила плюс правила своей полосы, и страница обещает
// ровно то, что объект везёт установке этой посадки.
//
// Сверяется в обе стороны на каждой из четырёх раскладок: два поставляемых
// профиля как есть и боевой профиль, явно переведённый на каждую из полос.
// Правило чужой полосы, уехавшее не под свой выключатель, видно только на
// второй полосе — поэтому обе рендерятся явно.
func TestDeliveredAlertRulesMatchThePublishedPage(t *testing.T) {
	root, err := surfaceroster.IAMRoot(".")
	require.NoError(t, err, "корень дерева службы")

	paged := pageAlertRules(t, root)
	require.NotEmpty(t, paged["own"], "страница не несёт ни одного правила полосы `own` — "+
		"тревога под этой посадкой не объявлена вовсе")
	require.NotEmpty(t, paged["external"], "страница не несёт ни одного правила полосы `external`")

	for _, r := range alertRenders(t) {
		t.Run(r.name, func(t *testing.T) {
			rendered := renderStandaloneChart(t, r.chain, r.sets...)
			chart, objects := chartAlertRules(t, rendered)
			page := paged.forPosture(r.posture)
			lane := 0
			if r.posture != "" {
				lane = len(paged[r.posture])
			}

			onlyPage, onlyChart := diffRuleSets(page, chart)

			t.Logf("ПЕРЕПИСЬ правил тревоги (%s, посадка %q):\n"+
				"  объектов правил %d · правил у объекта %d · правил на странице для посадки %d "+
				"(общих %d · полосы %d) · только на странице %d · только у объекта %d",
				r.name, r.posture, objects, len(chart), len(page), len(paged[""]), lane,
				len(onlyPage), len(onlyChart))

			// Предпосылка: обе стороны непусты. Пустая страница дала бы
			// совпадение с пустым объектом, и «расхождений ноль» означало бы
			// «сверять было нечего».
			require.NotZero(t, len(page), "опубликованная страница не несёт НИ ОДНОГО правила — "+
				"сверять нечего, вердикт беспредметен")
			require.Equalf(t, 1, objects, "объектов правил в рендере %d, а ожидается ровно один: "+
				"ноль означает, что поставка обещает страницей то, чего не везёт; больше одного — "+
				"что об одном предмете говорят два объекта", objects)
			require.NotZero(t, len(chart), "объект правил пуст — он есть, и он ничего не несёт")

			require.Emptyf(t, onlyPage, "страница обещает правила, которых объект НЕ ВЕЗЁТ: %s.\n"+
				"Тот, кто поставил продукт, прочтёт обещание и не получит тревоги",
				strings.Join(onlyPage, ", "))
			require.Emptyf(t, onlyChart, "объект везёт правила, которых на странице НЕТ: %s.\n"+
				"Тревога, о которой не написано, звонит дежурному без порядка разбора",
				strings.Join(onlyChart, ", "))
		})
	}
}

// TestAlertRulesObjectCanBeSwitchedOff — Р3: в установке без оператора
// Prometheus объект выключается, и выключенный не оставляет следа.
//
// Положительный контроль стоит рядом НАМЕРЕННО: без него утверждение
// «выключенный отсутствует» зеленело бы на чарте, где объекта нет вовсе.
func TestAlertRulesObjectCanBeSwitchedOff(t *testing.T) {
	on := renderStandaloneChart(t, chartProfiles)
	_, onObjects := chartAlertRules(t, on)
	require.Equal(t, 1, onObjects, "положительный контроль: при включённой ручке объект обязан быть — "+
		"иначе отрицание ниже беспредметно")

	off := renderStandaloneChart(t, chartProfiles, alertRulesToggle+"=false")
	offRules, offObjects := chartAlertRules(t, off)

	t.Logf("ПЕРЕПИСЬ выключателя: включено объектов %d · выключено объектов %d · правил при выключенном %d",
		onObjects, offObjects, len(offRules))

	require.Zerof(t, offObjects, "ручка %s=false объект НЕ убрала: в установке без оператора "+
		"Prometheus его отвергнет схема кластера — и отвергнет она всю установку, а не одну тревогу",
		alertRulesToggle)
	require.NotContains(t, off, "PrometheusRule",
		"выключенный объект оставил след в рендере — выключение обязано быть полным")
}

// TestSigningKeySweeperSilenceIsAlerted — ноль проходов сметателя выведенных
// ключей читается правилом тревоги как СИГНАЛ, а не как тишина (#314).
//
// Сметатель, переставший ходить, не отказывает — он молчит: выведенные ключи
// остаются в наборе дольше отсрочки, и ни одна проба положительного пути этого
// не видит. Поэтому предмет — правило, звонящее на ОТСУТСТВИЕ прохода, в
// объекте, который поставляет чарт, на каждой посадке. Совпадение объекта со
// страницей держит TestDeliveredAlertRulesMatchThePublishedPage, производителя
// ряда — TestAlertSelectorsNameAContractTheTreeProduces; здесь — только наличие.
func TestSigningKeySweeperSilenceIsAlerted(t *testing.T) {
	const series = `kaname_signing_key_events_total{event="swept"}`
	renders := alertRenders(t)
	require.NotEmpty(t, renders, "перепись посадок пуста — проверять нечего, это не зелёное")
	for _, r := range renders {
		t.Run(r.name, func(t *testing.T) {
			rules, objects := chartAlertRules(t, renderStandaloneChart(t, r.chain, r.sets...))
			require.Positive(t, objects, "объект правил не отрендерился — вердикта о правиле нет")
			var found []string
			for _, rule := range rules {
				expr := strings.Join(strings.Fields(rule.Expr), " ")
				if strings.Contains(expr, series) && strings.Contains(expr, "== 0") {
					found = append(found, rule.Alert)
				}
			}
			t.Logf("перепись: правил в объекте %d · звонящих на ноль проходов сметателя %d %v", len(rules), len(found), found)
			require.Len(t, found, 1, "ноль проходов сметателя обязан звонить ровно одним правилом")
		})
	}
}
