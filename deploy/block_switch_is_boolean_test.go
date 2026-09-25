// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// block_switch_is_boolean_test.go — ВЫКЛЮЧАТЕЛЬ БЛОКА ЧАРТА ПРИНИМАЕТ ТОЛЬКО
// БУЛЕВО ЗНАЧЕНИЕ, и правило об этом одно на все выключатели (задача #391).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Условие `if $x.enabled` судит ИСТИННОСТЬ значения, а не его булевость.
// Непустая строка истинна при любом тексте, поэтому `false`, поданное строкой
// (`--set-string`, `--set-literal`, `enabled: "false"` в накладке), включало
// блок, который оператор выключал. У блока токен-эндпоинта та же строка
// обходила и отказ «own без эндпоинта»: вместо него шла ветвь включённого.
//
// Правило одно — именованный шаблон `kaname-svc.blockEnabled`. Он читает
// выключатель по координате, принимает только булево значение и отвергает
// рендер на любом ином виде (строка, число, снятый ключ), называя координату
// и то, что пришло.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ ЕСТЬ
//
//	В1  (без helm) распознаватель шаблонов: выключатель читается ТОЛЬКО
//	    правилом. Любое иное чтение ключа `enabled` — находка с координатой
//	    файл:строка. Законные формы чтения, которые он знает: поле `.enabled`
//	    (у переменной, у `.Values…`, у точки), ключ-литерал `"enabled"`
//	    (`index`, `get`, `hasKey`, `dig`, `pluck`, `set`), точечный путь-литерал
//	    `"a.b.enabled"`. Вызов правила не в канонической форме — тоже находка:
//	    координату из него не вывести;
//	В2  (без helm) популяция выключателей выводится из умолчаний чарта обходом,
//	    а не выписывается, и сверяется с вызовами правила в обе стороны;
//	В3  (helm) по КАЖДОМУ выведенному выключателю — отказ рендера на каждом
//	    небулевом виде входа и рендер на каждом булевом; рендеры «включён» и
//	    «выключен» различаются, а блок карты настроек под `authn.` появляется
//	    ровно при включённом.
//
// В3 назван с приставки `TestProdProfile_Rendered`, поэтому его берёт полоса
// `deploy/render-guard.sh`; без helm и без объявленной полосы — пропуск
// третьей категорией, не зелёное.
package deploy_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// blockSwitchRule — имя правила; blockSwitchLeaf — ключ выключателя.
const (
	blockSwitchRule = "kaname-svc.blockEnabled"
	blockSwitchLeaf = "enabled"
	// blockSwitchRefusalMark — чем отказ ПРАВИЛА отличим от прочих отказов
	// рендера. Без него отказ «величины эндпоинта не названы», в чьём тексте
	// тоже стоит `authn.clientToken.enabled`, читался бы отказом правила.
	blockSwitchRefusalMark = "не булево значение"
)

// ── разбор шаблонов ──────────────────────────────────────────────────────────

// tplPiece — кусок действия шаблона: код либо строковый литерал.
type tplPiece struct {
	lit  bool
	text string // код дословно либо значение литерала
	line int    // строка файла, с которой кусок начинается
}

// tplAction — одно действие `{{ … }}`; комментарии в перечень не входят.
type tplAction struct {
	line   int
	pieces []tplPiece
}

// literals — значения литералов действия по порядку.
func (a tplAction) literals() []string {
	var out []string
	for _, p := range a.pieces {
		if p.lit {
			out = append(out, p.text)
		}
	}
	return out
}

// normalized — код действия, где каждый литерал заменён меткой `"@<номер>"`:
// форма вызова распознаётся по коду, и текст литерала её не подделает.
func (a tplAction) normalized() string {
	var b strings.Builder
	n := 0
	for _, p := range a.pieces {
		if p.lit {
			fmt.Fprintf(&b, `"@%d"`, n)
			n++
			continue
		}
		b.WriteString(p.text)
	}
	return b.String()
}

// source — действие с литералами в кавычках: так его и показывает находка.
func (a tplAction) source() string {
	var b strings.Builder
	for _, p := range a.pieces {
		if p.lit {
			b.WriteString(strconv.Quote(p.text))
			continue
		}
		b.WriteString(p.text)
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

// isTrimSpace — пробельный знак маркера обрезки (`{{- ` и ` -}}`).
func isTrimSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }

// scanTemplateActions делит исходник шаблона на действия по правилам лексера
// text/template: комментарий `{{/* … */}}` (с маркерами обрезки) действием не
// является; `}}` внутри строкового литерала действие не закрывает.
func scanTemplateActions(src string) (actions []tplAction, comments int, err error) {
	lineAt := func(pos int) int { return 1 + strings.Count(src[:pos], "\n") }
	i := 0
	for {
		k := strings.Index(src[i:], "{{")
		if k < 0 {
			return actions, comments, nil
		}
		start := i + k
		p := start + 2
		if p+1 < len(src) && src[p] == '-' && isTrimSpace(src[p+1]) {
			p += 2
		}
		if strings.HasPrefix(src[p:], "/*") {
			end := strings.Index(src[p+2:], "*/")
			if end < 0 {
				return nil, 0, fmt.Errorf("строка %d: комментарий не закрыт", lineAt(start))
			}
			r := p + 2 + end + 2
			switch {
			case strings.HasPrefix(src[r:], "}}"):
				r += 2
			case len(src) > r+3 && isTrimSpace(src[r]) && strings.HasPrefix(src[r+1:], "-}}"):
				r += 4
			default:
				return nil, 0, fmt.Errorf("строка %d: комментарий кончается раньше закрывающего разделителя", lineAt(start))
			}
			comments++
			i = r
			continue
		}

		act := tplAction{line: lineAt(start)}
		cs := p
		flush := func(to int) {
			if to > cs {
				act.pieces = append(act.pieces, tplPiece{text: src[cs:to], line: lineAt(cs)})
			}
		}
		j := p
		closed := false
		for j < len(src) && !closed {
			switch {
			case src[j] == '"' || src[j] == '\'':
				q := src[j]
				e := j + 1
				for e < len(src) && src[e] != q {
					if src[e] == '\\' {
						e++
					}
					if e < len(src) && src[e] == '\n' {
						return nil, 0, fmt.Errorf("строка %d: литерал не закрыт до конца строки", lineAt(j))
					}
					e++
				}
				if e >= len(src) {
					return nil, 0, fmt.Errorf("строка %d: литерал не закрыт", lineAt(j))
				}
				val := src[j+1 : e]
				if q == '"' {
					uq, uerr := strconv.Unquote(src[j : e+1])
					if uerr != nil {
						return nil, 0, fmt.Errorf("строка %d: литерал %s не разобран: %w", lineAt(j), src[j:e+1], uerr)
					}
					val = uq
				}
				flush(j)
				act.pieces = append(act.pieces, tplPiece{lit: true, text: val, line: lineAt(j)})
				cs = e + 1
				j = e + 1
			case src[j] == '`':
				e := strings.IndexByte(src[j+1:], '`')
				if e < 0 {
					return nil, 0, fmt.Errorf("строка %d: сырой литерал не закрыт", lineAt(j))
				}
				flush(j)
				act.pieces = append(act.pieces, tplPiece{lit: true, text: src[j+1 : j+1+e], line: lineAt(j)})
				cs = j + 1 + e + 1
				j = cs
			case strings.HasPrefix(src[j:], "}}"):
				to := j
				if to-2 >= cs && src[to-1] == '-' && isTrimSpace(src[to-2]) {
					to--
				}
				flush(to)
				closed = true
				i = j + 2
			default:
				j++
			}
		}
		if !closed {
			return nil, 0, fmt.Errorf("строка %d: действие не закрыто", lineAt(start))
		}
		actions = append(actions, act)
	}
}

// ── суд над шаблонами ────────────────────────────────────────────────────────

// switchCall — вызов правила: координата выключателя и место вызова.
type switchCall struct {
	coord string
	pos   string
}

// switchCensus — перепись обхода шаблонов. Предпосылки (`premise`) отделены от
// находок: «ни одной находки» на обходе без правила значило бы «ничего не
// прочитано», а не «всё читается правилом».
type switchCensus struct {
	files     int
	actions   int
	comments  int
	ruleDefs  []string
	ruleReads int
	calls     []switchCall
	findings  []string
	premise   []string
}

var (
	// Поле `.enabled` у чего угодно: переменной, `.Values…`, точки, скобки.
	fieldSwitchRe = regexp.MustCompile(`\.` + blockSwitchLeaf + `\b`)
	// Точечный путь-литерал, кончающийся выключателем: `"a.b.enabled"`.
	pathSwitchRe = regexp.MustCompile(`^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*\.` + blockSwitchLeaf + `$`)
	// Каноническая форма вызова: `include "<правило>" (list $ "<координата>")`.
	canonicalCallRe = regexp.MustCompile(`\binclude\s+"@(\d+)"\s+\(\s*list\s+\$\s+"@(\d+)"\s*\)`)
	// Координата — путь ключей значений в верблюжьем регистре.
	switchCoordRe  = regexp.MustCompile(`^[a-z][A-Za-z0-9]*(\.[a-z][A-Za-z0-9]*)*$`)
	openBlockRe    = regexp.MustCompile(`^(if|range|with|define|block)\b`)
	endBlockRe     = regexp.MustCompile(`^end\b`)
	switchDefineRe = regexp.MustCompile(`^(define|block)\s+"@0"`)
)

// judgeBlockSwitchTemplates обходит каталог шаблонов и судит каждое чтение
// выключателя. Перечень файлов берётся обходом, а не выписывается.
func judgeBlockSwitchTemplates(dir string) (switchCensus, error) {
	var c switchCensus
	entries, err := os.ReadDir(dir)
	if err != nil {
		return c, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		raw, rerr := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- путь из обхода каталога шаблонов
		if rerr != nil {
			return c, rerr
		}
		c.files++
		actions, comments, serr := scanTemplateActions(string(raw))
		if serr != nil {
			c.findings = append(c.findings, fmt.Sprintf("%s: шаблон не разобран — %v; чтений выключателя в нём не видно, и молчание было бы ложью", name, serr))
			continue
		}
		c.actions += len(actions)
		c.comments += comments
		judgeActions(&c, name, actions)
	}

	if c.files == 0 {
		c.premise = append(c.premise, fmt.Sprintf("обход шаблонов %s пуст — ни одного файла", dir))
	}
	if c.actions == 0 && c.files > 0 {
		c.premise = append(c.premise, "в шаблонах ни одного действия — разбор не видит кода")
	}
	if len(c.ruleDefs) != 1 {
		c.premise = append(c.premise, fmt.Sprintf("правило %q определено %d раз (%s) — судить «читается ли выключатель правилом» не по чему",
			blockSwitchRule, len(c.ruleDefs), strings.Join(c.ruleDefs, ", ")))
	}
	if len(c.ruleDefs) == 1 && c.ruleReads == 0 {
		c.premise = append(c.premise, fmt.Sprintf("правило %q определено, но ключа %q не читает — его вызовы судят не выключатель",
			blockSwitchRule, blockSwitchLeaf))
	}
	if len(c.calls) == 0 {
		c.premise = append(c.premise, fmt.Sprintf("ни одного вызова правила %q — популяция выключателей из шаблонов не выводится", blockSwitchRule))
	}
	return c, nil
}

// judgeActions судит действия одного файла; стек блоков нужен, чтобы отличить
// собственные чтения правила от чтений мимо него.
func judgeActions(c *switchCensus, file string, actions []tplAction) {
	var stack []string
	inRule := func() bool {
		for _, s := range stack {
			if s == blockSwitchRule {
				return true
			}
		}
		return false
	}
	for _, a := range actions {
		code := a.normalized()
		head := strings.TrimSpace(code)
		lits := a.literals()
		isRuleDef := false
		switch {
		case openBlockRe.MatchString(head):
			name := ""
			if switchDefineRe.MatchString(head) && len(lits) > 0 {
				name = lits[0]
			}
			if name == blockSwitchRule {
				isRuleDef = true
				c.ruleDefs = append(c.ruleDefs, fmt.Sprintf("%s:%d", file, a.line))
			}
			stack = append(stack, name)
		case endBlockRe.MatchString(head):
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
		own := inRule()

		read := func(line int, form string) {
			if own {
				c.ruleReads++
				return
			}
			c.findings = append(c.findings, fmt.Sprintf(
				"%s:%d: выключатель читается мимо правила — %s; истинность строки `\"false\"` включит блок. "+
					"Читайте его вызовом include %q (list $ \"<координата>\")", file, line, form, blockSwitchRule))
		}
		for _, p := range a.pieces {
			if p.lit {
				if p.text == blockSwitchLeaf {
					read(p.line, fmt.Sprintf("ключ-литерал %q", p.text))
				} else if pathSwitchRe.MatchString(p.text) {
					read(p.line, fmt.Sprintf("путь-литерал %q", p.text))
				}
				continue
			}
			for _, m := range fieldSwitchRe.FindAllStringIndex(p.text, -1) {
				read(p.line+strings.Count(p.text[:m[0]], "\n"), fmt.Sprintf("поле `.%s` в {{ %s }}", blockSwitchLeaf, a.source()))
			}
		}

		canonical := map[int]int{}
		for _, m := range canonicalCallRe.FindAllStringSubmatch(code, -1) {
			ruleIdx, _ := strconv.Atoi(m[1])
			coordIdx, _ := strconv.Atoi(m[2])
			canonical[ruleIdx] = coordIdx
		}
		for idx, v := range lits {
			if v != blockSwitchRule || (isRuleDef && idx == 0) {
				continue
			}
			coordIdx, ok := canonical[idx]
			if !ok {
				c.findings = append(c.findings, fmt.Sprintf(
					"%s:%d: вызов правила %q не в канонической форме include %q (list $ \"<координата>\") — "+
						"координату выключателя из него не вывести: {{ %s }}", file, a.line, blockSwitchRule, blockSwitchRule, a.source()))
				continue
			}
			coord := lits[coordIdx]
			if !switchCoordRe.MatchString(coord) {
				c.findings = append(c.findings, fmt.Sprintf(
					"%s:%d: координата %q вызова правила — не путь ключей значений", file, a.line, coord))
				continue
			}
			c.calls = append(c.calls, switchCall{coord: coord, pos: fmt.Sprintf("%s:%d", file, a.line)})
		}
	}
}

// ── популяция выключателей в значениях ───────────────────────────────────────

// switchesInValues выводит выключатели обходом дерева значений: каждый лист
// `enabled`. Булев лист — выключатель (его координата — путь родителя); иной
// вид — находка: правило отвергло бы такой профиль на рендере.
func switchesInValues(profile string, tree map[string]any) (coords []string, findings []string) {
	var walk func(path []string, node any)
	walk = func(path []string, node any) {
		switch n := node.(type) {
		case map[string]any:
			keys := make([]string, 0, len(n))
			for k := range n {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				v := n[k]
				if k == blockSwitchLeaf {
					coord := strings.Join(path, ".")
					if _, ok := v.(bool); ok && len(path) > 0 {
						coords = append(coords, coord)
					} else {
						findings = append(findings, fmt.Sprintf("%s: %s.%s = %#v — выключатель обязан быть булевым значением",
							profile, coord, blockSwitchLeaf, v))
					}
					continue
				}
				walk(append(append([]string{}, path...), k), v)
			}
		case []any:
			for i, v := range n {
				if m, ok := v.(map[string]any); ok {
					if _, has := m[blockSwitchLeaf]; has {
						findings = append(findings, fmt.Sprintf("%s: %s[%d].%s — выключатель внутри перечня координатой не адресуется",
							profile, strings.Join(path, "."), i, blockSwitchLeaf))
					}
				}
			}
		}
	}
	walk(nil, tree)
	return coords, findings
}

// shippedProfiles — профили, поставляемые рядом с чартом; выводятся обходом.
func shippedProfiles(t *testing.T, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "values*.yaml"))
	require.NoError(t, err)
	require.NotEmpty(t, files, "рядом с чартом ни одного профиля values*.yaml — обход пуст")
	sort.Strings(files)
	return files
}

// declaredBlockSwitches — выключатели из умолчаний чарта: только там объявлен
// каждый (правило отвергает снятый ключ, поэтому умолчание обязано быть).
func declaredBlockSwitches(t *testing.T) []string {
	t.Helper()
	coords, findings := switchesInValues(chartDefaultsFile, readChartProfile(t, chartDefaultsFile))
	require.Emptyf(t, findings, "умолчания чарта объявляют выключатель не булевым:\n%s", strings.Join(findings, "\n"))
	require.NotEmpty(t, coords, "в умолчаниях чарта ни одного выключателя `enabled` — обход пуст, "+
		"и «ни одного отказа» было бы неотличимо от «ни одного прочитанного»")
	return coords
}

// ── В1 + В2 ──────────────────────────────────────────────────────────────────

func TestBlockSwitchIsReadOnlyThroughTheBooleanRule(t *testing.T) {
	c, err := judgeBlockSwitchTemplates("templates")
	require.NoError(t, err)
	// Предпосылка и находки печатаются ВМЕСТЕ: на дереве без правила отказ
	// обязан назвать и отсутствие правила, и каждое чтение мимо него.
	if len(c.premise) > 0 || len(c.findings) > 0 {
		t.Fatalf("выключатель блока судится мимо правила.\nпредпосылка не выполнена — %d:\n%s\nнаходок %d:\n%s",
			len(c.premise), strings.Join(c.premise, "\n"), len(c.findings), strings.Join(c.findings, "\n"))
	}

	var profileFindings []string
	for _, f := range shippedProfiles(t, ".") {
		_, fs := switchesInValues(filepath.Base(f), readChartProfile(t, f))
		profileFindings = append(profileFindings, fs...)
	}
	require.Emptyf(t, profileFindings, "поставляемый профиль объявляет выключатель не булевым:\n%s",
		strings.Join(profileFindings, "\n"))

	declared := declaredBlockSwitches(t)
	called := map[string][]string{}
	for _, cl := range c.calls {
		called[cl.coord] = append(called[cl.coord], cl.pos)
	}
	var drift []string
	for _, d := range declared {
		if _, ok := called[d]; !ok {
			drift = append(drift, fmt.Sprintf("%s.%s объявлен умолчанием чарта, а правилом не читается ни разу", d, blockSwitchLeaf))
		}
	}
	isDeclared := map[string]bool{}
	for _, d := range declared {
		isDeclared[d] = true
	}
	for coord, pos := range called {
		if !isDeclared[coord] {
			drift = append(drift, fmt.Sprintf("%s (%s): правило читает %s.%s, которого нет в умолчаниях чарта — "+
				"рендер отказал бы на базовых значениях", strings.Join(pos, ", "), coord, coord, blockSwitchLeaf))
		}
	}
	sort.Strings(drift)
	require.Emptyf(t, drift, "выключатели умолчаний и вызовы правила разошлись:\n%s", strings.Join(drift, "\n"))

	t.Logf("перепись: файлов шаблонов %d · действий %d · комментариев %d · определений правила %d · "+
		"чтений внутри правила %d · вызовов правила %d · выключателей в умолчаниях %d (%s) · профилей %d · находок 0",
		c.files, c.actions, c.comments, len(c.ruleDefs), c.ruleReads, len(c.calls),
		len(declared), strings.Join(declared, ", "), len(shippedProfiles(t, ".")))
}

// ── В3 ───────────────────────────────────────────────────────────────────────

// blockSwitchCompanions — величины, без которых блок законно не рендерится в
// названном положении выключателя. Не перечень выключателей: запись без
// выключателя в умолчаниях — находка (самоистечение), выключатель без записи
// берёт пустые спутники.
var blockSwitchCompanions = map[string]struct{ on, off []string }{
	// Выключенный сбор обязан нести причину (`deployment.yaml`).
	"metricsScrape": {off: []string{"metricsScrape.disabledBecause=проба выключателя"}},
	// Включённый эндпоинт обязан нести четыре величины (`kaname-svc.requireClientTokenEndpoint`).
	"authn.clientToken": {on: clientTokenValueSets()},
}

// clientTokenValueSets — величины эндпоинта из накладки `own`, без самой
// посадки и без выключателя: у выключателя здесь своя ось.
func clientTokenValueSets() []string {
	var out []string
	for _, kv := range ownPostureOverlay {
		if strings.HasPrefix(kv, "authn.clientToken.") && !strings.HasPrefix(kv, clientTokenEnabledKnob+"=") {
			out = append(out, kv)
		}
	}
	return out
}

// helmTemplateArgs — `helm template` с произвольными аргументами: `--set` не
// умеет подать строку, а о строке этот вопрос и есть.
func helmTemplateArgs(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		if os.Getenv(renderGuardLaneEnv) != "" {
			t.Fatalf("helm не в PATH, а полоса рендера объявлена (%s задан): гейт обещал вердикт и дать его не может", renderGuardLaneEnv)
		}
		t.Skipf("helm не в PATH — вердикта НЕТ: третья категория, не зелёное и не красное (полоса %s)", renderGuardLaneEnv)
	}
	full := []string{"template", "kaname", dir, "--namespace", "kaname"}
	for _, f := range chartProfiles {
		full = append(full, "-f", filepath.Join(dir, f))
	}
	full = append(full, args...)
	out, err := exec.Command("helm", full...).CombinedOutput() // #nosec G204 -- фиксированный бинарь, аргументы из дерева и t.TempDir
	return string(out), err
}

// switchOverlay пишет накладку, задающую выключателю координаты значение
// дословным YAML: так вид входа задаёт автор файла, а не `--set`.
func switchOverlay(t *testing.T, coord, literal string) string {
	t.Helper()
	segs := strings.Split(coord, ".")
	var b strings.Builder
	for i, s := range segs {
		fmt.Fprintf(&b, "%s%s:\n", strings.Repeat("  ", i), s)
	}
	fmt.Fprintf(&b, "%s%s: %s\n", strings.Repeat("  ", len(segs)), blockSwitchLeaf, literal)
	file := filepath.Join(t.TempDir(), "switch.overlay.yaml")
	require.NoError(t, os.WriteFile(file, []byte(b.String()), 0o600))
	return file
}

// setsArgs — `--set` для спутников.
func setsArgs(sets []string) []string {
	var out []string
	for _, kv := range sets {
		out = append(out, "--set", kv)
	}
	return out
}

// kebabPath — ключ карты настроек для координаты значений (`tokenSigning` →
// `token-signing`): карта пишет сегменты через дефис.
func kebabPath(coord string) []string {
	segs := strings.Split(coord, ".")
	for i, s := range segs {
		var b strings.Builder
		for _, r := range s {
			if r >= 'A' && r <= 'Z' {
				b.WriteByte('-')
				b.WriteRune(r + ('a' - 'A'))
				continue
			}
			b.WriteRune(r)
		}
		segs[i] = b.String()
	}
	return segs
}

// renderedConfigTreeOf — дерево карты настроек из готового рендера; nil, если
// карты в рендере нет (об этом судит вызывающий).
func renderedConfigTreeOf(rendered string) map[string]any {
	dec := yaml.NewDecoder(strings.NewReader(rendered))
	for {
		var doc map[string]any
		if err := dec.Decode(&doc); err != nil {
			return nil
		}
		if doc["kind"] != "ConfigMap" {
			continue
		}
		data, _ := doc["data"].(map[string]any)
		body, _ := data["config.yaml"].(string)
		var tree map[string]any
		if yaml.Unmarshal([]byte(body), &tree) == nil {
			return tree
		}
	}
}

// blockSwitchRenderFindings судит один выключатель на чарте по пути dir:
// каждый небулев вид входа — отказ правила с координатой и видом пришедшего;
// каждый булев — рендер; положения различимы.
func blockSwitchRenderFindings(t *testing.T, dir, coord string) (findings []string, renders int) {
	t.Helper()
	knob := coord + "." + blockSwitchLeaf
	comp := blockSwitchCompanions[coord]

	refused := []struct {
		form string
		args []string
		got  string
	}{
		{"--set-string false", []string{"--set-string", knob + "=false"}, `string "false"`},
		{"--set-string true", []string{"--set-string", knob + "=true"}, `string "true"`},
		{"--set-literal false", []string{"--set-literal", knob + "=false"}, `string "false"`},
		{`накладка enabled: "false"`, []string{"-f", switchOverlay(t, coord, `"false"`)}, `string "false"`},
		{"накладка enabled: 0", []string{"-f", switchOverlay(t, coord, "0")}, "float64 0"},
		{"--set null (ключ снят)", []string{"--set", knob + "=null"}, "ключ не задан"},
	}
	for _, r := range refused {
		out, err := helmTemplateArgs(t, dir, r.args...)
		renders++
		switch {
		case err == nil:
			findings = append(findings, fmt.Sprintf("%s [%s]: рендер прошёл — небулев выключатель принят за положение блока", knob, r.form))
		case !strings.Contains(out, blockSwitchRefusalMark) || !strings.Contains(out, knob):
			findings = append(findings, fmt.Sprintf("%s [%s]: рендер отказал, но не правилом выключателя (нет %q и координаты):\n%s",
				knob, r.form, blockSwitchRefusalMark, headOf(out)))
		case !strings.Contains(out, r.got):
			findings = append(findings, fmt.Sprintf("%s [%s]: отказ правила не называет, что пришло (%s):\n%s",
				knob, r.form, r.got, headOf(out)))
		}
	}

	render := func(form string, args ...string) (string, bool) {
		out, err := helmTemplateArgs(t, dir, args...)
		renders++
		if err != nil {
			findings = append(findings, fmt.Sprintf("%s [%s]: булев выключатель отвергнут рендером:\n%s", knob, form, headOf(out)))
			return "", false
		}
		return out, true
	}
	off, okOff := render("--set false", append([]string{"--set", knob + "=false"}, setsArgs(comp.off)...)...)
	on, okOn := render("--set true", append([]string{"--set", knob + "=true"}, setsArgs(comp.on)...)...)
	if json, ok := render("--set-json false", append([]string{"--set-json", knob + "=false"}, setsArgs(comp.off)...)...); ok && okOff && json != off {
		findings = append(findings, fmt.Sprintf("%s: --set-json false рендерится иначе, чем --set false — один булев вход дал два рендера", knob))
	}
	if file, ok := render("накладка enabled: false", append([]string{"-f", switchOverlay(t, coord, "false")}, setsArgs(comp.off)...)...); ok && okOff && file != off {
		findings = append(findings, fmt.Sprintf("%s: накладка enabled: false рендерится иначе, чем --set false", knob))
	}
	if okOff && okOn {
		if on == off {
			findings = append(findings, fmt.Sprintf("%s: рендеры «включён» и «выключен» совпали — выключатель ничего не включает", knob))
		}
		if strings.HasPrefix(coord, "authn.") {
			block := kebabPath(coord)
			if at(renderedConfigTreeOf(on), block...) == nil {
				findings = append(findings, fmt.Sprintf("%s=true: блока %s в карте настроек нет", knob, strings.Join(block, ".")))
			}
			if at(renderedConfigTreeOf(off), block...) != nil {
				findings = append(findings, fmt.Sprintf("%s=false: блок %s в карте настроек есть", knob, strings.Join(block, ".")))
			}
		}
	}
	return findings, renders
}

func TestProdProfile_RenderedBlockSwitchRefusesEveryNonBooleanForm(t *testing.T) {
	declared := declaredBlockSwitches(t)
	isDeclared := map[string]bool{}
	for _, d := range declared {
		isDeclared[d] = true
	}
	var stale []string
	for coord := range blockSwitchCompanions {
		if !isDeclared[coord] {
			stale = append(stale, coord)
		}
	}
	sort.Strings(stale)
	require.Emptyf(t, stale, "записи спутников без выключателя в умолчаниях чарта — исключать им нечего: %v", stale)

	var all []string
	renders := 0
	for _, coord := range declared {
		f, n := blockSwitchRenderFindings(t, ".", coord)
		all = append(all, f...)
		renders += n
	}
	require.Emptyf(t, all, "выключатель блока судится истинностью, а не булевостью — находок %d:\n%s",
		len(all), strings.Join(all, "\n"))
	t.Logf("перепись: выключателей %d (%s) · рендеров %d · небулевых видов на выключатель 6 · булевых 4 · находок 0",
		len(declared), strings.Join(declared, ", "), renders)
}
