// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// posture_knob_has_one_address_test.go — У РУЧЕК СТРАЖА ПОСАДКИ ОДИН АДРЕС:
// КЛЮЧ ЗНАЧЕНИЙ ЧАРТА. Окружение пода их не несёт (задача #392).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Страж шаблона `kaname-svc.requireClientTokenEndpoint` судит посадку `own` и
// токен-эндпоинт по ключам значений (`authn.identityProvider`,
// `authn.clientToken.*`). Окружение пода отдаётся процессу как есть, а
// переменная перекрывает файл настроек. Поэтому посадка, объявленная
// переменной `KANAME_AUTHN__IDENTITY_PROVIDER=own` без эндпоинта, проходила
// рендер, и отказ приходил только от стража старта, уже в кластере.
//
// ВЫБРАН ВТОРОЙ ВАРИАНТ ЗАДАЧИ: окружение не может нести ручку стража, и отказ
// рендера называет каноническую координату. Довод: судить «обе формы» значило
// бы повторить в шаблоне правило старшинства процесса (переменная перекрывает
// файл) — второе место об одном предмете, и не одно: посадку читают ещё карта
// настроек и правила тревоги. Один адрес разойтись с собой не может.
//
// Класс, а не экземпляр: ручек у стража шесть (посадка, выключатель
// эндпоинта и четыре его величины), и каждая обходит отказ рендера одинаково.
// Популяция берётся у таблицы стража старта (`config.RequiredSettings`), а
// источники окружения пода — обходом дерева разбора шаблона развёртывания:
// всякий `range $k, $v := <адрес карты>`, чей ключ становится `name:`
// переменной, в любой законной форме адреса; адрес, который обход не выводит,
// — отказ с координатой, а не пропуск (`podEnvSources`).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ ЕСТЬ
//
//	Р1  (без helm) источники окружения выведены обходом, и страж шаблона
//	    называет в своём перечне ровно популяцию таблицы — в обе стороны;
//	Р2  (helm) предикат задачи: `env.KANAME_AUTHN__IDENTITY_PROVIDER=own` без
//	    эндпоинта — отказ рендера с канонической координатой;
//	Р3  (helm) близнец одним фактом: накладка `own` с эндпоинтом рендерится,
//	    а та же накладка, где посадка перенесена в окружение, — отказ;
//	Р4  (helm) класс: каждая ручка × каждый источник окружения — отказ с именем
//	    источника и канонической координатой; все сразу — один перечень;
//	    соседняя ручка той же полосы в окружении — рендер.
package deploy_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"text/template/parse"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// postureGuardHelper — страж шаблона, чьи ручки судятся.
const postureGuardHelper = "kaname-svc.requireClientTokenEndpoint"

// postureShadowMark — чем отказ ЭТОГО правила отличим от прочих отказов.
const postureShadowMark = "ручки стража посадки"

// postureGuardRow — ручка стража: переменная процесса и ключ значений чарта.
type postureGuardRow struct {
	env   string
	knob  string
	value string
}

// postureGuardRows — популяция у таблицы стража старта: посадка и все ручки
// токен-эндпоинта. Не выписывается: новая строка таблицы попадает сюда сама.
func postureGuardRows(t *testing.T) []postureGuardRow {
	t.Helper()
	var rows []postureGuardRow
	for _, s := range config.RequiredSettings {
		if s.Key != config.IdentityProviderSetting && !strings.HasPrefix(s.Key, "authn.client-token.") {
			continue
		}
		require.NotEmptyf(t, s.Env, "строка таблицы %s без переменной — источника в окружении у неё нет", s.Key)
		rows = append(rows, postureGuardRow{env: s.Env, knob: valuesKeyOf(s.Key), value: s.Sample})
	}
	require.NotEmpty(t, rows, "в таблице стража старта нет ни посадки, ни ручек эндпоинта — обход пуст")
	sort.Slice(rows, func(i, j int) bool { return rows[i].env < rows[j].env })
	return rows
}

var (
	// envNameKeyRe — строка текста перед действием, дающим имя переменной:
	// поле `name` элемента перечня `env`, первым полем элемента либо нет, с
	// открытой кавычкой либо без.
	envNameKeyRe = regexp.MustCompile(`^(-\s+)?name:\s*["']?$`)
	envNameRe    = regexp.MustCompile(`^KANAME_[A-Z0-9_]+$`)
)

// tplValue — что обход шаблона знает о значении выражения: множество путей от
// корня данных шаблона, откуда значение может прийти. known=false — значение
// распознавателю неизвестно; known и пустое множество — постоянная шаблона
// (`dict`, литерал), в значениях у неё адреса нет.
type tplValue struct {
	known bool
	paths [][]string
}

var unknownValue = tplValue{}

// field — значение поля (цепочки полей) каждого из путей.
func (v tplValue) field(idents ...string) tplValue {
	if !v.known {
		return unknownValue
	}
	out := tplValue{known: true}
	for _, p := range v.paths {
		out.paths = append(out.paths, append(append([]string{}, p...), idents...))
	}
	return out
}

// union — значение, приходящее из любого из двух выражений.
func (v tplValue) union(w tplValue) tplValue {
	if !v.known || !w.known {
		return unknownValue
	}
	return tplValue{known: true, paths: append(append([][]string{}, v.paths...), w.paths...)}
}

// tplScope — точка и переменные в месте шаблона. Переменные — указатели:
// присваивание `$x = …` во вложенной структуре меняет ту же переменную, а
// объявление `$x := …` заводит новую до `end` своей структуры.
type tplScope struct {
	dot  tplValue
	vars map[string]*tplValue
}

func (s tplScope) child(dot tplValue) tplScope {
	vars := make(map[string]*tplValue, len(s.vars))
	for k, v := range s.vars {
		vars[k] = v
	}
	return tplScope{dot: dot, vars: vars}
}

func (s tplScope) declare(pipe *parse.PipeNode, v tplValue) {
	if pipe == nil {
		return
	}
	for _, d := range pipe.Decl {
		if pipe.IsAssign {
			if cur := s.vars[d.Ident[0]]; cur != nil {
				*cur = cur.union(v)
				continue
			}
		}
		nv := v
		s.vars[d.Ident[0]] = &nv
	}
}

// podEnvSourceWalk — обход дерева разбора шаблона развёртывания.
type podEnvSourceWalk struct {
	src   string
	tree  *parse.Tree
	found map[string]bool
}

// podEnvSources выводит карты значений, чьи КЛЮЧИ становятся именами
// переменных окружения пода. Шаблон читается разбором text/template — тем же,
// которым его исполняет helm, — а не образцом строки.
//
// Признак источника стоит в ТЕЛЕ `range $k, $v := …`: действие после `name:`
// элемента перечня ссылается на переменную ключа. Адрес карты выводится из
// выражения `range` в любой законной форме: поле от точки корня, от `$`, от
// переменной, которой присвоен корень либо карта, в скобках, поле цепочки,
// `index`/`get`, `default`, точка и поле точки внутри `with` (перечень форм с
// пробой на каждую — `lawfulPodEnvSourceForms`). Адрес, который распознаватель
// не выводит, — ОШИБКА с координатой, а не пропуск: пропуск и был дефектом
// (опыты 392e и 392f проверяющего), потому что источник, не попавший в
// перепись, суд теней не судит вовсе.
func podEnvSources(src string) ([]string, error) {
	const name = "deployment.yaml"
	tr := parse.New(name)
	tr.Mode = parse.SkipFuncCheck
	set := map[string]*parse.Tree{}
	if _, err := tr.Parse(src, "{{", "}}", set); err != nil {
		return nil, fmt.Errorf("шаблон развёртывания не разобран: %w", err)
	}
	root := tplValue{known: true, paths: [][]string{{}}}
	w := &podEnvSourceWalk{src: src, tree: tr, found: map[string]bool{}}
	if err := w.walk(tr.Root, tplScope{dot: root, vars: map[string]*tplValue{"$": &root}}); err != nil {
		return nil, err
	}
	// Внутри define точка и `$` — аргумент шаблона, а не корень данных.
	defs := make([]string, 0, len(set))
	for n := range set {
		defs = append(defs, n)
	}
	sort.Strings(defs)
	for _, n := range defs {
		def := set[n]
		if n == name || def.Root == nil {
			continue
		}
		dw := &podEnvSourceWalk{src: src, tree: def, found: w.found}
		unknown := unknownValue
		if err := dw.walk(def.Root, tplScope{dot: unknownValue, vars: map[string]*tplValue{"$": &unknown}}); err != nil {
			return nil, err
		}
	}
	out := make([]string, 0, len(w.found))
	for s := range w.found {
		out = append(out, s)
	}
	sort.Strings(out)
	return out, nil
}

func (w *podEnvSourceWalk) walk(n parse.Node, s tplScope) error {
	switch x := n.(type) {
	case *parse.ListNode:
		if x == nil {
			return nil
		}
		for _, c := range x.Nodes {
			if err := w.walk(c, s); err != nil {
				return err
			}
		}
	case *parse.ActionNode:
		if len(x.Pipe.Decl) > 0 {
			s.declare(x.Pipe, resolvePipe(x.Pipe, s))
		}
	case *parse.IfNode:
		base := s.child(s.dot)
		base.declare(x.Pipe, resolvePipe(x.Pipe, s))
		if err := w.walk(x.List, base.child(s.dot)); err != nil {
			return err
		}
		return w.walk(x.ElseList, base.child(s.dot))
	case *parse.WithNode:
		v := resolvePipe(x.Pipe, s)
		base := s.child(s.dot)
		base.declare(x.Pipe, v)
		if err := w.walk(x.List, base.child(v)); err != nil {
			return err
		}
		return w.walk(x.ElseList, base.child(s.dot))
	case *parse.RangeNode:
		if err := w.judgeRange(x, s); err != nil {
			return err
		}
		base := s.child(s.dot)
		base.declare(x.Pipe, unknownValue)
		if err := w.walk(x.List, base.child(unknownValue)); err != nil {
			return err
		}
		return w.walk(x.ElseList, base.child(s.dot))
	}
	return nil
}

// judgeRange — источник ли range и какой: ключ становится именем переменной —
// адрес карты обязан быть выведен.
func (w *podEnvSourceWalk) judgeRange(r *parse.RangeNode, s tplScope) error {
	if len(r.Pipe.Decl) != 2 || !w.namesByVar(r.List, r.Pipe.Decl[0].Ident[0]) {
		return nil
	}
	v := resolvePipe(r.Pipe, s)
	var sources []string
	for _, p := range v.paths {
		if len(p) < 2 || p[0] != "Values" {
			v = unknownValue
			break
		}
		sources = append(sources, strings.Join(p[1:], "."))
	}
	if !v.known {
		loc, _ := w.tree.ErrorContext(r)
		return fmt.Errorf("%s: ключ карты становится именем переменной окружения пода, а адрес карты распознаватель не выводит — "+
			"`range %s`. Пропустить молча нельзя: источник вне переписи суд теней не судит вовсе; научите распознаватель "+
			"этой форме (lawfulPodEnvSourceForms) либо запишите источник формой из перечня", loc, r.Pipe)
	}
	for _, src := range sources {
		w.found[src] = true
	}
	return nil
}

// namesByVar — даёт ли тело имя переменной окружения переменной key: действие
// после `name:` ссылается на неё. Структура, объявившая key заново, её затеняет.
func (w *podEnvSourceWalk) namesByVar(list *parse.ListNode, key string) bool {
	if list == nil {
		return false
	}
	for _, n := range list.Nodes {
		switch x := n.(type) {
		case *parse.ActionNode:
			if declares(x.Pipe, key) {
				return false
			}
			if len(x.Pipe.Decl) == 0 && mentionsVar(x.Pipe, key) && w.afterNameKey(int(x.Pos)) {
				return true
			}
		case *parse.IfNode:
			if w.namesByVar(x.List, key) || w.namesByVar(x.ElseList, key) {
				return true
			}
		case *parse.WithNode:
			if !declares(x.Pipe, key) && (w.namesByVar(x.List, key) || w.namesByVar(x.ElseList, key)) {
				return true
			}
		case *parse.RangeNode:
			if !declares(x.Pipe, key) && (w.namesByVar(x.List, key) || w.namesByVar(x.ElseList, key)) {
				return true
			}
		}
	}
	return false
}

// afterNameKey — стоит ли действие, чей код начинается в pos, сразу после
// `name:` в своей строке исходника.
func (w *podEnvSourceWalk) afterNameKey(pos int) bool {
	open := strings.LastIndex(w.src[:pos], "{{")
	if open < 0 {
		return false
	}
	before := w.src[:open]
	return envNameKeyRe.MatchString(strings.TrimSpace(before[strings.LastIndexByte(before, '\n')+1:]))
}

func declares(pipe *parse.PipeNode, key string) bool {
	if pipe == nil || pipe.IsAssign {
		return false
	}
	for _, d := range pipe.Decl {
		if d.Ident[0] == key {
			return true
		}
	}
	return false
}

// mentionsVar — ссылается ли выражение на переменную key где угодно внутри.
func mentionsVar(n parse.Node, key string) bool {
	switch x := n.(type) {
	case *parse.PipeNode:
		if x == nil {
			return false
		}
		for _, c := range x.Cmds {
			if mentionsVar(c, key) {
				return true
			}
		}
	case *parse.CommandNode:
		for _, a := range x.Args {
			if mentionsVar(a, key) {
				return true
			}
		}
	case *parse.VariableNode:
		return x.Ident[0] == key
	case *parse.ChainNode:
		return mentionsVar(x.Node, key)
	}
	return false
}

// resolvePipe — значение конвейера: первая команда, затем каждая следующая
// с результатом предыдущей последним аргументом.
func resolvePipe(p *parse.PipeNode, s tplScope) tplValue {
	if p == nil || len(p.Cmds) == 0 {
		return unknownValue
	}
	v := resolveCommand(p.Cmds[0], nil, s)
	for _, c := range p.Cmds[1:] {
		prev := v
		v = resolveCommand(c, &prev, s)
	}
	return v
}

// resolveCommand знает функции, которые сохраняют адрес карты: `default`
// (значение — любой из двух операндов), `index`/`get` (поле по литералу),
// `dict`/`list` без операндов-значений (постоянная). Прочие — неизвестное
// значение, и вызывающий обязан отказать, а не пропустить.
func resolveCommand(c *parse.CommandNode, piped *tplValue, s tplScope) tplValue {
	if len(c.Args) == 0 {
		return unknownValue
	}
	id, isFunc := c.Args[0].(*parse.IdentifierNode)
	if !isFunc {
		if piped != nil || len(c.Args) != 1 {
			return unknownValue
		}
		return resolveArg(c.Args[0], s)
	}
	var ops []tplValue
	for _, a := range c.Args[1:] {
		ops = append(ops, resolveArg(a, s))
	}
	if piped != nil {
		ops = append(ops, *piped)
	}
	switch id.Ident {
	case "default":
		if len(ops) == 2 {
			return ops[0].union(ops[1])
		}
	case "index", "get":
		if piped != nil || len(c.Args) < 3 || (id.Ident == "get" && len(c.Args) != 3) {
			return unknownValue
		}
		var keys []string
		for _, a := range c.Args[2:] {
			k, ok := a.(*parse.StringNode)
			if !ok {
				return unknownValue
			}
			keys = append(keys, k.Text)
		}
		return ops[0].field(keys...)
	case "dict", "list":
		// Постоянная — только из постоянных операндов: карта, собранная из
		// значений, несёт их адрес, и её форма здесь не выводится.
		if all := (tplValue{known: true}).unionAll(ops); piped == nil && all.known && len(all.paths) == 0 {
			return all
		}
	}
	return unknownValue
}

// unionAll — объединение значений; нужно, чтобы отличить постоянную от
// значения, несущего адрес.
func (v tplValue) unionAll(ws []tplValue) tplValue {
	for _, w := range ws {
		v = v.union(w)
	}
	return v
}

func resolveArg(n parse.Node, s tplScope) tplValue {
	switch x := n.(type) {
	case *parse.FieldNode:
		return s.dot.field(x.Ident...)
	case *parse.DotNode:
		return s.dot
	case *parse.VariableNode:
		b := s.vars[x.Ident[0]]
		if b == nil {
			return unknownValue
		}
		return b.field(x.Ident[1:]...)
	case *parse.PipeNode:
		if len(x.Decl) > 0 {
			return unknownValue
		}
		return resolvePipe(x, s)
	case *parse.ChainNode:
		return resolveArg(x.Node, s).field(x.Field...)
	case *parse.StringNode, *parse.NumberNode, *parse.BoolNode, *parse.NilNode:
		return tplValue{known: true}
	case *parse.IdentifierNode:
		if x.Ident == "dict" || x.Ident == "list" {
			return tplValue{known: true}
		}
	}
	return unknownValue
}

// guardEnvRoster — перечень ручек в теле стража шаблона: пары литералов
// «переменная → ключ значений» его словаря.
func guardEnvRoster(src string) (map[string]string, error) {
	actions, _, err := scanTemplateActions(src)
	if err != nil {
		return nil, err
	}
	roster := map[string]string{}
	depth := -1
	for _, a := range actions {
		code := strings.TrimSpace(a.normalized())
		lits := a.literals()
		switch {
		case depth < 0:
			if switchDefineRe.MatchString(code) && len(lits) > 0 && lits[0] == postureGuardHelper {
				depth = 0
			}
			continue
		case openBlockRe.MatchString(code):
			depth++
		case endBlockRe.MatchString(code):
			if depth == 0 {
				return roster, nil
			}
			depth--
		}
		for i := 0; i+1 < len(lits); i++ {
			if envNameRe.MatchString(lits[i]) {
				roster[lits[i]] = lits[i+1]
				i++
			}
		}
	}
	return roster, nil
}

// ── Р1 ───────────────────────────────────────────────────────────────────────

// judgePostureGuardRoster сверяет перечень стража шаблона в каталоге dir с
// таблицей стража старта в обе стороны и выводит источники окружения пода.
func judgePostureGuardRoster(t *testing.T, dir string) (drift, sources []string, roster map[string]string) {
	t.Helper()
	deployment, err := os.ReadFile(filepath.Join(dir, "deployment.yaml")) // #nosec G304 -- путь из дерева чарта либо t.TempDir
	require.NoError(t, err)
	sources, err = podEnvSources(string(deployment))
	require.NoError(t, err)
	require.NotEmpty(t, sources, "в шаблоне развёртывания не найдено ни одной карты, дающей имя переменной — "+
		"обход пуст, и «ни одной тени» было бы неотличимо от «ни одного прочитанного источника»")

	helpers, err := os.ReadFile(filepath.Join(dir, "_helpers.tpl")) // #nosec G304 -- путь из дерева чарта либо t.TempDir
	require.NoError(t, err)
	roster, err = guardEnvRoster(string(helpers))
	require.NoError(t, err)

	want := map[string]bool{}
	for _, r := range postureGuardRows(t) {
		want[r.env] = true
		switch got, ok := roster[r.env]; {
		case !ok:
			drift = append(drift, fmt.Sprintf("%s (ручка %s) не значится в перечне стража %s — переменная обойдёт отказ рендера",
				r.env, r.knob, postureGuardHelper))
		case got != r.knob:
			drift = append(drift, fmt.Sprintf("%s: страж называет координатой %q, таблица стража старта — %q", r.env, got, r.knob))
		}
	}
	for env := range roster {
		if !want[env] {
			drift = append(drift, fmt.Sprintf("%s в перечне стража %s, а в таблице стража старта ручкой посадки не значится — "+
				"отказ без предмета", env, postureGuardHelper))
		}
	}
	sort.Strings(drift)
	return drift, sources, roster
}

func TestPostureGuardNamesEveryShadowOfItsKnobs(t *testing.T) {
	drift, sources, roster := judgePostureGuardRoster(t, "templates")
	require.Emptyf(t, drift, "перечень стража шаблона и таблица стража старта разошлись:\n%s", strings.Join(drift, "\n"))
	t.Logf("перепись: источников окружения пода %d (%s) · ручек стража в таблице %d · в перечне шаблона %d",
		len(sources), strings.Join(sources, ", "), len(postureGuardRows(t)), len(roster))
}

// ── helm: общая часть Р2–Р4 ──────────────────────────────────────────────────

// shadowSets — `--set`, кладущие ручку в названный источник окружения. У
// `secrets` значение — ссылка на объект Secret, иначе рендер отказал бы
// раньше и не тем.
func shadowSets(source string, r postureGuardRow) []string {
	if source == "secrets" {
		return []string{
			fmt.Sprintf("secrets.%s.secretName=kaname-authn", r.env),
			fmt.Sprintf("secrets.%s.secretKey=%s", r.env, strings.ToLower(r.env)),
		}
	}
	return []string{fmt.Sprintf("%s.%s=%s", source, r.env, strings.ReplaceAll(r.value, ",", `\,`))}
}

// ── Р2 ───────────────────────────────────────────────────────────────────────

func TestChartRefusesOwnPostureDeclaredThroughThePodEnvironment(t *testing.T) {
	out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, "env.KANAME_AUTHN__IDENTITY_PROVIDER=own")
	requireRenderRefusal(t, out, err, postureShadowMark, "env.KANAME_AUTHN__IDENTITY_PROVIDER", identityProviderKnob)
}

// ── Р3 ───────────────────────────────────────────────────────────────────────

func TestOwnPostureOverlayMovedIntoTheEnvironmentIsRefused(t *testing.T) {
	_, err := renderChartAtAllowingFailure(t, ".", chartProfiles, ownPostureOverlay...)
	require.NoError(t, err, "близнец: накладка `own` ключами значений обязана рендериться — иначе отказ ниже ничего не доказал бы")

	moved := []string{"env.KANAME_AUTHN__IDENTITY_PROVIDER=own"}
	for _, kv := range ownPostureOverlay {
		if !strings.HasPrefix(kv, identityProviderKnob+"=") {
			moved = append(moved, kv)
		}
	}
	require.Len(t, moved, len(ownPostureOverlay), "перенос изменил не ровно один факт")
	out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, moved...)
	requireRenderRefusal(t, out, err, postureShadowMark, "env.KANAME_AUTHN__IDENTITY_PROVIDER", identityProviderKnob)
}

// ── Р4 ───────────────────────────────────────────────────────────────────────

// postureShadowFindings судит чарт по пути dir: каждая ручка стража в каждом
// источнике окружения — отказ правила тени с источником и канонической
// координатой; все сразу — один перечень с числом; соседняя ручка — рендер.
func postureShadowFindings(t *testing.T, dir string) (findings []string, renders int) {
	t.Helper()
	deployment, err := os.ReadFile(filepath.Join(dir, "templates", "deployment.yaml")) // #nosec G304 -- путь из дерева чарта либо t.TempDir
	require.NoError(t, err)
	sources, err := podEnvSources(string(deployment))
	require.NoError(t, err)
	require.NotEmpty(t, sources, "источников окружения пода не выведено — обход пуст")
	rows := postureGuardRows(t)

	judge := func(what string, out string, err error, source string, want []postureGuardRow) {
		switch {
		case err == nil:
			findings = append(findings, fmt.Sprintf("%s: рендер прошёл — ручка стража посадки уехала в окружение пода мимо отказа", what))
		case !strings.Contains(out, postureShadowMark):
			findings = append(findings, fmt.Sprintf("%s: рендер отказал, но не правилом тени (нет %q):\n%s", what, postureShadowMark, headOf(out)))
		default:
			for _, r := range want {
				if !strings.Contains(out, source+"."+r.env) || !strings.Contains(out, r.knob) {
					findings = append(findings, fmt.Sprintf("%s: отказ не называет %s.%s и координату %s:\n%s", what, source, r.env, r.knob, headOf(out)))
				}
			}
		}
	}
	for _, source := range sources {
		var all []string
		for _, r := range rows {
			out, err := renderChartAtAllowingFailure(t, dir, chartProfiles, withOwnPosture(shadowSets(source, r)...)...)
			renders++
			judge(source+"."+r.env, out, err, source, []postureGuardRow{r})
			all = append(all, shadowSets(source, r)...)
		}
		out, err := renderChartAtAllowingFailure(t, dir, chartProfiles, withOwnPosture(all...)...)
		renders++
		judge(source+" (все ручки сразу)", out, err, source, rows)
		if err != nil && !strings.Contains(out, fmt.Sprintf("— %d.", len(rows))) {
			findings = append(findings, fmt.Sprintf("%s (все ручки сразу): отказ не называет число теней %d:\n%s", source, len(rows), headOf(out)))
		}
	}
	out, err := renderChartAtAllowingFailure(t, dir, chartProfiles, withOwnPosture("env.KANAME_AUTHN__DOMAIN=access.example.invalid")...)
	renders++
	if err != nil {
		findings = append(findings, fmt.Sprintf("близнец env.KANAME_AUTHN__DOMAIN: ручка, которую страж шаблона не судит, отвергнута — "+
			"правило шире своего предмета:\n%s", headOf(out)))
	}
	return findings, renders
}

func TestEveryPostureGuardKnobIsRefusedInEveryPodEnvSource(t *testing.T) {
	findings, renders := postureShadowFindings(t, ".")
	require.Emptyf(t, findings, "ручка стража посадки проходит рендер через окружение пода — находок %d:\n%s",
		len(findings), strings.Join(findings, "\n"))
	t.Logf("перепись: ручек %d · рендеров %d · находок 0", len(postureGuardRows(t)), renders)
}
