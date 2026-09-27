// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// pod_env_source_recognizer_test.go — ИСТОЧНИКИ ОКРУЖЕНИЯ ПОДА: какие карты
// значений чарта кладут свой КЛЮЧ в имя переменной окружения пода (задача #392).
//
// ─────────────────────────────────────────────────────────────────────────────
// ДВЕ СТУПЕНИ, И ПОЧЕМУ НЕ ОДНА
//
// Прежде источник узнавался одним разбором шаблона: `range` по карте, чей ключ
// стоит в тексте после `name:`. Такой распознаватель по построению знает лишь
// названные ему формы, и проверяющий показал шесть законных, которых он не знал
// (опыты 392h–392n: ключ через переменную, элемент из dict и toYaml, приставка
// текстом, карта через set в dict, источник в define), и одну, где он ошибался
// в обратную сторону (392o: ключ даёт имя ТОМА, а не переменной). Куда уходит
// ключ, разбор текста шаблона не решает — решает рендер.
//
// Поэтому ступеней две:
//
//  1. РАЗБОР (без helm) выводит КАНДИДАТОВ с избытком: всякая карта значений,
//     по чьим ключам проходит шаблон (`range $k, $v := <карта>`, чьё тело
//     упоминает ключ, либо проход по `keys <карта>`), во ВСЕХ шаблонах чарта,
//     включая define, вызванные через include, — с точкой места вызова. Адрес
//     карты выводится в любой законной форме (перечень форм с пробой на каждую —
//     `lawfulPodEnvSourceForms`); адрес, который разбор не выводит, — ОТКАЗ с
//     координатой, а не пропуск: кандидат вне переписи рендер не проверит вовсе.
//  2. РЕНДЕР решает, кто из кандидатов источник: в карту кладётся пробный ключ
//     вида ручки стража при КАЖДОМ условии суда (посадка own и боевой профиль
//     без посадки), и источник — та карта, чей пробный ключ оказался в ИМЕНИ
//     переменной окружения контейнера. Рендер же называет, как ключ становится
//     именем (приставка и окончание, 392j), — и называет каждую форму, какую
//     показал при каком-либо условии: одна карта может давать имя двумя
//     проходами и двумя формами. Тени каждой формы суд судит при первом
//     условии, её показавшем, и кладёт ручку так, чтобы в поде оказалась
//     именно она.
//
// Лишний кандидат стоит рендера на каждое условие суда (сейчас двух);
// пропущенный — молчание, которое и было дефектом. Поэтому избыток — на первой
// ступени, решение — на второй, и у решения три исхода, а не два
// (`confirmPodEnvSources`): источник; не источник — только когда пробный ключ лёг
// в другое место рендера, а каждый проход по карте ПРОСТ (`plainPass`); иначе —
// находка «не подтверждён и не опровергнут», называющая, чем проход не прост, с
// местом в шаблоне. Простой проход стоит вне всякого условия, а его тело — прямой
// код, чей вывод вокруг ключа выбирает один ключ: ни узла управления (`if`,
// `with`, `range`, `template`) — упоминает он ключ или нет, — ни выхода из
// итерации (`break`, `continue`), ни присваивания и функции побега, ни чтения
// значений чарта (`$`) и переменной, чьё значение не одно при всяком рендере
// (выбрано ветвью вне прохода, `ternary` по непостоянному условию, выведено из
// значений). Такой проход рендер исполнил целиком и в единственной форме.
// Кандидат, чей пробный ключ не дошёл ни до какого места (проход под условием,
// которого суд не создаёт, либо ключ отфильтрован, опыты 392p–392r), — находка,
// а не «не источник». Источник, чьи показанные формы имени не достигают какой-то
// ручки (приставка, окончание, смена регистра), молчит о ней по той же мере:
// только когда каждый проход прост; иначе другое исполнение места-причины могло
// дать другую форму, и это находка (`postureShadowFindings`).
//
// ГРАНИЦЫ, НАЗВАННЫЕ ВСЛУХ. Источник — КЛЮЧ карты. Перечень элементов, у
// которых имя берётся из поля элемента (опыт 392k), и `envFrom` — другой класс и
// другая задача. Перечень ключей, полученный выражением, которого разбор не
// выводит (не `keys`), кандидатом не становится; шаблон, собранный из строки
// (`tpl`), разбором не читается. Законный фильтр, отсекающий ключи вида ручки
// (392s), суд от выключателя не отличает: это находка «не подтверждён», ложная
// тревога, а не молчание. Ту же ложную тревогу дают тело, читающее значения
// чарта лишь в значении переменной, выход из итерации без всякого условия и
// переменная, чьё значение разбор не выводит (`printf` из постоянных): мера
// простоты судит тело целиком, а не одно выражение имени. Значение ЭЛЕМЕНТА карты
// пробный рендер кладёт одно (`valueSets`): имя, чья форма зависит от значения
// элемента (поле значения в выражении имени, `ternary` по нему), судится этим
// значением и только им. Место вывода прохода в документе — под каким ключом
// YAML, в комментарии ли — задаёт шаблон ВНЕ прохода: ветвь вне прохода, которая
// меняет это место, а не переменную, прочитанную проходом, суд не видит. Не
// простой проход, чьи показанные формы достигают КАЖДОЙ ручки, судится этими
// формами: форма, которую дало бы другое исполнение места-причины, при этом не
// судится.
package deploy_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"text/template/parse"

	"github.com/stretchr/testify/require"
)

// ── Ступень 1: разбор ────────────────────────────────────────────────────────

// tplValue — что разбор знает о значении выражения. known=false — значение
// неизвестно. Иначе значение приходит из любого из путей paths (от корня данных
// шаблона), а карта, собранная шаблоном, — ещё и из своих полей fields (`dict`,
// `set`). keysOf — значение есть перечень КЛЮЧЕЙ таких карт (`keys`); при
// known=false — перечень ключей карты, адрес которой не выведен. chosen —
// значение выбирает условие: переменная переприсвоена или правлена (`set`,
// `merge`) под ветвью, `ternary` выбирает по непостоянному условию.
type tplValue struct {
	known  bool
	paths  [][]string
	fields map[string]tplValue
	keysOf bool
	chosen bool
}

var (
	unknownValue  = tplValue{}
	constantValue = tplValue{known: true}
)

func (v tplValue) field(idents ...string) tplValue {
	if len(idents) == 0 {
		return v
	}
	if !v.known || v.keysOf {
		return unknownValue
	}
	out := tplValue{known: true, chosen: v.chosen}
	for _, p := range v.paths {
		out.paths = append(out.paths, append(append([]string{}, p...), idents[0]))
	}
	if f, ok := v.fields[idents[0]]; ok {
		out = out.union(f)
	}
	return out.field(idents[1:]...)
}

func (v tplValue) union(w tplValue) tplValue {
	if !v.known || !w.known || (v.keysOf != w.keysOf && v.hasContent() && w.hasContent()) {
		return unknownValue
	}
	out := tplValue{known: true, keysOf: v.keysOf || w.keysOf, chosen: v.chosen || w.chosen}
	seen := map[string]bool{}
	for _, p := range append(append([][]string{}, v.paths...), w.paths...) {
		if k := strings.Join(p, "\x00"); !seen[k] {
			seen[k] = true
			out.paths = append(out.paths, p)
		}
	}
	for _, src := range []map[string]tplValue{v.fields, w.fields} {
		for k, f := range src {
			if out.fields == nil {
				out.fields = map[string]tplValue{}
			}
			if cur, ok := out.fields[k]; ok {
				f = cur.union(f)
			}
			out.fields[k] = f
		}
	}
	return out
}

func (v tplValue) unionAll(ws []tplValue) tplValue {
	for _, w := range ws {
		v = v.union(w)
	}
	return v
}

func (v tplValue) hasContent() bool { return len(v.paths) > 0 || len(v.fields) > 0 }

// fixed — значение одно при всяком рендере: постоянная, которую не выбирает ни
// ветвь, ни значения чарта. Неизвестное значение, адрес в значениях, карта
// шаблона с полями и выбранное условием — не одно.
func (v tplValue) fixed() bool { return v.known && !v.keysOf && !v.hasContent() && !v.chosen }

// String — каноническая запись: по ней неподвижная точка вызовов define узнаёт,
// что точки мест вызова перестали меняться.
func (v tplValue) String() string {
	if !v.known {
		return "?"
	}
	parts := make([]string, 0, len(v.paths)+len(v.fields))
	for _, p := range v.paths {
		parts = append(parts, "."+strings.Join(p, "."))
	}
	for k, f := range v.fields {
		parts = append(parts, k+"="+f.String())
	}
	sort.Strings(parts)
	s := "{" + strings.Join(parts, ",") + "}"
	if v.chosen {
		s += "!"
	}
	if v.keysOf {
		return "keys" + s
	}
	return s
}

// envCandidate — карта значений, по чьим ключам проходит шаблон.
type envCandidate struct {
	path string
	// fields — поля ЗНАЧЕНИЯ, которые читает тело (`$v.secretName`): пробный
	// ключ рендера кладётся картой с этими полями, иначе рендер отказал бы
	// раньше и не тем.
	fields []string
	// notPlainBy — чем НЕ прост хоть один проход по ключам этой карты во всех
	// шаблонах чарта (`plainPass`), с местом в шаблоне; пусто — каждый проход
	// прост. Он решает, вправе ли рендер ОПРОВЕРГНУТЬ кандидата
	// (`confirmPodEnvSources`) и вправе ли показанные формы имени молчать о
	// ручке, которой не достигают (`postureShadowFindings`), и его же называет
	// находка.
	notPlainBy string
}

// walkEnv — общее для одного прохода разбора: точки мест вызова define,
// признак вызова по вычисляемому имени, найденные кандидаты и чем не прост их
// первый не простой проход.
type walkEnv struct {
	sites      map[string]tplValue
	dynamic    bool
	judge      bool
	candidates map[string]map[string]bool
	notPlain   map[string]string
}

func (e *walkEnv) site(name string, arg tplValue) {
	if cur, ok := e.sites[name]; ok {
		arg = cur.union(arg)
	}
	e.sites[name] = arg
}

// tplScope — точка и переменные в месте шаблона. Переменные — указатели:
// присваивание `$x = …` и `set $x …` во вложенной структуре меняют ту же
// переменную, а объявление `$x := …` заводит новую до `end` своей структуры.
// gated — место исполняется не при всяком рендере: внутри ветви if и with, тела
// или else внешнего range, внутри define; присваивание и правка переменной в
// таком месте делают её значение выбранным условием (`tplValue.chosen`).
type tplScope struct {
	dot   tplValue
	vars  map[string]*tplValue
	env   *walkEnv
	tree  *parse.Tree
	gated bool
}

func (s tplScope) child(dot tplValue) tplScope {
	vars := make(map[string]*tplValue, len(s.vars))
	for k, v := range s.vars {
		vars[k] = v
	}
	return tplScope{dot: dot, vars: vars, env: s.env, tree: s.tree, gated: s.gated}
}

// branch — место внутри ветви: исполняется не при всяком рендере.
func (s tplScope) branch(dot tplValue) tplScope {
	c := s.child(dot)
	c.gated = true
	return c
}

func (s tplScope) bind(name string, v tplValue) { nv := v; s.vars[name] = &nv }

func (s tplScope) declare(pipe *parse.PipeNode, v tplValue) {
	if pipe == nil {
		return
	}
	for _, d := range pipe.Decl {
		if cur := s.vars[d.Ident[0]]; pipe.IsAssign && cur != nil {
			s.mutate(cur, cur.union(v))
			continue
		}
		s.bind(d.Ident[0], v)
	}
}

// mutate — новое значение переменной, переприсвоенной или правленой в этом
// месте; в месте под условием значение выбирает условие.
func (s tplScope) mutate(cur *tplValue, v tplValue) {
	v.chosen = v.chosen || s.gated
	*cur = v
}

// podEnvSources — кандидаты шаблона развёртывания, заданного одним текстом.
func podEnvSources(src string) ([]string, error) {
	cands, err := podEnvSourcesIn(map[string]string{"deployment.yaml": src})
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(cands))
	for _, c := range cands {
		out = append(out, c.path)
	}
	return out, nil
}

// chartTemplates — шаблоны чарта в каталоге dir: имя файла → текст.
func chartTemplates(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	files := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || (filepath.Ext(e.Name()) != ".yaml" && filepath.Ext(e.Name()) != ".tpl") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- путь из дерева чарта либо t.TempDir
		require.NoError(t, err)
		files[e.Name()] = string(b)
	}
	require.NotEmpty(t, files, "в каталоге шаблонов %s ни одного шаблона — обход пуст", dir)
	return files
}

// podEnvSourcesIn выводит кандидатов по ВСЕМ шаблонам чарта (имя файла →
// текст). Их разбирает тот же text/template, которым helm их исполняет, в одно
// множество определений: define из _helpers.tpl видны шаблону развёртывания
// так же, как helm их видит, а точка внутри define — аргумент места вызова.
func podEnvSourcesIn(files map[string]string) ([]envCandidate, error) {
	set := map[string]*parse.Tree{}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	mains := map[string]*parse.Tree{}
	for _, n := range names {
		tr := parse.New(n)
		tr.Mode = parse.SkipFuncCheck
		if _, err := tr.Parse(files[n], "{{", "}}", set); err != nil {
			return nil, fmt.Errorf("шаблон %s не разобран: %w", n, err)
		}
		mains[n] = tr
	}
	defs := make([]string, 0, len(set))
	for n, tr := range set {
		if _, isFile := files[n]; !isFile && tr.Root != nil {
			defs = append(defs, n)
		}
	}
	sort.Strings(defs)

	env := &walkEnv{sites: map[string]tplValue{}, candidates: map[string]map[string]bool{},
		notPlain: map[string]string{}}
	pass := func() error {
		for _, n := range names {
			if mains[n].Root == nil {
				continue
			}
			root := tplValue{known: true, paths: [][]string{{}}}
			s := tplScope{dot: root, vars: map[string]*tplValue{}, env: env, tree: mains[n]}
			s.bind("$", root)
			if err := walkTemplate(mains[n].Root, s); err != nil {
				return err
			}
		}
		for _, n := range defs {
			// Точка и `$` внутри define — аргумент места вызова. Define без
			// литерального места вызова, как и при вызове по вычисляемому
			// имени, судится с неизвестной точкой: кандидат в нём — отказ, а не
			// догадка.
			dot, called := env.sites[n]
			if !called || env.dynamic {
				dot = unknownValue
			}
			s := tplScope{dot: dot, vars: map[string]*tplValue{}, env: env, tree: set[n], gated: true}
			s.bind("$", dot)
			if err := walkTemplate(set[n].Root, s); err != nil {
				return err
			}
		}
		return nil
	}
	for round := 0; ; round++ {
		before := sitesKey(env.sites)
		if err := pass(); err != nil {
			return nil, err
		}
		if sitesKey(env.sites) == before {
			break
		}
		if round > len(defs)+1 {
			return nil, fmt.Errorf("точки мест вызова define не сошлись за %d проходов", round)
		}
	}
	env.judge = true
	if err := pass(); err != nil {
		return nil, err
	}

	out := make([]envCandidate, 0, len(env.candidates))
	for p, fs := range env.candidates {
		c := envCandidate{path: p, notPlainBy: env.notPlain[p]}
		for f := range fs {
			c.fields = append(c.fields, f)
		}
		sort.Strings(c.fields)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out, nil
}

func sitesKey(m map[string]tplValue) string {
	keys := make([]string, 0, len(m))
	for k, v := range m {
		keys = append(keys, k+"→"+v.String())
	}
	sort.Strings(keys)
	return strings.Join(keys, ";")
}

func walkTemplate(n parse.Node, s tplScope) error {
	switch x := n.(type) {
	case *parse.ListNode:
		if x == nil {
			return nil
		}
		for _, c := range x.Nodes {
			if err := walkTemplate(c, s); err != nil {
				return err
			}
		}
	case *parse.ActionNode:
		// Конвейер разбирается ВСЕГДА, а не только с объявлением: `set` и
		// `include` действуют и без него.
		v := resolvePipe(x.Pipe, s)
		if len(x.Pipe.Decl) > 0 {
			s.declare(x.Pipe, v)
		}
	case *parse.TemplateNode:
		s.env.site(x.Name, resolvePipe(x.Pipe, s))
	case *parse.IfNode:
		base := s.child(s.dot)
		base.declare(x.Pipe, resolvePipe(x.Pipe, s))
		if err := walkTemplate(x.List, base.branch(s.dot)); err != nil {
			return err
		}
		return walkTemplate(x.ElseList, base.branch(s.dot))
	case *parse.WithNode:
		v := resolvePipe(x.Pipe, s)
		base := s.child(s.dot)
		base.declare(x.Pipe, v)
		if err := walkTemplate(x.List, base.branch(v)); err != nil {
			return err
		}
		return walkTemplate(x.ElseList, base.branch(s.dot))
	case *parse.RangeNode:
		over := resolvePipe(x.Pipe, s)
		if err := judgeRange(x, over, s); err != nil {
			return err
		}
		// Элемент прохода и ключ выбирает оператор: их значения неизвестны.
		base := s.child(s.dot)
		for _, d := range x.Pipe.Decl {
			base.bind(d.Ident[0], unknownValue)
		}
		if err := walkTemplate(x.List, base.branch(unknownValue)); err != nil {
			return err
		}
		return walkTemplate(x.ElseList, base.branch(s.dot))
	}
	return nil
}

// judgeRange — кандидат ли range и какой: карта, по чьим ключам проходит
// шаблон, когда тело упоминает ключ, — `range $k, $v := <карта>` с упоминанием
// $k либо проход по `keys <карта>` с упоминанием элемента (точки).
func judgeRange(r *parse.RangeNode, over tplValue, s tplScope) error {
	key, valueVar := "", ""
	switch decl := r.Pipe.Decl; {
	case over.keysOf && len(decl) == 2:
		key = decl[1].Ident[0]
	case over.keysOf && len(decl) == 1:
		key = decl[0].Ident[0]
	case over.keysOf:
		key = "."
	case len(decl) == 2:
		key, valueVar = decl[0].Ident[0], decl[1].Ident[0]
	default:
		return nil
	}
	if !s.env.judge || !bodyMentions(r.List, key) {
		return nil
	}
	known := over.known
	var sources []string
	for _, p := range over.paths {
		if len(p) < 2 || p[0] != "Values" {
			known = false
			break
		}
		sources = append(sources, strings.Join(p[1:], "."))
	}
	if !known {
		loc, _ := s.tree.ErrorContext(r)
		return fmt.Errorf("%s: шаблон проходит по ключам карты, а адрес карты распознаватель не выводит — "+
			"`range %s`. Пропустить молча нельзя: кандидат вне переписи рендер не проверит вовсе; научите "+
			"распознаватель этой форме (lawfulPodEnvSourceForms) либо запишите источник формой из перечня", loc, r.Pipe)
	}
	fields := map[string]bool{}
	if valueVar != "" {
		collectFieldsOf(r.List, valueVar, fields)
	}
	var why string
	if s.gated {
		loc, _ := s.tree.ErrorContext(r)
		why = loc + ": проход стоит под условием — в ветви if или with, в теле внешнего range либо в define"
	} else {
		why = plainPass(r, s)
	}
	for _, src := range sources {
		if s.env.candidates[src] == nil {
			s.env.candidates[src] = map[string]bool{}
		}
		for f := range fields {
			s.env.candidates[src][f] = true
		}
		if why != "" && s.env.notPlain[src] == "" {
			s.env.notPlain[src] = why
		}
	}
	return nil
}

// passEscapes — функции, через которые ключ либо вывод уходят из тела прохода
// туда, где рендер их места не называет: в define (`include`, `tpl`) и во
// внешнюю карту (`set`, семейство `merge`).
var passEscapes = map[string]bool{
	"include": true, "tpl": true, "set": true, "unset": true,
	"merge": true, "mergeOverwrite": true, "mustMerge": true, "mustMergeOverwrite": true,
}

// plainPass — чем проход НЕ прост, с местом в шаблоне; пусто — прост. Простой
// проход — прямой код, чей вывод вокруг ключа выбирает один ключ: в теле только
// текст, комментарии и действия, а действия читают лишь ключ, элемент,
// переменные, объявленные в теле, и переменные с одним значением при всяком
// рендере (`tplValue.fixed`). Не прост проход, в теле которого
//
//   - выход из итерации (`break`, `continue`) на любой глубине, кроме тела
//     вложенного range: исполнено ли место тела после него, решает не ключ;
//   - узел управления (`if`, `with`, `range`, `template`), упоминает он ключ или
//     нет: ветвь без ключа меняет форму имени и место записи — приставка под
//     ветвью, запись, которую ветвь делает комментарием;
//   - присваивание `=` либо функция побега (`passEscapes`): ключ либо вывод
//     уходят туда, где рендер их места не называет;
//   - чтение `$` (значений чарта) либо переменной вне прохода, чьё значение не
//     одно: выбрано условием, выведено из значений, не выведено разбором.
//
// Выполненный простой проход — это выполненное КАЖДОЕ место его тела, и в
// единственной форме: место, куда рендер положил пробный ключ, — всё, куда
// проход его кладёт.
func plainPass(r *parse.RangeNode, s tplScope) string {
	at := func(n parse.Node) string {
		loc, _ := s.tree.ErrorContext(n)
		return loc
	}
	if exit, word := passExit(r.List); exit != nil {
		return fmt.Sprintf("%s: в теле прохода выход из итерации `%s` — исполнено ли место тела после него, решает не ключ",
			at(exit), word)
	}
	if r.List == nil {
		return ""
	}
	local := map[string]bool{}
	for _, d := range r.Pipe.Decl {
		local[d.Ident[0]] = true
	}
	for _, n := range r.List.Nodes {
		switch x := n.(type) {
		case *parse.TextNode, *parse.CommentNode:
		case *parse.ActionNode:
			if x.Pipe.IsAssign {
				return fmt.Sprintf("%s: в теле прохода присваивание `%s` — ключ либо вывод уходят туда, где рендер их места не называет",
					at(x), x)
			}
			if fn := firstCallOf(x.Pipe, passEscapes); fn != "" {
				return fmt.Sprintf("%s: тело прохода зовёт `%s` — ключ либо вывод уходят туда, где рендер их места не называет", at(x), fn)
			}
			if what := passReads(x.Pipe, local, s); what != "" {
				return fmt.Sprintf("%s: тело прохода читает %s — вывод вокруг ключа выбирает не один ключ", at(x), what)
			}
			for _, d := range x.Pipe.Decl {
				local[d.Ident[0]] = true
			}
		default:
			return fmt.Sprintf("%s: в теле прохода узел управления `%s` — он меняет форму имени и место записи, упоминает он "+
				"ключ или нет", at(n), controlWord(n))
		}
	}
	return ""
}

// passExit — первый выход из итерации (`break`, `continue`), который принадлежит
// ЭТОМУ проходу: на любой глубине ветвей и в else вложенного range, но не в теле
// вложенного range — там он выходит из вложенного.
func passExit(list *parse.ListNode) (parse.Node, string) {
	if list == nil {
		return nil, ""
	}
	for _, n := range list.Nodes {
		switch x := n.(type) {
		case *parse.BreakNode:
			return x, "break"
		case *parse.ContinueNode:
			return x, "continue"
		case *parse.IfNode:
			if e, w := passExit(x.List); e != nil {
				return e, w
			}
			if e, w := passExit(x.ElseList); e != nil {
				return e, w
			}
		case *parse.WithNode:
			if e, w := passExit(x.List); e != nil {
				return e, w
			}
			if e, w := passExit(x.ElseList); e != nil {
				return e, w
			}
		case *parse.RangeNode:
			if e, w := passExit(x.ElseList); e != nil {
				return e, w
			}
		}
	}
	return nil, ""
}

// controlWord — слово шаблона, которым записан узел управления.
func controlWord(n parse.Node) string {
	switch n.(type) {
	case *parse.IfNode:
		return "if"
	case *parse.WithNode:
		return "with"
	case *parse.RangeNode:
		return "range"
	case *parse.TemplateNode:
		return "template"
	}
	return fmt.Sprintf("%T", n)
}

// passReads — что из того, что выбирает не проход, читает действие тела: `$`
// (значения чарта) либо переменную вне прохода с не одним значением; пусто —
// ничего такого. local — ключ, элемент и переменные, объявленные в теле.
func passReads(n parse.Node, local map[string]bool, s tplScope) string {
	switch x := n.(type) {
	case *parse.PipeNode:
		if x == nil {
			return ""
		}
		for _, c := range x.Cmds {
			if what := passReads(c, local, s); what != "" {
				return what
			}
		}
	case *parse.CommandNode:
		for _, a := range x.Args {
			if what := passReads(a, local, s); what != "" {
				return what
			}
		}
	case *parse.ChainNode:
		return passReads(x.Node, local, s)
	case *parse.VariableNode:
		name := x.Ident[0]
		switch v := s.vars[name]; {
		case local[name]:
		case name == "$":
			return fmt.Sprintf("значения чарта (`%s`)", x)
		case v == nil || !v.field(x.Ident[1:]...).fixed():
			return fmt.Sprintf("переменную `%s`, чьё значение не одно при всяком рендере — выбрано условием, выведено из "+
				"значений чарта либо не выведено разбором", name)
		}
	}
	return ""
}

// firstCallOf — первая из функций funcs, которую зовёт конвейер (и вложенные в
// его аргументы); пусто — ни одной.
func firstCallOf(n parse.Node, funcs map[string]bool) string {
	switch x := n.(type) {
	case *parse.PipeNode:
		if x == nil {
			return ""
		}
		for _, c := range x.Cmds {
			if fn := firstCallOf(c, funcs); fn != "" {
				return fn
			}
		}
	case *parse.CommandNode:
		for i, a := range x.Args {
			if id, ok := a.(*parse.IdentifierNode); ok && i == 0 && funcs[id.Ident] {
				return id.Ident
			}
			if fn := firstCallOf(a, funcs); fn != "" {
				return fn
			}
		}
	case *parse.ChainNode:
		return firstCallOf(x.Node, funcs)
	}
	return ""
}

// bodyMentions — упоминает ли тело ключ: переменную key (с учётом затенения
// объявлением) либо, если key — «.», точку вне вложенных with и range.
func bodyMentions(list *parse.ListNode, key string) bool {
	if list == nil {
		return false
	}
	for _, n := range list.Nodes {
		switch x := n.(type) {
		case *parse.ActionNode:
			if mentions(x.Pipe, key) {
				return true
			}
			if declares(x.Pipe, key) {
				return false
			}
		case *parse.TemplateNode:
			if mentions(x.Pipe, key) {
				return true
			}
		case *parse.IfNode:
			if mentions(x.Pipe, key) || (!declares(x.Pipe, key) && (bodyMentions(x.List, key) || bodyMentions(x.ElseList, key))) {
				return true
			}
		case *parse.WithNode:
			if mentions(x.Pipe, key) || bodyMentions(x.ElseList, key) {
				return true
			}
			if key != "." && !declares(x.Pipe, key) && bodyMentions(x.List, key) {
				return true
			}
		case *parse.RangeNode:
			if mentions(x.Pipe, key) || bodyMentions(x.ElseList, key) {
				return true
			}
			if key != "." && !declares(x.Pipe, key) && bodyMentions(x.List, key) {
				return true
			}
		}
	}
	return false
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

// mentions — ссылается ли выражение на ключ где угодно внутри.
func mentions(n parse.Node, key string) bool {
	switch x := n.(type) {
	case *parse.PipeNode:
		if x == nil {
			return false
		}
		for _, c := range x.Cmds {
			if mentions(c, key) {
				return true
			}
		}
	case *parse.CommandNode:
		for _, a := range x.Args {
			if mentions(a, key) {
				return true
			}
		}
	case *parse.VariableNode:
		return x.Ident[0] == key
	case *parse.DotNode:
		return key == "."
	case *parse.FieldNode:
		return key == "."
	case *parse.ChainNode:
		return mentions(x.Node, key)
	}
	return false
}

// collectFieldsOf — поля переменной v, которые читает тело (`$v.secretName`).
func collectFieldsOf(n parse.Node, v string, into map[string]bool) {
	switch x := n.(type) {
	case *parse.ListNode:
		if x != nil {
			for _, c := range x.Nodes {
				collectFieldsOf(c, v, into)
			}
		}
	case *parse.ActionNode:
		collectFieldsOf(x.Pipe, v, into)
	case *parse.TemplateNode:
		collectFieldsOf(x.Pipe, v, into)
	case *parse.IfNode:
		collectFieldsOf(x.Pipe, v, into)
		collectFieldsOf(x.List, v, into)
		collectFieldsOf(x.ElseList, v, into)
	case *parse.WithNode:
		collectFieldsOf(x.Pipe, v, into)
		collectFieldsOf(x.List, v, into)
		collectFieldsOf(x.ElseList, v, into)
	case *parse.RangeNode:
		collectFieldsOf(x.Pipe, v, into)
		collectFieldsOf(x.List, v, into)
		collectFieldsOf(x.ElseList, v, into)
	case *parse.PipeNode:
		if x != nil {
			for _, c := range x.Cmds {
				collectFieldsOf(c, v, into)
			}
		}
	case *parse.CommandNode:
		for _, a := range x.Args {
			collectFieldsOf(a, v, into)
		}
	case *parse.VariableNode:
		if x.Ident[0] == v && len(x.Ident) > 1 {
			into[x.Ident[1]] = true
		}
	case *parse.ChainNode:
		collectFieldsOf(x.Node, v, into)
	}
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

// resolveCommand знает функции, которые переносят адрес карты: `default`,
// `required`, `ternary`, `coalesce` (значение — любой из операндов),
// `index`/`get` (поле по литералу), `dict` (карта шаблона с литеральными
// ключами), `set` и семейство `merge` (правка карты в переменной), `deepCopy`,
// `pick`, `omit`, `unset` (та же карта), `keys` (перечень ключей) и
// `sortAlpha`/`uniq`/`compact` над ним. `include` запоминает точку места вызова
// define. Прочие — неизвестное значение, и проход по ним с упоминанием ключа —
// отказ, а не пропуск. Значение `ternary` по непостоянному условию и правка
// переменной под ветвью — значение, выбранное условием (`tplValue.chosen`).
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
	ops := make([]tplValue, 0, len(c.Args))
	for _, a := range c.Args[1:] {
		ops = append(ops, resolveArg(a, s))
	}
	if piped != nil {
		ops = append(ops, *piped)
	}
	switch id.Ident {
	case "default", "ternary", "coalesce":
		if id.Ident == "ternary" && len(ops) == 3 {
			out := ops[0].union(ops[1])
			out.chosen = out.chosen || !ops[2].fixed()
			return out
		}
		if len(ops) >= 2 && id.Ident != "ternary" {
			return ops[0].unionAll(ops[1:])
		}
	case "required":
		if len(ops) == 2 {
			return ops[1]
		}
	case "index", "get":
		if piped != nil || len(c.Args) < 3 || (id.Ident == "get" && len(c.Args) != 3) {
			return unknownValue
		}
		keys := make([]string, 0, len(c.Args)-2)
		for _, a := range c.Args[2:] {
			k, ok := a.(*parse.StringNode)
			if !ok {
				return unknownValue
			}
			keys = append(keys, k.Text)
		}
		return ops[0].field(keys...)
	case "dict":
		if piped != nil || len(ops)%2 != 0 {
			return unknownValue
		}
		out := tplValue{known: true}
		for i := 0; i < len(ops); i += 2 {
			k, ok := c.Args[1+i].(*parse.StringNode)
			if !ok {
				return unknownValue
			}
			if out.fields == nil {
				out.fields = map[string]tplValue{}
			}
			out.fields[k.Text] = ops[i+1]
		}
		return out
	case "list":
		// Постоянная — только из постоянных операндов: перечень, собранный из
		// значений, несёт их адрес, и его форма здесь не выводится.
		if all := constantValue.unionAll(ops); piped == nil && all.known && !all.hasContent() {
			return all
		}
	case "set":
		if piped != nil || len(c.Args) != 4 {
			return unknownValue
		}
		cur := mutableVar(c.Args[1], s)
		k, literal := c.Args[2].(*parse.StringNode)
		if cur == nil {
			return unknownValue
		}
		if !literal {
			*cur = unknownValue
			return unknownValue
		}
		s.mutate(cur, cur.union(tplValue{known: true, fields: map[string]tplValue{k.Text: ops[2]}}))
		return *cur
	case "merge", "mergeOverwrite", "mustMerge", "mustMergeOverwrite":
		if len(ops) == 0 {
			return unknownValue
		}
		out := ops[0].unionAll(ops[1:])
		if cur := mutableVar(c.Args[1], s); cur != nil && piped == nil {
			s.mutate(cur, out)
		}
		return out
	case "deepCopy", "mustDeepCopy", "pick", "omit", "unset":
		if len(ops) >= 1 {
			if piped != nil && (id.Ident == "deepCopy" || id.Ident == "mustDeepCopy") {
				return *piped
			}
			if piped == nil {
				return ops[0]
			}
		}
	case "keys":
		if len(ops) == 0 {
			return unknownValue
		}
		// Перечень ключей неизвестной карты — всё равно ПЕРЕЧЕНЬ КЛЮЧЕЙ: проход
		// по нему с упоминанием элемента — отказ, а не «не кандидат».
		all := ops[0].unionAll(ops[1:])
		if !all.known || all.keysOf {
			return tplValue{keysOf: true}
		}
		all.keysOf = true
		return all
	case "sortAlpha", "uniq", "compact", "mustUniq", "mustCompact":
		if len(ops) == 1 && ops[0].keysOf {
			return ops[0]
		}
	case "include":
		if len(c.Args) < 2 {
			return unknownValue
		}
		arg := constantValue
		if len(c.Args) > 2 {
			arg = resolveArg(c.Args[2], s)
		}
		switch name := c.Args[1].(type) {
		case *parse.StringNode:
			s.env.site(name.Text, arg)
		default:
			// Вызов файла шаблона по его пути (`print $.Template.BasePath
			// "/configmap.yaml"`) — вызов шаблона-файла, который обходится
			// сам, с корнем. Иной вычисляемый вызов неизвестно куда ведёт —
			// define судятся тогда с неизвестной точкой.
			if !strings.Contains(c.Args[1].String(), ".Template.BasePath") {
				s.env.dynamic = true
			}
		}
	}
	return unknownValue
}

// mutableVar — переменная, которую правит `set`/`merge`: `$x` без полей.
func mutableVar(n parse.Node, s tplScope) *tplValue {
	v, ok := n.(*parse.VariableNode)
	if !ok || len(v.Ident) != 1 {
		return nil
	}
	return s.vars[v.Ident[0]]
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
		return constantValue
	case *parse.IdentifierNode:
		if x.Ident == "dict" || x.Ident == "list" {
			return constantValue
		}
	}
	return unknownValue
}

// ── Ступень 2: рендер ────────────────────────────────────────────────────────

// envSource — подтверждённый рендером источник: карта значений и то, как её
// ключ становится именем переменной (приставка и окончание вокруг ключа).
// folded — шаблон меняет регистр ключа: пробный ключ написан заглавными, и
// изменить его могло лишь понижение — такой источник имени ручки стража
// (заглавными) не даёт вовсе.
// cond — первое условие суда, при котором рендер показал ЭТУ форму имени; при
// нём же суд судит её тени. Карта, давшая имя несколькими формами, — несколько
// источников, по одному на форму.
type envSource struct {
	envCandidate
	prefix, suffix string
	folded         bool
	cond           podEnvCondition
}

// podEnvCondition — условие рендера поверх боевого профиля chartProfiles:
// накладка `--set`, при которой ищется пробный ключ и судится тень.
type podEnvCondition struct {
	name    string
	overlay []string
}

// with — накладка условия плюс названные `--set`; копия, а не общий срез:
// append в общий срез переписал бы его соседям.
func (c podEnvCondition) with(sets ...string) []string {
	return append(append([]string{}, c.overlay...), sets...)
}

// podEnvConditions — условия суда по порядку. Первое — посадка own: при ней тень
// ручки стража и есть дефект (#392), и при ней же судятся прежние источники.
// Второе — боевой профиль БЕЗ посадки: проход, выключенный на own и
// включённый на любой другой посадке, судится там, где он включён.
//
// Прежде вторым условием был боевой профиль как есть — он стоял на посадке
// `external`. Посадка снята (PRO-Robotech/corelib#30), профиль стоит на `own`
// (#424), и «как есть» совпало бы с первым условием: проход, включённый вне
// `own`, выпал бы из суда. Посадка, отличная от `own`, которую чарт
// рендерит, одна — незаявленная.
var podEnvConditions = []podEnvCondition{
	{name: "накладка own", overlay: ownPostureOverlay},
	{name: "боевой профиль без посадки", overlay: []string{identityProviderKnob + "="}},
}

// podEnvCanary — пробный ключ кандидата ВИДА РУЧКИ СТРАЖА: приставка `KANAME_`,
// заглавные буквы, цифры, подчёркивание. Так его пропускает фильтр, которым
// шаблон отбирал бы ключи-ручки (392q), и не портят ни `--set`, ни
// преобразования регистра.
func podEnvCanary(i int) string { return fmt.Sprintf("KANAME_QZCANARY%dQZ", i) }

// valueSets — `--set`, кладущие под ключ key карты кандидата значение: картой с
// полями, которые читает тело, либо строкой. Значения полей от ключа не
// зависят: иначе пробный ключ оказался бы в рендере значением поля, и место,
// куда его положил проход, было бы неотличимо от места, куда его положил сам
// пробный рендер.
func valueSets(c envCandidate, key, value string) []string {
	if len(c.fields) == 0 {
		return []string{fmt.Sprintf("%s.%s=%s", c.path, key, strings.ReplaceAll(value, ",", `\,`))}
	}
	sets := make([]string, 0, len(c.fields))
	for _, f := range c.fields {
		sets = append(sets, fmt.Sprintf("%s.%s.%s=%s", c.path, key, f, "kaname-"+strings.ToLower(f)))
	}
	return sets
}

// podEnvNames — имена переменных окружения контейнеров всех подов рендера.
func podEnvNames(t *testing.T, rendered string) []string {
	t.Helper()
	var names []string
	var visit func(any)
	visit = func(n any) {
		switch x := n.(type) {
		case map[string]any:
			for k, v := range x {
				if k == "containers" || k == "initContainers" || k == "ephemeralContainers" {
					if list, ok := v.([]any); ok {
						for _, c := range list {
							cm, _ := c.(map[string]any)
							env, _ := cm["env"].([]any)
							for _, e := range env {
								if em, ok := e.(map[string]any); ok {
									if name, ok := em["name"].(string); ok {
										names = append(names, name)
									}
								}
							}
						}
					}
				}
				visit(v)
			}
		case []any:
			for _, v := range x {
				visit(v)
			}
		}
	}
	forEachDoc(t, rendered, func(doc map[string]any) { visit(doc) })
	return names
}

// confirmPodEnvSources — ступень 2. Пробный ключ кандидата кладётся при КАЖДОМ
// условии суда (`podEnvConditions`), а не до первого подтверждения, и исход у
// кандидата один из трёх — «выпал без суждения» среди них нет:
//
//   - ИСТОЧНИК: пробный ключ оказался в ИМЕНИ переменной окружения контейнера
//     хоть при одном условии; источник — каждая форма имени, которую рендер
//     показал при каком-либо условии, и тени каждой формы суд судит при первом
//     условии, её показавшем. Форма, которую показало лишь второе условие
//     (окончание имени под посадкой own, голое — на поставке), иначе выпала бы
//     из суда: при первом условии она невидима;
//   - НЕ ИСТОЧНИК (refuted): ни при одном условии имени он не дал, а рендер
//     положил его в другое место (том, порт, аннотация, значение), и КАЖДЫЙ
//     проход по карте прост (`plainPass`): стоит вне всякого условия, а его
//     тело — прямой код, чей вывод вокруг ключа выбирает один ключ. Такие
//     проходы исполнены при каждом рендере целиком и в единственной форме, и ни
//     один не положил пробный ключ в имя переменной;
//   - НАХОДКА «не подтверждён и не опровергнут»: рендер отказал; пробный ключ не
//     дошёл ни до какого места рендера ни при одном условии (проход выключен
//     условием, которого суд не создаёт, либо ключ отфильтрован); хоть один
//     проход по карте не прост — находка называет чем, с местом в шаблоне, — и
//     как он положил бы ключ при другом исполнении этого места, рендер не
//     называет: место, где лёг пробный ключ, мог дать и не этот проход (другой
//     проход, карта, выведенная целиком).
func confirmPodEnvSources(t *testing.T, dir string, cands []envCandidate) (sources []envSource, refuted, findings []string, renders int) {
	t.Helper()
	condNames := make([]string, 0, len(podEnvConditions))
	for _, cond := range podEnvConditions {
		condNames = append(condNames, cond.name)
	}
candidates:
	for i, c := range cands {
		canary := podEnvCanary(i)
		seen := false
		forms := map[string]bool{}
		for _, cond := range podEnvConditions {
			out, err := renderChartAtAllowingFailure(t, dir, chartProfiles, cond.with(valueSets(c, canary, "qzvalue")...)...)
			renders++
			if err != nil {
				findings = append(findings, fmt.Sprintf("кандидат %s: рендер с пробным ключом %s отказал (%s) — источник не "+
					"подтверждён и не опровергнут:\n%s", c.path, canary, cond.name, headOf(out)))
				continue candidates
			}
			for _, src := range envSourcesIn(t, out, c, canary, cond) {
				if !forms[src.form()] {
					forms[src.form()] = true
					sources = append(sources, src)
				}
			}
			seen = seen || strings.Contains(strings.ToUpper(out), canary)
		}
		switch {
		case len(forms) > 0:
		case !seen:
			findings = append(findings, fmt.Sprintf("кандидат %s: пробный ключ %s не дошёл ни до какого места рендера ни при "+
				"одном условии суда (%s) — проход по карте выключен условием, которого суд не создаёт, либо ключ "+
				"отфильтрован: источник не подтверждён и не опровергнут", c.path, canary, strings.Join(condNames, ", ")))
		case c.notPlainBy != "":
			findings = append(findings, fmt.Sprintf("кандидат %s: пробный ключ %s рендер положил не в имя переменной пода, а "+
				"проход по карте не прост — %s; как он положил бы ключ при другом исполнении этого места, рендер не "+
				"называет: источник не подтверждён и не опровергнут", c.path, canary, c.notPlainBy))
		default:
			refuted = append(refuted, c.path)
		}
	}
	return sources, refuted, findings, renders
}

// envSourcesIn — источники кандидата в рендере out: по одному на КАЖДУЮ форму
// имени переменной окружения контейнера, в которой оказался пробный ключ. Одна
// карта даёт имя не обязательно одним проходом и не обязательно одной формой
// (приставка текстом в одном проходе, голое имя в другом), и форма первого
// найденного имени о прочих ничего не говорит: суд теней судит каждую.
func envSourcesIn(t *testing.T, out string, c envCandidate, canary string, cond podEnvCondition) []envSource {
	t.Helper()
	var srcs []envSource
	forms := map[string]bool{}
	for _, name := range podEnvNames(t, out) {
		at := strings.Index(strings.ToUpper(name), canary)
		if at < 0 {
			continue
		}
		s := envSource{envCandidate: c, cond: cond, prefix: name[:at], suffix: name[at+len(canary):],
			folded: name[at:at+len(canary)] != canary}
		if !forms[s.form()] {
			forms[s.form()] = true
			srcs = append(srcs, s)
		}
	}
	return srcs
}

// bareEnvForm — форма имени, где ключ карты и есть имя переменной пода.
const bareEnvForm = "<ключ>"

// form — форма имени переменной пода: как ключ карты становится именем.
func (s envSource) form() string {
	f := s.prefix + bareEnvForm + s.suffix
	if s.folded {
		f += " (регистр изменён)"
	}
	return f
}

// keyFor — ключ карты источника, который даст переменной пода имя env; ложь —
// источник такого имени не даёт (приставка и окончание не те).
func (s envSource) keyFor(env string) (string, bool) {
	if s.folded {
		return "", false
	}
	if !strings.HasPrefix(strings.ToUpper(env), strings.ToUpper(s.prefix)) ||
		!strings.HasSuffix(strings.ToUpper(env), strings.ToUpper(s.suffix)) || len(env) <= len(s.prefix)+len(s.suffix) {
		return "", false
	}
	return env[len(s.prefix) : len(env)-len(s.suffix)], true
}

// label — как находка называет ручку в источнике: ключ карты и, если имя
// переменной другое, само имя.
func (s envSource) label(key, env string) string {
	if key == env {
		return s.path + "." + key
	}
	return s.path + "." + key + " → " + env
}

func containsName(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}
