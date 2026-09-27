// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// pod_env_execution_test.go — ИМЕНА ПЕРЕМЕННЫХ ОКРУЖЕНИЯ ПОДА СУДЯТСЯ ПО
// ИСПОЛНЕНИЮ ЧАРТА, а не по тексту шаблонов (задача #433, держатель правила
// #392 «у ручек стража посадки один адрес — ключ значений чарта»).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ НЕ ТЕКСТ
//
// Прежний держатель выводил источники окружения пода разбором шаблонов
// (`pod_env_source_recognizer_test.go`): распознаватель знал перечень форм, как
// ключ карты становится именем переменной, и простоту прохода по карте. Каждый
// круг ревью сборки #425 находил форму, которой разбор не видел, хотя ручка
// доходила до пода: выход из итерации в теле прохода (392-C1), вызов функции,
// читающей не значения чарта (392-C2), ветви без упоминания ключа (U1–U3),
// правка карты через псевдоним, вложенное поле, `define`, смена регистра
// приставки, выбор формы имени по содержимому ключа. Класс «все формы»
// перечнем форм не закрывается: следующая форма молчит.
//
// ВЫБОР: распознаватель СНЯТ тем же изменением вместе со своими правилами и
// границами, а не оставлен производителем кандидатов. Довод: кандидат, которого
// он не назвал, выпадал бы из суда — пропуск производителя давал бы зелёное,
// а держатель обязан судить и то, чего не знает. Здесь ни одна форма шаблона не
// названа: судится итоговое окружение каждого контейнера каждого рендера.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ИСПОЛНЯЕТСЯ
//
// Популяция берётся у продукта, а не у текста:
//
//   - ручки — таблица стража старта (`config.RequiredSettings`, `postureGuardRows`);
//   - посадки — объявленные чартом (`podEnvConditions`): накладка own и боевой
//     профиль без посадки;
//   - места, где ключ может стать именем, — КАЖДАЯ карта дерева значений
//     посадки. Дерево берёт сам helm: рендер копии чарта с шаблоном,
//     выводящим `.Values` целиком (`podEnvValuesDump`), — со слиянием профилей
//     и накладки, а не переложение слияния. В каждую карту кладётся свой
//     пробный ключ смешанного регистра (`podEnvCanary`): так видно и
//     приставку, и окончание, и смену регистра;
//   - исполнения — КАЖДЫЙ узел управления шаблонов принуждается: `if`, `with`,
//     `range`, `ternary` (`forceNodesIn`). Три исполнения на посадку: как есть;
//     каждая ветвь — then; каждая ветвь — else. Принуждение правит текст
//     шаблона по позициям разбора (узел `text/template/parse`), а не образцом:
//     условие `if` заменяется постоянной, `with` и `range` над пустым получают
//     непустое, у `ternary` условие постоянное; действие `fail` и функция
//     `required` в принуждённом исполнении молчат — вопрос принуждения «куда
//     ляжет ключ, если сюда дойдёт исполнение», а не «примет ли чарт этот
//     вход». Проход по пустому перечню получает пробный элемент своего узла
//     (`forcedRangeKey`): им судится и карта, которой нет в дереве значений ни
//     одной посадки. Суд стража (исход 1 ниже) идёт исполнением как есть —
//     принуждение его отказ заглушило бы.
//
// Разбор здесь даёт ПОЗИЦИИ узлов, и только их: какой узел меняет имя
// переменной и меняет ли вообще, решает рендер.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО СУДИТСЯ
//
// Имя каждой переменной окружения каждого контейнера (`containers`,
// `initContainers`, `ephemeralContainers`) каждого документа каждого рендера.
// Пробный ключ, оказавшийся в имени в ЛЮБОЙ форме (без учёта регистра),
// делает карту источником при этой посадке и этом исполнении. Исход у
// источника один из двух:
//
//  1. карту СУДИТ СТРАЖ шаблона: рендер как есть с каждой ручкой стража
//     ключом этой карты — отказ правилом тени, называющий ключ в карте и
//     каноническую координату; все ручки сразу — один перечень с числом. Тогда
//     каждое имя, в которое ушёл пробный ключ, обязано быть самим ключом
//     дословно: страж сравнивает ключ дословно, и любая другая форма
//     (приставка, окончание, регистр) пронесла бы ручку ключом, которого он не
//     узнаёт;
//  2. иначе — находка на каждое такое имя: посадка, исполнение, документ,
//     контейнер, форма. Карту, которую страж не судит, ключ не покидает
//     именем переменной НИ В КАКОЙ форме и НИ ПРИ КАКОМ исполнении ветвей:
//     форму, которую выбрало бы другое исполнение (значение, кластер, время),
//     рендер не называет, а ручка доходит до пода любой из них.
//
// Отказ принуждённого рендера чинится снятием принуждения с узла, ближайшего
// перед местом отказа (`forcedRender`); отказ разбора YAML места в шаблоне не
// называет, и виновный узел его файла ищется делением пополам (`yamlCulprit`). Каждый снятый узел называется в переписи; отказ, который так не
// чинится, — «не выполнилось» и находка, а не зелёное. Рендер как есть обязан
// пройти: иначе вердикта нет.
//
// ─────────────────────────────────────────────────────────────────────────────
// ГРАНИЦЫ, НАЗВАННЫЕ ВСЛУХ
//
//   - сочетания ветвей: исполнение, где одно условие обязано дать then, а
//     другое — else, судится, только если его даёт одно из трёх исполнений;
//     средняя ветвь `else if` — лишь когда её даёт исполнение как есть;
//   - выбор значением, а не условием (`default`, `coalesce`, `or`, `and` над
//     значениями) судится значениями дерева посадки;
//   - шаблон из строки (`tpl`) принуждению недоступен и исполняется как есть;
//     `ternary` принуждается в двух формах записи — тремя операндами и
//     условием конвейером; `fail` — действием из одной команды;
//   - узел, принуждение которого снято починкой, исполняется как есть — он
//     назван в переписи;
//   - имя, взятое из поля ЭЛЕМЕНТА перечня (392k), и `envFrom` — другой класс:
//     пробный элемент перечня строковый, и проход, читающий его поле, отказывает
//     и принуждения лишается;
//   - законный фильтр ключей (392s) принуждение не отличает от выключателя:
//     это находка, ложная тревога, а не молчание.
package deploy_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"text/template/parse"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// ── Посадки ──────────────────────────────────────────────────────────────────

// podEnvCondition — посадка поверх боевого профиля chartProfiles: накладка
// `--set`, при которой рендерится чарт.
type podEnvCondition struct {
	name    string
	overlay []string
}

// with — накладка посадки плюс названные `--set`; копия, а не общий срез.
func (c podEnvCondition) with(sets ...string) []string {
	return append(append([]string{}, c.overlay...), sets...)
}

// podEnvConditions — посадки, объявленные чартом. Первая — own: при ней тень
// ручки стража и есть дефект (#392). Вторая — боевой профиль БЕЗ посадки:
// профиль стоит на own (#424), и «как есть» совпал бы с первой; посадка,
// отличная от own, которую чарт рендерит, одна — незаявленная.
var podEnvConditions = []podEnvCondition{
	{name: "накладка own", overlay: ownPostureOverlay},
	{name: "боевой профиль без посадки", overlay: []string{identityProviderKnob + "="}},
}

// ── Исполнения ───────────────────────────────────────────────────────────────

// execState — исполнение шаблонов: как есть либо с принуждёнными ветвями.
type execState int

const (
	execAsIs execState = iota
	execThen
	execElse
)

var execStates = []execState{execAsIs, execThen, execElse}

func (s execState) String() string {
	switch s {
	case execThen:
		return "каждая ветвь — then"
	case execElse:
		return "каждая ветвь — else"
	}
	return "как есть"
}

// textEdit — правка текста шаблона: [at, end) заменяется text; at == end —
// вставка.
type textEdit struct {
	at, end int
	text    string
}

// forceNode — узел шаблона, который принуждение исполняет: правки на каждое
// принуждённое исполнение.
type forceNode struct {
	kind  string
	file  string
	coord string
	edits map[execState][]textEdit
}

// forcedRangeKey — пробный элемент прохода по ПУСТОМУ перечню узла id: ключ
// карты для `range $k, $v`, элемент перечня для прочих. Смешанный регистр и
// приставка `KANAME_` — по той же причине, что у podEnvCanary.
func forcedRangeKey(id int) string { return fmt.Sprintf("KANAME_QzForced%dQz", id) }

// podEnvCanary — пробный ключ карты i: смешанный регистр, чтобы имя
// переменной показало смену регистра, и приставка `KANAME_` — её пропускает
// фильтр, которым шаблон отбирал бы ключи-ручки (392q).
func podEnvCanary(i int) string { return fmt.Sprintf("KANAME_QzCanary%dQz", i) }

// scanActionEnd — конец выражения в действии шаблона с позиции from: первое на
// верхнем уровне скобок из stops (`|` конвейера, `)` объемлющей скобки) либо
// закрывающий разделитель действия. Строки, сырые строки и знаковые литералы
// пропускаются. Пробелы и маркер обрезки перед разделителем в выражение не
// входят.
func scanActionEnd(text string, from int, stops string) (int, error) {
	depth := 0
	for i := from; i < len(text); i++ {
		c := text[i]
		switch {
		case c == '"' || c == '\'':
			for i++; i < len(text) && text[i] != c; i++ {
				if text[i] == '\\' {
					i++
				}
			}
		case c == '`':
			j := strings.IndexByte(text[i+1:], '`')
			if j < 0 {
				return 0, fmt.Errorf("сырая строка с позиции %d не закрыта", i)
			}
			i += j + 1
		case c == '(':
			depth++
		case c == ')' && depth > 0:
			depth--
		case depth == 0 && (strings.IndexByte(stops, c) >= 0 || strings.HasPrefix(text[i:], "}}")):
			end := i
			if strings.HasPrefix(text[i:], "}}") && end > from && text[end-1] == '-' {
				end--
			}
			for end > from && (text[end-1] == ' ' || text[end-1] == '\t' || text[end-1] == '\n' || text[end-1] == '\r') {
				end--
			}
			return end, nil
		}
	}
	return 0, fmt.Errorf("конец выражения с позиции %d не найден", from)
}

// operandStarts — начала операндов команды [from, end) верхнего уровня скобок.
func operandStarts(text string, from, end int) []int {
	var starts []int
	depth, in := 0, false
	for i := from; i < end; i++ {
		c := text[i]
		if !in && c != ' ' && c != '\t' && c != '\n' && c != '\r' && depth == 0 {
			starts = append(starts, i)
			in = true
		}
		switch {
		case c == '"' || c == '\'':
			for i++; i < end && text[i] != c; i++ {
				if text[i] == '\\' {
					i++
				}
			}
		case c == '`':
			if j := strings.IndexByte(text[i+1:end], '`'); j >= 0 {
				i += j + 1
			}
		case c == '(':
			depth++
		case c == ')':
			depth--
		case (c == ' ' || c == '\t' || c == '\n' || c == '\r') && depth == 0:
			in = false
		}
	}
	return starts
}

// coordOf — «файл:строка:столбец» позиции pos в тексте файла.
func coordOf(file, text string, pos int) string {
	line := 1 + strings.Count(text[:pos], "\n")
	col := pos - (strings.LastIndex(text[:pos], "\n") + 1)
	return fmt.Sprintf("%s:%d:%d", file, line, col)
}

// forceNodesIn — узлы принуждения ВСЕХ шаблонов чарта (имя файла → текст):
// каждый `if`, `with`, `range`, `ternary`, `fail`-действие и `required`, с
// правками на каждое принуждённое исполнение. Файлы разбирает тот же
// text/template, которым их исполняет helm, одним множеством определений.
func forceNodesIn(files map[string]string) ([]*forceNode, error) {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	set := map[string]*parse.Tree{}
	var trees []*parse.Tree
	for _, n := range names {
		tr := parse.New(n)
		tr.Mode = parse.SkipFuncCheck
		if _, err := tr.Parse(files[n], "{{", "}}", set); err != nil {
			return nil, fmt.Errorf("шаблон %s не разобран: %w", n, err)
		}
		trees = append(trees, tr)
	}
	for _, n := range sortedTreeNames(set) {
		if _, isFile := files[n]; !isFile {
			trees = append(trees, set[n])
		}
	}

	var nodes []*forceNode
	var walkErr error
	add := func(kind, file string, pos int, edits map[execState][]textEdit) {
		nodes = append(nodes, &forceNode{kind: kind, file: file, coord: coordOf(file, files[file], pos), edits: edits})
	}
	pipeSpan := func(text string, p *parse.PipeNode) (int, int, bool) {
		if p == nil || len(p.Cmds) == 0 {
			return 0, 0, false
		}
		at := int(p.Cmds[0].Position())
		end, err := scanActionEnd(text, at, "")
		if err != nil {
			walkErr = err
			return 0, 0, false
		}
		return at, end, true
	}
	var walkPipe func(file string, p *parse.PipeNode, action bool)
	var walkArg func(file string, n parse.Node)
	walkArg = func(file string, n parse.Node) {
		switch x := n.(type) {
		case *parse.PipeNode:
			walkPipe(file, x, false)
		case *parse.ChainNode:
			walkArg(file, x.Node)
		}
	}
	walkPipe = func(file string, p *parse.PipeNode, action bool) {
		if p == nil {
			return
		}
		text := files[file]
		for i, c := range p.Cmds {
			id, isFunc := c.Args[0].(*parse.IdentifierNode)
			if isFunc {
				at := int(c.Position())
				switch id.Ident {
				case "ternary":
					switch {
					case i > 0 && len(c.Args) == 3:
						add("ternary", file, at, map[execState][]textEdit{
							execThen: {{at: at, end: at, text: "or true | "}},
							execElse: {{at: at, end: at, text: "and false | "}},
						})
					case len(c.Args) == 4:
						end, err := scanActionEnd(text, at, "|)")
						if err != nil {
							walkErr = err
							return
						}
						ops := operandStarts(text, at, end)
						if len(ops) != 4 {
							walkErr = fmt.Errorf("%s: у ternary операндов %d, а разбор называет 4", coordOf(file, text, at), len(ops))
							return
						}
						add("ternary", file, at, map[execState][]textEdit{
							execThen: {{at: ops[3], end: end, text: "true"}},
							execElse: {{at: ops[3], end: end, text: "false"}},
						})
					}
				case "required":
					idAt := int(id.Position())
					e := []textEdit{{at: idAt, end: idAt + len("required"), text: "default"}}
					add("required", file, idAt, map[execState][]textEdit{execThen: e, execElse: e})
				case "fail":
					if action && len(p.Cmds) == 1 && len(p.Decl) == 0 {
						if at, end, ok := pipeSpan(text, p); ok {
							e := []textEdit{{at: at, end: end, text: `""`}}
							add("fail", file, at, map[execState][]textEdit{execThen: e, execElse: e})
						}
					}
				}
			}
			for _, a := range c.Args {
				walkArg(file, a)
			}
		}
	}
	var walk func(file string, n parse.Node)
	walk = func(file string, n parse.Node) {
		text := files[file]
		switch x := n.(type) {
		case *parse.ListNode:
			if x == nil {
				return
			}
			for _, c := range x.Nodes {
				walk(file, c)
			}
		case *parse.ActionNode:
			walkPipe(file, x.Pipe, true)
		case *parse.TemplateNode:
			walkPipe(file, x.Pipe, false)
		case *parse.IfNode:
			if at, end, ok := pipeSpan(text, x.Pipe); ok {
				add("if", file, at, map[execState][]textEdit{
					execThen: {{at: at, end: end, text: "true"}},
					execElse: {{at: at, end: end, text: "false"}},
				})
			}
			walkPipe(file, x.Pipe, false)
			walk(file, x.List)
			walk(file, x.ElseList)
		case *parse.WithNode:
			if at, end, ok := pipeSpan(text, x.Pipe); ok {
				add("with", file, at, map[execState][]textEdit{
					execThen: {{at: at, end: at, text: "("}, {at: end, end: end, text: ") | default (dict \"qzForced\" true)"}},
					execElse: {{at: at, end: end, text: "false"}},
				})
			}
			walkPipe(file, x.Pipe, false)
			walk(file, x.List)
			walk(file, x.ElseList)
		case *parse.RangeNode:
			if at, end, ok := pipeSpan(text, x.Pipe); ok {
				key := forcedRangeKey(len(nodes))
				forced := fmt.Sprintf("list %q", key)
				if len(x.Pipe.Decl) == 2 {
					forced = fmt.Sprintf("dict %q (dict)", key)
				}
				e := []textEdit{{at: at, end: at, text: "("}, {at: end, end: end, text: ") | default (" + forced + ")"}}
				add("range", file, at, map[execState][]textEdit{execThen: e, execElse: e})
			}
			walkPipe(file, x.Pipe, false)
			walk(file, x.List)
			walk(file, x.ElseList)
		}
	}
	for _, tr := range trees {
		if tr.Root == nil {
			continue
		}
		file := tr.ParseName
		if _, ok := files[file]; !ok {
			return nil, fmt.Errorf("узел определения %s называет файл %q, которого в чарте нет", tr.Name, file)
		}
		walk(file, tr.Root)
		if walkErr != nil {
			return nil, walkErr
		}
	}
	return nodes, nil
}

func sortedTreeNames(set map[string]*parse.Tree) []string {
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// appliedEdit — правка, приложенная к тексту, и её узел.
type appliedEdit struct {
	textEdit
	node *forceNode
}

// applyForcing — тексты шаблонов при исполнении state без узлов из off: правки
// каждого узла, кроме правок внутри заменённого участка другого узла, по
// убыванию позиции. Возвращает и приложенные правки каждого файла по
// возрастанию — по ним место отказа принуждённого рендера сводится к узлу.
func applyForcing(files map[string]string, nodes []*forceNode, state execState, off map[*forceNode]bool) (map[string]string, map[string][]appliedEdit) {
	byFile := map[string][]appliedEdit{}
	for _, n := range nodes {
		if off[n] {
			continue
		}
		for _, e := range n.edits[state] {
			byFile[n.file] = append(byFile[n.file], appliedEdit{textEdit: e, node: n})
		}
	}
	out := map[string]string{}
	applied := map[string][]appliedEdit{}
	for file, text := range files {
		edits := byFile[file]
		var kept []appliedEdit
		for _, e := range edits {
			inside := false
			for _, r := range edits {
				if r.node == e.node || r.at >= r.end {
					continue
				}
				if (e.at == e.end && r.at < e.at && e.at < r.end) ||
					(e.at < e.end && r.at <= e.at && e.end <= r.end && (r.at != e.at || r.end != e.end)) {
					inside = true
					break
				}
			}
			if !inside {
				kept = append(kept, e)
			}
		}
		sort.SliceStable(kept, func(i, j int) bool {
			if kept[i].at != kept[j].at {
				return kept[i].at > kept[j].at
			}
			return kept[i].end > kept[j].end
		})
		for _, e := range kept {
			text = text[:e.at] + e.text + text[e.end:]
		}
		out[file] = text
		for i, j := 0, len(kept)-1; i < j; i, j = i+1, j-1 {
			kept[i], kept[j] = kept[j], kept[i]
		}
		applied[file] = kept
	}
	return out, applied
}

// originalOffset — позиция в исходном тексте для позиции forced в тексте с
// приложенными правками (по возрастанию).
func originalOffset(applied []appliedEdit, forced int) int {
	delta := 0
	for _, e := range applied {
		fs := e.at + delta
		if forced < fs {
			break
		}
		if forced < fs+len(e.text) {
			return e.at
		}
		delta += len(e.text) - (e.end - e.at)
	}
	return forced - delta
}

// renderRefusalAt — файл шаблонов и позиция, которые называет отказ helm:
// последнее место `…/templates/<файл>:<строка>:<столбец>` исполнения либо файл
// отказа разбора YAML (позиции у него нет — pos < 0).
var (
	renderRefusalAtRe  = regexp.MustCompile(`/templates/([^:\s()"]+):(\d+):(\d+)`)
	renderRefusalYAMLe = regexp.MustCompile(`YAML parse error on [^\s]*/templates/([^:\s()"]+)`)
)

func renderRefusalAt(out string, texts map[string]string) (file string, pos int, ok bool) {
	// Отказ include из другого шаблона называет цепочку мест; виновно
	// последнее — самое глубокое.
	if all := renderRefusalAtRe.FindAllStringSubmatch(out, -1); len(all) > 0 {
		m := all[len(all)-1]
		text, known := texts[m[1]]
		if !known {
			return "", 0, false
		}
		line, _ := strconv.Atoi(m[2])
		col, _ := strconv.Atoi(m[3])
		at := 0
		for l := 1; l < line; l++ {
			j := strings.IndexByte(text[at:], '\n')
			if j < 0 {
				return "", 0, false
			}
			at += j + 1
		}
		return m[1], at + col, true
	}
	if m := renderRefusalYAMLe.FindStringSubmatch(out); m != nil {
		if _, known := texts[m[1]]; known {
			return m[1], -1, true
		}
	}
	return "", 0, false
}

// ── Рабочая копия чарта ──────────────────────────────────────────────────────

// podEnvValuesDump — шаблон, которым helm отдаёт дерево значений посадки
// целиком: слияние профилей и накладки делает он сам.
const (
	podEnvValuesDumpFile = "zz-qz-values-dump.yaml"
	podEnvValuesDump     = "---\nqzValuesDump: {{ toJson .Values | quote }}\n"
	podEnvProbesFile     = "qz-probes.yaml"
)

// podEnvWork — рабочая копия чарта держателя: исходные шаблоны и узлы
// принуждения; каталог каждого исполнения — отдельный.
type podEnvWork struct {
	src      string
	files    map[string]string
	nodes    []*forceNode
	dirs     map[execState]string
	off      map[execState]map[*forceNode]bool
	applied  map[execState]map[string][]appliedEdit
	repaired map[execState][]string
	renders  int
}

// newPodEnvWork копирует чарт каталога src (Chart.yaml, значения, шаблоны) в
// каталог на каждое исполнение и разбирает шаблоны на узлы принуждения.
func newPodEnvWork(t *testing.T, src string) *podEnvWork {
	t.Helper()
	w := &podEnvWork{src: src, files: map[string]string{}, dirs: map[execState]string{},
		off: map[execState]map[*forceNode]bool{}, applied: map[execState]map[string][]appliedEdit{},
		repaired: map[execState][]string{}}
	entries, err := os.ReadDir(filepath.Join(src, "templates"))
	require.NoError(t, err, "каталог шаблонов чарта %s не прочитан", src)
	for _, e := range entries {
		if e.IsDir() || (filepath.Ext(e.Name()) != ".yaml" && filepath.Ext(e.Name()) != ".tpl") {
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(src, "templates", e.Name())) // #nosec G304 -- путь из дерева чарта либо t.TempDir
		require.NoError(t, rerr)
		w.files[e.Name()] = string(b)
	}
	require.NotEmpty(t, w.files, "в каталоге шаблонов %s ни одного шаблона — исполнять нечего", src)
	w.nodes, err = forceNodesIn(w.files)
	require.NoError(t, err, "узлы принуждения не выведены")

	top, err := os.ReadDir(src)
	require.NoError(t, err)
	for _, st := range execStates {
		dir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "templates"), 0o750))
		for _, e := range top {
			if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
				continue
			}
			b, rerr := os.ReadFile(filepath.Join(src, e.Name())) // #nosec G304 -- путь из дерева чарта либо t.TempDir
			require.NoError(t, rerr)
			require.NoError(t, os.WriteFile(filepath.Join(dir, e.Name()), b, 0o600))
		}
		w.dirs[st] = dir
		w.off[st] = map[*forceNode]bool{}
		w.writeState(t, st)
	}
	require.NoError(t, os.WriteFile(filepath.Join(w.dirs[execAsIs], "templates", podEnvValuesDumpFile), []byte(podEnvValuesDump), 0o600))
	return w
}

// writeState пишет шаблоны исполнения st: как есть — исходные, иначе —
// принуждённые без снятых узлов.
func (w *podEnvWork) writeState(t *testing.T, st execState) {
	t.Helper()
	texts := w.files
	if st != execAsIs {
		texts, w.applied[st] = applyForcing(w.files, w.nodes, st, w.off[st])
	}
	for name, text := range texts {
		require.NoError(t, os.WriteFile(filepath.Join(w.dirs[st], "templates", name), []byte(text), 0o600))
	}
}

// render — рендер исполнения st при посадке cond с пробами probes (дерево
// значений поверх профилей; nil — без проб) и `--set` sets.
func (w *podEnvWork) render(t *testing.T, st execState, cond podEnvCondition, probes map[string]any, sets ...string) (string, error) {
	t.Helper()
	files := append([]string{}, chartProfiles...)
	probePath := filepath.Join(w.dirs[st], podEnvProbesFile)
	if probes != nil {
		b, err := json.Marshal(probes)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(probePath, b, 0o600))
		files = append(files, podEnvProbesFile)
	}
	w.renders++
	out, err := renderChartAtAllowingFailure(t, w.dirs[st], files, cond.with(sets...)...)
	if probes != nil {
		require.NoError(t, os.Remove(probePath))
	}
	return out, err
}

// forcedRender — рендер принуждённого исполнения. Отказ чинится снятием
// принуждения с узла, чья правка стоит ближе всего перед местом отказа
// (отказ разбора YAML места не называет — снимается последний узел файла), и
// снятый узел называется в переписи; отказ, который так не чинится, — ошибка:
// исполнение не выполнилось.
func (w *podEnvWork) forcedRender(t *testing.T, st execState, cond podEnvCondition, probes map[string]any) (string, error) {
	t.Helper()
	for {
		out, err := w.render(t, st, cond, probes)
		if err == nil || st == execAsIs {
			return out, err
		}
		texts, _ := applyForcing(w.files, w.nodes, st, w.off[st])
		file, pos, ok := renderRefusalAt(out, texts)
		if !ok {
			return out, fmt.Errorf("принуждённое исполнение «%s» (%s) отказало, и место отказа не называет файл шаблонов: %w", st, cond.name, err)
		}
		var drop *forceNode
		if pos >= 0 {
			orig := originalOffset(w.applied[st][file], pos)
			for _, e := range w.applied[st][file] {
				if e.at <= orig {
					drop = e.node
				}
			}
		} else {
			drop = w.yamlCulprit(t, st, cond, probes, file)
		}
		if drop == nil {
			return out, fmt.Errorf("принуждённое исполнение «%s» (%s) отказало в %s, и снятие принуждения с узлов этого файла отказа не чинит: %w", st, cond.name, file, err)
		}
		w.off[st][drop] = true
		w.repaired[st] = append(w.repaired[st], fmt.Sprintf("%s %s (%s)", drop.kind, drop.coord, cond.name))
		w.writeState(t, st)
	}
}

// yamlCulprit — узел файла file, принуждение которого делает документ не
// читаемым как YAML: отказ разбора места в шаблоне не называет, и узел
// ищется делением пополам — наименьшее k, при котором снятие первых k узлов
// файла чинит рендер; виновен k-й. Снятие всех узлов файла не чинит — nil.
func (w *podEnvWork) yamlCulprit(t *testing.T, st execState, cond podEnvCondition, probes map[string]any, file string) *forceNode {
	t.Helper()
	var order []*forceNode
	seen := map[*forceNode]bool{}
	for _, e := range w.applied[st][file] {
		if !seen[e.node] {
			seen[e.node] = true
			order = append(order, e.node)
		}
	}
	base := w.off[st]
	fixedBy := func(k int) bool {
		off := map[*forceNode]bool{}
		for n := range base {
			off[n] = true
		}
		for _, n := range order[:k] {
			off[n] = true
		}
		w.off[st] = off
		w.writeState(t, st)
		_, err := w.render(t, st, cond, probes)
		return err == nil
	}
	defer func() { w.off[st] = base; w.writeState(t, st) }()
	if len(order) == 0 || !fixedBy(len(order)) {
		return nil
	}
	lo, hi := 1, len(order)
	for lo < hi {
		mid := (lo + hi) / 2
		if fixedBy(mid) {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	return order[lo-1]
}

// ── Дерево значений и пробы ──────────────────────────────────────────────────

// valuesTreeAt — дерево значений посадки cond, каким его сливает helm.
func (w *podEnvWork) valuesTreeAt(t *testing.T, cond podEnvCondition) map[string]any {
	t.Helper()
	out, err := w.render(t, execAsIs, cond, nil)
	require.NoErrorf(t, err, "чарт при посадке «%s» не рендерится как есть — вердикта нет:\n%s", cond.name, headOf(out))
	var tree map[string]any
	forEachDoc(t, out, func(doc map[string]any) {
		if s, ok := doc["qzValuesDump"].(string); ok {
			require.NoError(t, json.Unmarshal([]byte(s), &tree))
		}
	})
	require.NotNil(t, tree, "рендер не отдал дерева значений посадки «%s»", cond.name)
	return tree
}

// valuesMaps — пути всех карт дерева (корень — пустой путь), отсортированно.
func valuesMaps(tree map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	var visit func(path string, m map[string]any)
	visit = func(path string, m map[string]any) {
		out[path] = m
		for k, v := range m {
			if sub, ok := v.(map[string]any); ok {
				p := k
				if path != "" {
					p = path + "." + k
				}
				visit(p, sub)
			}
		}
	}
	visit("", tree)
	return out
}

// probeShape — значение пробного элемента карты m: карта с полями первого
// элемента-карты (значения полей от ключа не зависят), иначе строка value.
func probeShape(m map[string]any, value string) any {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if sub, ok := m[k].(map[string]any); ok && len(sub) > 0 {
			shaped := map[string]any{}
			for f := range sub {
				shaped[f] = "qz-" + strings.ToLower(f)
			}
			return shaped
		}
	}
	return value
}

// probeTree — дерево проб: под каждым путём из keys — ключи со значениями.
func probeTree(entries map[string]map[string]any) map[string]any {
	root := map[string]any{}
	for path, kv := range entries {
		node := root
		if path != "" {
			for _, seg := range strings.Split(path, ".") {
				next, ok := node[seg].(map[string]any)
				if !ok {
					next = map[string]any{}
					node[seg] = next
				}
				node = next
			}
		}
		for k, v := range kv {
			node[k] = v
		}
	}
	return root
}

// ── Окружение контейнеров ────────────────────────────────────────────────────

// podEnvEntry — переменная окружения контейнера в документе рендера.
type podEnvEntry struct {
	doc, container, name string
}

// podEnvEntries — переменные окружения каждого контейнера каждого документа
// рендера и число контейнеров.
func podEnvEntries(rendered string) (entries []podEnvEntry, containers int, err error) {
	docs, err := decodeDocs(rendered)
	if err != nil {
		return nil, 0, err
	}
	if len(docs) == 0 {
		return nil, 0, fmt.Errorf("рендер не дал ни одного документа")
	}
	for _, doc := range docs {
		meta, _ := doc["metadata"].(map[string]any)
		docName := fmt.Sprintf("%v/%v", doc["kind"], meta["name"])
		var visit func(any)
		visit = func(n any) {
			switch x := n.(type) {
			case map[string]any:
				for k, v := range x {
					if list, ok := v.([]any); ok && (k == "containers" || k == "initContainers" || k == "ephemeralContainers") {
						for _, c := range list {
							cm, _ := c.(map[string]any)
							containers++
							env, _ := cm["env"].([]any)
							for _, e := range env {
								if em, ok := e.(map[string]any); ok {
									if name, ok := em["name"].(string); ok {
										entries = append(entries, podEnvEntry{doc: docName,
											container: fmt.Sprintf("%s %v", k, cm["name"]), name: name})
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
		visit(doc)
	}
	return entries, containers, nil
}

// podEnvSighting — пробный ключ в имени переменной окружения контейнера.
type podEnvSighting struct {
	probe string // путь карты либо координата прохода
	key   string // пробный ключ
	cond  podEnvCondition
	state execState
	entry podEnvEntry
}

// form — как ключ стал именем: приставка и окончание вокруг ключа и регистр.
func (s podEnvSighting) form() string {
	up := strings.ToUpper(s.entry.name)
	at := strings.Index(up, strings.ToUpper(s.key))
	f := s.entry.name[:at] + "<ключ>" + s.entry.name[at+len(s.key):]
	if s.entry.name[at:at+len(s.key)] != s.key {
		f += " (регистр ключа изменён)"
	}
	return f
}

// mapLabel — как находка называет карту дерева значений: путь либо корень.
func mapLabel(path string) string {
	if path == "" {
		return "(корень значений)"
	}
	return path
}

func (s podEnvSighting) where() string {
	return fmt.Sprintf("посадка «%s», исполнение «%s», %s, %s", s.cond.name, s.state, s.entry.doc, s.entry.container)
}

// ── Держатель ────────────────────────────────────────────────────────────────

// podEnvCensus — объём осмотренного.
type podEnvCensus struct {
	conds, maps, renders, containers, names int
	nodes                                   map[string]int
	repaired                                []string
	sources                                 []string
}

func (c podEnvCensus) String() string {
	kinds := make([]string, 0, len(c.nodes))
	total := 0
	for k, n := range c.nodes {
		kinds = append(kinds, fmt.Sprintf("%s %d", k, n))
		total += n
	}
	sort.Strings(kinds)
	return fmt.Sprintf("посадок %d · исполнений на посадку %d · узлов принуждения %d (%s) · принуждение снято починкой %d %v · "+
		"карт дерева значений %d · рендеров %d · контейнеров %d · имён переменных %d · источников %d %v",
		c.conds, len(execStates), total, strings.Join(kinds, " · "), len(c.repaired), c.repaired,
		c.maps, c.renders, c.containers, c.names, len(c.sources), c.sources)
}

// judgePodEnvByExecution судит чарт каталога dir при посадках conds. Ошибка —
// «не выполнилось»: пустой обход и рендер, который не прошёл как есть.
func judgePodEnvByExecution(t *testing.T, dir string, conds []podEnvCondition) (findings []string, census podEnvCensus, err error) {
	t.Helper()
	census.conds = len(conds)
	if len(conds) == 0 {
		return nil, census, fmt.Errorf("не выполнилось: посадок ноль — «ни одной тени» значило бы «ни одного рендера»")
	}
	rows := postureGuardRows(t)
	w := newPodEnvWork(t, dir)
	census.nodes = map[string]int{}
	for _, n := range w.nodes {
		census.nodes[n.kind]++
	}

	// Пробные ключи: у каждой карты дерева любой посадки — свой.
	trees := make([]map[string]map[string]any, len(conds))
	all := map[string]bool{}
	for i, cond := range conds {
		trees[i] = valuesMaps(w.valuesTreeAt(t, cond))
		for p := range trees[i] {
			all[p] = true
		}
	}
	paths := make([]string, 0, len(all))
	for p := range all {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	census.maps = len(paths)
	if len(paths) == 0 {
		return nil, census, fmt.Errorf("не выполнилось: в дереве значений ни одной карты")
	}
	canaryOf := map[string]string{}
	pathOf := map[string]string{}
	for i, p := range paths {
		canaryOf[p] = podEnvCanary(i)
		pathOf[strings.ToUpper(podEnvCanary(i))] = p
	}
	type forcedProbe struct{ probe, key string }
	forcedOf := map[string]forcedProbe{}
	for i, n := range w.nodes {
		if n.kind == "range" {
			forcedOf[strings.ToUpper(forcedRangeKey(i))] = forcedProbe{probe: "проход " + n.coord, key: forcedRangeKey(i)}
		}
	}

	var sightings []podEnvSighting
	for ci, cond := range conds {
		entries := map[string]map[string]any{}
		for _, p := range paths {
			if m, ok := trees[ci][p]; ok {
				entries[p] = map[string]any{canaryOf[p]: probeShape(m, "qzvalue")}
			}
		}
		probes := probeTree(entries)
		for _, st := range execStates {
			out, rerr := w.forcedRender(t, st, cond, probes)
			if rerr != nil || (st == execAsIs && out == "") {
				if st == execAsIs {
					return nil, census, fmt.Errorf("не выполнилось: чарт с пробами при посадке «%s» не рендерится как есть: %v\n%s", cond.name, rerr, headOf(out))
				}
				findings = append(findings, fmt.Sprintf("не выполнилось: %v\n%s", rerr, headOf(out)))
				continue
			}
			got, containers, perr := podEnvEntries(out)
			if perr != nil {
				if st == execAsIs {
					return nil, census, fmt.Errorf("не выполнилось: рендер посадки «%s» как есть не прочитан: %w", cond.name, perr)
				}
				findings = append(findings, fmt.Sprintf("не выполнилось: исполнение «%s», посадка «%s»: %v", st, cond.name, perr))
				continue
			}
			if st == execAsIs {
				if containers == 0 {
					return nil, census, fmt.Errorf("не выполнилось: рендер посадки «%s» не дал ни одного контейнера — судить нечего", cond.name)
				}
				census.containers += containers
			}
			census.names += len(got)
			for _, e := range got {
				up := strings.ToUpper(e.name)
				for key, probe := range pathOf {
					if strings.Contains(up, key) {
						sightings = append(sightings, podEnvSighting{probe: probe, key: canaryOf[probe], cond: cond, state: st, entry: e})
					}
				}
				for key, f := range forcedOf {
					if strings.Contains(up, key) {
						sightings = append(sightings, podEnvSighting{probe: f.probe, key: f.key, cond: cond, state: st, entry: e})
					}
				}
			}
		}
	}
	for _, st := range execStates {
		census.repaired = append(census.repaired, w.repaired[st]...)
	}

	// Источник — проба, дошедшая до имени; судит ли его страж — рендер как
	// есть с каждой ручкой ключом этой карты при каждой посадке, где он найден.
	type sourceAt struct{ probe, cond string }
	seen := map[sourceAt]bool{}
	bySource := map[string][]podEnvSighting{}
	var order []string
	for _, s := range sightings {
		if bySource[s.probe] == nil {
			order = append(order, s.probe)
		}
		bySource[s.probe] = append(bySource[s.probe], s)
	}
	sort.Strings(order)
	for _, probe := range order {
		ss := bySource[probe]
		forms := map[string]bool{}
		for _, s := range ss {
			forms[s.form()] = true
		}
		census.sources = append(census.sources, fmt.Sprintf("%s %v", mapLabel(probe), sortedSet(forms)))
		if strings.HasPrefix(probe, "проход ") {
			for _, s := range ss {
				findings = append(findings, fmt.Sprintf("%s: ключ перечня, которого нет в дереве значений ни одной посадки, стал именем "+
					"переменной пода формой %s — %s; ни проба, ни страж посадки такой перечень не судят: объявите его в values.yaml",
					probe, s.form(), s.where()))
			}
			continue
		}
		for _, s := range ss {
			at := sourceAt{probe, s.cond.name}
			if seen[at] {
				continue
			}
			seen[at] = true
			ci := 0
			for i, c := range conds {
				if c.name == s.cond.name {
					ci = i
				}
			}
			guarded, gfs := judgeGuardOf(t, w, s.cond, probe, trees[ci][probe], rows)
			findings = append(findings, gfs...)
			for _, o := range ss {
				if o.cond.name != s.cond.name {
					continue
				}
				switch {
				case !guarded:
					findings = append(findings, fmt.Sprintf("%s: ключ карты стал именем переменной пода формой %s — %s, а страж посадки "+
						"эту карту не судит: ручка стража дойдёт до пода той же дорогой", mapLabel(probe), o.form(), o.where()))
				case o.entry.name != o.key:
					findings = append(findings, fmt.Sprintf("%s: страж судит ключ карты дословно, а именем переменной пода он стал "+
						"формой %s — %s: ручка дойдёт до пода ключом, которого страж не узнаёт", mapLabel(probe), o.form(), o.where()))
				}
			}
		}
	}
	census.renders = w.renders
	if len(order) == 0 {
		return findings, census, fmt.Errorf("не выполнилось: ни одна проба не стала именем переменной пода — суд теней судил бы пустое множество")
	}

	// Близнец: ручка, которую страж шаблона не судит, в окружении пода —
	// рендер. Иначе правило шире своего предмета.
	out, rerr := w.render(t, execAsIs, conds[0], nil, "env.KANAME_AUTHN__DOMAIN=access.example.invalid")
	census.renders = w.renders
	if rerr != nil {
		findings = append(findings, fmt.Sprintf("близнец env.KANAME_AUTHN__DOMAIN: ручка, которую страж шаблона не судит, отвергнута — "+
			"правило шире своего предмета:\n%s", headOf(out)))
	}
	sort.Strings(findings)
	return findings, census, nil
}

// judgeGuardOf — судит ли страж шаблона карту path при посадке cond: рендер как
// есть с каждой ручкой ключом карты — отказ правилом тени, называющий ключ в
// карте и координату ручки; все ручки сразу — один перечень с числом. Ложь —
// хоть одна ручка прошла; находки — рендер, положивший ручку в под, и отказ не
// тем правилом либо без координаты.
func judgeGuardOf(t *testing.T, w *podEnvWork, cond podEnvCondition, path string, m map[string]any, rows []postureGuardRow) (bool, []string) {
	t.Helper()
	guarded := true
	var findings []string
	all := map[string]any{}
	for _, r := range rows {
		v := probeShape(m, r.value)
		all[r.env] = v
		out, err := w.render(t, execAsIs, cond, probeTree(map[string]map[string]any{path: {r.env: v}}))
		switch {
		case err == nil:
			guarded = false
			entries, _, perr := podEnvEntries(out)
			if perr != nil {
				findings = append(findings, fmt.Sprintf("%s.%s: рендер прошёл, а не прочитан (посадка «%s»): %v", path, r.env, cond.name, perr))
			}
			for _, e := range entries {
				if e.name == r.env {
					findings = append(findings, fmt.Sprintf("%s.%s: рендер прошёл — ручка стража посадки уехала в окружение пода — "+
						"посадка «%s», %s, %s", path, r.env, cond.name, e.doc, e.container))
				}
			}
		case !strings.Contains(out, postureShadowMark):
			guarded = false
			findings = append(findings, fmt.Sprintf("%s.%s: рендер отказал, но не правилом тени (нет %q), посадка «%s»:\n%s",
				path, r.env, postureShadowMark, cond.name, headOf(out)))
		case !strings.Contains(out, path+"."+r.env) || !strings.Contains(out, r.knob):
			findings = append(findings, fmt.Sprintf("%s.%s: отказ не называет ключ в карте и координату %s, посадка «%s»:\n%s",
				path, r.env, r.knob, cond.name, headOf(out)))
		}
	}
	if !guarded {
		return false, findings
	}
	out, err := w.render(t, execAsIs, cond, probeTree(map[string]map[string]any{path: all}))
	switch {
	case err == nil:
		findings = append(findings, fmt.Sprintf("%s (все ручки сразу): рендер прошёл, посадка «%s»", path, cond.name))
	case !strings.Contains(out, fmt.Sprintf("— %d.", len(rows))):
		findings = append(findings, fmt.Sprintf("%s (все ручки сразу): отказ не называет число теней %d, посадка «%s»:\n%s",
			path, len(rows), cond.name, headOf(out)))
	}
	return true, findings
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// decodeDocs — документы рендера. В отличие от forEachDoc, документ, не
// читаемый как YAML, — ошибка, а не конец чтения: иначе контейнеры
// документов после него выпали бы из суда молча.
func decodeDocs(rendered string) ([]map[string]any, error) {
	dec := yaml.NewDecoder(strings.NewReader(rendered))
	var docs []map[string]any
	for {
		var doc map[string]any
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return docs, nil
		}
		if err != nil {
			return docs, fmt.Errorf("документ %d рендера не читается как YAML: %w", len(docs)+1, err)
		}
		if doc != nil {
			docs = append(docs, doc)
		}
	}
}
