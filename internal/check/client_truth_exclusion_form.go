// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// client_truth_exclusion_form.go — извлечение для гейта «форма взаимоисключения,
// НАЗВАННАЯ оператору, есть та, которой оно держится» (задача #17, порт-ПОЛОВИНА
// семейства `clienttruth_kaname_exclusion_form` с монорепо
// `internal/repohygiene/clienttruth_kaname_exclusion_form.go`, снятого выносом
// службы — `kacho#2597`).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Назваться на публичном слушателе Kaname можно двумя способами: предъявить
// удостоверение самому либо получить личность от нашего края. Способы
// взаимоисключающи, и держится это ПОСТРОЕНИЕМ, а не проверкой.
//
// Держалось оно не всегда так. Прежняя редакция требовала ОТВЕРГАТЬ запрос,
// несущий обе формы, — и эта проверка отвергала бы каждый запрос, проксированный
// нашим же краем, потому что сочетание производил он сам. Ветвь отказа снята
// вместе со своим предметом; страница оператора об этом узнать не могла — она
// не собирается и ничего не импортирует.
//
// ─────────────────────────────────────────────────────────────────────────────
// ДВА УТВЕРЖДЕНИЯ, И ВТОРОЕ ПОЛОЖИТЕЛЬНОЕ
//
//	A. отказ, ОБЕЩАННЫЙ страницей, обязан иметь производителя в не-тестовом коде
//	   читателя. Обещание без производителя — утверждение, пережившее свой
//	   предмет: оператор ждёт отказа, которого служба не делает;
//	B. пока построение живо, страница обязана НАЗЫВАТЬ его.
//
// Второе — положительное, и это не стилистика. Отрицание («страница не говорит
// такого-то слова») ЗАМОЛКАЕТ при первой же переформулировке: вход, на котором
// оно находит нарушение, перестаёт быть представимым, а ветвь остаётся в коде и
// вердикт остаётся зелёным — а отличить это от исправной работы нельзя ничем,
// потому что обе стороны печатают ноль находок. Утверждение B умолкнуть не
// может: оно краснеет ровно тогда, когда объяснение исчезает.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО РАЗРЕЗ СДЕЛАЛ С УТВЕРЖДЕНИЕМ B — И ПОЧЕМУ ЭТО НЕ ОСЛАБЛЕНИЕ
//
// Взаимоисключение держат ДВА построения, по одному на сторону провода, и
// разрез развёл их по репозиториям:
//
//	СНЯТИЕ у края   — край снимает арендаторское удостоверение перед пересылкой
//	                  за себя. Замер этого дерева: `git ls-files gateway | wc -l`
//	                  → 0; `git grep -l StripPresentedCredential` → 0. Живёт в
//	                  `PRO-Robotech/kacho`.
//	ОБЁРТКА у нас   — читатель предъявленного удостоверения НАКРЫВАЕТ пару
//	                  звеньев переданной личности и решает по её вердикту, а не
//	                  становится с ней в цепочку. Живёт ЗДЕСЬ.
//
// Предок брал премисой первое, потому что оба лежали в одном дереве. Здесь
// премисой берётся ВТОРОЕ — наша половина построения, и она судится тем же
// разбором, что и всё остальное.
//
// Это НЕ ослабление предмета, а смена ОПЕРАНДА ПРЕМИСЫ: утверждение B осталось
// прежним («построение живо ⇒ страница его называет»), сменилось то, чем
// доказывается «живо». Судить снятие у края отсюда было бы можно только чтением
// чужого репозитория с диска — тогда вердикт стал бы свойством того, что
// случайно лежит в кеше машины прогона, а не свойством коммита ни одного из двух
// деревьев.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ОБЁРТКА — ИМЕННО ПОСТРОЕНИЕ, А НЕ ПРОВЯЗКА
//
// Носитель личности платформы устроен так, что снятие имеет приоритет над любым
// последующим назначением. Читатель, поставленный ПОСЛЕ пары, назначил бы
// вызывающего, и назначение молча не доехало бы до обработчика. Поэтому читатель
// прогоняет пару САМ и решает по её вердикту — решение о том, КТО звонит,
// принимается в одном месте, и сочетания двух форм не возникает by construction.
//
// Разомкни обёртку — и взаимоисключение перестаёт держаться построением на нашей
// стороне, то есть страница начинает объяснять механизм, которого нет. Ровно это
// утверждение B и стережёт.
//
// ─────────────────────────────────────────────────────────────────────────────
// РАСПОЗНАВАТЕЛИ — ЧЕМ СУДЯТ, И ПОЧЕМУ НЕ ПОДСТРОКОЙ ПО ФАЙЛУ
//
// Сторона ДЕРЕВА судится РАЗБОРОМ, а не текстом, и это несущее: файл читателя
// несёт НАДГРОБИЕ снятой ветви — связный абзац по-русски о том самом сочетании
// форм, — и проверка по подстроке объявила бы живым ровно то, что снято:
// предикат, судящий СЛОВО вместо УЗЛА, находит собственное объяснение.
// Поэтому считаются УЗЛЫ-ВЫЗОВЫ и литеральные аргументы, а комментарии не
// читаются вовсе.
//
// Сообщение отказа собирают конкатенацией (`refuse("… " + err.Error())`),
// поэтому разбор аргументов идёт по дереву выражения: читатель одиночного
// литерала такое сообщение НЕ УВИДЕЛ БЫ — то есть дал бы молчание вместо
// вердикта.
//
// Сторона СТРАНИЦЫ судится по абзацу — прозы иначе не судить, и это сказано
// прямо, а не спрятано. Смягчает три вещи:
//
//   - корень предмета один и это ИМЯ предмета (`взаимоисключ`), а не оборот
//     речи: переформулировать объяснение, не назвав предмета, значит перестать
//     его объяснять, и это ловит утверждение B;
//   - регистр снимается. Страница пишет `ОБЕ` прописными, и предикат, читающий
//     написанное, промолчал бы на живом производителе;
//   - вердикт выносится ПОАБЗАЦНО. Соседний абзац той же страницы законно
//     говорит об отказе — о единообразии его текста, — и файл целиком читать
//     нельзя: отказ соседа зачёлся бы обещанием предмета.
package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/PRO-Robotech/corelib/treecorpus"
)

// ExclusionGuideRel — страница установки: то, что читает оператор.
const ExclusionGuideRel = "INSTALL.md"

// ExclusionReaderDirRel — не-тестовый код читателя предъявленного удостоверения.
const ExclusionReaderDirRel = "internal/presentedcred"

// ExclusionReaderDeclFileRel — файл, ОБЪЯВЛЯЮЩИЙ обёртку.
//
// Его собственные определения вызовами не являются: объявление без вызывающего
// механизма не даёт — ровно тот класс, ради которого предок отделял объявление
// снятия от его вызовов.
const ExclusionReaderDeclFileRel = "internal/presentedcred/reader.go"

// ExclusionRefuseFunc — имя конструктора отказа читателя.
const ExclusionRefuseFunc = "refuse"

// ExclusionWrapFuncs — имена, которыми читатель НАКРЫВАЕТ пару звеньев
// переданной личности. Обе полосы вызова: одиночная и потоковая.
var ExclusionWrapFuncs = []string{"UnaryOver", "StreamOver"}

// ExclusionCoPresenceTerms — слова, которыми сообщение отказа называет
// СОЧЕТАНИЕ двух форм.
//
// Требуются ВСЕ: отказ, назвавший одну форму, — про неё одну. Сообщения отказа
// читателя английские, поэтому и слова английские.
var ExclusionCoPresenceTerms = []string{"presented", "forwarded"}

// ExclusionEdgeStripHome — дерево и файл, где живёт ВТОРАЯ половина построения.
const ExclusionEdgeStripHome = "PRO-Robotech/kacho:gateway/internal/principalmeta/credential_strip.go"

// exclusionSubjectRoots — корень имени предмета.
//
// Один и именно этот: `взаимоисключ` есть ИМЯ предмета, а не оборот речи. Им
// зовут его и приёмка, и надгробие снятой ветви.
var exclusionSubjectRoots = []string{"взаимоисключ"}

// exclusionRefusalRoots — чем абзац обещает ОТКАЗ службы.
var exclusionRefusalRoots = []string{"отверга", "отказыва", "не принима", "получает отказ"}

// exclusionBuildRoots — чем абзац называет ПОСТРОЕНИЕ.
//
// Оборот «не несёт» сюда НЕ входит намеренно — им равно описывается и мир
// проверки («запрос несёт обе формы»), и мир построения, а маркер, годный для
// обоих миров, не различает ничего.
var exclusionBuildRoots = []string{"снима", "снят", "не пересыла", "накрыва", "построением"}

// ExclusionFormInput — что судить.
//
// Координаты и тела приходят параметрами, а не читаются внутри: инъекция подаёт
// синтетику тем же входом, что и гейт — настоящее дерево.
type ExclusionFormInput struct {
	GuideRel  string
	GuideBody string
	// ReaderFiles — не-тестовые файлы читателя: координата → исходник.
	ReaderFiles map[string]string
	// WrapFiles — не-тестовый код, в котором ищутся обращения-обёртки.
	// Объявляющий файл читателя вызывающим не считается.
	WrapFiles map[string]string
}

// ExclusionFormCensus — объём осмотренного, по ОБЕИМ сторонам.
type ExclusionFormCensus struct {
	GuideParagraphs   int
	SubjectParagraphs int
	ExplainByRefusal  int
	ExplainByBuild    int

	ReaderGoFiles      int
	RefuseCalls        int
	CoPresenceRefusals int

	WrapGoFiles int
	WrapCalls   int
	WrapSites   []string
}

// ExclusionFormFinding — одно расхождение страницы с деревом.
type ExclusionFormFinding struct {
	// Kind — "refusal-without-producer" | "construction-unnamed".
	Kind string
	Rel  string
	// Line — первая строка абзаца предмета; 0, когда абзаца предмета нет вовсе.
	Line    int
	Excerpt string
}

func (f ExclusionFormFinding) String() string {
	where := f.Rel
	if f.Line > 0 {
		where = fmt.Sprintf("%s:%d", f.Rel, f.Line)
	}
	switch f.Kind {
	case "refusal-without-producer":
		return fmt.Sprintf("%s — страница обещает оператору ОТКАЗ на сочетании двух форм "+
			"личности, а производителя такого отказа в не-тестовом коде читателя НЕТ: %q",
			where, f.Excerpt)
	case "construction-unnamed":
		return fmt.Sprintf("%s — читатель НАКРЫВАЕТ пару звеньев переданной личности и решает "+
			"по её вердикту, то есть взаимоисключение держится построением, а страница им "+
			"не объясняет: %q", where, f.Excerpt)
	default:
		return fmt.Sprintf("%s — %s: %q", where, f.Kind, f.Excerpt)
	}
}

// AuditExclusionForm сверяет форму взаимоисключения, названную оператору, с той,
// которой оно держится в этом дереве.
// ExclusionFormGoCorpus — непроверочные файлы Go дерева: и сторона отказа, и
// сторона обёртки берутся из одного обхода.
//
// Дерево приходит параметром, отбор объявлен один раз, пустой обход — отказ, а
// не «находок ноль» (задача #17). Отбор сужен `ProductionGoFile`, то есть
// служебные каталоги (документация, оснастка, вендоренное) из него выпадают;
// на этом дереве сужение не меняет НИЧЕГО — файлов Go под ними ноль, — а по
// построению делает обход тем же, каким его видят соседние семейства.
func ExclusionFormGoCorpus(tree *treecorpus.Tree) (TreeCorpus, error) {
	return CorpusFrom(tree, ProductionGoFile)
}

func AuditExclusionForm(in ExclusionFormInput) ([]ExclusionFormFinding, ExclusionFormCensus, error) {
	var census ExclusionFormCensus

	// ── сторона ДЕРЕВА: производит ли читатель отказ на сочетании ────────────
	for _, rel := range exclusionSortedKeys(in.ReaderFiles) {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path.Base(rel), in.ReaderFiles[rel], 0)
		if err != nil {
			return nil, census, fmt.Errorf("файл читателя %s не разобран: %w", rel, err)
		}
		census.ReaderGoFiles++
		ast.Inspect(f, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok || exclusionCalleeName(c) != ExclusionRefuseFunc {
				return true
			}
			census.RefuseCalls++
			msg := strings.ToLower(exclusionLiteralArgs(c))
			for _, term := range ExclusionCoPresenceTerms {
				if !strings.Contains(msg, strings.ToLower(term)) {
					return true
				}
			}
			census.CoPresenceRefusals++
			return true
		})
	}

	// ── сторона ДЕРЕВА: живо ли НАШЕ построение ─────────────────────────────
	wrap := map[string]bool{}
	for _, n := range ExclusionWrapFuncs {
		wrap[n] = true
	}
	for _, rel := range exclusionSortedKeys(in.WrapFiles) {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path.Base(rel), in.WrapFiles[rel], 0)
		if err != nil {
			return nil, census, fmt.Errorf("файл %s не разобран: %w", rel, err)
		}
		census.WrapGoFiles++
		if rel == ExclusionReaderDeclFileRel {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok || !wrap[exclusionCalleeName(c)] {
				return true
			}
			census.WrapCalls++
			census.WrapSites = append(census.WrapSites,
				fmt.Sprintf("%s:%d", rel, fset.Position(c.Pos()).Line))
			return true
		})
	}

	// ── сторона СТРАНИЦЫ: чем она объясняет ─────────────────────────────────
	var findings []ExclusionFormFinding
	var firstSubject *exclusionParagraph
	for _, p := range exclusionSplitParagraphs(in.GuideBody) {
		census.GuideParagraphs++
		lowered := strings.ToLower(p.Text)
		if !exclusionHasAny(lowered, exclusionSubjectRoots) {
			continue
		}
		census.SubjectParagraphs++
		if firstSubject == nil {
			cp := p
			firstSubject = &cp
		}
		if exclusionHasAny(lowered, exclusionRefusalRoots) {
			census.ExplainByRefusal++
			if census.CoPresenceRefusals == 0 {
				findings = append(findings, ExclusionFormFinding{
					Kind: "refusal-without-producer", Rel: in.GuideRel,
					Line: p.Line, Excerpt: exclusionExcerpt(p.Text),
				})
			}
		}
		if exclusionHasAny(lowered, exclusionBuildRoots) {
			census.ExplainByBuild++
		}
	}

	// Утверждение B — положительное: пока построение живо, страница обязана его
	// называть. Ноль абзацев предмета — тот же случай: объяснение исчезло.
	if census.WrapCalls > 0 && census.ExplainByBuild == 0 {
		f := ExclusionFormFinding{
			Kind: "construction-unnamed", Rel: in.GuideRel,
			Excerpt: "абзаца предмета на странице нет вовсе",
		}
		if firstSubject != nil {
			f.Line = firstSubject.Line
			f.Excerpt = exclusionExcerpt(firstSubject.Text)
		}
		findings = append(findings, f)
	}
	return findings, census, nil
}

// exclusionParagraph — абзац страницы вместе с номером своей первой строки.
type exclusionParagraph struct {
	Line int
	Text string
}

// exclusionSplitParagraphs режет страницу на абзацы по пустой строке, храня
// номер первой строки каждого: находка обязана называть координату, а не файл.
func exclusionSplitParagraphs(body string) []exclusionParagraph {
	var out []exclusionParagraph
	cur := exclusionParagraph{Line: 1}
	var buf []string
	flush := func(next int) {
		if strings.TrimSpace(strings.Join(buf, "\n")) != "" {
			cur.Text = strings.Join(buf, "\n")
			out = append(out, cur)
		}
		buf = nil
		cur = exclusionParagraph{Line: next}
	}
	for i, line := range strings.Split(body, "\n") {
		if strings.TrimSpace(line) == "" {
			flush(i + 2)
			continue
		}
		if len(buf) == 0 {
			cur.Line = i + 1
		}
		buf = append(buf, line)
	}
	flush(0)
	return out
}

// exclusionHasAny — несёт ли текст хоть один корень. Регистр снят вызывающим.
func exclusionHasAny(lowered string, roots []string) bool {
	for _, r := range roots {
		if strings.Contains(lowered, r) {
			return true
		}
	}
	return false
}

// exclusionExcerpt — короткая выдержка абзаца для находки.
func exclusionExcerpt(text string) string {
	flat := strings.Join(strings.Fields(text), " ")
	const limit = 140
	if len(flat) <= limit {
		return flat
	}
	cut := flat[:limit]
	if i := strings.LastIndex(cut, " "); i > 0 {
		cut = cut[:i]
	}
	return cut + "…"
}

// exclusionCalleeName — имя вызываемого: `f(…)` и `x.f(…)` дают `f`.
func exclusionCalleeName(c *ast.CallExpr) string {
	switch fn := c.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}
	return ""
}

// exclusionLiteralArgs — строковые литералы аргументов вызова, склеенные.
//
// Склейка `"a" + "b"` разбирается: сообщение отказа собирают конкатенацией, и
// разбор, читающий только одиночный литерал, такое сообщение НЕ УВИДЕЛ БЫ — то
// есть дал бы молчание вместо вердикта.
func exclusionLiteralArgs(c *ast.CallExpr) string {
	var sb strings.Builder
	var walk func(ast.Expr)
	walk = func(e ast.Expr) {
		switch v := e.(type) {
		case *ast.BasicLit:
			if v.Kind == token.STRING {
				if s, err := strconv.Unquote(v.Value); err == nil {
					sb.WriteString(s)
					sb.WriteString(" ")
				}
			}
		case *ast.BinaryExpr:
			walk(v.X)
			walk(v.Y)
		}
	}
	for _, a := range c.Args {
		walk(a)
	}
	return sb.String()
}

func exclusionSortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
