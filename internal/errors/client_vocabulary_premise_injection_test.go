// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package errors_test

// client_vocabulary_premise_injection_test.go — доказательство, что гейт
// словаря СПОСОБЕН упасть на ложной предпосылке и способен смолчать на верной
// (задача PRO-Robotech/kacho#2478).
//
// Вход — НАСТОЯЩИЙ канонический переводчик из дерева, а не синтетика: подача
// берёт его исходник, разбором находит ветвь признака полосы фиксированного
// текста и меняет в ней РОВНО ОДИН факт — выражение текста статуса — на форму,
// стоявшую здесь до задачи #2464. Контрольная подача — тот же исходник без
// правки; остальное в них совпадает побайтово, поэтому красное может прийти
// только от внесённого факта.
//
// Законный близнец в контрольной подаче тоже настоящий: тот же переводчик
// несёт ту же форму на СОСЕДНИХ полосах, где текст адресован вызывающему и
// обязан доехать. Молчание на ней — утверждение, а не совпадение: проба
// требует, чтобы такая конструкция во входе БЫЛА.
//
// Подачи порождаются из `fixedTextSentinels`, а не выписываются: признак,
// внесённый в перечень полос фиксированного текста, получает инъекцию сам. Нет
// его ветви в каноне, отдаёт она другой код или разбор не судит её полосу —
// подача называет это, а не молчит. Этим и держится связь «признак → код»,
// которую разбор без типов увидеть не может.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// canonicalTranslatorRel — канонический переводчик признак → статус.
const canonicalTranslatorRel = "internal/apps/kaname/shared/errors.go"

// canonicalTranslatorFunc — функция переводчика внутри файла.
const canonicalTranslatorFunc = "MapRepoErr"

// preFixForm — выражение текста, стоявшее на ветви недоступности до #2464:
// разбор цепочки, то есть текст обёртки вызывающего на проводе.
const preFixForm = "iamerr.StripSentinel(err)"

// neighbourLaneSentinel — признак СОСЕДНЕЙ полосы, на которой та же форма
// законна: текст «<Resource> <id> not found» производит сама служба, и он
// обязан доехать.
const neighbourLaneSentinel = "ErrNotFound"

// translatorBranch — ветвь признака в переводчике, как её нашёл разбор.
type translatorBranch struct {
	code      string // код статуса, как он записан (`Unavailable`, `Internal`)
	text      string // выражение текста, как оно записано
	textStart int    // смещение выражения текста в исходнике
	textEnd   int
	line      int
}

func readCanonicalTranslator(t *testing.T) []byte {
	t.Helper()
	src, err := os.ReadFile(path.Join(serviceRoot, canonicalTranslatorRel))
	if err != nil {
		t.Fatalf("подача НЕ ИСПОЛНЯЛАСЬ: канонический переводчик не прочитан: %v", err)
	}
	return src
}

// locateBranch — ветвь `case …Is(err, <пакет>.<признак>):` функции
// переводчика и в её теле ровно одно `return status.Error(codes.<код>, <текст>)`.
// Всё, кроме «ровно одна ветвь и ровно один возврат», — «подача не исполнялась»:
// правка подаётся в место, которое разбор назвал однозначно, или не подаётся.
func locateBranch(t *testing.T, src []byte, sentinel string) translatorBranch {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "errors.go", src, 0)
	if err != nil {
		t.Fatalf("подача НЕ ИСПОЛНЯЛАСЬ: канонический переводчик не разобран: %v", err)
	}
	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == canonicalTranslatorFunc && fd.Recv == nil {
			fn = fd
		}
	}
	if fn == nil || fn.Body == nil {
		t.Fatalf("подача НЕ ИСПОЛНЯЛАСЬ: в %s нет функции %s — канон переехал, инъекцию "+
			"надо навести заново", canonicalTranslatorRel, canonicalTranslatorFunc)
	}

	var branches []translatorBranch
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		cc, ok := n.(*ast.CaseClause)
		if !ok || !caseTestsSentinel(cc, sentinel) {
			return true
		}
		for _, st := range cc.Body {
			ret, ok := st.(*ast.ReturnStmt)
			if !ok || len(ret.Results) != 1 {
				continue
			}
			call, ok := ret.Results[0].(*ast.CallExpr)
			if !ok || !isSelector(call.Fun, "status", "Error") || len(call.Args) != 2 {
				continue
			}
			code, ok := call.Args[0].(*ast.SelectorExpr)
			if !ok || !isSelector(code, "codes", code.Sel.Name) {
				continue
			}
			start := fset.Position(call.Args[1].Pos()).Offset
			end := fset.Position(call.Args[1].End()).Offset
			branches = append(branches, translatorBranch{
				code:      code.Sel.Name,
				text:      string(src[start:end]),
				textStart: start,
				textEnd:   end,
				line:      fset.Position(call.Pos()).Line,
			})
		}
		return true
	})
	if len(branches) != 1 {
		t.Fatalf("подача НЕ ИСПОЛНЯЛАСЬ: ветвей признака %s с возвратом статуса в %s найдено "+
			"%d, ожидалась ровно одна — место правки неоднозначно: %+v",
			sentinel, canonicalTranslatorFunc, len(branches), branches)
	}
	return branches[0]
}

// caseTestsSentinel — спрашивает ли ветвь `<пакет>.Is(err, <пакет>.<признак>)`.
func caseTestsSentinel(cc *ast.CaseClause, sentinel string) bool {
	for _, e := range cc.List {
		call, ok := e.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			continue
		}
		fun, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || fun.Sel.Name != "Is" {
			continue
		}
		if s, ok := call.Args[1].(*ast.SelectorExpr); ok && s.Sel.Name == sentinel {
			return true
		}
	}
	return false
}

func isSelector(e ast.Expr, pkg, name string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg && sel.Sel.Name == name
}

// scanSource — прогон ТОГО ЖЕ разбора, что у гейта, над одним файлом.
func scanSource(t *testing.T, src []byte) (check.RefusalTextCensus, []check.RefusalTextFinding) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "errors.go")
	if err := os.WriteFile(p, src, 0o600); err != nil {
		t.Fatalf("подача НЕ ИСПОЛНЯЛАСЬ: запись подачи: %v", err)
	}
	census, findings, err := check.ScanFixedRefusalTexts(dir, []string{p})
	if err != nil {
		t.Fatalf("подача НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	return census, findings
}

func sortedFixedTextSentinels() []string {
	out := make([]string, 0, len(fixedTextSentinels))
	for s := range fixedTextSentinels {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func TestClientVocabularyPremiseInjection(t *testing.T) {
	src := readCanonicalTranslator(t)

	t.Run("КОНТРОЛЬ: канон как есть — предпосылка держится, близнец молчит", func(t *testing.T) {
		// Близнец обязан БЫТЬ во входе: та же форма, что у инъекции, на соседней
		// полосе. Без него молчание ниже ничего не удостоверяло бы.
		twin := locateBranch(t, src, neighbourLaneSentinel)
		if twin.text != preFixForm {
			t.Fatalf("законного близнеца во входе нет: ветвь %s отдаёт текст %q, а не %q — "+
				"молчание контроля перестало различать полосы", neighbourLaneSentinel, twin.text, preFixForm)
		}

		census, findings := scanSource(t, src)
		t.Log(census.String())
		outcome, text := judgePremise(census, findings)
		if outcome != premiseHolds {
			t.Fatalf("на нетронутом каноне предпосылка не держится (исход %d): %s", outcome, text)
		}
		t.Logf("близнец: codes.%s, текст %s (строка %d) — молчание", twin.code, twin.text, twin.line)
	})

	for _, sentinel := range sortedFixedTextSentinels() {
		sentinel := sentinel
		t.Run("ИНЪЕКЦИЯ: ветвь "+sentinel+" канона отдаёт текст цепочки", func(t *testing.T) {
			b := locateBranch(t, src, sentinel)
			if want := fixedTextSentinels[sentinel]; b.code != want {
				t.Fatalf("перечень полос фиксированного текста называет %s кодом %s, а канон "+
					"отдаёт на его ветви codes.%s (строка %d) — проверка кода перестала быть "+
					"проверкой признака", sentinel, want, b.code, b.line)
			}
			if b.text == preFixForm {
				t.Fatalf("подача НЕ ИСПОЛНЯЛАСЬ: ветвь %s уже несёт %s — правка не меняла бы "+
					"ничего, а контроль обязан был покраснеть", sentinel, preFixForm)
			}

			// Ровно один факт: подача отличается от контрольной только этим выражением.
			mutated := make([]byte, 0, len(src)+len(preFixForm))
			mutated = append(mutated, src[:b.textStart]...)
			mutated = append(mutated, preFixForm...)
			mutated = append(mutated, src[b.textEnd:]...)

			census, findings := scanSource(t, mutated)
			t.Log(census.String())
			outcome, text := judgePremise(census, findings)
			if outcome != premiseFalse {
				t.Fatalf("ветвь %s с текстом цепочки не опровергла предпосылку (исход %d) — "+
					"разбор не судит полосу codes.%s, и исключение признака держится ничем: %s",
					sentinel, outcome, b.code, text)
			}
			if len(findings) != 1 {
				t.Fatalf("находок %d, ожидалась ровно 1 — внесён один факт: %+v", len(findings), findings)
			}
			t.Logf("отказ, как его прочтёт тот, кто сломал предпосылку:\n%s", text)
			wantCoord := "errors.go:" + strconv.Itoa(b.line)
			for _, want := range []string{wantCoord, preFixForm, "codes." + b.code, sentinel} {
				if !strings.Contains(text, want) {
					t.Errorf("отказ не называет %q — находка, не называющая где и что, посылает "+
						"читателя искать не там:\n%s", want, text)
				}
			}
		})
	}

	t.Run("ПУСТОЙ КОРПУС: предпосылка не проверена, а не держится", func(t *testing.T) {
		census, findings, err := check.ScanFixedRefusalTexts(t.TempDir(), nil)
		if err != nil {
			t.Fatalf("подача НЕ ИСПОЛНЯЛАСЬ: %v", err)
		}
		outcome, text := judgePremise(census, findings)
		if outcome != premiseUnchecked {
			t.Fatalf("пустой обход принят за исход %d — «ноль прочитанного» выдан за вердикт: %s",
				outcome, text)
		}
		t.Log(text)
	})

	t.Run("КОРПУС БЕЗ ПОПУЛЯЦИИ: судить не о чем — не проверена", func(t *testing.T) {
		// Файл разобран, конструкция статуса есть, но ни одной на полосах
		// фиксированного текста: распознаватель, переставший их узнавать, дал бы
		// ровно это. Ноль здесь не цель, а слепота.
		census, findings := scanSource(t, []byte(`package fixture

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func f() error { return status.Error(codes.NotFound, "Group grp_1 not found") }
`))
		if census.Files == 0 || census.Constructions == 0 {
			t.Fatalf("подача НЕ ИСПОЛНЯЛАСЬ: вход не разобран: %s", census.String())
		}
		outcome, text := judgePremise(census, findings)
		if outcome != premiseUnchecked {
			t.Fatalf("корпус без популяции принят за исход %d: %s", outcome, text)
		}
		t.Log(text)
	})
}

// TestClientVocabularySentinelPartitionInjection — вторая ось предпосылки:
// КАЖДЫЙ объявленный признак отнесён ровно к одному перечню. Проверка кода
// полос выше доказывает, что полосы фиксированного текста фиксированы, но
// ничего не говорит о том, что исключены ИМЕННО их признаки: признак, не
// попавший ни в один перечень, выпадает из наблюдения молча, и никакая
// перепись полос этого не покажет.
//
// Оси по одной, каждая против одного и того же контроля: признак не отнесён ·
// отнесён к обоим · запись называет признак, которого пакет не объявляет ·
// пакет не объявляет ничего.
func TestClientVocabularySentinelPartitionInjection(t *testing.T) {
	pass := map[string]bool{"ErrNotFound": true}
	fixed := map[string]string{"ErrUnavailable": "Unavailable"}

	t.Run("КОНТРОЛЬ: каждый отнесён ровно к одному — молчание", func(t *testing.T) {
		outcome, findings := sentinelPartition([]string{"ErrNotFound", "ErrUnavailable"}, pass, fixed)
		if outcome != premiseHolds || len(findings) != 0 {
			t.Fatalf("законное разбиение отвергнуто (исход %d): %v", outcome, findings)
		}
	})

	cases := []struct {
		name     string
		declared []string
		pass     map[string]bool
		fixed    map[string]string
		want     string // имя, которое находка обязана назвать
	}{
		{
			name:     "ИНЪЕКЦИЯ: признак не отнесён ни к одному перечню",
			declared: []string{"ErrNotFound", "ErrUnavailable", "ErrSelfRevoke"},
			pass:     pass, fixed: fixed, want: "ErrSelfRevoke",
		},
		{
			name:     "ИНЪЕКЦИЯ: признак отнесён к обоим",
			declared: []string{"ErrNotFound", "ErrUnavailable"},
			pass:     map[string]bool{"ErrNotFound": true, "ErrUnavailable": true}, fixed: fixed,
			want: "ErrUnavailable",
		},
		{
			name:     "ИНЪЕКЦИЯ: запись называет признак, которого пакет не объявляет",
			declared: []string{"ErrNotFound", "ErrUnavailable"},
			pass:     map[string]bool{"ErrNotFound": true, "ErrGone": true}, fixed: fixed,
			want: "ErrGone",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			outcome, findings := sentinelPartition(tc.declared, tc.pass, tc.fixed)
			if outcome != premiseFalse {
				t.Fatalf("исход %d, ожидалось «ложна»: %v", outcome, findings)
			}
			if len(findings) != 1 || !strings.Contains(findings[0], tc.want) {
				t.Fatalf("находка обязана быть одна и назвать %s, вернулось %v", tc.want, findings)
			}
		})
	}

	t.Run("ПУСТОЕ ОБЪЯВЛЕНИЕ: не проверена, а не держится", func(t *testing.T) {
		if outcome, findings := sentinelPartition(nil, pass, fixed); outcome != premiseUnchecked {
			t.Fatalf("пустой перечень объявленных принят за исход %d: %v", outcome, findings)
		}
	})

	t.Run("РАСПОЗНАВАТЕЛЬ: все три формы объявления признака, и только они", func(t *testing.T) {
		// Три формы, которыми пакет объявляет признак сегодня, плюс соседи,
		// которые признаком не являются: переменная без приставки, локальная
		// переменная функции, неэкспортируемое имя.
		got, err := declaredSentinelsIn([]byte(`package errors

import (
	stderrors "errors"
	"fmt"
)

var (
	ErrPlain = stderrors.New("plain")
	ErrNested = fmt.Errorf("%w: nested", ErrPlain)
	ErrTyped error = specialised{general: ErrPlain}
	errHidden = stderrors.New("hidden")
	Registry = []error{ErrPlain}
)

var ErrLone = stderrors.New("lone")

type specialised struct{ general error }

func (s specialised) Error() string { return s.general.Error() }

func f() { ErrLocal := stderrors.New("local"); _ = ErrLocal }
`))
		if err != nil {
			t.Fatalf("подача НЕ ИСПОЛНЯЛАСЬ: %v", err)
		}
		want := "ErrLone,ErrNested,ErrPlain,ErrTyped"
		if strings.Join(got, ",") != want {
			t.Fatalf("распознаватель вернул %v, ожидалось %s — форма, которой он не знает, "+
				"выпадает из разбиения не нарушением, а невидимостью", got, want)
		}
	})
}
