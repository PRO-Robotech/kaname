// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// envelope_composition_root_injection_test.go — способность стража корня
// композиции упасть, доказанная инъекцией в обе стороны: каждая форма дефекта
// краснеет и называет координату и выражение меры, законный близнец той же
// формы молчит. Деревья синтетические (t.TempDir), кроме пары на настоящем
// входе: дом огибающей и файл корня, прочитанные из этого дерева, с одним
// изменённым фактом.
package check_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

const envGoMod = "module github.com/PRO-Robotech/kaname\n\ngo 1.26\n"

// envHome — синтетический дом огибающей: объявления, по которым страж узнаёт
// построение, меру и порт, — в той же форме, что у настоящего дома.
const envHome = `package passwordverify

import (
	"context"
	"time"
)

type Verifier struct{}

type EnvelopeObserver interface{}

type Admission struct{ Cost time.Duration }

// CostMeter — мера одного прогона.
type CostMeter func(class string, verify func()) time.Duration

func WallClockCostMeter(_ string, verify func()) time.Duration {
	start := time.Now()
	verify()
	return time.Since(start)
}

type Envelope struct {
	verifier *Verifier
	observer EnvelopeObserver
	meter    CostMeter
}

func NewEnvelope(verifier *Verifier, observer EnvelopeObserver, meter CostMeter) (*Envelope, error) {
	return &Envelope{verifier: verifier, observer: observer, meter: meter}, nil
}

func (e *Envelope) Floor() time.Duration { return 0 }

func (e *Envelope) Admit(ctx context.Context, class string) (Admission, error) { return Admission{}, nil }
`

// envRoot — законный корень: одно построение на мере настенных часов.
const envRoot = `package main

import "github.com/PRO-Robotech/kaname/internal/passwordverify"

func buildEnvelope(v *passwordverify.Verifier, rec passwordverify.EnvelopeObserver) (*passwordverify.Envelope, error) {
	return passwordverify.NewEnvelope(v, rec, passwordverify.WallClockCostMeter)
}
`

const envRootRel = "cmd/kaname/loginlane.go"

// envBase — законное синтетическое дерево.
func envBase() map[string]string {
	return map[string]string{
		"go.mod":                              envGoMod,
		"internal/passwordverify/envelope.go": envHome,
		envRootRel:                            envRoot,
	}
}

// envWith — законное дерево с правками: пустое тело снимает файл.
func envWith(edits map[string]string) map[string]string {
	files := envBase()
	for rel, body := range edits {
		if body == "" {
			delete(files, rel)
			continue
		}
		files[rel] = body
	}
	return files
}

func envJudge(t *testing.T, files map[string]string) (check.EnvelopeRootVerdict, error) {
	t.Helper()
	dir := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	}
	tree, err := treecorpus.SyntheticTree(dir)
	require.NoError(t, err, "синтетическое дерево не собрано — инъекция НЕ ИСПОЛНЯЛАСЬ")
	return check.JudgeEnvelopeCompositionRoot(tree, check.EnvelopeCompositionRootSpec())
}

func envMustJudge(t *testing.T, files map[string]string) check.EnvelopeRootVerdict {
	t.Helper()
	v, err := envJudge(t, files)
	require.NoError(t, err, "посылка обязана держаться на этом дереве")
	t.Logf("перепись: %s", v.Summary())
	return v
}

// envRequireFinding — находка, называющая каждую из подстрок.
func envRequireFinding(t *testing.T, v check.EnvelopeRootVerdict, parts ...string) {
	t.Helper()
	for _, f := range v.Findings {
		all := true
		for _, p := range parts {
			if !strings.Contains(f, p) {
				all = false
				break
			}
		}
		if all {
			return
		}
	}
	t.Fatalf("нет находки, называющей %q; находки:\n%s", parts, strings.Join(v.Findings, "\n"))
}

// envRequireSilent — законный близнец: находок нет, законное место одно.
func envRequireSilent(t *testing.T, v check.EnvelopeRootVerdict) {
	t.Helper()
	require.Empty(t, v.Findings, "законный близнец обязан молчать")
	require.Len(t, v.Sites, 1, "законное построение найдено ровно одно")
	require.True(t, v.Sites[0].WallClock)
}

// TestEnvelopeRootGate_LawfulTreeIsSilentAndNamesItsSite — законное дерево:
// находок 0, построение одно, перепись непуста (T-G1, T-G8).
func TestEnvelopeRootGate_LawfulTreeIsSilentAndNamesItsSite(t *testing.T) {
	t.Parallel()
	v := envMustJudge(t, envBase())
	envRequireSilent(t, v)
	require.Equal(t, envRootRel, v.Sites[0].Rel)
	require.Equal(t, 6, v.Sites[0].Line)
	require.Equal(t, 2, v.Census.Examined, "разобраны оба не-тестовых файла")
	require.Equal(t, 3, v.Census.MeterParam, "позиция меры выведена из объявления")
	require.Contains(t, v.Summary(), "построений 1")
}

// TestEnvelopeRootGate_RealRootAndHomeWithOneChangedFact — настоящий вход:
// дом и файл корня из этого дерева. Без правки — молчание; мера корня заменена
// литералом функции — красное с координатой настоящей строки построения (G1).
func TestEnvelopeRootGate_RealRootAndHomeWithOneChangedFact(t *testing.T) {
	t.Parallel()
	wd, err := os.Getwd()
	require.NoError(t, err)
	root, err := platformtree.ModuleRootFrom(wd)
	require.NoError(t, err)
	files := map[string]string{}
	for _, rel := range []string{"go.mod", envRootRel} {
		body, err := os.ReadFile(filepath.Join(root, rel))
		require.NoError(t, err, "настоящий вход %s не прочитан — инъекция НЕ ИСПОЛНЯЛАСЬ", rel)
		files[rel] = string(body)
	}
	homes, err := filepath.Glob(filepath.Join(root, "internal", "passwordverify", "*.go"))
	require.NoError(t, err)
	for _, p := range homes {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		body, err := os.ReadFile(p)
		require.NoError(t, err)
		files["internal/passwordverify/"+filepath.Base(p)] = string(body)
	}

	control := envMustJudge(t, files)
	envRequireSilent(t, control)
	line := control.Sites[0].Line

	const wall = "passwordverify.WallClockCostMeter)"
	rootBody := files[envRootRel]
	require.Equal(t, 1, strings.Count(rootBody, wall), "предпосылка: в настоящем корне мера записана одним местом — иначе инъекция НЕ ИСПОЛНЯЛАСЬ")
	files[envRootRel] = strings.Replace(rootBody, wall,
		"func(_ domain.PasswordCostClass, verify func()) time.Duration { verify(); return time.Millisecond })", 1)
	injected := envMustJudge(t, files)
	envRequireFinding(t, injected, fmt.Sprintf("%s:%d", envRootRel, line), "мера огибающей `(func(", "literal)`")
	require.Len(t, injected.Sites, 1)
}

// TestEnvelopeRootGate_AnotherMeterInTheRootIsFound — иная мера в корне: литерал
// функции, метод меры пробы, переменная, довод обёртки — красное с выражением.
func TestEnvelopeRootGate_AnotherMeterInTheRootIsFound(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, root, expr string }{
		{"литерал функции", `package main

import (
	"time"

	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

func build(v *passwordverify.Verifier, rec passwordverify.EnvelopeObserver) {
	_, _ = passwordverify.NewEnvelope(v, rec, func(_ string, verify func()) time.Duration { verify(); return time.Millisecond })
}
`, "(func(_ string, verify func()) time.Duration literal)"},
		{"метод меры назначенной стоимости", `package main

import (
	"time"

	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

type assignedMeter struct{ cost time.Duration }

func (m *assignedMeter) measure(_ string, verify func()) time.Duration { verify(); return m.cost }

func build(v *passwordverify.Verifier, rec passwordverify.EnvelopeObserver) {
	meter := &assignedMeter{cost: time.Millisecond}
	_, _ = passwordverify.NewEnvelope(v, rec, meter.measure)
}
`, "meter.measure"},
		{"мера из переменной", `package main

import "github.com/PRO-Robotech/kaname/internal/passwordverify"

func build(v *passwordverify.Verifier, rec passwordverify.EnvelopeObserver) {
	m := passwordverify.WallClockCostMeter
	_, _ = passwordverify.NewEnvelope(v, rec, m)
}
`, "`m`"},
		{"обёртка с доводом-мерой", `package main

import "github.com/PRO-Robotech/kaname/internal/passwordverify"

func build(v *passwordverify.Verifier, rec passwordverify.EnvelopeObserver, meter passwordverify.CostMeter) {
	_, _ = passwordverify.NewEnvelope(v, rec, meter)
}
`, "`meter`"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v := envMustJudge(t, envWith(map[string]string{envRootRel: tc.root}))
			require.Len(t, v.Sites, 1)
			envRequireFinding(t, v, envRootRel+":", "мера огибающей", tc.expr, "passwordverify.WallClockCostMeter")
		})
	}
}

// TestEnvelopeRootGate_ASecondConstructionIsFound — второе построение с
// настенной мерой в другом не-тестовом файле: названы обе координаты и
// «построений 2» (G2); его законный близнец — то же в файле пробы (T-G3).
func TestEnvelopeRootGate_ASecondConstructionIsFound(t *testing.T) {
	t.Parallel()
	second := `package humansession

import "github.com/PRO-Robotech/kaname/internal/passwordverify"

func envelopeOf(v *passwordverify.Verifier, rec passwordverify.EnvelopeObserver) (*passwordverify.Envelope, error) {
	return passwordverify.NewEnvelope(v, rec, passwordverify.WallClockCostMeter)
}
`
	const rel = "internal/apps/kaname/api/humansession/envelope.go"
	v := envMustJudge(t, envWith(map[string]string{rel: second}))
	envRequireFinding(t, v, "построений 2", envRootRel+":6", rel+":6")
	envRequireFinding(t, v, rel+":6", "построение вне композиционного корня cmd/kaname")

	twin := envMustJudge(t, envWith(map[string]string{"internal/apps/kaname/api/humansession/envelope_test.go": second}))
	envRequireSilent(t, twin)
}

// TestEnvelopeRootGate_TheBoundaryIsTheKindOfFile — помощник пробы с мерой
// назначенной стоимости: в не-тестовом файле корня — красное (G3), в файле
// пробы — молчание (T-G2). Различие одно — суффикс `_test.go`.
func TestEnvelopeRootGate_TheBoundaryIsTheKindOfFile(t *testing.T) {
	t.Parallel()
	helper := `package main

import (
	"time"

	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

type assignedMeter struct{ costs map[string]time.Duration }

func (m *assignedMeter) measure(class string, verify func()) time.Duration { verify(); return m.costs[class] }

func envelopeForProbe(costs map[string]time.Duration) *passwordverify.Envelope {
	meter := &assignedMeter{costs: costs}
	e, _ := passwordverify.NewEnvelope(&passwordverify.Verifier{}, nil, meter.measure)
	return e
}
`
	red := envMustJudge(t, envWith(map[string]string{"cmd/kaname/probe_support.go": helper}))
	envRequireFinding(t, red, "построений 2")
	envRequireFinding(t, red, "cmd/kaname/probe_support.go:15", "мера огибающей `meter.measure`")

	silent := envMustJudge(t, envWith(map[string]string{"cmd/kaname/probe_support_test.go": helper}))
	envRequireSilent(t, silent)

	// Тег сборки границы не сдвигает: файл пробы под тегом — по-прежнему проба,
	// не-тестовый файл под тегом — судится (T-G6).
	tagged := envMustJudge(t, envWith(map[string]string{"cmd/kaname/probe_unix_test.go": "//go:build unix\n\n" + helper}))
	envRequireSilent(t, tagged)
	tool := envMustJudge(t, envWith(map[string]string{"cmd/kaname/tools.go": "//go:build tools\n\n" + helper}))
	envRequireFinding(t, tool, "cmd/kaname/tools.go:17", "мера огибающей `meter.measure`")
}

// TestEnvelopeRootGate_AConstructionOutsideTheRootIsFound — единственное
// построение на настенной мере перенесено из корня в `internal/…` (G4).
func TestEnvelopeRootGate_AConstructionOutsideTheRootIsFound(t *testing.T) {
	t.Parallel()
	moved := `package wiring

import "github.com/PRO-Robotech/kaname/internal/passwordverify"

func Envelope(v *passwordverify.Verifier, rec passwordverify.EnvelopeObserver) (*passwordverify.Envelope, error) {
	return passwordverify.NewEnvelope(v, rec, passwordverify.WallClockCostMeter)
}
`
	v := envMustJudge(t, envWith(map[string]string{
		envRootRel:                    "package main\n\nfunc main() {}\n",
		"internal/wiring/envelope.go": moved,
	}))
	require.Len(t, v.Sites, 1)
	envRequireFinding(t, v, "internal/wiring/envelope.go:6", "построение вне композиционного корня cmd/kaname")
}

// TestEnvelopeRootGate_NoConstructionIsAFindingNotAnEmptyWalk — построений 0:
// находка «построений 0», отличимая от пустого обхода (G5).
func TestEnvelopeRootGate_NoConstructionIsAFindingNotAnEmptyWalk(t *testing.T) {
	t.Parallel()
	v := envMustJudge(t, envWith(map[string]string{envRootRel: "package main\n\nfunc main() {}\n"}))
	require.Empty(t, v.Sites)
	require.Equal(t, 2, v.Census.Examined, "обход НЕ пуст — находка о дереве, а не о чтении")
	envRequireFinding(t, v, "построений 0")
}

// TestEnvelopeRootGate_AnEmptyWalkIsARefusal — пустое дерево и дерево из одних
// файлов проб: ErrEmptyTraversal, а не «находок ноль» (G6, T-G8).
func TestEnvelopeRootGate_AnEmptyWalkIsARefusal(t *testing.T) {
	t.Parallel()
	for name, files := range map[string]map[string]string{
		"пустое дерево": {},
		"только пробы": {
			"go.mod":                            envGoMod,
			"cmd/kaname/loginlane_test.go":      envRoot,
			"internal/passwordverify/e_test.go": envHome,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := envJudge(t, files)
			require.Error(t, err)
			require.True(t, errors.Is(err, check.ErrEmptyTraversal), "пустой обход — отказ пустого обхода: %v", err)
			require.Contains(t, err.Error(), "не-тестовых файлов Go в области обхода 0")
		})
	}
}

// TestEnvelopeRootGate_ABrokenPremiseIsARefusal — посылка стража не держится:
// отказ посылки с названным недостающим, а не молчание и не красное по всему
// дереву (G7).
func TestEnvelopeRootGate_ABrokenPremiseIsARefusal(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"мера настенных часов переименована", envWith(map[string]string{
			"internal/passwordverify/envelope.go": strings.ReplaceAll(envHome, "WallClockCostMeter", "ProcessClockMeter"),
		}), "мера настенных часов WallClockCostMeter объявлена в доме 0 раз(а)"},
		{"довод меры потерял тип меры", envWith(map[string]string{
			"internal/passwordverify/envelope.go": strings.Replace(envHome, "meter CostMeter) (*Envelope", "meter func(string, func()) time.Duration) (*Envelope", 1),
		}), "доводов типа CostMeter 0"},
		{"конструктора нет", envWith(map[string]string{
			"internal/passwordverify/envelope.go": strings.Replace(envHome, "func NewEnvelope", "func BuildEnvelope", 1),
		}), "конструктор NewEnvelope объявлен в доме 0 раз(а)"},
		{"дома нет", envWith(map[string]string{"internal/passwordverify/envelope.go": ""}), "дом internal/passwordverify не-тестовых файлов не несёт"},
		{"корня нет", envWith(map[string]string{
			envRootRel:                    "",
			"internal/wiring/envelope.go": strings.Replace(envRoot, "package main", "package wiring", 1),
		}), "корень композиции cmd/kaname не-тестовых файлов не несёт"},
		{"go.mod нет", envWith(map[string]string{"go.mod": ""}), "go.mod в составе дерева нет"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := envJudge(t, tc.files)
			require.Error(t, err)
			require.True(t, errors.Is(err, check.ErrEnvelopeRootPremise), "отказ посылки, а не иной: %v", err)
			require.Contains(t, err.Error(), tc.want)
		})
	}

	// Мера, перенесённая на первый довод и в объявлении, и у места вызова, —
	// позиция выведена, а не записана литералом: молчание.
	moved := envWith(map[string]string{
		"internal/passwordverify/envelope.go": strings.Replace(envHome,
			"NewEnvelope(verifier *Verifier, observer EnvelopeObserver, meter CostMeter)",
			"NewEnvelope(meter CostMeter, verifier *Verifier, observer EnvelopeObserver)", 1),
		envRootRel: strings.Replace(envRoot, "NewEnvelope(v, rec, passwordverify.WallClockCostMeter)",
			"NewEnvelope(passwordverify.WallClockCostMeter, v, rec)", 1),
	})
	v := envMustJudge(t, moved)
	envRequireSilent(t, v)
	require.Equal(t, 1, v.Census.MeterParam)
}

// TestEnvelopeRootGate_EveryConstructionFormIsKnown — каждая законная форма
// ЗАПИСИ построения узнаётся: с иной мерой каждая краснеет (G8), с мерой
// настенных часов вызов молчит (T-G5).
func TestEnvelopeRootGate_EveryConstructionFormIsKnown(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, root string
		parts      []string
	}{
		{"импорт под псевдонимом", `package main

import pv "github.com/PRO-Robotech/kaname/internal/passwordverify"

func build(v *pv.Verifier, rec pv.EnvelopeObserver, m pv.CostMeter) { _, _ = pv.NewEnvelope(v, rec, m) }
`, []string{envRootRel + ":5", "мера огибающей `m`"}},
		{"импорт с точкой", `package main

import . "github.com/PRO-Robotech/kaname/internal/passwordverify"

func build(v *Verifier, rec EnvelopeObserver, m CostMeter) { _, _ = NewEnvelope(v, rec, m) }
`, []string{envRootRel + ":5", "мера огибающей `m`"}},
		{"конструктор в скобках", `package main

import "github.com/PRO-Robotech/kaname/internal/passwordverify"

func build(v *passwordverify.Verifier, rec passwordverify.EnvelopeObserver, m passwordverify.CostMeter) {
	_, _ = (passwordverify.NewEnvelope)(v, rec, m)
}
`, []string{envRootRel + ":6", "мера огибающей `m`"}},
		{"конструктор значением", `package main

import "github.com/PRO-Robotech/kaname/internal/passwordverify"

func build(v *passwordverify.Verifier, rec passwordverify.EnvelopeObserver) {
	f := passwordverify.NewEnvelope
	_, _ = f(v, rec, passwordverify.WallClockCostMeter)
}
`, []string{envRootRel + ":6", "конструктор огибающей взят значением `passwordverify.NewEnvelope`"}},
		{"составной литерал по указателю", `package main

import "github.com/PRO-Robotech/kaname/internal/passwordverify"

func build() *passwordverify.Envelope { return &passwordverify.Envelope{} }
`, []string{envRootRel + ":5", "значение огибающей мимо конструктора `passwordverify.Envelope{…}`"}},
		{"new от типа", `package main

import "github.com/PRO-Robotech/kaname/internal/passwordverify"

func build() *passwordverify.Envelope { return new(passwordverify.Envelope) }
`, []string{envRootRel + ":5", "значение огибающей мимо конструктора `new(passwordverify.Envelope)`"}},
		{"нулевое значение переменной", `package main

import "github.com/PRO-Robotech/kaname/internal/passwordverify"

var zero passwordverify.Envelope

func build() *passwordverify.Envelope { return &zero }
`, []string{envRootRel + ":5", "значение огибающей мимо конструктора `passwordverify.Envelope`"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v := envMustJudge(t, envWith(map[string]string{envRootRel: tc.root}))
			envRequireFinding(t, v, tc.parts...)
		})
	}

	for _, tc := range []struct{ name, root string }{
		{"псевдоним с настенной мерой", `package main

import pv "github.com/PRO-Robotech/kaname/internal/passwordverify"

func build(v *pv.Verifier, rec pv.EnvelopeObserver) { _, _ = pv.NewEnvelope(v, rec, pv.WallClockCostMeter) }
`},
		{"точка с настенной мерой", `package main

import . "github.com/PRO-Robotech/kaname/internal/passwordverify"

func build(v *Verifier, rec EnvelopeObserver) { _, _ = NewEnvelope(v, rec, WallClockCostMeter) }
`},
		{"мера в скобках", `package main

import "github.com/PRO-Robotech/kaname/internal/passwordverify"

func build(v *passwordverify.Verifier, rec passwordverify.EnvelopeObserver) {
	_, _ = passwordverify.NewEnvelope(v, rec, (passwordverify.WallClockCostMeter))
}
`},
		{"мера приведением к типу меры", `package main

import "github.com/PRO-Robotech/kaname/internal/passwordverify"

func build(v *passwordverify.Verifier, rec passwordverify.EnvelopeObserver) {
	_, _ = passwordverify.NewEnvelope(v, rec, passwordverify.CostMeter(passwordverify.WallClockCostMeter))
}
`},
	} {
		t.Run("близнец: "+tc.name, func(t *testing.T) {
			t.Parallel()
			envRequireSilent(t, envMustJudge(t, envWith(map[string]string{envRootRel: tc.root})))
		})
	}
}

// TestEnvelopeRootGate_ASecondConstructorInTheHomeIsFound — второй конструктор в
// доме: литералом типа мимо конструктора и вызовом конструктора с доводом-мерой
// — оба краснеют; литерал в теле самого конструктора — молчание.
func TestEnvelopeRootGate_ASecondConstructorInTheHomeIsFound(t *testing.T) {
	t.Parallel()
	literal := envMustJudge(t, envWith(map[string]string{"internal/passwordverify/fixed.go": `package passwordverify

func NewFixedEnvelope() *Envelope { return &Envelope{} }
`}))
	envRequireFinding(t, literal, "internal/passwordverify/fixed.go:3", "значение огибающей мимо конструктора `Envelope{…}`")

	delegating := envMustJudge(t, envWith(map[string]string{"internal/passwordverify/fixed.go": `package passwordverify

func NewMeteredEnvelope(v *Verifier, m CostMeter) (*Envelope, error) { return NewEnvelope(v, nil, m) }
`}))
	envRequireFinding(t, delegating, "internal/passwordverify/fixed.go:3", "построение вне композиционного корня")
	envRequireFinding(t, delegating, "internal/passwordverify/fixed.go:3", "мера огибающей `m`")
	envRequireFinding(t, delegating, "построений 2")
}

// TestEnvelopeRootGate_TheHomeIsKnownByItsImportPath — дом узнаётся по пути
// импорта: чужой пакет под именем дома со своей мерой — иная мера, красное
// (T-G7); чужой конструктор под тем же именем — не построение, молчание.
func TestEnvelopeRootGate_TheHomeIsKnownByItsImportPath(t *testing.T) {
	t.Parallel()
	foreignMeter := envMustJudge(t, envWith(map[string]string{envRootRel: `package main

import (
	pv "github.com/PRO-Robotech/kaname/internal/passwordverify"
	"example.com/impostor/passwordverify"
)

func build(v *pv.Verifier, rec pv.EnvelopeObserver) { _, _ = pv.NewEnvelope(v, rec, passwordverify.WallClockCostMeter) }
`}))
	envRequireFinding(t, foreignMeter, envRootRel+":8", "мера огибающей `passwordverify.WallClockCostMeter`")

	foreignCtor := envMustJudge(t, envWith(map[string]string{"internal/other/impostor.go": `package other

import "example.com/impostor/passwordverify"

func build() { _, _ = passwordverify.NewEnvelope(nil, nil, nil) }
`}))
	envRequireSilent(t, foreignCtor)
}

// TestEnvelopeRootGate_TextAndPointersAreNotConstructions — упоминания в
// комментарии и строке, тип за указателем, в доводах функции и в получателе,
// объявления дома — не построения: молчание (T-G4).
func TestEnvelopeRootGate_TextAndPointersAreNotConstructions(t *testing.T) {
	t.Parallel()
	v := envMustJudge(t, envWith(map[string]string{"internal/apps/kaname/api/humansession/port.go": `package humansession

import "github.com/PRO-Robotech/kaname/internal/passwordverify"

// Корень строит огибающую так: passwordverify.NewEnvelope(v, rec, meter.measure).
const howTheRootBuildsIt = "passwordverify.NewEnvelope(v, rec, meter.measure) и &passwordverify.Envelope{}"

type lane struct {
	envelope *passwordverify.Envelope
}

func use(e *passwordverify.Envelope, byValue passwordverify.Envelope, all []*passwordverify.Envelope) *passwordverify.Envelope {
	var _ = (*passwordverify.Envelope)(nil)
	return e
}
`}))
	envRequireSilent(t, v)
	require.Equal(t, 3, v.Census.ReferringHome)
}

// TestEnvelopeRootGate_APortImplementationOutsideTheHomeIsFound — тип вне дома,
// чей метод допуска отдаёт исход допуска дома, — красное; тот же тип в файле
// пробы — молчание; метод с тем же именем без исхода дома — молчание.
func TestEnvelopeRootGate_APortImplementationOutsideTheHomeIsFound(t *testing.T) {
	t.Parallel()
	impl := `package humansession

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

type zeroEnvelope struct{}

func (zeroEnvelope) Floor() time.Duration { return 0 }

func (zeroEnvelope) Admit(ctx context.Context, class string) (passwordverify.Admission, error) {
	return passwordverify.Admission{}, nil
}
`
	const rel = "internal/apps/kaname/api/humansession/zero.go"
	red := envMustJudge(t, envWith(map[string]string{rel: impl}))
	envRequireFinding(t, red, rel+":14", "реализация порта огибающей вне её дома", "zeroEnvelope", "passwordverify.Admission")

	envRequireSilent(t, envMustJudge(t, envWith(map[string]string{"internal/apps/kaname/api/humansession/zero_test.go": impl})))

	envRequireSilent(t, envMustJudge(t, envWith(map[string]string{"internal/other/admit.go": `package other

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

type gate struct{ env *passwordverify.Envelope }

func (gate) Admit(ctx context.Context) error { return nil }
`})))
}

// TestEnvelopeRootGate_TheWalkAreaIsCountedNotSilent — не-тестовый файл под
// сегментом вне области обхода не судится, и перепись называет его числом.
func TestEnvelopeRootGate_TheWalkAreaIsCountedNotSilent(t *testing.T) {
	t.Parallel()
	v := envMustJudge(t, envWith(map[string]string{"docs/example/envelope.go": `package example

import "github.com/PRO-Robotech/kaname/internal/passwordverify"

func build() { _, _ = passwordverify.NewEnvelope(nil, nil, nil) }
`}))
	envRequireSilent(t, v)
	require.Equal(t, 3, v.Census.ProductionGo)
	require.Equal(t, 1, v.Census.OutsideTraversal)
	require.Contains(t, v.Summary(), "из них вне области обхода 1")
}
