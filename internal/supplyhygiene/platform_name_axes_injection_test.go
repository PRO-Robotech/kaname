// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// platform_name_axes_injection_test.go — ДОКАЗАТЕЛЬСТВО, что перепись осей
// способна упасть и способна смолчать.
//
// Инъекция подаёт ТОГО ЖЕ судью (`JudgePlatformNameAxes`) и тот же разбор
// объявлений (`declaredFuncNames`), что исполняются на боевом прогоне. Каждая
// проба меняет РОВНО ОДИН факт против положительного контроля.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/treecorpus"
)

const (
	injHolder   = "TestProbeHoldsTheAxis"
	injSubject  = "internal/probe"
	injSpiffeYA = "deploy/values.yaml"
)

// injAxes — перепись из двух осей: одна с держателем, одна держимая числом.
func injAxes(occurrences, files int) []PlatformNameAxis {
	return []PlatformNameAxis{
		{Axis: "ось с держателем", Holders: []string{injHolder}, Judges: "судит ось", Subject: injSubject},
		{Axis: "ось числом", Subject: injSpiffeYA, Census: &AxisCensus{
			Paths:       []string{"deploy"},
			LineHas:     []string{"spiffe://"},
			Occurrences: occurrences,
			Files:       files,
			Composition: "имя соседа",
			Owner:       "задача",
		}},
	}
}

// injCorpus — дерево в тексте: одно вхождение на строке SPIFFE, одно — на
// строке без неё (не считается), одно — в пробе (не судится).
func injCorpus() map[string]string {
	return map[string]string{
		injSpiffeYA:                  "senders:\n  - \"spiffe://example.invalid/sa/kacho-api-gateway\"\nnote: kacho\n",
		"deploy/values_test.go":      "// spiffe://example.invalid/sa/kacho-probe\n",
		"internal/probe/probe.go":    "package probe\n",
		"internal/probe/probe_hi.go": "package probe\n",
	}
}

func injExists(rel string) bool {
	return rel == injSubject || rel == injSpiffeYA
}

func judgeInjectedAxes(axes []PlatformNameAxis, declared map[string]bool, corpus map[string]string) []string {
	_, findings := JudgePlatformNameAxes(axes, declared, injExists, corpus)
	return findings
}

// TestAxesInjection_ControlIsSilent — положительный контроль.
func TestAxesInjection_ControlIsSilent(t *testing.T) {
	census, findings := JudgePlatformNameAxes(injAxes(1, 1), map[string]bool{injHolder: true},
		injExists, injCorpus())
	require.Empty(t, findings, "законная перепись дала находку")
	require.Equal(t, 1, census.Held)
	require.Equal(t, 1, census.Counted)
	require.Equal(t, 1, census.Residue, "строка без SPIFFE либо проба попали в остаток")
}

// TestAxesInjection_UndeclaredHolderIsFound — ось, держимая именем, которого
// нет в дереве.
func TestAxesInjection_UndeclaredHolderIsFound(t *testing.T) {
	findings := judgeInjectedAxes(injAxes(1, 1), map[string]bool{}, injCorpus())
	requireOneFinding(t, findings, injHolder, "не объявлен")
}

// TestAxesInjection_MissingSubjectIsFound — предмет оси из дерева ушёл.
func TestAxesInjection_MissingSubjectIsFound(t *testing.T) {
	axes := injAxes(1, 1)
	axes[0].Subject = "internal/gone"
	findings := judgeInjectedAxes(axes, map[string]bool{injHolder: true}, injCorpus())
	requireOneFinding(t, findings, "internal/gone", "предмета")
}

// TestAxesInjection_ResidueGrowthIsFound — второе вхождение на строке SPIFFE.
func TestAxesInjection_ResidueGrowthIsFound(t *testing.T) {
	corpus := injCorpus()
	corpus[injSpiffeYA] += "  - \"spiffe://kacho.cloud/sa/extra\"\n"
	findings := judgeInjectedAxes(injAxes(1, 1), map[string]bool{injHolder: true}, corpus)
	requireOneFinding(t, findings, "вырос", "2 вхождений")
}

// TestAxesInjection_ResidueDropIsFound — остаток снят, а число осталось:
// перепись отстала и обязана быть опущена тем же изменением.
func TestAxesInjection_ResidueDropIsFound(t *testing.T) {
	corpus := injCorpus()
	corpus[injSpiffeYA] = "senders:\n  - \"spiffe://example.invalid/sa/edge\"\nnote: kacho\n"
	findings := judgeInjectedAxes(injAxes(1, 1), map[string]bool{injHolder: true}, corpus)
	requireOneFinding(t, findings, "снизился", "0 вхождений")
}

// TestAxesInjection_TokenFilterIsHonoured — фильтр токена отбирает ровно свою
// форму: имя ряда считается, имя соседа на той же строке — нет.
func TestAxesInjection_TokenFilterIsHonoured(t *testing.T) {
	axes := []PlatformNameAxis{{Axis: "метрики", Subject: injSpiffeYA, Census: &AxisCensus{
		Paths:       []string{"deploy"},
		Token:       regexp.MustCompile(`^kacho_[a-z_]+$`),
		Occurrences: 1, Files: 1, Composition: "ряд фундамента", Owner: "задача",
	}}}
	corpus := map[string]string{injSpiffeYA: "expr: rate(kacho_grpc_server_handled_total[5m]) # kacho-api-gateway\n"}
	census, findings := JudgePlatformNameAxes(axes, nil, injExists, corpus)
	require.Empty(t, findings)
	require.Equal(t, 1, census.Residue)
}

// TestAxesInjection_ShapeIsJudged — ось обязана держаться ровно одним способом
// и называть, чья работа остаток; дважды названная ось — два места об одном.
func TestAxesInjection_ShapeIsJudged(t *testing.T) {
	both := injAxes(1, 1)
	both[0].Census = both[1].Census
	neither := injAxes(1, 1)
	neither[0].Holders = nil
	noOwner := injAxes(1, 1)
	noOwner[1].Census = &AxisCensus{Paths: []string{"deploy"}, LineHas: []string{"spiffe://"},
		Occurrences: 1, Files: 1, Composition: "имя соседа"}
	dup := append(injAxes(1, 1), injAxes(1, 1)[0])
	noJudges := injAxes(1, 1)
	noJudges[0].Judges = ""

	for name, tc := range map[string]struct {
		axes []PlatformNameAxis
		want string
	}{
		"и держатель, и число":            {both, "ровно одно из двух"},
		"ни того ни другого":              {neither, "не держится ничем"},
		"остаток без владельца":           {noOwner, "владелец"},
		"ось дважды":                      {dup, "дважды"},
		"держатель без предмета держания": {noJudges, "ЧТО судит"},
	} {
		t.Run(name, func(t *testing.T) {
			findings := judgeInjectedAxes(tc.axes, map[string]bool{injHolder: true}, injCorpus())
			requireOneFinding(t, findings, tc.want)
		})
	}
}

// TestAxesInjection_HolderIsReadFromADeclarationNotAMention — держатель живёт
// ОБЪЯВЛЕНИЕМ функции, а не упоминанием: имя в комментарии и в строке не
// делает ось держимой, а объявление — делает. Разбор тот же, что у гейта.
func TestAxesInjection_HolderIsReadFromADeclarationNotAMention(t *testing.T) {
	build := func(files map[string]string) *treecorpus.Tree {
		root := t.TempDir()
		for rel, body := range files {
			p := filepath.Join(root, filepath.FromSlash(rel))
			require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
			require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
		}
		tree, err := treecorpus.SyntheticTree(root)
		require.NoError(t, err)
		return tree
	}

	mention := build(map[string]string{"internal/probe/x_test.go": "package probe\n\n// " + injHolder +
		" держит ось.\nvar name = \"" + injHolder + "\"\n"})
	declared, census, parsed, err := declaredFuncNames(mention)
	require.NoError(t, err)
	require.Equal(t, 1, parsed)
	require.Zero(t, census.Tests, "упоминание прочитано как объявление пробы")
	requireOneFinding(t, judgeInjectedAxes(injAxes(1, 1), declared, injCorpus()), "не объявлен")

	twin := build(map[string]string{"internal/probe/x_test.go": "package probe\n\nimport \"testing\"\n\nfunc " +
		injHolder + "(t *testing.T) {}\n"})
	declared, census, _, err = declaredFuncNames(twin)
	require.NoError(t, err)
	require.Equal(t, 1, census.Tests)
	require.Empty(t, judgeInjectedAxes(injAxes(1, 1), declared, injCorpus()))

	empty := build(map[string]string{"docs/x.md": "текст\n"})
	_, census, parsed, err = declaredFuncNames(empty)
	require.NoError(t, err)
	require.Zero(t, parsed+census.Tests, "дерево без Go дало объявления — предпосылка гейта "+
		"«проб прочитано больше нуля» перестала бы что-либо значить")
}
