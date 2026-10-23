// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modulecatalog_test

// revision_test.go — решатель редакции и его места (kaname#865, приёмка
// `docs/engineering/acceptance/module-manifest-revision-only-moves-forward.md`):
// таблица Д2, старшинство вердиктов плана (865-33), перепись старта (Д3) и
// отказ глагола с текстом Д7 — без базы. Оператор базы и последовательность
// старта судят интеграционные пробы.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

// probemodAt — документ R(n, open) фикстуры P11, разобранный загрузчиком.
// n == 0 — документ без ключа `revision`.
func probemodAt(t *testing.T, n int64, open bool) *manifest.Manifest {
	t.Helper()
	doc, err := publicreadfixture.Read(publicreadfixture.ProbemodFile)
	require.NoError(t, err)
	if !open {
		doc, err = publicreadfixture.WithoutKey(doc)
		require.NoError(t, err)
	}
	if n > 0 {
		doc, err = publicreadfixture.WithRevision(doc, n)
		require.NoError(t, err)
	}
	m, err := manifest.Load(doc)
	require.NoError(t, err)
	return m
}

func ed(n int64, digest string) *modulecatalog.Edition {
	return &modulecatalog.Edition{Revision: n, Digest: digest}
}

// TestJudgeRevisionFollowsTheTableOfD2 — каждая строка таблицы Д2 и обе строки
// переходной ветки S1.
func TestJudgeRevisionFollowsTheTableOfD2(t *testing.T) {
	const h, g = "sha256:" + "aa", "sha256:" + "bb"
	cases := []struct {
		name              string
		applied, declared *modulecatalog.Edition
		want              modulecatalog.RevisionOutcome
		writes, refused   bool
	}{
		{"a нет, d есть", nil, ed(3, g), modulecatalog.RevisionFirst, true, false},
		{"d < a", ed(5, h), ed(3, g), modulecatalog.RevisionStale, false, true},
		{"d < a при равном отпечатке", ed(5, h), ed(3, h), modulecatalog.RevisionStale, false, true},
		{"d = a, g = h", ed(5, h), ed(5, h), modulecatalog.RevisionRepeat, false, false},
		{"d = a, g ≠ h", ed(5, h), ed(5, g), modulecatalog.RevisionConflict, false, true},
		{"d > a", ed(5, h), ed(6, g), modulecatalog.RevisionNewer, true, false},
		{"d > a при равном отпечатке", ed(5, h), ed(6, h), modulecatalog.RevisionNewer, true, false},
		{"S1: d нет, a нет", nil, nil, modulecatalog.RevisionUndeclaredOverUnapplied, false, false},
		{"S1: d нет, a есть", ed(5, h), nil, modulecatalog.RevisionStale, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := modulecatalog.JudgeRevision(c.applied, c.declared)
			require.Equal(t, c.want, got)
			require.Equal(t, c.writes, got.Writes())
			require.Equal(t, c.refused, got.Refused())
		})
	}
}

// Test865_33_PlanVerdictPrecedence — исход редакции судится раньше опоры, а
// перечни опоры от него не зависят. Состояния — `IAM-MA-1-36` (опора
// отвергает) и близнец `IAM-MA-1-02` (опора пропускает) соседней приёмки.
func Test865_33_PlanVerdictPrecedence(t *testing.T) {
	states := planStates(t)
	byID := map[string]planState{}
	for _, s := range states {
		byID[s.id] = s
	}
	outcomes := []struct {
		name    string
		outcome modulecatalog.RevisionOutcome
	}{
		{"(а) младшая", modulecatalog.RevisionStale},
		{"(б) конфликт", modulecatalog.RevisionConflict},
		{"(в) старшая", modulecatalog.RevisionNewer},
	}
	want := map[string][]modulecatalog.Verdict{
		"IAM-MA-1-36": {
			modulecatalog.VerdictWouldBeRefusedStaleRevision,
			modulecatalog.VerdictWouldBeRefusedRevisionConflict,
			modulecatalog.VerdictWouldBeRefusedBeyondAnchor,
		},
		"IAM-MA-1-02": {
			modulecatalog.VerdictWouldBeRefusedStaleRevision,
			modulecatalog.VerdictWouldBeRefusedRevisionConflict,
			modulecatalog.VerdictWouldApply,
		},
	}
	for id, verdicts := range want {
		s, ok := byID[id]
		require.True(t, ok, "состояние %s в наборе planStates не найдено", id)
		anchor, err := modulecatalog.PlanAgainstAnchor(context.Background(),
			modulecatalog.NewCatalogState(s.live, s.retired), s.declared, seed.ImageAnchor())
		require.NoError(t, err)
		for i, o := range outcomes {
			t.Run(id+"/"+o.name, func(t *testing.T) {
				require.Equal(t, verdicts[i], modulecatalog.PlanVerdict(anchor, o.outcome))
				// Перечни опоры — те же, что без учёта редакции: функция их не
				// трогает, а план отдаёт их при любом вердикте.
				again, err := modulecatalog.PlanAgainstAnchor(context.Background(),
					modulecatalog.NewCatalogState(s.live, s.retired), s.declared, seed.ImageAnchor())
				require.NoError(t, err)
				require.Equal(t, again.BeyondAnchorExtra, anchor.BeyondAnchorExtra)
				require.Equal(t, again.BeyondAnchorMissing, anchor.BeyondAnchorMissing)
				require.Equal(t, again.WithdrawnRows, anchor.WithdrawnRows)
			})
		}
	}
}

// TestApplyAllNamesStaleAndConflictAndGoesOn — путь СТАРТА (Д3): младшая
// редакция и конфликт — строки переписи, а не отказ; обход идёт дальше, а
// перечень применённых манифестов — ровно применённые.
func TestApplyAllNamesStaleAndConflictAndGoesOn(t *testing.T) {
	r5 := probemodAt(t, 5, true)
	w := &recordingWriter{applied: map[string]*modulecatalog.Edition{
		"probemod": ed(5, r5.Digest()),
	}}
	applier := modulecatalog.NewApplier(&recordingTx{w: w})

	other := fixtureManifest("alpha", "widgets")

	census, err := applier.ApplyAll(context.Background(), []*manifest.Manifest{probemodAt(t, 3, false), other})
	require.NoError(t, err, "младшая редакция на старте — пропуск, а не отказ (Д3)")
	require.Equal(t, 1, census.Applied)
	require.Equal(t, []string{"alpha"}, census.Modules)
	require.Len(t, census.SkippedStale, 1)
	require.Empty(t, census.RefusedConflict)
	require.Equal(t, "probemod", census.SkippedStale[0].Module)
	require.Equal(t, []*manifest.Manifest{other}, census.AppliedManifests)
	require.NotContains(t, w.calls, "module:probemod", "младшая редакция не пишет ни строки: %v", w.calls)

	census, err = applier.ApplyAll(context.Background(), []*manifest.Manifest{probemodAt(t, 5, false), other})
	require.NoError(t, err, "конфликт содержимого на старте — строка переписи, а не отказ (Д3)")
	require.Len(t, census.RefusedConflict, 1)
	require.Empty(t, census.SkippedStale)
	require.Equal(t, []*manifest.Manifest{other}, census.AppliedManifests)

	// Близнец: старшая редакция применяется и входит в перечень.
	r6 := probemodAt(t, 6, false)
	census, err = applier.ApplyAll(context.Background(), []*manifest.Manifest{r6, other})
	require.NoError(t, err)
	require.Equal(t, 2, census.Applied)
	require.Empty(t, census.SkippedStale)
	require.Empty(t, census.RefusedConflict)
	require.Equal(t, []*manifest.Manifest{r6, other}, census.AppliedManifests)
}

// TestRevisionDecisionsMustAgree — решатель и оператор сравнения-и-записи
// разошлись: отказ `ErrWriteFailed`, а не выбор одного из них молча (CE-07).
func TestRevisionDecisionsMustAgree(t *testing.T) {
	w := &recordingWriter{lieAboutWrite: "probemod"}
	_, err := modulecatalog.NewApplier(&recordingTx{w: w}).Apply(context.Background(), probemodAt(t, 3, true))
	require.ErrorIs(t, err, modulecatalog.ErrWriteFailed)

	// Близнец: тот же манифест, оператор отвечает правду — проходит.
	w2 := &recordingWriter{}
	rep, err := modulecatalog.NewApplier(&recordingTx{w: w2}).Apply(context.Background(), probemodAt(t, 3, true))
	require.NoError(t, err)
	require.Equal(t, modulecatalog.RevisionFirst, rep.Revision.Outcome)
}

// verbCtx — контекст глагола с проверенной личностью.
func verbCtx() context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{ID: "usr-probe865", Type: "user"})
}

// TestVerbRefusalTextsAreTheContractTexts — отказ глагола по редакции несёт
// РОВНО текст Д7 (условие CE-15): без английской приставки сентинела.
func TestVerbRefusalTextsAreTheContractTexts(t *testing.T) {
	r5 := probemodAt(t, 5, true)
	r5closed := probemodAt(t, 5, false)
	cases := []struct {
		name string
		m    *manifest.Manifest
		want string
		is   error
	}{
		{"младшая", probemodAt(t, 3, false),
			"модуль probemod: редакция манифеста 3 старше применённой 5; откат выражается новой редакцией больше 5",
			modulecatalog.ErrStaleRevision},
		{"ключ не объявлен", probemodAt(t, 0, true),
			"модуль probemod: манифест не объявляет редакцию, а применена редакция 5; применяется только редакция не меньше 5",
			modulecatalog.ErrStaleRevision},
		{"конфликт", r5closed,
			"модуль probemod: редакция манифеста 5 уже применена с другим содержимым (отпечаток манифеста " +
				r5closed.Digest() + ", применённый " + r5.Digest() + "); изменение содержимого выражается новой редакцией больше 5",
			modulecatalog.ErrRevisionConflict},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := &recordingWriter{applied: map[string]*modulecatalog.Edition{"probemod": ed(5, r5.Digest())}}
			v := modulecatalog.NewVerbApplier(&recordingTx{w: w})
			_, err := v.Apply(verbCtx(), modulecatalog.Request{
				Manifest: c.m, ExpectedState: "x",
				MaxResettledRuleRefs: modulecatalog.Limit(0), MaxResettledRoleVerbs: modulecatalog.Limit(0),
				Anchor: seed.ImageAnchor(),
			})
			require.Error(t, err)
			require.Equal(t, c.want, err.Error())
			require.True(t, errors.Is(err, c.is), "%v", err)
			require.NotContains(t, w.calls, "module:probemod", "отказ по редакции не пишет строк: %v", w.calls)
		})
	}
}
