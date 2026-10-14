// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

// store_unavailable_cells_test.go — КАЖДЫЙ выход глагола своих данных по сбою
// хранилища растит клетку этого глагола ровно на единицу (kaname#691).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Глаголы под живой сессией — повышение уровня, заведение, подтверждение,
// состояние и снятие второго фактора, перечеканка запасных кодов, смена и
// заведение пароля — отдают на сбой хранилища `ErrStoreUnavailable` с десятков
// мест. Наружу это один `UNAVAILABLE`; клетки у них не было, и правило отказов
// нашей стороны о них молчало.
//
// Судится не «есть вызов наблюдателя», а ИСХОД: подставной отказ порта на
// КАЖДОЙ точке отказа дублёра хранилища, которую глагол спрашивает. Точки
// выводятся обходом исходника дублёра (`fake_store_test.go`: `x.fail("…")` и
// `x.failsAt("…")`), а не выписываются по памяти — новая точка отказа дублёра
// входит в перепись сама. Сравнение `failOn == "…"` мимо `failsAt` — находка:
// такая точка спрошенной не отмечается и выпала бы из суда молча.
//
// Судятся точки, которые законный близнец (прогон без отказа) СПРОСИЛ: точку,
// которую глагол не спрашивает, отказ на ней не достигает — прогон с ней
// совпадает с близнецом. Так проба не платит полную сборку дублёра за точку,
// заведомо холостую для глагола.
//
// Для каждой пары «сценарий × точка»: глагол вернул `ErrStoreUnavailable` —
// клетка его глагола +1, прочие клетки не тронуты; глагол вернул иное — ни
// одна клетка не тронута (отказ вызывающего и успех сбоем хранилища не
// считаются).
//
// ПРЕДПОСЫЛКА: у каждого сценария есть хоть одна точка, дающая
// `ErrStoreUnavailable` (иначе сценарий не доходит до хранилища и судить нечего),
// и законный близнец без отказа проходит, клетку не трогая.

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"sort"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/assurance"
)

// fakeStoreFailPoints — имена подставных отказов дублёра хранилища, выведенные
// разбором его исходника: литерал-аргумент `x.fail("…")` и `x.failsAt("…")`.
// Сравнение `….failOn == "…"` с литералом точку спрошенной не отмечает — оно
// возвращается находкой.
func fakeStoreFailPoints(t *testing.T) ([]string, []string) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fake_store_test.go", nil, 0)
	require.NoError(t, err, "исходник дублёра не разбирается")
	seen := map[string]bool{}
	var bypass []string
	lit := func(e ast.Expr) (string, bool) {
		bl, ok := e.(*ast.BasicLit)
		if !ok || bl.Kind != token.STRING {
			return "", false
		}
		v, err := strconv.Unquote(bl.Value)
		return v, err == nil && v != ""
	}
	isFailOn := func(e ast.Expr) bool {
		sel, ok := e.(*ast.SelectorExpr)
		return ok && sel.Sel.Name == "failOn"
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok && (sel.Sel.Name == "fail" || sel.Sel.Name == "failsAt") && len(x.Args) == 1 {
				if v, ok := lit(x.Args[0]); ok {
					seen[v] = true
				}
			}
		case *ast.BinaryExpr:
			if x.Op != token.EQL {
				return true
			}
			for _, side := range [][2]ast.Expr{{x.X, x.Y}, {x.Y, x.X}} {
				if isFailOn(side[0]) {
					if v, ok := lit(side[1]); ok {
						bypass = append(bypass, fset.Position(x.Pos()).String()+": failOn == "+strconv.Quote(v))
					}
				}
			}
		}
		return true
	})
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, bypass
}

// storeFailureScenario — глагол, доведённый до вызова: setup готовит личность
// и сессию без отказа, run исполняет глагол (отказ ставится между ними).
type storeFailureScenario struct {
	verb  humansession.StoreFailureVerb
	setup func(t *testing.T, h *sfHarness) func() error
}

const sfStorePassword = "correct horse battery"

func storeFailureScenarios() map[string]storeFailureScenario {
	ctx := context.Background()
	return map[string]storeFailureScenario{
		"повышение уровня кодом": {verb: humansession.StoreFailureStepUp, setup: func(t *testing.T, h *sfHarness) func() error {
			login, secret, _ := h.enrolled(t, "usr-sf-su1", "su1@example.invalid", sfStorePassword)
			return func() error {
				_, err := h.stepUp.Execute(ctx, humansession.StepUpInput{Bearer: login.Bearer, Method: assurance.MethodTOTP,
					Code: probeTOTP(t, secret, h.step()), Source: "203.0.113.7"})
				return err
			}
		}},
		"повышение уровня паролем": {verb: humansession.StoreFailureStepUp, setup: func(t *testing.T, h *sfHarness) func() error {
			h.person(t, "usr-sf-su2", "su2@example.invalid", sfStorePassword, true)
			login := h.freshSession(t, "su2@example.invalid", sfStorePassword)
			return func() error {
				_, err := h.stepUp.Execute(ctx, humansession.StepUpInput{Bearer: login.Bearer, Method: assurance.MethodPassword,
					Password: sfStorePassword, Source: "203.0.113.7"})
				return err
			}
		}},
		"заведение второго фактора": {verb: humansession.StoreFailureSecondFactorEnroll, setup: func(t *testing.T, h *sfHarness) func() error {
			h.person(t, "usr-sf-en", "en@example.invalid", sfStorePassword, true)
			login := h.freshSession(t, "en@example.invalid", sfStorePassword)
			return func() error {
				_, err := h.enroll.Execute(ctx, humansession.EnrollInput{Bearer: login.Bearer})
				return err
			}
		}},
		"подтверждение второго фактора": {verb: humansession.StoreFailureSecondFactorConfirm, setup: func(t *testing.T, h *sfHarness) func() error {
			h.person(t, "usr-sf-cf", "cf@example.invalid", sfStorePassword, true)
			login := h.freshSession(t, "cf@example.invalid", sfStorePassword)
			en, err := h.enroll.Execute(ctx, humansession.EnrollInput{Bearer: login.Bearer})
			require.NoError(t, err)
			return func() error {
				_, err := h.confirm.Execute(ctx, humansession.ConfirmInput{Bearer: login.Bearer,
					Code: probeTOTP(t, en.Secret, h.step()), Source: "203.0.113.7"})
				return err
			}
		}},
		"состояние второго фактора": {verb: humansession.StoreFailureSecondFactorStatus, setup: func(t *testing.T, h *sfHarness) func() error {
			login, _, _ := h.enrolled(t, "usr-sf-st", "st@example.invalid", sfStorePassword)
			return func() error {
				_, err := h.status.Execute(ctx, humansession.StatusInput{Bearer: login.Bearer})
				return err
			}
		}},
		"снятие второго фактора": {verb: humansession.StoreFailureSecondFactorRemove, setup: func(t *testing.T, h *sfHarness) func() error {
			login, secret, _ := h.enrolled(t, "usr-sf-rm", "rm@example.invalid", sfStorePassword)
			return func() error {
				_, err := h.remove.Execute(ctx, humansession.RemoveSecondFactorInput{Bearer: login.Bearer,
					Factor: humansession.SecondFactorPresentation{Method: assurance.MethodTOTP, Code: probeTOTP(t, secret, h.step())},
					Source: "203.0.113.7"})
				return err
			}
		}},
		"перечеканка запасных кодов": {verb: humansession.StoreFailureBackupCodesRegenerate, setup: func(t *testing.T, h *sfHarness) func() error {
			login, secret, _ := h.enrolled(t, "usr-sf-bc", "bc@example.invalid", sfStorePassword)
			return func() error {
				_, err := h.regenerate.Execute(ctx, humansession.RegenerateBackupCodesInput{Bearer: login.Bearer,
					Factor: humansession.SecondFactorPresentation{Method: assurance.MethodTOTP, Code: probeTOTP(t, secret, h.step())},
					Source: "203.0.113.7"})
				return err
			}
		}},
		"смена пароля": {verb: humansession.StoreFailurePasswordChange, setup: func(t *testing.T, h *sfHarness) func() error {
			h.person(t, "usr-sf-pc", "pc@example.invalid", sfStorePassword, true)
			login := h.freshSession(t, "pc@example.invalid", sfStorePassword)
			return func() error {
				_, err := h.change.Execute(ctx, humansession.ChangePasswordInput{Bearer: login.Bearer,
					CurrentPassword: sfStorePassword, NewPassword: "brand new passphrase", Source: "203.0.113.7"})
				return err
			}
		}},
		"заведение пароля": {verb: humansession.StoreFailurePasswordEnroll, setup: func(t *testing.T, h *sfHarness) func() error {
			u := h.person(t, "usr-sf-pe", "pe@example.invalid", "", true)
			w, err := h.store.Writer(ctx)
			require.NoError(t, err)
			_, bearer, err := humansession.IssueSession(ctx, w, humansession.IssueInput{
				User: u, Presented: []assurance.Presentation{assurance.KeyAssertion(true, false)}, At: h.clock, TTL: ucTTL,
			})
			require.NoError(t, err)
			require.NoError(t, w.Commit(ctx))
			uc, err := humansession.NewEnrollPasswordUseCase(humansession.EnrollPasswordDeps{
				Store: h.store, Hasher: h.hasher, Rule: h.rule, Freshness: 15 * time.Minute,
				Observer: h.obs, Now: func() time.Time { return h.clock }, Logger: slog.New(slog.DiscardHandler),
			})
			require.NoError(t, err)
			return func() error {
				_, err := uc.Execute(ctx, humansession.EnrollPasswordInput{Bearer: bearer, NewPassword: "a clean passphrase"})
				return err
			}
		}},
	}
}

// storeFailureCells — снимок клеток наблюдателя.
func storeFailureCells(h *sfHarness) map[humansession.StoreFailureVerb]int {
	h.obs.mu.Lock()
	defer h.obs.mu.Unlock()
	out := map[humansession.StoreFailureVerb]int{}
	for k, v := range h.obs.storeFailures {
		out[k] = v
	}
	return out
}

// TestStoreFailureVerbsHaveAScenarioEach — перечень производителя и перечень
// сценариев совпадают: глагол без сценария не судим, сценарий без глагола
// пережил свой предмет.
func TestStoreFailureVerbsHaveAScenarioEach(t *testing.T) {
	covered := map[humansession.StoreFailureVerb]bool{}
	for _, sc := range storeFailureScenarios() {
		covered[sc.verb] = true
	}
	for _, v := range humansession.StoreFailureVerbs() {
		require.Truef(t, covered[v], "глагол %q без сценария — его клетку никто не судит", v)
		delete(covered, v)
	}
	require.Emptyf(t, covered, "сценарии о глаголах вне перечня производителя: %v", covered)
}

// TestEveryStoreUnavailableExitOfASelfServiceVerbCountsItsCell — kaname#691.
func TestEveryStoreUnavailableExitOfASelfServiceVerbCountsItsCell(t *testing.T) {
	points, bypass := fakeStoreFailPoints(t)
	require.NotEmpty(t, points, "обход дублёра не нашёл ни одной точки отказа — судить нечего, это не зелёное")
	require.Emptyf(t, bypass, "точки дублёра сравниваются мимо failsAt — спрошенными не отмечаются и выпали бы из суда:\n  %v", bypass)
	known := map[string]bool{}
	for _, p := range points {
		known[p] = true
	}
	scenarios := storeFailureScenarios()
	names := make([]string, 0, len(scenarios))
	for n := range scenarios {
		names = append(names, n)
	}
	sort.Strings(names)

	// Сценарии независимы (свой дублёр у каждой пары) и идут параллельно;
	// перепись печатается, когда отработали все.
	var runs, unavailable atomic.Int64
	t.Cleanup(func() {
		t.Logf("ПЕРЕПИСЬ: точек отказа дублёра %d · сценариев %d · глаголов %d · прогонов с отказом на спрошенной точке %d · "+
			"из них ErrStoreUnavailable %d",
			len(points), len(scenarios), len(humansession.StoreFailureVerbs()), runs.Load(), unavailable.Load())
		if !t.Failed() && unavailable.Load() == 0 {
			t.Error("ни один прогон не дал ErrStoreUnavailable — судить нечего, это не зелёное")
		}
	})
	for _, name := range names {
		sc := scenarios[name]
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			// Законный близнец: без отказа глагол проходит, клетки не тронуты.
			h := newSFHarness(t)
			run := sc.setup(t, h)
			before := storeFailureCells(h)
			h.store.resetTouched()
			require.NoError(t, run(), "близнец без отказа обязан пройти — сценарий не доводит глагол до успеха")
			require.Equal(t, before, storeFailureCells(h), "успех не сбой хранилища")
			var asked []string
			for p := range h.store.touchedPoints() {
				require.Truef(t, known[p], "глагол спросил точку %q, которой обход дублёра не знает", p)
				asked = append(asked, p)
			}
			sort.Strings(asked)
			require.NotEmpty(t, asked, "близнец не спросил ни одной точки — глагол до хранилища не доходит")

			hits := 0
			for _, point := range asked {
				h := newSFHarness(t)
				run := sc.setup(t, h)
				before := storeFailureCells(h)
				h.store.failOn = point
				err := run()
				runs.Add(1)
				after := storeFailureCells(h)
				want := map[humansession.StoreFailureVerb]int{}
				for k, v := range before {
					want[k] = v
				}
				if errors.Is(err, humansession.ErrStoreUnavailable) {
					hits++
					unavailable.Add(1)
					want[sc.verb]++
				}
				require.Equalf(t, want, after, "точка отказа %q: глагол вернул %v — клетка сбоя хранилища "+
					"%q обязана вырасти ровно на единицу при ErrStoreUnavailable и стоять при ином исходе", point, err, sc.verb)
			}
			t.Logf("точек спрошено %d из %d · сбоев хранилища %d", len(asked), len(points), hits)
			require.NotZerof(t, hits, "ни одна из %d спрошенных точек не довела глагол до сбоя хранилища — "+
				"судить нечего", len(asked))
		})
	}
}
