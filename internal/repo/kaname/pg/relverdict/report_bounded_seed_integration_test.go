// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/scalegrid"
	"github.com/PRO-Robotech/kaname/internal/testsupport/activewayin"
)

// Отчёт начинает с N=100: фиксированный bootstrap R7 N=200 сюда не подходит.
// Владение и TX прежние; SQL посева берётся у существующих фикстур.
func newReportSeed(t *testing.T) *r7CostSeed {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(pgtest.NewDB(t))
	must(t, err)
	h := &r7CostSeed{capture: &verdictCapture{}}
	cfg.ConnConfig.Tracer = h.capture
	cfg.MaxConns = 1
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	h.pool, err = pgxpool.NewWithConfig(ctx, cfg)
	if h.pool != nil {
		pgtest.ClosePoolAtEnd(t, h.pool)
	}
	must(t, err)
	return h
}

// Одна база и набор ролей на ось; время Given включает bootstrap и COMMIT.
func runBoundedFullReportAxis(t *testing.T, axis []scalegrid.Point) []pointResult {
	t.Helper()
	if len(axis) == 0 {
		return nil
	}
	started := time.Now()
	h := newReportSeed(t)
	h.transaction(t, true, func(ctx context.Context, tx pgx.Tx) {
		h.fixture = newR7CostGridFixture(t, ctx, tx)
	})
	out := make([]pointResult, 0, len(axis))
	for i, p := range axis {
		if i > 0 {
			started = time.Now()
		}
		seedRecruitConstructibilityPoint(t, h, p)
		h.transaction(t, true, func(ctx context.Context, tx pgx.Tx) {
			h.fixture.analyze(t, ctx)
		})
		seedFor := time.Since(started)
		var r pointResult
		var distinct int
		h.transaction(t, false, func(ctx context.Context, tx pgx.Tx) {
			r = measurePoint(t, ctx, tx, h.capture, p)
			if r.verdict != relverdict.Allow.String() {
				t.Fatalf("точка %s дала %s вместо allow", p, r.verdict)
			}
			distinct = distinctScope(t, ctx, tx)
		})
		t.Logf("точка %s: посев %s · строк(несущая) %d · тронуто %d · сверочная %d · "+
			"обращений %d · вердикт %s · p50 %s · S_набл %d (d=%d, различных %d) · план [%s]",
			p, seedFor.Round(time.Millisecond), r.rows, r.touched, r.tuples, r.calls,
			r.verdict, r.p50.Round(time.Microsecond), r.sObs, r.depth, distinct, r.plan)
		out = append(out, r)
	}
	return out
}

// Strength имеет собственную фикстуру, но тот же ограниченный срок и cleanup TX.
func strengthReportTransaction(t *testing.T, h *r7CostSeed, f *strFixture, commit bool, run func(context.Context, pgx.Tx)) {
	t.Helper()
	h.transaction(t, commit, func(ctx context.Context, tx pgx.Tx) {
		f.tx = tx
		defer func() { f.tx = nil }()
		run(ctx, tx)
	})
}

func seedBoundedStrengthPoint(t *testing.T, h *r7CostSeed, f *strFixture, p scalegrid.StrengthPoint) {
	t.Helper()
	if p.N < f.seedN || p.M < f.seedM || p.L < f.seedL {
		t.Fatalf("точка %s уменьшает уже посаженную ось", p)
	}
	share := 100
	if p.Axis == scalegrid.AxisPg {
		share = p.AllowedShare
	}
	if share != f.shareSeeded {
		strengthReportTransaction(t, h, f, true, func(ctx context.Context, tx pgx.Tx) {
			f.recolorAllowObject(t, ctx, share)
		})
		for first := 0; first < f.seedN; first += r7CostSeedBatch {
			last := min(first+r7CostSeedBatch, f.seedN)
			strengthReportTransaction(t, h, f, true, func(ctx context.Context, tx pgx.Tx) {
				changed := f.recolorBulkRange(t, ctx, share, fmt.Sprintf("bulk-%07d", first), fmt.Sprintf("bulk-%07d", last))
				if changed != int64(last-first) {
					t.Fatalf("перекрашено %d объектов вместо %d", changed, last-first)
				}
			})
		}
	}
	for f.seedN < p.N {
		next := min(f.seedN+r7CostSeedBatch, p.N)
		strengthReportTransaction(t, h, f, true, func(ctx context.Context, tx pgx.Tx) {
			f.growNObjects(t, ctx, next, share)
		})
	}
	if p.Axis == scalegrid.AxisS {
		strengthReportTransaction(t, h, f, true, func(ctx context.Context, tx pgx.Tx) {
			f.setScopeShape(t, ctx, p.S)
		})
	}
	for f.seedM < p.M {
		next := min(f.seedM+r7CostSeedBatch, p.M)
		strengthReportTransaction(t, h, f, true, func(ctx context.Context, tx pgx.Tx) {
			f.setM(t, ctx, next)
		})
	}
	for f.seedL < p.L {
		next := min(f.seedL+r7CostSeedBatch, p.L)
		strengthReportTransaction(t, h, f, true, func(ctx context.Context, tx pgx.Tx) {
			f.setL(t, ctx, next)
			activewayin.Seed(t, ctx, tx)
		})
	}
	strengthReportTransaction(t, h, f, true, func(ctx context.Context, tx pgx.Tx) {
		f.setK(t, ctx, p.K)
		f.analyze(t, ctx)
	})
	// Проверяем всю раскраску до счётчиков, включая особый объект Ask.
	strengthReportTransaction(t, h, f, false, func(ctx context.Context, tx pgx.Tx) {
		var total, mismatched int
		must(t, tx.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE labels IS DISTINCT FROM
 CASE WHEN (substr(object_id,6)::int % 100)<$1 THEN $2::jsonb ELSE $3::jsonb END)
 FROM kaname.resource_mirror WHERE object_type=$4 AND object_id LIKE 'bulk-%'`,
			share, strJSON(t, strSelectorLabels(0)), strJSON(t, map[string]string{"env": "dev"}), strCatalogType).Scan(&total, &mismatched))
		if total != p.N || mismatched != 0 {
			t.Fatalf("неполная раскраска %s: объектов %d, неверных %d", p, total, mismatched)
		}
		labels := strLabelKeys()
		if share == 0 {
			labels = map[string]string{"env": "dev"}
		}
		var matches bool
		must(t, tx.QueryRow(ctx, `SELECT labels=$1::jsonb FROM kaname.resource_mirror WHERE object_type=$2 AND object_id=$3`, strJSON(t, labels), strCatalogType, f.allowObj).Scan(&matches))
		if !matches {
			t.Fatalf("неверная раскраска особого объекта %s", f.allowObj)
		}
	})
	// Весь Given, его COMMIT и проверка завершены; частичная доля не публикуется.
	f.shareSeeded = share
}

func runBoundedStrengthReportAxis(t *testing.T, axis []scalegrid.StrengthPoint) []strPointResult {
	t.Helper()
	if len(axis) == 0 {
		return nil
	}
	started := time.Now()
	h := newReportSeed(t)
	var f *strFixture
	h.transaction(t, true, func(ctx context.Context, tx pgx.Tx) {
		f = newStrFixture(t, ctx, tx)
		defer func() { f.tx = nil }()
		activewayin.Seed(t, ctx, tx)
	})
	out := make([]strPointResult, 0, len(axis))
	for i, p := range axis {
		if i > 0 {
			started = time.Now()
		}
		seedBoundedStrengthPoint(t, h, f, p)
		seedFor := time.Since(started)
		var r strPointResult
		strengthReportTransaction(t, h, f, false, func(ctx context.Context, tx pgx.Tx) {
			r = measureStrengthPoint(t, ctx, tx, h.capture, f, p)
			for _, a := range r.asks {
				if p.Axis == scalegrid.AxisPg {
					want := p.Pg
					if p.AllowedShare == 0 {
						want = 0
					}
					if a.listed != want {
						t.Fatalf("точка %s вернула %d объектов вместо %d", p, a.listed, want)
					}
				} else {
					want := relverdict.Deny.String()
					if a.mode == scalegrid.AskAllow {
						want = relverdict.Allow.String()
					}
					if a.verdict != want {
						t.Fatalf("точка %s, вопрос %s: %s вместо %s", p, a.mode, a.verdict, want)
					}
				}
			}
		})
		r.seedIn = seedFor
		t.Logf("точка %s: посев %s · сценариев %d", p, seedFor.Round(time.Millisecond), len(r.asks))
		out = append(out, r)
	}
	return out
}
