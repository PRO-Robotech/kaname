// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/scalegrid"
)

// Только две оси constructibility: сохраняем одну базу и роли между точками.
// Владение пулом, lawful WayIn и bounded TX берутся из закреплённого R7 helper.
func seedRecruitConstructibilityPoint(t *testing.T, h *r7CostSeed, p scalegrid.Point) {
	t.Helper()
	f := h.fixture
	if p.N < f.seedN || p.B < f.seedB || p.R < 1 || p.F < 0 || p.F > 100 {
		t.Fatalf("точка %s вне ограниченного посева constructibility", p)
	}
	for f.seedN < p.N {
		next := min(f.seedN+r7CostSeedBatch, p.N)
		h.transaction(t, true, func(ctx context.Context, tx pgx.Tx) {
			f.growN(t, ctx, next)
		})
	}
	h.growB(t, p.B)

	recruit := recruitForR(p)
	if recruit != f.recR {
		// Удаляем только прежние выдачи, не роли. Штатный setR затем выполнит
		// свой сброс формы над уже пустым набором, не накопив 1000 удалений в TX.
		for first := 0; first < f.seedR; first += r7CostSeedBatch {
			last := min(first+r7CostSeedBatch, f.seedR)
			ids := make([]string, 0, last-first)
			for i := first; i < last; i++ {
				ids = append(ids, fmt.Sprintf("acb-r%05d", i))
			}
			h.transaction(t, true, func(ctx context.Context, tx pgx.Tx) {
				tag, err := tx.Exec(ctx, `DELETE FROM kaname.access_bindings WHERE id=ANY($1::text[])`, ids)
				if err != nil {
					t.Fatalf("снятие прежней формы recruit: %v", err)
				}
				if tag.RowsAffected() != int64(len(ids)) {
					t.Fatalf("снято %d прежних выдач из %d", tag.RowsAffected(), len(ids))
				}
			})
		}
		// Вызов обязателен и при одинаковом R: старый seedR пока не сброшен.
		h.transaction(t, true, func(ctx context.Context, tx pgx.Tx) {
			var remaining int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM kaname.access_bindings WHERE id LIKE 'acb-r%'`).Scan(&remaining); err != nil {
				t.Fatalf("перепись снятой формы recruit: %v", err)
			}
			if remaining != 0 {
				t.Fatalf("перед сменой формы осталось %d прежних выдач", remaining)
			}
			f.setR(t, ctx, min(r7CostSeedBatch, p.R), recruit)
		})
	}
	if p.R < f.seedR {
		t.Fatalf("точка %s уменьшает R без смены формы", p)
	}
	for f.seedR < p.R {
		next := min(f.seedR+r7CostSeedBatch, p.R)
		h.transaction(t, true, func(ctx context.Context, tx pgx.Tx) {
			f.setR(t, ctx, next, recruit)
		})
	}
	h.transaction(t, true, func(ctx context.Context, tx pgx.Tx) {
		f.setF(t, ctx, p.F, recruitForF(p))
	})

	// Точные количества и форма проверяются до измерения; старый census
	// внутри measurePoint также остаётся и видит полный завершённый Given.
	h.transaction(t, false, func(ctx context.Context, tx pgx.Tx) {
		subjectType, subjectID := "user", "usr-1"
		if recruit == scalegrid.RecruitViaGroup {
			subjectType, subjectID = "group", probeGroupID
		}
		var objects, foreign, grants, subjects, roles, facts, shaped, carrier int
		err := tx.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM kaname.resource_mirror WHERE object_type=$1 AND object_id LIKE 'repo-%'),
 (SELECT count(*) FROM kaname.access_bindings WHERE id LIKE 'acb-b%'),
 (SELECT count(*) FROM kaname.access_bindings WHERE id LIKE 'acb-r%'),
 (SELECT count(*) FROM kaname.access_binding_subjects WHERE binding_id LIKE 'acb-r%'),
 (SELECT count(*) FROM kaname.roles WHERE id LIKE 'rol-r%'),
 (SELECT count(*) FROM kaname.relation_fact),
 (SELECT count(*) FROM generate_series(0,$2::integer-1) i
  JOIN kaname.access_bindings b ON b.id='acb-r'||lpad(i::text,5,'0')
  JOIN kaname.access_binding_subjects s ON s.binding_id=b.id
  WHERE b.subject_type=$3 AND b.subject_id=$4 AND s.subject_type=$3 AND s.subject_id=$4
    AND b.role_id='rol-r'||lpad(i::text,5,'0') AND b.resource_type='project'
    AND b.resource_id='prj-1' AND b.status='ACTIVE'),
 (SELECT count(*) FROM kaname.group_members WHERE group_id=$5 AND member_type='user' AND member_id='usr-1')`,
			probeCatalogType, p.R, subjectType, subjectID, probeGroupID).Scan(&objects, &foreign, &grants, &subjects, &roles, &facts, &shaped, &carrier)
		if err != nil {
			t.Fatalf("перепись формы constructibility: %v", err)
		}
		if objects != p.N || foreign != p.B || grants != p.R || subjects != p.R || roles != f.seedRoles || facts != p.F || shaped != p.R || carrier != 1 {
			t.Fatalf("неполный Given %s: N=%d B=%d R=%d subjects=%d roles=%d/%d F=%d shaped=%d carrier=%d",
				p, objects, foreign, grants, subjects, roles, f.seedRoles, facts, shaped, carrier)
		}
	})
}
