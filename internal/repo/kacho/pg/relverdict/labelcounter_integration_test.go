// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package relverdict_test

// labelcounter_integration_test.go — «расхождений нет» обязано отличаться от
// «меточную ветвь ни разу не спросили».
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАЧЕМ ЧИСЛО, ЕСЛИ ЕСТЬ ПРОБЫ НА КАЖДЫЙ ТИП
//
// Пробы утверждают, что ветвь ОТВЕЧАЕТ, — на данных, которые сами и посеяли.
// Число отвечает на другой вопрос: спрашивали ли её на живом потоке. Ноль
// оснований по оси означает, что сравнение форм по этой оси не состоялось, и
// вердикт «формы сходятся» тогда сказан о том, чего не мерили. Именно этим
// состоянием дефект и жил: ветвь была тождественно ложна, а наблюдаемого числа,
// которое бы это показало, не существовало.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЧИСЛА ДВА, А НЕ ОДНО
//
// Оси две, и предикат равенства форм у них РАЗНЫЙ. Одно общее число зеленело бы
// от одной живой оси и молчало про мёртвую вторую — ровно та половина
// доказательства, на которой класс и дожил до находки.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/relverdict"
)

// TestAskerCountsLabelArmGroundsPerAxis — счётчик оснований меточной ветви
// растёт на ТОЙ оси, у которой спрашивали, и не растёт на другой.
func TestAskerCountsLabelArmGroundsPerAxis(t *testing.T) {
	pool, ctx := withCommittedPool(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedLabelGrant(t, ctx, tx, "iam_group")
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.groups (id, account_id, name, labels)
			 VALUES ('grp-9', 'acc-1', 'probe-group', '{"env":"prod"}'::jsonb)`)
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.resource_parent_edge
			   (object_type, object_id, parent_type, parent_id, depth)
			 VALUES ('iam_group', 'grp-9', 'account', 'acc-1', 1)`)
	})
	asker := relverdict.NewAsker(pool)

	mirror, iamDirect := asker.LabelArmGrounds()
	if mirror != 0 || iamDirect != 0 {
		t.Fatalf("свежий источник обязан начинать с нуля, а начал с (%d, %d)", mirror, iamDirect)
	}

	allowed, err := asker.Allowed(ctx, "user:usr-1", "iam_group", "grp-9", "v_get", nil)
	if err != nil {
		t.Fatalf("вопрос: %v", err)
	}
	if !allowed {
		t.Fatalf("меточная выдача не достала iam_group:grp-9")
	}
	mirror, iamDirect = asker.LabelArmGrounds()
	t.Logf("после вопроса на оси собственных таблиц: зеркало %d, iam-direct %d", mirror, iamDirect)
	if iamDirect != 1 {
		t.Errorf("основание меточной ветви на оси собственных таблиц не засчитано: %d — "+
			"с нулём здесь «расхождений нет» означает «не сравнивали»", iamDirect)
	}
	// Отрицательный близнец числа: ось зеркала на этом вопросе не спрашивали, и
	// её счётчик обязан стоять. Без него счётчик, растущий на всём подряд,
	// выглядел бы работающим и не различал бы оси.
	if mirror != 0 {
		t.Errorf("счётчик оси зеркала вырос на вопросе о собственном типе iam: %d", mirror)
	}
}

// TestAskerCountsLabelArmGroundsOnTheMirrorAxis — ЗАКОННЫЙ БЛИЗНЕЦ: та же
// механика считает ось зеркала.
func TestAskerCountsLabelArmGroundsOnTheMirrorAxis(t *testing.T) {
	pool, ctx := withCommittedPool(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedLabelGrant(t, ctx, tx, "vpc_network")
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.resource_mirror (object_type, object_id, labels)
			 VALUES ($1, 'net-9', '{"env":"prod"}'::jsonb)`,
			catalogFormOf(t, "vpc_network"))
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.resource_parent_edge
			   (object_type, object_id, parent_type, parent_id, depth)
			 VALUES ('vpc_network', 'net-9', 'account', 'acc-1', 1)`)
	})
	asker := relverdict.NewAsker(pool)

	allowed, err := asker.Allowed(ctx, "user:usr-1", "vpc_network", "net-9", "v_get", nil)
	if err != nil {
		t.Fatalf("вопрос: %v", err)
	}
	if !allowed {
		t.Fatalf("меточная выдача не достала vpc_network:net-9")
	}
	mirror, iamDirect := asker.LabelArmGrounds()
	t.Logf("после вопроса на оси зеркала: зеркало %d, iam-direct %d", mirror, iamDirect)
	if mirror != 1 {
		t.Errorf("основание меточной ветви на оси зеркала не засчитано: %d", mirror)
	}
	if iamDirect != 0 {
		t.Errorf("счётчик оси собственных таблиц вырос на вопросе о чужом типе: %d", iamDirect)
	}
}

// TestAskerDoesNotCountWhenTheLabelArmGaveNothing — число считает ОСНОВАНИЯ, а не
// вопросы.
//
// Счётчик, растущий на каждом вопросе, был бы наблюдаемым и бессмысленным: он
// остался бы ненулевым и на тождественно ложной ветви, то есть ровно на том
// состоянии, ради обнаружения которого заведён.
func TestAskerDoesNotCountWhenTheLabelArmGaveNothing(t *testing.T) {
	pool, ctx := withCommittedPool(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		// Ветвь ЯКОРНАЯ: право есть, метки не читаются вовсе.
		seedRole(t, ctx, tx, "rol-anchor", "iam_group", "get", "anchor", "{}")
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.access_bindings
			   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
			 VALUES ('acb-anchor', 'user', 'usr-1', 'rol-anchor', 'account', 'acc-1', 'ACTIVE')`)
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
			 VALUES ('acb-anchor', 'user', 'usr-1')`)
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.groups (id, account_id, name, labels)
			 VALUES ('grp-9', 'acc-1', 'probe-group', '{"env":"prod"}'::jsonb)`)
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.resource_parent_edge
			   (object_type, object_id, parent_type, parent_id, depth)
			 VALUES ('iam_group', 'grp-9', 'account', 'acc-1', 1)`)
	})
	asker := relverdict.NewAsker(pool)

	allowed, err := asker.Allowed(ctx, "user:usr-1", "iam_group", "grp-9", "v_get", nil)
	if err != nil {
		t.Fatalf("вопрос: %v", err)
	}
	if !allowed {
		t.Fatalf("якорная выдача не достала iam_group:grp-9 — сломана фикстура, а не предмет")
	}
	mirror, iamDirect := asker.LabelArmGrounds()
	if mirror != 0 || iamDirect != 0 {
		t.Errorf("основание якорной ветви засчитано как меточное: (%d, %d)", mirror, iamDirect)
	}
}
