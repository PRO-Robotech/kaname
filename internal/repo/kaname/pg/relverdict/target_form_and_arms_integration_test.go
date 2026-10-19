// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// target_form_and_arms_integration_test.go — цель привязки (kaname#857): форму
// цели вне контракта база не принимает (kaname#863), а выдачи без неё нет —
// значит нет и права; сужение цели
// пересекается с каждой ветвью правила роли; класс говорящего «аноним»
// сужается так же, как человек.
//
// Вход — тот же, что у target_narrows_grant_integration_test.go:
// `relverdict.NewAsker` над закоммиченным посевом, все пять форм вопроса.
// Каждый отказ стоит в паре с законным близнецом, отличающимся ОДНИМ фактом:
// формой цели либо перечнем ветви правила.

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
)

// tgCheckReverse сверяет обратные формы (Subjects, Sources) на X и Y.
func tgCheckReverse(t *testing.T, ctx context.Context, a *relverdict.Asker, onX, onY bool) {
	t.Helper()
	for _, c := range []struct {
		id   string
		want bool
	}{{tgObjX, onX}, {tgObjY, onY}} {
		bySubjects, bySources := tgSubjectNamed(t, ctx, a, c.id, tgSpeaker)
		if bySubjects != c.want || bySources != c.want {
			t.Errorf("обратные формы на %s: Subjects=%v Sources=%v, ждали %v",
				c.id, bySubjects, bySources, c.want)
		}
	}
}

// tgSeedBindingRefused — выдача с целью вне контракта: база отвергает вставку
// ограничением формы (kaname#863). Отказ гасится точкой сохранения, чтобы
// посев остального прошёл, и проба утверждает именно ОТКАЗ по имени
// ограничения, а не любую ошибку.
func tgSeedBindingRefused(t *testing.T, ctx context.Context, tx pgx.Tx, target string) {
	t.Helper()
	exec(t, ctx, tx, `SAVEPOINT tg_refused`)
	_, err := tx.Exec(ctx,
		bindingset.With(`INSERT INTO kaname.access_bindings
		   (id, subject_type, subject_id, role_id, resource_type, resource_id, status, target)
		 VALUES ($1, 'user', 'usr-1', $2, 'account', 'acc-1', 'ACTIVE', $3::jsonb)`),
		tgBinding, tgRole, target)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.ConstraintName != relverdict.TargetFormConstraint {
		t.Fatalf("цель %s: ждали отказ ограничением %s, получено %v", target, relverdict.TargetFormConstraint, err)
	}
	exec(t, ctx, tx, `ROLLBACK TO SAVEPOINT tg_refused`)
}

// Цель, корень которой не объект либо чей `resources` не перечень, база не
// принимает, и права по ней нет ни в одной форме вопроса. Близнец каждого
// случая — ближайшая законная форма той же цели.
func TestTarget_UnrecognisedFormGrantsNothing(t *testing.T) {
	net := func(t *testing.T) string { return catalogFormOf(t, "vpc_network") }
	onlyX := tgWant{x: true, listed: []string{tgObjX}}
	whole := tgWant{x: true, y: true, subnet: true, listed: []string{tgObjX, tgObjY}}
	nothing := tgWant{listed: []string{}}

	for _, c := range []struct {
		name         string
		target, twin func(t *testing.T) string
		twinWant     tgWant
	}{
		{
			name:     "корень — пустой массив",
			target:   func(*testing.T) string { return `[]` },
			twin:     func(*testing.T) string { return `{"resources": []}` },
			twinWant: whole,
		},
		{
			name:     "корень — строка",
			target:   func(*testing.T) string { return `"x"` },
			twin:     func(*testing.T) string { return `{}` },
			twinWant: whole,
		},
		{
			name: "корень — массив с целью внутри",
			target: func(t *testing.T) string {
				return `[` + tgTargetResources(t, [2]string{net(t), tgObjX}) + `]`
			},
			twin: func(t *testing.T) string {
				return tgTargetResources(t, [2]string{net(t), tgObjX})
			},
			twinWant: onlyX,
		},
		{
			name:     "resources — null",
			target:   func(*testing.T) string { return `{"resources": null}` },
			twin:     func(*testing.T) string { return `{"resources": []}` },
			twinWant: whole,
		},
		{
			name: "resources — объект",
			target: func(t *testing.T) string {
				return `{"resources": {"type": "` + net(t) + `", "id": "` + tgObjX + `"}}`
			},
			twin: func(t *testing.T) string {
				return `{"resources": [{"type": "` + net(t) + `", "id": "` + tgObjX + `"}]}`
			},
			twinWant: onlyX,
		},
		{
			name:   "resources — строка",
			target: func(*testing.T) string { return `{"resources": "` + tgObjX + `"}` },
			twin: func(t *testing.T) string {
				return tgTargetResources(t, [2]string{net(t), tgObjX})
			},
			twinWant: onlyX,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			pool, ctx := withCommittedPool(t, func(ctx context.Context, tx pgx.Tx) {
				tgSeedTopology(t, ctx, tx)
				tgSeedBindingRefused(t, ctx, tx, c.target(t))
			})
			a := relverdict.NewAsker(pool)
			tgAskAll(t, ctx, a, tgSpeaker, nothing)
			tgCheckReverse(t, ctx, a, false, false)
		})
		t.Run(c.name+" — близнец", func(t *testing.T) {
			pool, ctx := withCommittedPool(t, func(ctx context.Context, tx pgx.Tx) {
				tgSeedTopology(t, ctx, tx)
				tgSeedBinding(t, ctx, tx, "user", "usr-1", c.twin(t))
			})
			a := relverdict.NewAsker(pool)
			tgAskAll(t, ctx, a, tgSpeaker, c.twinWant)
			tgCheckReverse(t, ctx, a, c.twinWant.x, c.twinWant.y)
		})
	}
}

// Аноним — класс говорящего, у которого нет ни одного другого основания: выдача
// классу `anonymous` с целью [X] даёт ему X и только X.
func TestTarget_AnonymousClassIsNarrowedTheSameWay(t *testing.T) {
	const anon = "system_class:anonymous"
	for name, c := range map[string]struct {
		target func(t *testing.T) string
		want   tgWant
	}{
		"цель [X]": {
			target: func(t *testing.T) string {
				return tgTargetResources(t, [2]string{catalogFormOf(t, "vpc_network"), tgObjX})
			},
			want: tgWant{x: true, listed: []string{tgObjX}},
		},
		"близнец allInScope": {
			target: func(*testing.T) string { return `{"allInScope": true}` },
			want:   tgWant{x: true, y: true, subnet: true, listed: []string{tgObjX, tgObjY}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			pool, ctx := withCommittedPool(t, func(ctx context.Context, tx pgx.Tx) {
				tgSeedTopology(t, ctx, tx)
				tgSeedBinding(t, ctx, tx, "system_class", "anonymous", c.target(t))
			})
			tgAskAll(t, ctx, relverdict.NewAsker(pool), anon, c.want)
		})
	}
}

// tgSeedArmTopology — роль с ОДНОЙ ветвью правила (имена либо метки) на тип
// сети и два объекта X, Y со своими метками. Выдачи нет.
func tgSeedArmTopology(t *testing.T, ctx context.Context, tx pgx.Tx,
	arm string, names []string, matchLabels, labelsX, labelsY string) {
	t.Helper()
	seedTenant(t, ctx, tx)
	net := catalogFormOf(t, "vpc_network")
	exec(t, ctx, tx,
		`INSERT INTO kaname.clusters (id, name) VALUES ('cluster_root', 'kacho') ON CONFLICT DO NOTHING`)
	exec(t, ctx, tx,
		`INSERT INTO kaname.roles (id, name, permissions, rules, cluster_id)
		 VALUES ($1, $2, '[]'::jsonb,
		         jsonb_build_array(jsonb_build_object(
		             'module',    'vpc',
		             'resources', jsonb_build_array('network'),
		             'verbs',     jsonb_build_array('get'))),
		         'cluster_root')`, tgRole, "tg."+arm)
	exec(t, ctx, tx,
		`INSERT INTO kaname.role_verb (role_id, object_type, verb) VALUES ($1, $2, 'get')`, tgRole, net)
	if arm == "names" {
		exec(t, ctx, tx,
			`INSERT INTO kaname.role_rule_selectors
			   (role_id, rule_fp, arm, object_types, match_labels, resource_names, verbs_by_type)
			 VALUES ($1, 'fp-arm', 'names', ARRAY[$2::text], '{}'::jsonb, $3::text[],
			         jsonb_build_object($2::text, jsonb_build_array('get')))`,
			tgRole, net, names)
	} else {
		exec(t, ctx, tx,
			`INSERT INTO kaname.role_rule_selectors
			   (role_id, rule_fp, arm, object_types, match_labels, verbs_by_type)
			 VALUES ($1, 'fp-arm', 'labels', ARRAY[$2::text], $3::jsonb,
			         jsonb_build_object($2::text, jsonb_build_array('get')))`,
			tgRole, net, matchLabels)
	}
	for _, o := range []struct{ id, labels string }{{tgObjX, labelsX}, {tgObjY, labelsY}} {
		exec(t, ctx, tx,
			`INSERT INTO kaname.resource_mirror (object_type, object_id, labels) VALUES ($1, $2, $3::jsonb)`,
			net, o.id, o.labels)
		exec(t, ctx, tx,
			`INSERT INTO kaname.resource_parent_edge
			   (object_type, object_id, parent_type, parent_id, depth)
			 VALUES ('vpc_network', $1, 'project', 'prj-1', 1)`, o.id)
	}
}

// Ветви имён и меток пересекаются с целью: правило роли И цель. Правило,
// достающее до обоих объектов, при цели [X] даёт только X; близнец без сужения
// (allInScope) — оба; правило, не достающее до X, при цели [X] — ничего.
func TestTarget_IntersectsWithNamesAndLabelsArms(t *testing.T) {
	const prod, dev = `{"env": "prod"}`, `{"env": "dev"}`
	targetX := func(t *testing.T) string {
		return tgTargetResources(t, [2]string{catalogFormOf(t, "vpc_network"), tgObjX})
	}
	all := func(*testing.T) string { return `{"allInScope": true}` }
	for _, c := range []struct {
		name               string
		arm                string
		names              []string
		match, lx, ly      string
		target             func(t *testing.T) string
		want               tgWant
		reverseX, reverseY bool
	}{
		{"имена [X Y], цель [X]", "names", []string{tgObjX, tgObjY}, "", prod, prod, targetX,
			tgWant{x: true, listed: []string{tgObjX}}, true, false},
		{"имена [X Y], близнец allInScope", "names", []string{tgObjX, tgObjY}, "", prod, prod, all,
			tgWant{x: true, y: true, listed: []string{tgObjX, tgObjY}}, true, true},
		{"имена [Y], цель [X] — пересечение пусто", "names", []string{tgObjY}, "", prod, prod, targetX,
			tgWant{listed: []string{}}, false, false},
		{"метки prod на X и Y, цель [X]", "labels", nil, prod, prod, prod, targetX,
			tgWant{x: true, listed: []string{tgObjX}}, true, false},
		{"метки prod на X и Y, близнец allInScope", "labels", nil, prod, prod, prod, all,
			tgWant{x: true, y: true, listed: []string{tgObjX, tgObjY}}, true, true},
		{"метки prod только на Y, цель [X] — пересечение пусто", "labels", nil, prod, dev, prod, targetX,
			tgWant{listed: []string{}}, false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			pool, ctx := withCommittedPool(t, func(ctx context.Context, tx pgx.Tx) {
				tgSeedArmTopology(t, ctx, tx, c.arm, c.names, c.match, c.lx, c.ly)
				tgSeedBinding(t, ctx, tx, "user", "usr-1", c.target(t))
			})
			a := relverdict.NewAsker(pool)
			tgAskAll(t, ctx, a, tgSpeaker, c.want)
			tgCheckReverse(t, ctx, a, c.reverseX, c.reverseY)
		})
	}
}
