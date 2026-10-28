// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// rule_grain_window_integration_test.go — ОКНО МИГРАЦИИ 20261018030000 НА
// ЖИВОЙ БАЗЕ (kaname#878).
//
// (а) Роль, записанная ДО миграции (строки селекторов без карты), после
//     миграции получает тот же вердикт, что прежде, — объединение глаголов по
//     роли: миграция доступа не отнимает и не добавляет.
// (б) Пересчёт очереди даёт точные карты по правилу: вердикт больше не
//     сочетает глагол одного правила с охватом другого, проекция роли
//     `role_verb` не меняется, очередь пуста.
// (в) Роль вне очереди пересчёт не трогает — двойник.

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/testsupport/activewayin"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// windowPreviousVersion — версия цепи ДО миграции карты глаголов правила.
const windowPreviousVersion = 20261017140000

func windowRules() domain.Rules {
	return domain.Rules{
		{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get"}},
		{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"delete"}, ResourceNames: []string{ndX}},
	}
}

func windowProjection(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id string) []string {
	t.Helper()
	rows, err := pool.Query(ctx, `SELECT object_type || ' ' || verb FROM kaname.role_verb WHERE role_id = $1`, id)
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		require.NoError(t, rows.Scan(&s))
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

func windowMaps(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id string) map[string]map[string][]string {
	t.Helper()
	rows, err := pool.Query(ctx, `SELECT rule_fp, verbs_by_type FROM kaname.role_rule_selectors WHERE role_id = $1`, id)
	require.NoError(t, err)
	defer rows.Close()
	out := map[string]map[string][]string{}
	for rows.Next() {
		var fp string
		var raw []byte
		require.NoError(t, rows.Scan(&fp, &raw))
		m := map[string][]string{}
		require.NoError(t, json.Unmarshal(raw, &m))
		for k := range m {
			slices.Sort(m[k])
		}
		out[fp] = m
	}
	return out
}

func TestRuleGrainWindow_MigrationKeepsTheVerdictAndTheQueueClosesTheWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	ctx := context.Background()
	dsn := pgtest.NewDB(t)
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	goose.SetLogger(goose.NopLogger())
	require.NoError(t, goose.DownTo(db, ".", windowPreviousVersion), "цепь не сошла до версии прежде миграции")

	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	// Посев прежней формы: объекты, роль, её селекторы БЕЗ карты и проекция роли.
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	ndSeedObjects(t, ctx, tx, "{}", "{}")
	activewayin.Seed(t, ctx, tx)
	rules := windowRules()
	raw, err := domain.EncodeRules(rules)
	require.NoError(t, err)
	const id = "rol-window-old"
	exec(t, ctx, tx, `INSERT INTO kaname.roles (id, account_id, name, permissions, rules)
	                   VALUES ($1, 'acc-1', 'window_old', '[]'::jsonb, $2::jsonb)`, id, raw)
	sels := rules.MaterializingSelectors()
	for _, p := range catalogfixture.Facts().RoleVerbsFromSelectors(sels, domain.TenantPolicy()) {
		exec(t, ctx, tx, `INSERT INTO kaname.role_verb (role_id, object_type, verb) VALUES ($1, $2, $3)`, id, p.ObjectType, p.Verb)
	}
	for _, s := range sels {
		arm, names := "anchor", []string{}
		if s.Arm == domain.ArmNames {
			arm, names = "names", s.ResourceNames
		}
		exec(t, ctx, tx, `INSERT INTO kaname.role_rule_selectors (role_id, rule_fp, arm, object_types, resource_names, match_labels)
		                   VALUES ($1, $2, $3, $4, $5, '{}'::jsonb)`, id, s.RuleFP, arm, s.ObjectTypes, names)
	}
	require.NoError(t, tx.Commit(ctx))
	ndBind(t, ctx, pool, "acb-window", "user", "usr-1", id, `{"allInScope": true}`)
	projectionBefore := windowProjection(t, ctx, pool, id)

	require.NoError(t, goose.Up(db, "."), "миграция карты глаголов не накатилась")

	// (а) Вердикт после заполнения миграцией — прежний: объединение по роли.
	a := relverdict.NewAsker(pool)
	ids := []string{ndX, ndY}
	rgFormsAgree(t, ctx, a, ndRegType, "v_get", ids, map[string]bool{ndX: true, ndY: true})
	rgFormsAgree(t, ctx, a, ndRegType, "v_delete", ids, map[string]bool{ndX: true, ndY: true})

	// (в) Двойник: роль, записанная путём роли ПОСЛЕ миграции, в очередь не
	// встаёт; её карта помечена законным, но отличимым от вычисленного
	// значением — пересчёт очереди не вправе её коснуться.
	ndSeedRole(t, ctx, pool, "rol-window-new", domain.Rules{
		{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get", "list"}}})
	_, err = pool.Exec(ctx, `UPDATE kaname.role_rule_selectors SET verbs_by_type = '{"registry.registries": ["list"]}'::jsonb
	                         WHERE role_id = 'rol-window-new'`)
	require.NoError(t, err)
	twinBefore := windowMaps(t, ctx, pool, "rol-window-new")

	// (б) Пересчёт очереди.
	census, err := seed.RegrainQueuedSelectorVerbs(ctx, kanamepg.New(pool, nil), pool, catalogfixture.Facts())
	require.NoError(t, err)
	require.Equal(t, 0, census.Pending, "очередь не опустела")
	require.Positive(t, census.Regrained, "пересчёт не дошёл")

	want := map[string]map[string][]string{}
	for _, s := range catalogfixture.Facts().GrantSelectors(sels, domain.TenantPolicy()) {
		m := map[string][]string{}
		for k, v := range s.Grants {
			m[k] = slices.Sorted(slices.Values(v))
		}
		want[s.RuleFP] = m
	}
	require.Equal(t, want, windowMaps(t, ctx, pool, id), "карты после пересчёта — не по правилу")
	rgFormsAgree(t, ctx, a, ndRegType, "v_get", ids, map[string]bool{ndX: true, ndY: true})
	rgFormsAgree(t, ctx, a, ndRegType, "v_delete", ids, map[string]bool{ndX: true, ndY: false})
	require.Equal(t, projectionBefore, windowProjection(t, ctx, pool, id), "пересчёт глаголов правил изменил проекцию роли")
	require.Equal(t, twinBefore, windowMaps(t, ctx, pool, "rol-window-new"), "пересчёт очереди тронул роль вне очереди")
}
