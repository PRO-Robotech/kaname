// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed_test

// selector_verbs_lanes_integration_test.go — ГРАНИЦЫ ПОЛОС ДОСЕВА ВОКРУГ ОЧЕРЕДИ
// ПЕРЕСЧЁТА ГЛАГОЛОВ ПРАВИЛ (kaname#878).
//
// Очередь `role_selector_verbs_pending` — предмет ОДНОЙ полосы (пересчёт глаголов
// правил). Полоса сегментов правила судит только живые системные роли и о
// очереди не знает; досев селекторов системной роли кладёт новую строку в
// состояние «не вычислено» — в очередь, — а не пустой картой.

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

func ruleRefRowsOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool, roleID string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.role_rule_ref WHERE role_id = $1`, roleID).Scan(&n))
	return n
}

func enqueueForRegrain(t *testing.T, ctx context.Context, pool *pgxpool.Pool, roleID string) {
	t.Helper()
	_, err := pool.Exec(ctx,
		`INSERT INTO kaname.role_selector_verbs_pending (role_id) VALUES ($1) ON CONFLICT DO NOTHING`, roleID)
	require.NoError(t, err)
}

// (е) Полоса сегментов не трогает роль арендатора из очереди и снятую роль из
// очереди; положительный контроль — живая системная роль сегменты получает.
func TestSelectorVerbsQueue_RuleRefLaneIgnoresTheQueue(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := newReseedPool(t)
	_, accID := seedProbeAccountWithoutOwnerBinding(t, ctx, pool, "sve")
	system := seedProbeSystemRole(t, ctx, pool, "rol-sve-sys", "iam.svesys", materializingRules)
	gone := seedProbeSystemRole(t, ctx, pool, "rol-sve-gone", "iam.svegone", materializingRules)
	retireProbeRole(t, ctx, pool, gone)
	_, err := pool.Exec(ctx,
		`INSERT INTO kaname.roles (id, account_id, name, permissions, rules)
		 VALUES ('rol-sve-tenant', $1, 'probe_sve_tenant', '["iam.role.*.get"]'::jsonb, $2::jsonb)`,
		accID, materializingRules)
	require.NoError(t, err)
	enqueueForRegrain(t, ctx, pool, "rol-sve-tenant")
	enqueueForRegrain(t, ctx, pool, gone)

	census, err := seed.ReseedSystemRoleRuleRefs(ctx, kanamepg.New(pool, nil), pool, nil)
	require.NoError(t, err)
	require.Positive(t, ruleRefRowsOf(t, ctx, pool, system), "КОНТРОЛЬ: системная роль сегментов не получила")
	require.Zero(t, ruleRefRowsOf(t, ctx, pool, "rol-sve-tenant"), "полоса сегментов переписала роль арендатора из очереди")
	require.Zero(t, ruleRefRowsOf(t, ctx, pool, gone), "полоса сегментов писала снятую роль")
	require.Zero(t, census.Failed, "полоса сегментов отказала на роли вне своего перечня")
}

// Досев селекторов системной роли кладёт НОВУЮ строку в состояние «не
// вычислено»: верхняя граница — живые глаголы типа — и роль в очереди
// пересчёта. Пустая карта значила бы «правило не даёт ничего», а это ложь.
func TestSelectorVerbsQueue_SystemSeedMarksANewSelectorUncomputed(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := newReseedPool(t)
	role := seedProbeSystemRole(t, ctx, pool, "rol-svf-sys", "iam.svfsys", materializingRules)
	require.NoError(t, seed.SyncAllSystemRoleSelectors(ctx, pool))

	var raw []byte
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT verbs_by_type FROM kaname.role_rule_selectors WHERE role_id = $1`, role).Scan(&raw))
	got := map[string][]string{}
	require.NoError(t, json.Unmarshal(raw, &got))
	require.NotEmpty(t, got["iam.role"], "новая строка досева несёт пустую карту вместо верхней границы")
	var pending int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.role_selector_verbs_pending WHERE role_id = $1`, role).Scan(&pending))
	require.Equal(t, 1, pending, "роль с невычисленной картой не поставлена в очередь")
}
