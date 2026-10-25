// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed_test

// module_role_reseed_integration_test.go — пересчёт проекции глаголов и глаголов
// правил системных ролей на старте судит роль МОДУЛЯ её политикой: правка у неё
// удаления не влечёт (kaname#1006), и строка удаления, записанная прежним
// вычислением, снимается первым же стартом.
//
// Политика приходит из строки роли (`RulesForRegrain` читает `is_system` и
// `owner_module` под тем же замком), поэтому проба заводит роль сырым SQL с
// владельцем — тем же видом строки, что пишет применитель ролей модуля.

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// moduleReseedRules — правка на сетях: тип объявляет и правку, и удаление.
const moduleReseedRules = `[{"module":"vpc","resources":["network"],"verbs":["get","update"]}]`

// seedRoleWithOwner — системная роль с владельцем `owner` (пусто — роль
// платформы).
func seedRoleWithOwner(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id, name, owner string) {
	t.Helper()
	var ownerArg any
	if owner != "" {
		ownerArg = owner
	}
	_, err := pool.Exec(ctx,
		`INSERT INTO kaname.roles (id, name, permissions, rules, cluster_id, owner_module)
		 VALUES ($1, $2, '[]'::jsonb, $3::jsonb, $4, $5)`,
		id, name, moduleReseedRules, reseedProbeCluster, ownerArg)
	require.NoErrorf(t, err, "посев роли %s", id)
}

func roleVerbHas(t *testing.T, ctx context.Context, pool *pgxpool.Pool, roleID, objectType, verb string) bool {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.role_verb WHERE role_id = $1 AND object_type = $2 AND verb = $3`,
		roleID, objectType, verb).Scan(&n))
	return n > 0
}

func selectorVerbsOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool, roleID, objectType string) []string {
	t.Helper()
	var raw []byte
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT verbs_by_type FROM kaname.role_rule_selectors WHERE role_id = $1 AND $2 = ANY(object_types)`,
		roleID, objectType).Scan(&raw))
	var byType map[string][]string
	require.NoError(t, json.Unmarshal(raw, &byType))
	return byType[objectType]
}

// TestReseedModuleRoleCarriesNoImpliedDelete — роль модуля с правкой после
// досева старта не несёт удаления ни в проекции, ни в глаголах правила, и
// строка удаления, оставленная прежним вычислением, снята. Близнец меняет ровно
// владельца: роль платформы с той же правкой удаление получает.
func TestReseedModuleRoleCarriesNoImpliedDelete(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := newReseedPool(t)
	const dotted = "vpc.network"

	seedRoleWithOwner(t, ctx, pool, "rol-mr1006-module", "vpc.probe_mr1006", "vpc")
	seedRoleWithOwner(t, ctx, pool, "rol-mr1006-platform", "probe.mr1006", "")

	require.NoError(t, bootSeedLanes(ctx, pool))
	// Прежнее вычисление: строка удаления роли модуля, как её писал досев до
	// kaname#1006. Повторный старт обязан её снять.
	_, err := pool.Exec(ctx,
		`INSERT INTO kaname.role_verb (role_id, object_type, verb) VALUES ($1, $2, 'delete')
		 ON CONFLICT DO NOTHING`, "rol-mr1006-module", dotted)
	require.NoError(t, err, "посев прежней строки удаления")
	require.NoError(t, bootSeedLanes(ctx, pool))

	require.True(t, roleVerbHas(t, ctx, pool, "rol-mr1006-module", dotted, "update"),
		"роль модуля потеряла объявленную правку — проба не дошла до предмета")
	require.False(t, roleVerbHas(t, ctx, pool, "rol-mr1006-module", dotted, "delete"),
		"проекция роли модуля несёт удаление после досева — манифест удаления не объявлял")
	require.NotContains(t, selectorVerbsOf(t, ctx, pool, "rol-mr1006-module", dotted), "delete",
		"глаголы правила роли модуля несут удаление")

	require.True(t, roleVerbHas(t, ctx, pool, "rol-mr1006-platform", dotted, "delete"),
		"близнец: роль платформы с правкой потеряла удаление — правило снято шире предмета")
	require.Contains(t, selectorVerbsOf(t, ctx, pool, "rol-mr1006-platform", dotted), "delete",
		"близнец: глаголы правила роли платформы потеряли удаление")
}
