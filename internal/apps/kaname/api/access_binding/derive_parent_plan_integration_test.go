// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// derive_parent_plan_integration_test.go — планы чтений вывода родителя (DoD п.8
// приёмки kaname-derives-the-parent-of-a-registered-object.md, kaname#982):
// `EXPLAIN` трёх операторов адаптера тем же текстом, каким он читает, на мире П6.
//
// Ручная операция под той же ручкой, что замер задержки
// (`KACHO_DERIVE_PARENT_COST=1`): планы печатаются в журнал прогона. План на
// малой таблице законно выбирает последовательный проход, поэтому печатается и
// план при `enable_seqscan = off` — он показывает, каким индексом оператор
// обслуживается, когда таблица велика.

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// TestDeriveParentCost_DerivationReadPlans — планы трёх чтений вывода.
func TestDeriveParentCost_DerivationReadPlans(t *testing.T) {
	if os.Getenv(deriveParentCostEnv) == "" {
		t.Skipf("замер не запрошен (%s пуст) — это ручная операция, как и замеры R7", deriveParentCostEnv)
	}
	p := newPCRWorld(t)
	queries := []struct {
		name string
		sql  string
		args []any
	}{
		{"проект → аккаунт", kanamepg.ProjectAccountQuery, []any{string(p.prjA)}},
		{"область контейнера", kanamepg.ContainerScopeQuery, []any{pcrRegType, pcrX}},
		{"факты указателя", kanamepg.PointerSubjectsQuery, []any{pcrRepoType, pcrXApp, []string{"parent"}}},
	}
	for _, seqscan := range []string{"on", "off"} {
		conn, err := p.pool.Acquire(p.ctx)
		require.NoError(t, err)
		_, err = conn.Exec(p.ctx, "SET enable_seqscan = "+seqscan)
		require.NoError(t, err)
		for _, q := range queries {
			rows, err := conn.Query(p.ctx, "EXPLAIN (COSTS OFF) "+q.sql, q.args...)
			require.NoErrorf(t, err, "EXPLAIN %s", q.name)
			var plan []string
			for rows.Next() {
				var line string
				require.NoError(t, rows.Scan(&line))
				plan = append(plan, line)
			}
			require.NoError(t, rows.Err())
			t.Logf("ПЛАН %s (enable_seqscan=%s):\n%s", q.name, seqscan, strings.Join(plan, "\n"))
		}
		_, err = conn.Exec(p.ctx, "RESET enable_seqscan")
		require.NoError(t, err)
		conn.Release()
	}
}
