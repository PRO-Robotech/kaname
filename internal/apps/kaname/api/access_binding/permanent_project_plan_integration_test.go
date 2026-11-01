// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// permanent_project_plan_integration_test.go — план сверки привязки (DoD п.8
// приёмки object-keeps-its-project-after-unregistration.md, kaname#983): чтение
// привязки предикатом `kaname.object_project_binding_refuses` идёт по первичному
// ключу `object_project_binding_pkey`.
//
// Ручная операция под той же ручкой, что замер задержки
// (`KACHO_PERMANENT_PROJECT_COST=1`). План внутреннего оператора функции снаружи
// не виден, поэтому снимается план того же чтения — `SELECT project_id` по паре
// `(object_type, object_id)` — на мире ПП после доставки D-K и регистрации; при
// `enable_seqscan = off` он показывает индекс, которым чтение обслуживается.

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPermanentProjectCost_BindingReadPlan — план чтения привязки.
func TestPermanentProjectCost_BindingReadPlan(t *testing.T) {
	if os.Getenv(permanentProjectCostEnv) == "" {
		t.Skipf("замер не запрошен (%s пуст) — это ручная операция, как и замеры R7", permanentProjectCostEnv)
	}
	w := newPPWorld(t)
	w.deliverDK()
	w.requireReg(dpQ, w.prjA, w.accA, "план: «Дано»")
	for _, seqscan := range []string{"on", "off"} {
		conn, err := w.pool.Acquire(w.ctx)
		require.NoError(t, err)
		_, err = conn.Exec(w.ctx, "SET enable_seqscan = "+seqscan)
		require.NoError(t, err)
		rows, err := conn.Query(w.ctx, `EXPLAIN (ANALYZE, BUFFERS, COSTS OFF)
			SELECT b.project_id FROM kaname.object_project_binding b
			 WHERE b.object_type = $1 AND b.object_id = $2`, pcrRegType, dpQ)
		require.NoError(t, err)
		var plan []string
		for rows.Next() {
			var l string
			require.NoError(t, rows.Scan(&l))
			plan = append(plan, l)
		}
		require.NoError(t, rows.Err())
		t.Logf("ПЛАН чтение привязки (enable_seqscan=%s):\n%s", seqscan, strings.Join(plan, "\n"))
		_, err = conn.Exec(w.ctx, "RESET enable_seqscan")
		require.NoError(t, err)
		conn.Release()
	}
}
