// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// grant_delegation_explain_integration_test.go — DoD S1 п.9 приёмки делегированных
// выдач (PRO-Robotech/kaname#986): чтение делегирования по паре «аккаунт,
// делегат» и отбор выдач отзыва по `delegation_id` идут по индексу, без перебора
// выдач аккаунта (критерий «производительность», §3 приёмки).
//
// На базе мира проб строк мало, и планировщик вправе выбрать перебор как более
// дешёвый: исход «перебор» на десятке строк о пригодности индекса не говорит.
// Поэтому план снимается с `enable_seqscan = off` — так проба отвечает ровно на
// свой вопрос: ПРИГОДЕН ли индекс этому запросу (форма предиката совпадает с
// частичным условием индекса). Положительный контроль — тот же план без
// предиката по делегату индексом пары НЕ идёт.

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// explainPlan — план запроса текстом при выключенном переборе.
func explainPlan(t *testing.T, ctx context.Context, pool *pgxpool.Pool, q string, args ...any) string {
	t.Helper()
	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()
	tx, err := conn.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `SET LOCAL enable_seqscan = off`)
	require.NoError(t, err)
	rows, err := tx.Query(ctx, "EXPLAIN "+q, args...)
	require.NoError(t, err)
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var l string
		require.NoError(t, rows.Scan(&l))
		lines = append(lines, l)
	}
	require.NoError(t, rows.Err())
	return strings.Join(lines, "\n")
}

// TestGrantDelegation_DoD9_DelegationReadsGoByIndex — оба запроса делегированного
// пути пригодны своему индексу.
func TestGrantDelegation_DoD9_DelegationReadsGoByIndex(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("DoD-9")
	d1 := w.d1()
	requireGranted(t, w.tryGrant(asSA(w.ctx, w.svaIss), w.v()), "DoD-9 Дано: выдача по D1")

	pair := explainPlan(t, w.ctx, w.pool,
		`SELECT id FROM kaname.grant_delegations WHERE account_id = $1 AND delegate_id = $2 AND status = 'ACTIVE'`,
		string(w.accA), w.svaIss)
	t.Logf("DoD-9 план чтения делегирования по паре:\n%s", pair)
	require.Contains(t, pair, "grant_delegations_active_pair_uniq", "DoD-9: чтение по паре не идёт индексом пары")

	byDelegation := explainPlan(t, w.ctx, w.pool,
		`SELECT id FROM kaname.access_bindings WHERE delegation_id = $1 AND revoked_at IS NULL ORDER BY id FOR UPDATE`, d1)
	t.Logf("DoD-9 план отбора выдач отзыва:\n%s", byDelegation)
	require.Contains(t, byDelegation, "access_bindings_delegation_live_idx", "DoD-9: отбор выдач отзыва не идёт индексом delegation_id")

	// Положительный контроль: без предиката «действующее» частичный индекс пары
	// неприменим — проба различает «индекс пригоден» и «индекс назван всегда».
	control := explainPlan(t, w.ctx, w.pool,
		`SELECT id FROM kaname.grant_delegations WHERE account_id = $1 AND delegate_id = $2`, string(w.accA), w.svaIss)
	t.Logf("DoD-9 контроль (без условия ACTIVE):\n%s", control)
	require.NotContains(t, control, "grant_delegations_active_pair_uniq",
		"DoD-9 контроль: частичный индекс назван и там, где его условие не выполнено — проба вакуумна")
}
