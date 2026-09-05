// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// service_account_project_column_retired_integration_test.go — колонка,
// снятая вместе с полем контракта.
//
// `service_accounts.project_id` (плюс её внешний ключ и частичный индекс) не
// заполнялась ничем: единственный INSERT её не передавал, единственный UPDATE
// её не допускал, выборка агрегата её не выбирала. Хранить колонку, в которую
// нельзя записать, — обещание возможности, за которую никто не отвечает.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
)

func TestServiceAccounts_ProjectColumnRetired(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()

	var cols int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM information_schema.columns
		 WHERE table_schema = 'kacho_iam' AND table_name = 'service_accounts'
		   AND column_name = 'project_id'`).Scan(&cols))
	assert.Zero(t, cols, "колонка снята вместе с полем контракта")

	var idx int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM pg_indexes
		 WHERE schemaname = 'kacho_iam' AND indexname = 'service_accounts_project_idx'`).Scan(&idx))
	assert.Zero(t, idx, "частичный индекс по снятой колонке")

	var fk int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM pg_constraint
		 WHERE conname = 'service_accounts_project_fk'`).Scan(&fk))
	assert.Zero(t, fk, "внешний ключ снятой колонки")

	// Контроль той же формы: остальные колонки на месте — проверка умеет
	// отличать «колонки нет» от «таблицы не видно».
	var enabled int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM information_schema.columns
		 WHERE table_schema = 'kacho_iam' AND table_name = 'service_accounts'
		   AND column_name = 'enabled'`).Scan(&enabled))
	assert.Equal(t, 1, enabled, "проверка смотрит на существующую таблицу")
}
