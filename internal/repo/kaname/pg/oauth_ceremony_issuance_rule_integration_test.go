// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"testing"
	"time"

	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/stretchr/testify/require"
)

// Единственную связь уже держит церемония: оба чтения обязаны использовать
// её транзакцию и настоящий контекст запроса, включая обёртку со сроком.
func TestCeremonyIssuanceRuleReadsBothFactsOnOwnedSingleConnection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	for _, mode := range []string{"unit", "request", "request-unit"} {
		t.Run(mode, func(t *testing.T) {
			ctx, pool := narrowPool(t, 1)
			sc := ceremonyScene(t, ctx, pool, "cd01")
			cutoff := sessionAuthenticatedAt(t, ctx, pool, sc).Add(-time.Second)
			writeCutoff(t, ctx, pool, sc, cutoff)
			vaults := ceremonyVaults(t, pool)
			rule := kanamepg.NewCeremonyIssuanceRule(pool)
			readCtx := ctx
			var settle func(context.Context) error
			const signatureSeed = 0x7f0201
			sig := ceremonyDigest(signatureSeed)
			if mode != "unit" {
				storeVaultCode(t, ctx, vaults, sc, sig)
				readCtx, settle = vaults.OpenRequest(ctx)
				defer func() { require.NoError(t, settle(ctx)) }()
				consumed, err := vaults.ConsumeAuthorizationCode(readCtx, sig)
				require.NoError(t, err)
				require.EqualValues(t, 1, consumed.Rows())
			}
			if mode != "request" {
				unitCtx, err := vaults.Begin(readCtx)
				require.NoError(t, err)
				readCtx = unitCtx
				defer func() { require.NoError(t, vaults.Rollback(unitCtx)) }()
			}
			require.EqualValues(t, 1, pool.Stat().AcquiredConns())
			bounded, cancel := context.WithTimeout(readCtx, 500*time.Millisecond)
			defer cancel()
			marks, err := rule.PersonMarks(bounded, []string{sc.UserID, sc.ClientID})
			require.NoError(t, err, "отметки не должны ждать вторую связь")
			require.Equal(t, map[string]bool{sc.UserID: true}, marks)
			before, found, err := rule.UserRevokedBefore(bounded, sc.UserID)
			require.NoError(t, err, "отсечка не должна ждать вторую связь")
			require.True(t, found)
			require.True(t, before.Equal(cutoff))
			require.EqualValues(t, 1, pool.Stat().AcquiredConns(), "читатели не закрепляют и не освобождают чужую транзакцию")
		})
	}
}

// Без открытой транзакции читается пул. Тот же путь нужен пустому или уже
// урегулированному request; подтверждение адреса перечитывается без кеша.
func TestCeremonyIssuanceRulePoolFallbackPreservesFactsAndContext(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, pool := narrowPool(t, 1)
	sc := ceremonyScene(t, ctx, pool, "cd02")
	cutoff := sessionAuthenticatedAt(t, ctx, pool, sc).Add(-time.Second)
	writeCutoff(t, ctx, pool, sc, cutoff)
	vaults := ceremonyVaults(t, pool)
	rule := kanamepg.NewCeremonyIssuanceRule(pool)
	requestCtx, settle := vaults.OpenRequest(ctx)
	defer func() { require.NoError(t, settle(ctx)) }()
	for _, readCtx := range []context.Context{ctx, requestCtx} {
		marks, err := rule.PersonMarks(readCtx, []string{sc.UserID, sc.ClientID})
		require.NoError(t, err)
		require.Equal(t, map[string]bool{sc.UserID: true}, marks)
		before, found, err := rule.UserRevokedBefore(readCtx, sc.UserID)
		require.NoError(t, err)
		require.True(t, found)
		require.True(t, before.Equal(cutoff))
	}
	require.NoError(t, settle(ctx))
	_, err := pool.Exec(ctx, `UPDATE kaname.users SET email_verified_at = NULL WHERE id = $1`, sc.UserID)
	require.NoError(t, err)
	marks, err := rule.PersonMarks(requestCtx, []string{sc.UserID})
	require.NoError(t, err)
	require.Equal(t, map[string]bool{sc.UserID: false}, marks)
	before, found, err := rule.UserRevokedBefore(requestCtx, sc.ClientID)
	require.NoError(t, err)
	require.False(t, found)
	require.True(t, before.IsZero())
	cancelled, cancel := context.WithCancel(requestCtx)
	cancel()
	_, err = rule.PersonMarks(cancelled, []string{sc.UserID})
	require.Error(t, err, "отмена исходного контекста не теряется")
	_, _, err = rule.UserRevokedBefore(cancelled, sc.UserID)
	require.Error(t, err, "отмена исходного контекста не теряется")
	marks, err = rule.PersonMarks(cancelled, nil)
	require.NoError(t, err, "пустой список по-прежнему не выполняет SQL")
	require.NotNil(t, marks)
	require.Empty(t, marks)
}
