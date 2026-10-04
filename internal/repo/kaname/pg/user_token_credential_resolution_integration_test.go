// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// user_token_credential_resolution_integration_test.go — удостоверение
// персонального токена кладётся, разрешается нашим реестром по идентификатору
// своей строки и отзывается до предъявления, ни разу не обращаясь к внешнему
// поставщику (задача #1121; столбец имени клиента у поставщика снят kaname#362).
//
// # НА КАКОЙ НЕВЕРНОЙ РЕАЛИЗАЦИИ ЭТИ ПРОБЫ БЫЛИ БЫ ЗЕЛЕНЫ — И ЧЕМ ЭТО ЗАКРЫТО
//
//   - «строка кладётся» зелено на реализации, кладущей ОДНУ такую строку ⇒
//     проба кладёт ДВЕ одному пользователю: второй персональный токен обязан
//     выпускаться;
//   - «строка кладётся» зелено на дереве, где строка не годится как
//     удостоверение ⇒ каждая обязана разрешаться нашим реестром и нести
//     открытый ключ.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/journalfixture"
)

// insertCredential — Insert через writer-tx с ОТКАТОМ на отказе.
//
// Существует отдельно от общего помощника пакета намеренно: тот на отказе
// вставки завершает пробу, не закрыв транзакцию, и соединение остаётся занятым
// — а `pool.Close()` в отложенном вызове ждёт его освобождения и не дожидается
// НИКОГДА. Красный прогон тогда не краснеет, а виснет: вердикта нет ни у одной
// пробы пакета. Наблюдалось на красном прогоне этой самой пробы.
func insertCredential(t *testing.T, ctx context.Context, txb service.TxBeginner,
	repo *kanamepg.UserOAuthClientRepo, c domain.UserOAuthClient) domain.UserOAuthClient {
	t.Helper()
	tx, err := txb.Begin(ctx)
	require.NoError(t, err)
	out, ierr := repo.Insert(ctx, tx, c)
	if ierr != nil {
		_ = tx.Rollback(ctx)
		require.NoError(t, ierr, "строка удостоверения не легла: %s", c.ID)
	}
	require.NoError(t, tx.Commit(ctx))
	return out
}

// TestUserToken_CredentialIsStorableAndResolvableByItsOwnID — два
// удостоверения одного пользователя кладутся и разрешаются нашим реестром.
func TestUserToken_CredentialIsStorableAndResolvableByItsOwnID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	// Закрытие с ПРЕДЕЛОМ, а не отложенное: отложенное ждёт соединение, которое
	// проба, упавшая внутри открытой транзакции, не вернёт никогда, — и уносит с
	// собой вердикт всего пакета.
	pgtest.ClosePoolAtEnd(t, pool)

	uid := mustSeedUser(t, ctx, pool, "uocownid")
	repo := kanamepg.NewUserOAuthClientRepo(pool)
	txb := kanamepg.NewPoolTxBeginner(pool)
	assertions := kanamepg.NewAssertionClientRepo(pool)

	first := insertCredential(t, ctx, txb, repo, newUOC(uid, "ownid-1"))
	second := insertCredential(t, ctx, txb, repo, newUOC(uid, "ownid-2"))

	for _, id := range []domain.UserOAuthClientID{first.ID, second.ID} {
		got, rerr := assertions.ResolveAssertionClient(ctx, string(id))
		require.NoError(t, rerr, "реестр не разрешил выданное удостоверение %s", id)
		assert.Equal(t, string(id), got.ID)
		assert.Equal(t, domain.AssertionClientUser, got.Kind)
		assert.Equal(t, string(uid), got.OwnerID)
		assert.NotEmpty(t, got.PublicKeyPEM, "у удостоверения нет открытого ключа")
		assert.True(t, got.OwnerActive)
	}
}

// TestUserToken_RevocationReachesPresentationWithoutTheProvider — отзыв доходит
// до предъявления, не обращаясь к поставщику.
//
// Это положительный контроль к снятию вызова удаления клиента у поставщика:
// отсечку порождает снятие СТРОКИ, и ключом отсечки стоит идентификатор нашей
// строки, а не зеркало. Пока это верно, отзыв остаётся отзывом при недоступном
// (и при снятом) поставщике.
func TestUserToken_RevocationReachesPresentationWithoutTheProvider(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	// Закрытие с ПРЕДЕЛОМ, а не отложенное: отложенное ждёт соединение, которое
	// проба, упавшая внутри открытой транзакции, не вернёт никогда, — и уносит с
	// собой вердикт всего пакета. Наблюдалось на красном прогоне этой пробы:
	// прогон не покраснел, а завис.
	pgtest.ClosePoolAtEnd(t, pool)

	uid := mustSeedUser(t, ctx, pool, "uocrevoke")
	repo := kanamepg.NewUserOAuthClientRepo(pool)
	txb := kanamepg.NewPoolTxBeginner(pool)
	assertions := kanamepg.NewAssertionClientRepo(pool)

	row := newUOC(uid, "revoke")
	insertCredential(t, ctx, txb, repo, row)

	// Положительный контроль ДО отзыва: удостоверение действует.
	_, rerr := assertions.ResolveAssertionClient(ctx, string(row.ID))
	require.NoError(t, rerr, "удостоверение не действовало и до отзыва — отрицание ниже вакуумно")

	var before int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.minted_token_revocations WHERE subject = $1`,
		string(row.ID)).Scan(&before))
	require.Equal(t, 0, before, "отсечка существовала до отзыва")

	tx, err := txb.Begin(journalfixture.Writing(ctx))
	require.NoError(t, err)
	_, deleted, err := repo.DeleteOwnedByID(ctx, tx, row.UserID, row.ID)
	require.NoError(t, err)
	require.True(t, deleted, "строка не снята — отрицания ниже были бы вакуумны")
	require.NoError(t, tx.Commit(ctx))

	// 1) удостоверение больше не разрешается — новое им не выпустить;
	_, rerr = assertions.ResolveAssertionClient(ctx, string(row.ID))
	assert.True(t, domain.IsAssertionClientUnknown(rerr),
		"отозванное удостоверение всё ещё разрешается: %v", rerr)

	// 2) уже отчеканенное отсечено — и ключом отсечки стоит НАША строка.
	var reason string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT reason FROM kaname.minted_token_revocations WHERE subject = $1`,
		string(row.ID)).Scan(&reason),
		"отзыв не породил отсечки — он перестал выдавать, но выданное продолжает проходить")
	assert.NotEmpty(t, reason)
}
