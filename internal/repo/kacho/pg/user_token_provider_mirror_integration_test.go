// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// user_token_provider_mirror_integration_test.go — удостоверение персонального
// токена живёт БЕЗ зеркала у поставщика (задача #1121, подфаза Ф4б-3 эпика #896).
//
// # ПРЕДМЕТ
//
// Зеркало (идентификатор клиента у внешнего поставщика) нужно ровно для одного —
// обмена утверждения У НЕГО. Наш издатель разрешает клиента по идентификатору
// СВОЕЙ строки (`AssertionClientRepo`, разрешение идёт по `c.id`), и зеркальной
// колонки на этом пути нет вовсе. Значит выдача, переставшая заводить клиента у
// поставщика, обязана уметь положить строку БЕЗ зеркала — и это свойство
// хранилища, а не кода: его держат `NOT NULL`, `CHECK` и уникальный индекс.
//
// # НА КАКОЙ НЕВЕРНОЙ РЕАЛИЗАЦИИ ЭТИ ПРОБЫ БЫЛИ БЫ ЗЕЛЕНЫ — И ЧЕМ ЭТО ЗАКРЫТО
//
//   - «строка без зеркала кладётся» зелено на представлении, где вместо зеркала
//     пишется наш же идентификатор ⇒ проба читает колонку обратно и требует,
//     чтобы значения НЕ БЫЛО (`NULL`), а не чтобы оно было каким-то;
//   - «строка без зеркала кладётся» зелено на реализации, кладущей ОДНУ такую
//     строку ⇒ проба кладёт ДВЕ: пустая строка вместо `NULL` прошла бы первую и
//     упёрлась во второй в уникальный индекс, то есть второй выпуск токена не
//     состоялся бы никогда;
//   - «зеркала нет» зелено на дереве, где нет и самой строки ⇒ у каждого
//     отрицания стоит положительный контроль: та же строка обязана разрешаться
//     нашим реестром и нести открытый ключ.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
)

// insertCredential — Insert через writer-tx с ОТКАТОМ на отказе.
//
// Существует отдельно от общего помощника пакета намеренно: тот на отказе
// вставки завершает пробу, не закрыв транзакцию, и соединение остаётся занятым
// — а `pool.Close()` в отложенном вызове ждёт его освобождения и не дожидается
// НИКОГДА. Красный прогон тогда не краснеет, а виснет: вердикта нет ни у одной
// пробы пакета. Наблюдалось на красном прогоне этой самой пробы.
func insertCredential(t *testing.T, ctx context.Context, txb service.TxBeginner,
	repo *kachopg.UserOAuthClientRepo, c domain.UserOAuthClient) domain.UserOAuthClient {
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

// TestUserToken_CredentialWithoutProviderMirrorIsStorableAndResolvable —
// удостоверение без зеркала кладётся, читается и разрешается нашим реестром.
func TestUserToken_CredentialWithoutProviderMirrorIsStorableAndResolvable(t *testing.T) {
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

	uid := mustSeedUser(t, ctx, pool, "uocnomirror")
	repo := kachopg.NewUserOAuthClientRepo(pool)
	txb := kachopg.NewPoolTxBeginner(pool)
	assertions := kachopg.NewAssertionClientRepo(pool)

	// ДВЕ выдачи одному пользователю, обе без зеркала. Вторая и есть предмет:
	// на пустой строке вместо отсутствия значения она упёрлась бы в уникальный
	// индекс зеркала, и второй персональный токен не выпускался бы никогда.
	first := newUOC(uid, "nomirror-1")
	first.OAuthClientID = ""
	second := newUOC(uid, "nomirror-2")
	second.OAuthClientID = ""

	persistedFirst := insertCredential(t, ctx, txb, repo, first)
	persistedSecond := insertCredential(t, ctx, txb, repo, second)

	assert.Equal(t, domain.OAuthClientID(""), persistedFirst.OAuthClientID,
		"ответ записи объявляет зеркало у поставщика, которого не заводили")
	assert.Equal(t, domain.OAuthClientID(""), persistedSecond.OAuthClientID)

	// Колонка обязана быть ПУСТА (значения нет), а не заполнена чем-нибудь
	// нашим: заполненная выглядит как живая регистрация у поставщика и делает
	// две группы строк — с регистрацией и без — неразличимыми.
	var mirrorPresent bool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT hydra_client_id IS NOT NULL FROM kacho_iam.user_oauth_clients WHERE id = $1`,
		string(first.ID)).Scan(&mirrorPresent))
	assert.False(t, mirrorPresent,
		"колонка зеркала заполнена — регистрации у поставщика нет, а строка о ней заявляет")

	// Положительный контроль: строка не только легла, но и годится как
	// удостоверение — наш реестр разрешает её по НАШЕМУ идентификатору.
	for _, id := range []domain.UserOAuthClientID{first.ID, second.ID} {
		got, rerr := assertions.ResolveAssertionClient(ctx, string(id))
		require.NoError(t, rerr, "реестр не разрешил выданное удостоверение %s", id)
		assert.Equal(t, string(id), got.ID)
		assert.Equal(t, domain.AssertionClientUser, got.Kind)
		assert.Equal(t, string(uid), got.OwnerID)
		assert.NotEmpty(t, got.PublicKeyPEM, "у удостоверения нет открытого ключа")
		assert.True(t, got.OwnerActive)
	}

	// Окно двух издателей: строка, заведённая ДО перевода, своё зеркало
	// сохраняет и по-прежнему кладётся и разрешается. Без этого контроля
	// послабление колонки читалось бы как «зеркала больше не бывает».
	legacy := newUOC(uid, "legacy")
	persistedLegacy := insertCredential(t, ctx, txb, repo, legacy)
	assert.Equal(t, legacy.OAuthClientID, persistedLegacy.OAuthClientID,
		"строка прежнего выпуска обязана сохранить своё зеркало")
	gotLegacy, rerr := assertions.ResolveAssertionClient(ctx, string(legacy.ID))
	require.NoError(t, rerr)
	assert.Equal(t, string(legacy.ID), gotLegacy.ID)
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
	repo := kachopg.NewUserOAuthClientRepo(pool)
	txb := kachopg.NewPoolTxBeginner(pool)
	assertions := kachopg.NewAssertionClientRepo(pool)

	row := newUOC(uid, "revoke")
	row.OAuthClientID = ""
	insertCredential(t, ctx, txb, repo, row)

	// Положительный контроль ДО отзыва: удостоверение действует.
	_, rerr := assertions.ResolveAssertionClient(ctx, string(row.ID))
	require.NoError(t, rerr, "удостоверение не действовало и до отзыва — отрицание ниже вакуумно")

	var before int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.minted_token_revocations WHERE subject = $1`,
		string(row.ID)).Scan(&before))
	require.Equal(t, 0, before, "отсечка существовала до отзыва")

	tx, err := txb.Begin(ctx)
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
		`SELECT reason FROM kacho_iam.minted_token_revocations WHERE subject = $1`,
		string(row.ID)).Scan(&reason),
		"отзыв не породил отсечки — он перестал выдавать, но выданное продолжает проходить")
	assert.NotEmpty(t, reason)
}
