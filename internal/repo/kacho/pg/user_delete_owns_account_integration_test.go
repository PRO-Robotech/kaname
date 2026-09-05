// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// user_delete_owns_account_integration_test.go — зеркало
// `account_owner_fk_commit_integration_test.go` по ВТОРОЙ стороне того же
// ограничения (#2048).
//
// Сосед проверяет сторону ССЫЛКИ: вставка аккаунта с несуществующим владельцем
// срывает КОММИТ (ключ `DEFERRABLE INITIALLY DEFERRED`) и даёт
// FailedPrecondition «User <id> not found».
//
// Здесь — сторона ССЫЛАЮЩИХСЯ: снятие человека, который аккаунтом ВЛАДЕЕТ.
// `ON DELETE RESTRICT` отвергает его тем же ключом, но на СВОЁМ ОПЕРАТОРЕ
// (немедленная проверка; отложенность ключа относится к стороне вставки), а
// состояние при этом ПРОТИВОПОЛОЖНОЕ — «ещё ссылаются». До #2048 обе стороны
// отвечали одним текстом, и человек, которого только что вернул `ListUsers`,
// получал утверждение о собственном отсутствии.
//
// Утверждается ПАРА «текст + сентинел». Одного кода мало by construction: обе
// стороны вложены в `ErrFailedPrecondition`, различает их только сообщение, а
// тон сообщений — часть контракта (api-conventions.md §Error-format).

import (
	"context"
	stderrors "errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
)

// TestUserDelete_OwnsAccount_SaysSoInsteadOfNotFound — снятие владельца аккаунта
// отвергается состоянием «ещё ссылаются», называет блокер и НЕ утверждает
// отсутствия существующего человека.
func TestUserDelete_OwnsAccount_SaysSoInsteadOfNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	// Закрытие ОГРАНИЧЕННОЕ (`pgtest.ClosePoolAtEnd`), а не `defer pool.Close()`:
	// безусловное закрытие вешает прогон, если пул держит незакрытую связь, и
	// это свойство дерева стережёт гейт `TestPoolCloseInTestsIsBounded`.
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kachopg.New(pool, nil)

	// Условие пробы: человек и принадлежащий ему аккаунт существуют. Заводится
	// каноническим посевом пакета — он и есть тот путь, которым эта пара строк
	// появляется у арендатора.
	ownerID, _ := bootstrapAdmin(t, ctx, repo, "ownsacc")

	// Предмет: снятие ВЛАДЕЮЩЕГО человека.
	//
	// Отказ приходит из САМОГО оператора, а не с коммита, хотя ключ объявлен
	// отложенным: `ON DELETE RESTRICT` в Postgres проверяется немедленно и
	// откладыванию не подлежит (тем он и отличается от `NO ACTION`).
	// Отложенность этого ключа относится к стороне ВСТАВКИ — её и проверяет
	// соседняя проба. Место отказа утверждается здесь дословно, потому что
	// именно оно решает, какая подсказка доезжает до разбора.
	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	cerr := w2.UsersW().Delete(ctx, ownerID)
	_ = w2.Rollback(ctx)
	require.Error(t, cerr, "оператор снятия обязан отвергнуть владельца аккаунта")

	assert.True(t, stderrors.Is(cerr, iamerr.ErrFailedPrecondition),
		"отказ обязан остаться отказом ПРЕДУСЛОВИЯ, получено %v", cerr)
	assert.True(t, stderrors.Is(cerr, iamerr.ErrReferenceInUse),
		"полоса обязана быть «ещё ссылаются», получено %v", cerr)
	assert.False(t, stderrors.Is(cerr, iamerr.ErrReferenceMissing),
		"полоса «ссылки нет» на существующем человеке — то самое утверждение об отсутствии")

	got := iamerr.StripSentinel(cerr)
	assert.Equal(t, "User "+string(ownerID)+" owns accounts and cannot be deleted", got)
	assert.NotContains(t, got, "not found",
		"отказ не вправе утверждать отсутствие человека, которого возвращает ListUsers")
	for _, frag := range []string{"accounts_owner_fk", "constraint", "kacho_iam", "SQLSTATE"} {
		assert.NotContains(t, strings.ToLower(got), strings.ToLower(frag),
			"текст клиенту не вправе нести обломок pgx %q", frag)
	}

	// Положительный контроль на живой базе: человек, аккаунтом НЕ владеющий,
	// снимается. Без него утверждения выше зеленели бы на снятии, отвергающем
	// вообще всё.
	_, loneAcc := bootstrapAdmin(t, ctx, repo, "loneacc")
	loneID := domain.UserID(ids.NewID(domain.PrefixUser))
	w3, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w3.UsersW().InsertActive(ctx, domain.User{
		ID:           loneID,
		AccountID:    loneAcc,
		ExternalID:   domain.ExternalSubject("ext-lone-" + string(loneID)),
		Email:        domain.Email("lone-" + strings.ToLower(string(loneID)) + "@example.com"),
		DisplayName:  domain.DisplayName("Lone"),
		InviteStatus: domain.InviteStatusActive,
	})
	require.NoError(t, err)
	require.NoError(t, w3.Commit(ctx))

	w4, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w4.UsersW().Delete(ctx, loneID))
	require.NoError(t, w4.Commit(ctx),
		"человек, аккаунтом не владеющий, обязан сниматься — иначе отказ выше ничего не различает")

	t.Logf("перепись: сторон ограничения accounts_owner_fk осмотрено на живой базе 1 (ещё ссылаются) · положительных контролей 1")
}
