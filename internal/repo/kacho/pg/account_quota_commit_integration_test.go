// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// account_quota_commit_integration_test.go — отказ учёта приходит из COMMIT, и
// это МЕСТО, а не только ответ.
//
// Списание аккаунтов объявлено `CONSTRAINT TRIGGER … DEFERRABLE INITIALLY
// DEFERRED` (миграция 484002): личность резолвится через строку владельца, чей
// внешний ключ сам отложен, и схема ЯВНО разрешает вставить аккаунт раньше
// пользователя. Значит `KQ001` не приходит из INSERT — он приходит из `Commit`,
// ровно как отложенный `accounts_owner_fk` (проба-соседка). Юнит на мосте
// закрепляет ОТВЕТ моста; здесь закрепляется, что отказ ЧЕРЕЗ ЭТОТ МОСТ и
// проходит.
//
// Наблюдалось на сквозном прогоне: операция создания аккаунта завершалась
// `{"code":13,"message":"internal error"}` — вызывающий видел поломку платформы
// там, где платформа отказала как задумано.
//
// testcontainers Postgres — пропускается под `testing.Short()`.

import (
	"context"
	stderrors "errors"
	"fmt"
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

// TestAccountQuota_CommitTime_ResourceExhaustedSentinel — шестой аккаунт одной
// личности, заведённый ТЕМ ЖЕ путём, каким его заводит продукт.
func TestAccountQuota_CommitTime_ResourceExhaustedSentinel(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	// Закрытие с пределом: отложенное `pool.Close()` ждёт соединение, которое
	// проба, упавшая внутри открытой транзакции, не вернёт никогда, — и уносит
	// с собой вердикт всего пакета. Здесь такая транзакция есть по построению.
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	// Предмет этой пробы — потолок ОБЪЁМА. Потолок ТЕМПА (задача #618) по умолчанию
	// бьёт раньше — три заведения в час против пяти аккаунтов, — поэтому он
	// поднимается из-под ног: иначе проба судила бы не свою полосу.
	liftRateCeilingOutOfTheWay(t, ctx, pool)

	_, userID := accountQuotaFixture(t, ctx, pool, "commit")
	// Фикстура завела первый; добираем до пяти — предела умолчания.
	for i := 2; i <= 5; i++ {
		require.NoErrorf(t, insertAccount(ctx, pool, fmt.Sprintf("quota-acc-commit-%d", i), userID),
			"аккаунт %d из пяти обязан пройти", i)
	}

	repo := kachopg.New(pool, nil)
	w, werr := repo.Writer(ctx)
	require.NoError(t, werr)

	// Сама вставка НЕ падает: списание отложено до фиксации.
	_, ierr := w.AccountsW().Insert(ctx, domain.Account{
		ID:          domain.AccountID(ids.NewID(domain.PrefixAccount)),
		Name:        domain.AccountName("quota-acc-commit-6"),
		OwnerUserID: domain.UserID(userID),
		Labels:      domain.Labels{},
	})
	require.NoError(t, ierr, "INSERT обязан пройти — списание отложено до COMMIT")

	cerr := w.Commit(ctx)
	require.Error(t, cerr, "шестой аккаунт одной личности прошёл: потолка нет")
	_ = w.Rollback(ctx)

	assert.True(t, stderrors.Is(cerr, iamerr.ErrQuotaExceeded),
		"отказ учёта на COMMIT обязан быть ErrQuotaExceeded, получено: %v", cerr)
	assert.False(t, stderrors.Is(cerr, iamerr.ErrInternal),
		"отказ арендатора уехал в INTERNAL: вызывающий видит поломку платформы "+
			"там, где платформа сработала как задумано")

	got := iamerr.StripSentinel(cerr)
	assert.True(t, strings.Contains(got, "has reached its limit of 5 iam.account"),
		"текст производителя — часть контракта: он называет носителя, предел и вид; получено %q", got)
	assert.NotContains(t, got, "accounts_quota_count",
		"наружу утекло имя триггера: это разведка по нашей схеме, а не ответ арендатору")
}
