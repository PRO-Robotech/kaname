// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// r73_ledger_historicity_integration_test.go — сценарий R7-3-29: ИСТОРИЧНОСТЬ
// ВЕДОМОСТИ ПЕРЕЖИВАЕТ СНЯТИЕ ДВИЖКА.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО УТВЕРЖДАЕТСЯ И ЧТО НЕТ (решение Р2 приёмки R7-3)
//
// Утверждается ровно одно: вопрос «какие выдачи ДЕЙСТВОВАЛИ в момент T» отвечается
// после снятия так же, как до него. Строка отзыва НЕ УДАЛЯЕТСЯ, интервал читается
// целиком — когда выдана, когда истекает, когда отозвана, кем и каким стало
// состояние.
//
// НЕ утверждается историчность ВЕРДИКТА («был ли доступ разрешён в момент T»): её
// не было и она не заводится. Ответ вычисляется по ТЕКУЩЕМУ состоянию, и оба
// утверждения записаны там, где их прочитает арендатор, — иначе первое читается
// как обещание второго.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТА ПРОБА НЕ ЛИШНЯЯ, ХОТЯ СНЯТИЕ ЭТИХ СТОЛБЦОВ НЕ КАСАЛОСЬ
//
// Именно потому и не лишняя. Снятие движка убрало из этого пути ТРИ писателя
// (синхронное удаление кортежей при отзыве, дренаж очереди и прямого применителя),
// и «отзыв записан» перестало иметь второго свидетеля. Проба фиксирует, что
// свидетель остался ОДИН и он достаточен: ведомость.
//
// Читается ПРОДУКТОВЫМ путём — writer'ом и reader'ом репозитория, — а не своим SQL:
// проба со своим запросом осталась бы зелёной при сломанной проекции чтения.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// TestR7_3_29_LedgerHistoricitySurvivesTheRetirement — R7-3-29.
func TestR7_3_29_LedgerHistoricitySurvivesTheRetirement(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "r73hist")
	admin := mustSeedUser(t, ctx, pool, "r73histadm")
	acc := seedAccount(t, ctx, repo, "acc-r73hist", owner)

	binding := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(owner),
		RoleID:       seedSystemRoleIDIAMAdmin,
		ResourceType: "account",
		ResourceID:   string(acc.ID),
	})

	// ── Положительный контроль: до отзыва интервал ОТКРЫТ ─────────────────────
	//
	// Без него «после отзыва поля заполнены» ничего не утверждает: они могли быть
	// заполнены всегда.
	before, err := repo.Reader(ctx)
	require.NoError(t, err)
	live, err := before.AccessBindings().Get(ctx, binding.ID)
	require.NoError(t, before.Rollback(ctx))
	require.NoError(t, err)
	require.Equal(t, domain.AccessBindingStatusActive, live.Status,
		"свежая выдача обязана быть действующей — иначе контроль не различает состояний")
	require.Nil(t, live.RevokedAt, "у действующей выдачи отметки отзыва быть не может")
	require.False(t, live.CreatedAt.IsZero(), "начало интервала обязано быть записано")

	// ── Отзыв ПРОДУКТОВЫМ путём ───────────────────────────────────────────────
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	revoked, err := w.AccessBindingsW().RevokeGuarded(ctx, binding.ID, domain.UserID(admin))
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	// ── Интервал читается ЦЕЛИКОМ, и строка НЕ удалена ────────────────────────
	after, err := repo.Reader(ctx)
	require.NoError(t, err)
	got, err := after.AccessBindings().Get(ctx, binding.ID)
	require.NoError(t, after.Rollback(ctx))
	require.NoError(t, err,
		"строка отозванной выдачи ЧИТАЕТСЯ: удаление вместо отметки стёрло бы ответ на "+
			"вопрос «какие выдачи действовали в момент T» — тот самый, который решение Р2 "+
			"обещает арендатору сохранить")

	require.Equal(t, domain.AccessBindingStatusRevoked, got.Status)
	require.NotNil(t, got.RevokedAt, "конец интервала обязан быть записан")
	require.Equal(t, revoked.Status, got.Status, "чтение обязано совпасть с записью")
	require.Equal(t, live.CreatedAt.Truncate(time.Second), got.CreatedAt.Truncate(time.Second),
		"начало интервала не двигается отзывом: иначе «когда выдана» отвечало бы неправду")
	require.False(t, got.RevokedAt.Before(got.CreatedAt),
		"конец интервала раньше начала — интервал не читается как интервал")

	t.Logf("интервал прочитан после снятия движка: выдана %s, отозвана %s, состояние %s",
		got.CreatedAt.Format(time.RFC3339), got.RevokedAt.Format(time.RFC3339), got.Status)
}
