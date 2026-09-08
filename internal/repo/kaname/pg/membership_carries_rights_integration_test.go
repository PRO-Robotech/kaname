// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// membership_carries_rights_integration_test.go — стадия S2 перехода IAM-ID-1
// (задача kacho#472), сценарий IAM-ID-1-60: осиротить право снятием членства
// НЕЛЬЗЯ.
//
// # Три роли, и их нельзя путать
//
// Приёмка разбирает это отдельным примечанием, потому что первая её редакция
// объявляла `RESTRICT` и «гранты уходят вместе» одновременно — а это
// взаимоисключающие вещи:
//
//	невозможность осиротить  — КОНСТРУКЦИЯ базы: членство нельзя снять, пока
//	                           на него опирается живая выдача;
//	снятие выдач             — ШАГ use-case в той же транзакции;
//	исчезновение доступа     — материализация, наблюдаемая Check'ом.
//
// Здесь живёт ПЕРВАЯ роль и только она. Она — гарантия: если шаг снятия выдач
// однажды напишут неверно, транзакция не пройдёт вовсе, вместо того чтобы тихо
// оставить право без носителя.
//
// # Почему проверка ОТЛОЖЕННАЯ, а не немедленная
//
// Немедленная отвергала бы законный порядок внутри транзакции. Удаление
// аккаунта снимает свои выдачи и свои членства в ОДНОЙ транзакции, и порядок
// внутри неё — деталь реализации, а не контракт. Отложенная проверка задаёт
// вопрос на COMMIT, когда состояние уже приведено к целевому: аккаунта нет,
// выдач нет, спорить не о чем.
//
// Проба на удаление аккаунта поэтому исполняет аккаунт **С ВЫДАННЫМИ ПРАВАМИ**,
// а не пустой: на пустом любой порядок зелен, и утверждение не значит ничего.

package pg_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// grantAccountScoped кладёт ACTIVE-выдачу на сам аккаунт: субъект — человек,
// область — аккаунт. Пишется сырым SQL намеренно: предмет пробы — КОНСТРУКЦИЯ
// базы, и она обязана держать любого писателя, а не только use-case.
func grantAccountScoped(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	userID domain.UserID, accID domain.AccountID, roleID string,
) string {
	t.Helper()
	bindingID := ids.NewID("acb")
	_, err := pool.Exec(ctx, `
		INSERT INTO kaname.access_bindings
		    (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
		VALUES ($1, 'user', $2, $3, 'account', $4, 'ACTIVE')`,
		bindingID, string(userID), roleID, string(accID))
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id, ordinal)
		VALUES ($1, 'user', $2, 0)`, bindingID, string(userID))
	require.NoError(t, err)
	return bindingID
}

// anyRoleID — любая существующая роль: FK на roles — RESTRICT, поэтому выдумать
// идентификатор нельзя.
func anyRoleID(t *testing.T, ctx context.Context, pool *pgxpool.Pool) string {
	t.Helper()
	var id string
	require.NoError(t, pool.QueryRow(ctx, `SELECT id FROM kaname.roles LIMIT 1`).Scan(&id))
	require.NotEmpty(t, id, "ПРЕДПОСЫЛКА: в дереве обязана быть хоть одна роль")
	return id
}

func membershipRowExists(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	userID domain.UserID, accID domain.AccountID,
) bool {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kaname.memberships
		 WHERE user_id = $1 AND account_id = $2`, string(userID), string(accID)).Scan(&n))
	return n > 0
}

// TestIntegration_MembershipCannotBeRemovedWhileItCarriesRights — IAM-ID-1-60.
func TestIntegration_MembershipCannotBeRemovedWhileItCarriesRights(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	userID, accID := bootstrapAdmin(t, ctx, repo, "car1")
	role := anyRoleID(t, ctx, pool)
	require.True(t, membershipRowExists(t, ctx, pool, userID, accID),
		"ПРЕДПОСЫЛКА: зеркало S1 обязано было завести членство")

	bindingID := grantAccountScoped(t, ctx, pool, userID, accID, role)

	// ── снятие членства, пока выдача жива, — отвергается ─────────────────────
	_, err = pool.Exec(ctx, `
		DELETE FROM kaname.memberships WHERE user_id = $1 AND account_id = $2`,
		string(userID), string(accID))
	require.Error(t, err,
		"членство, на которое опирается живая выдача, снять нельзя: иначе право осталось бы "+
			"в леджере без носителя, и молчаливое сиротство было бы неотличимо от намеренного отзыва")
	require.True(t, membershipRowExists(t, ctx, pool, userID, accID),
		"и строка обязана остаться на месте")

	// ── положительный контроль: ШТАТНЫЙ путь проходит ───────────────────────
	// Снятие выдачи и снятие членства ОДНОЙ транзакцией — то, что и делает
	// use-case. Без этого контроля отказ выше означал бы «членство снять нельзя
	// никогда», а не «нельзя, пока оно несёт права».
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `DELETE FROM kaname.access_bindings WHERE id = $1`, bindingID)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `
		DELETE FROM kaname.memberships WHERE user_id = $1 AND account_id = $2`,
		string(userID), string(accID))
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx),
		"штатный путь — снять выдачи и членство одной транзакцией — обязан проходить; "+
			"проверка отложенная, поэтому порядок внутри транзакции значения не имеет")
	require.False(t, membershipRowExists(t, ctx, pool, userID, accID))
}

// TestIntegration_MembershipRemovalIgnoresRevokedAndForeignGrants — граница
// запрета названа с обеих сторон.
//
// Запрет обязан срабатывать на ЖИВОЙ выдаче В ЭТОМ аккаунте и молчать на всём
// прочем. Без этой пробы «снять нельзя» могло бы означать «снять нельзя
// никогда», и первый же законный отзыв уперся бы в запрет.
func TestIntegration_MembershipRemovalIgnoresRevokedAndForeignGrants(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	userID, accID := bootstrapAdmin(t, ctx, repo, "car2")
	otherUser, otherAcc := bootstrapAdmin(t, ctx, repo, "car3")
	role := anyRoleID(t, ctx, pool)

	// (а) ОТОЗВАННАЯ выдача носителем не является.
	revoked := ids.NewID("acb")
	_, err = pool.Exec(ctx, `
		INSERT INTO kaname.access_bindings
		    (id, subject_type, subject_id, role_id, resource_type, resource_id, status, revoked_at)
		VALUES ($1, 'user', $2, $3, 'account', $4, 'REVOKED', now())`,
		revoked, string(userID), role, string(accID))
	require.NoError(t, err)

	// (б) Выдача ДРУГОМУ человеку в этом же аккаунте — не про наше членство.
	_ = grantAccountScoped(t, ctx, pool, otherUser, accID, role)

	// (в) Выдача НАШЕМУ человеку, но в ЧУЖОМ аккаунте — не про это членство.
	_ = grantAccountScoped(t, ctx, pool, userID, otherAcc, role)

	_, err = pool.Exec(ctx, `
		DELETE FROM kaname.memberships WHERE user_id = $1 AND account_id = $2`,
		string(userID), string(accID))
	require.NoError(t, err,
		"ни отозванная выдача, ни выдача другому человеку, ни выдача в другом аккаунте "+
			"не удерживают ЭТО членство: запрет обязан быть узким, иначе он отвергает законное")
	require.False(t, membershipRowExists(t, ctx, pool, userID, accID))
}

// TestIntegration_MembershipRemovalCheckIsDeferredWithinTheTransaction —
// порядок внутри транзакции значения не имеет.
//
// Это и есть свойство, ради которого проверка отложена. Немедленная отвергала бы
// снятие членства, выполненное ДО снятия выдачи, — то есть навязывала бы
// вызывающему порядок стейтментов, который контрактом не является. Отложенная
// задаёт вопрос на COMMIT, когда состояние уже целевое.
//
// # Чего эта проба НЕ утверждает — и почему
//
// Приёмка предупреждает про удаление аккаунта с выданными правами. На дереве S2
// оно НЕ КОНСТРУИРУЕМО вовсе, и не из-за этой проверки: строка человека держит
// свой аккаунт ключом `users_account_fk` (`ON DELETE RESTRICT`) — тот самый цикл,
// который снимается только на S4 вместе с колонкой. Утверждать здесь про
// удаление аккаунта значило бы писать пробу, красную по чужой причине.
// Её предмет — IAM-ID-1-08, стадия S3.
func TestIntegration_MembershipRemovalCheckIsDeferredWithinTheTransaction(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	userID, accID := bootstrapAdmin(t, ctx, repo, "car4")
	role := anyRoleID(t, ctx, pool)
	bindingID := grantAccountScoped(t, ctx, pool, userID, accID, role)

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	// Соединение возвращается в пул даже если утверждение ниже провалит пробу:
	// незакрытая транзакция уносит вердикт всего пакета вместе с собой.
	defer func() { _ = tx.Rollback(ctx) }()

	// ОБРАТНЫЙ порядок: сперва членство, потом выдача.
	_, err = tx.Exec(ctx, `
		DELETE FROM kaname.memberships WHERE user_id = $1 AND account_id = $2`,
		string(userID), string(accID))
	require.NoError(t, err,
		"на стейтменте проверка молчать обязана — она отложенная")

	_, err = tx.Exec(ctx, `DELETE FROM kaname.access_bindings WHERE id = $1`, bindingID)
	require.NoError(t, err)

	require.NoError(t, tx.Commit(ctx),
		"на COMMIT состояние целевое: выдачи нет, членства нет — держать нечего. "+
			"Немедленная проверка отвергла бы этот порядок, навязав вызывающему "+
			"последовательность стейтментов, которая контрактом не является")

	require.False(t, membershipRowExists(t, ctx, pool, userID, accID))
}
