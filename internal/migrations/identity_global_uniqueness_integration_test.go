// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// identity_global_uniqueness_integration_test.go — принадлежность аккаунту
// перестаёт входить в ключ идентичности (IAM-ID-1, задача kacho#470).
//
// # Предмет
//
// Уникальность строки пользователя объявлена ПАРОЙ — `(account_id, lower(email))`
// и `(account_id, external_id)`. Пока аккаунт входит в ключ, «тот же человек в
// другом аккаунте» есть ДРУГАЯ строка: два идентификатора, два набора прав, и
// активировать можно только одну. Ключ обязан стать глобальным.
//
// # Что утверждают пробы этого файла
//
//   - IAM-ID-1-06 · вторая строка с той же почтой (в любом регистре, в любом
//     аккаунте) отвергается на уровне БД;
//   - глобальность ключа внешнего субъекта — строго шире прежнего
//     `users_active_external_id_uniq` (он накрывал только ACTIVE).
//
// # Здесь стояла проба ОТКАЗА МИГРАЦИИ (IAM-ID-1-52) — предмета у неё нет
//
// Она останавливала цепочку перед `20260823050000`, сеяла две строки на одну
// почту и требовала, чтобы миграция отказала, назвала ключ и число групп и не
// оставила за собой индекса. Миграций сервиса теперь ОДНА — свод, — и версии,
// на которой можно остановиться «перед ключом», не существует; глобальный ключ
// лежит в своде, поэтому две строки на одну почту отвергаются вставкой, а не
// миграцией.
//
// Проба снята вместе со своим предметом, а не ослаблена: разовый отказ разовой
// миграции свойством схемы не является. То, ради чего он вводился, — что второй
// строки на одну почту не бывает — утверждается пробой ниже и утверждалось ею и
// прежде. Сценарий приёмки IAM-ID-1-52 остался без держателя; он назван в отчёте
// линии как остаток, а не как починка.
//
// # Почему у каждого отрицания стоит положительный контроль
//
// «Вставка отвергнута» истинно и тогда, когда отвергается ВСЁ — например, когда
// фикстура нарушает посторонний CHECK. Поэтому рядом с каждым отказом стоит
// вставка, которая обязана ПРОЙТИ, и утверждается ИМЯ сработавшего ограничения,
// а не только факт отказа (`testing.md` §«Гейт на класс» п. 2).
package migrations_test

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

// seedUserInAccount сеет строку пользователя вместе с её аккаунтом одной
// транзакцией — оба ключа цикла отложены, поэтому порядок не значим.
//
// Отличие от `seedUser` соседней пробы намеренное: здесь почта и внешний субъект
// задаются ВЫЗЫВАЮЩИМ, потому что предмет этой пробы — именно их совпадение
// между аккаунтами.
func seedUserInAccount(t *testing.T, db *sql.DB, tag, email, externalID, inviteStatus string) (userID, accountID string) {
	t.Helper()
	userID = "usr" + fmt.Sprintf("%017s", tag)
	accountID = "acc" + fmt.Sprintf("%017s", tag)

	tx, err := db.Begin()
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()

	_, err = tx.Exec(`
		INSERT INTO kaname.users (id, external_id, email, display_name, account_id, invite_status)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		userID, externalID, email, "User "+tag, accountID, inviteStatus)
	require.NoError(t, err, "посев строки %s", tag)

	_, err = tx.Exec(`
		INSERT INTO kaname.accounts (id, name, owner_user_id)
		VALUES ($1, $2, $3)`,
		accountID, "acc-"+tag, userID)
	require.NoError(t, err, "посев аккаунта для %s", tag)

	require.NoError(t, tx.Commit())
	return userID, accountID
}

// TestIntegration_GlobalUniquenessHoldsAfterMigration — IAM-ID-1-06.
func TestIntegration_GlobalUniquenessHoldsAfterMigration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := pgtest.NewEmptyDB(t)
	db := upAllIAMMigrations(t, dsn)
	defer func() { _ = db.Close() }()

	// Перепись: на пустой таблице каждое утверждение ниже истинно тождественно.
	var seeded int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT count(*) FROM kaname.users`).Scan(&seeded))
	require.Positive(t, seeded,
		"посевных строк обязано быть не ноль — иначе проба зеленеет, не прочитав ничего")
	t.Logf("перепись: строк пользователей после цепочки %d; ключи глобальны", seeded)

	first, _ := seedUserInAccount(t, db, "orig", "one@example.test", "ext-one", "ACTIVE")
	require.NotEmpty(t, first)

	// ── та же почта в ДРУГОМ регистре и в ДРУГОМ аккаунте ────────────────────
	twinAcc := "acc" + fmt.Sprintf("%017s", "twinacc")
	tx, err := db.Begin()
	require.NoError(t, err)
	_, err = tx.Exec(`
		INSERT INTO kaname.users (id, external_id, email, display_name, account_id, invite_status)
		VALUES ($1, '', $2, 'twin', $3, 'PENDING')`,
		"usr"+fmt.Sprintf("%017s", "twinusr"), "ONE@example.test", twinAcc)
	if err == nil {
		_, err = tx.Exec(`INSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ($1,$2,$3)`,
			twinAcc, "acc-twin", "usr"+fmt.Sprintf("%017s", "twinusr"))
	}
	if err == nil {
		err = tx.Commit()
	}
	_ = tx.Rollback()
	require.Error(t, err, "IAM-ID-1-06: вторая строка с той же почтой обязана быть отвергнута БД")
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "23505", pgErr.Code, "отказ обязан прийти нарушением уникальности, а не чем-то ещё")
	require.Equal(t, "users_identity_email_uniq", pgErr.ConstraintName,
		"сработать обязан ИМЕННО глобальный ключ почты: сработай пер-аккаунтный, "+
			"утверждение зеленело бы на неизменённой модели")

	// ── тот же внешний субъект в другом аккаунте ─────────────────────────────
	extAcc := "acc" + fmt.Sprintf("%017s", "extacc")
	tx2, err := db.Begin()
	require.NoError(t, err)
	_, err = tx2.Exec(`
		INSERT INTO kaname.users (id, external_id, email, display_name, account_id, invite_status)
		VALUES ($1, $2, $3, 'ext twin', $4, 'ACTIVE')`,
		"usr"+fmt.Sprintf("%017s", "extusr"), "ext-one", "other@example.test", extAcc)
	if err == nil {
		_, err = tx2.Exec(`INSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ($1,$2,$3)`,
			extAcc, "acc-ext", "usr"+fmt.Sprintf("%017s", "extusr"))
	}
	if err == nil {
		err = tx2.Commit()
	}
	_ = tx2.Rollback()
	require.Error(t, err, "вторая строка с тем же внешним субъектом обязана быть отвергнута")
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "23505", pgErr.Code)
	require.Contains(t,
		[]string{"users_identity_external_id_uniq", "users_active_external_id_uniq"},
		pgErr.ConstraintName,
		"сработать обязан глобальный ключ внешнего субъекта")

	// ── положительный контроль: непересекающаяся строка ПРОХОДИТ ─────────────
	//
	// Без него «отвергнуто» неотличимо от «отвергается всё».
	_, freeAcc := seedUserInAccount(t, db, "free", "free@example.test", "ext-free", "ACTIVE")
	require.NotEmpty(t, freeAcc)
}
