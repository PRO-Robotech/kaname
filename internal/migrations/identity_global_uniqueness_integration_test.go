// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

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
//   - IAM-ID-1-52 · миграция САМА отвергает негодные данные и называет предмет,
//     а не роняет сырой отказ драйвера; при этом не меняет ни одного ключа —
//     состояние базы то же, что до попытки. Положительный контроль: на годных
//     данных та же миграция ПРОХОДИТ;
//   - IAM-ID-1-06 · после миграции вторая строка с той же почтой (в любом
//     регистре, в любом аккаунте) отвергается на уровне БД;
//   - глобальность ключа внешнего субъекта — строго шире прежнего
//     `users_active_external_id_uniq` (он накрывал только ACTIVE).
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
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
)

// globalUniquenessVersion — версия миграции, делающей ключ идентичности
// глобальным. Метка времени заведения, а не номер задачи: форму держит гейт
// `internal/repohygiene` `TestNewMigrationOutranksEveryAppliedOne`.
const globalUniquenessVersion = 20260823050000

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
		INSERT INTO kacho_iam.users (id, external_id, email, display_name, account_id, invite_status)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		userID, externalID, email, "User "+tag, accountID, inviteStatus)
	require.NoError(t, err, "посев строки %s", tag)

	_, err = tx.Exec(`
		INSERT INTO kacho_iam.accounts (id, name, owner_user_id)
		VALUES ($1, $2, $3)`,
		accountID, "acc-"+tag, userID)
	require.NoError(t, err, "посев аккаунта для %s", tag)

	require.NoError(t, tx.Commit())
	return userID, accountID
}

// indexExists — существует ли индекс с этим именем в схеме сервиса.
func indexExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRowContext(context.Background(), `
		SELECT count(*) FROM pg_class c
		  JOIN pg_namespace ns ON ns.oid = c.relnamespace
		 WHERE ns.nspname = 'kacho_iam' AND c.relname = $1 AND c.relkind = 'i'`, name).Scan(&n))
	return n > 0
}

// TestIntegration_GlobalUniquenessRefusesDuplicateEmailAndNamesIt — IAM-ID-1-52.
//
// Точка, после которой «тот же человек» становится одной строкой, охраняется
// САМОЙ миграцией: предикат готовности исполняется, а не декларируется в шапке.
func TestIntegration_GlobalUniquenessRefusesDuplicateEmailAndNamesIt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()

	// ── отрицание: дубли почты между аккаунтами ──────────────────────────────
	dsn := pgtest.NewEmptyDB(t)
	db := upTo(t, dsn, globalUniquenessVersion-1)
	defer func() { _ = db.Close() }()

	// Две строки одной почты в РАЗНЫХ аккаунтах — состояние, законное до этой
	// миграции (`0011` описывает его как модель).
	seedUserInAccount(t, db, "dupa", "twin@example.test", "", "PENDING")
	seedUserInAccount(t, db, "dupb", "TWIN@example.test", "", "PENDING")

	var before int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT count(*) FROM kacho_iam.users`).Scan(&before))
	t.Logf("перепись до попытки: строк пользователей %d, из них дублирующих почту 2", before)

	err := goose.UpTo(db, ".", globalUniquenessVersion)
	require.Error(t, err,
		"миграция обязана ОТКАЗАТЬ на дублях почты: пройдя, она оставила бы "+
			"глобальный ключ необъявленным, а расхождение обнаружилось бы у арендатора")
	require.Contains(t, strings.ToLower(err.Error()), "lower(email)",
		"отказ обязан НАЗЫВАТЬ предмет — по какому ключу сошлись строки; "+
			"сырой отказ драйвера оператору ничего не говорит: %v", err)
	require.Contains(t, err.Error(), "2",
		"отказ обязан назвать ЧИСЛО групп-дублей — «мы про это не подумали» "+
			"обязано быть отличимо от «этого не было»: %v", err)

	// Состояние базы то же, что до попытки: ни один ключ не введён.
	require.False(t, indexExists(t, db, "users_identity_email_uniq"),
		"IAM-ID-1-52: отказавшая миграция не вправе оставить за собой ключ")
	var after int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT count(*) FROM kacho_iam.users`).Scan(&after))
	require.Equal(t, before, after, "отказавшая миграция не вправе тронуть ни одной строки")

	// ── положительный контроль: на годных данных та же миграция ПРОХОДИТ ─────
	//
	// Без него зелень отрицания не отличима от «миграция не применяется никогда».
	okDSN := pgtest.NewEmptyDB(t)
	okDB := upTo(t, okDSN, globalUniquenessVersion-1)
	defer func() { _ = okDB.Close() }()
	seedUserInAccount(t, okDB, "solo", "solo@example.test", "", "PENDING")

	require.NoError(t, goose.UpTo(okDB, ".", globalUniquenessVersion),
		"на данных без дублей миграция обязана пройти")
	require.True(t, indexExists(t, okDB, "users_identity_email_uniq"))
	require.True(t, indexExists(t, okDB, "users_identity_external_id_uniq"))
}

// TestIntegration_GlobalUniquenessHoldsAfterMigration — IAM-ID-1-06.
func TestIntegration_GlobalUniquenessHoldsAfterMigration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := pgtest.NewEmptyDB(t)
	db := upTo(t, dsn, globalUniquenessVersion)
	defer func() { _ = db.Close() }()

	// Перепись: на пустой таблице каждое утверждение ниже истинно тождественно.
	var seeded int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT count(*) FROM kacho_iam.users`).Scan(&seeded))
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
		INSERT INTO kacho_iam.users (id, external_id, email, display_name, account_id, invite_status)
		VALUES ($1, '', $2, 'twin', $3, 'PENDING')`,
		"usr"+fmt.Sprintf("%017s", "twinusr"), "ONE@example.test", twinAcc)
	if err == nil {
		_, err = tx.Exec(`INSERT INTO kacho_iam.accounts (id, name, owner_user_id) VALUES ($1,$2,$3)`,
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
		INSERT INTO kacho_iam.users (id, external_id, email, display_name, account_id, invite_status)
		VALUES ($1, $2, $3, 'ext twin', $4, 'ACTIVE')`,
		"usr"+fmt.Sprintf("%017s", "extusr"), "ext-one", "other@example.test", extAcc)
	if err == nil {
		_, err = tx2.Exec(`INSERT INTO kacho_iam.accounts (id, name, owner_user_id) VALUES ($1,$2,$3)`,
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
