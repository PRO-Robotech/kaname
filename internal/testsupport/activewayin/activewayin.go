// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package activewayin — посев фикстур под инвариант «у действующей личности
// есть способ входа» (задача PRO-Robotech/kaname#608, приёмка
// `active-identity-has-a-way-in.md` §1 «радиус», §4.1 п. 5).
//
// Отложенный ключ `users_active_has_a_way_in_fk` отвергает фиксацию транзакции,
// оставившей личность `ACTIVE` без строки пароля и без открытого пути
// восстановления. Фикстура не снисходительнее продукта: она заводит то, что
// заводит продукт, — строку пароля той же транзакцией, что строку личности
// (как регистрация). Материал строки — фиксированное значение, которым не
// войти: пробы, которым нужен вход, заводят пароль сами продуктом.
//
// # Почему это ОТДЕЛЬНЫЙ пакет, а не файл `*_test.go` рядом с пробой
//
// Посев зовут пробы двадцати двух пакетов (kaname#816), а `*_test.go` из
// другого пакета импортировать нельзя. До этого пакета посев лежал копией
// `active_way_in_fixture*_test.go` в каждом из них — двадцать четыре копии, из
// них две пары внутри одного каталога: внутренний (`package x`) и внешний
// (`package x_test`) тестовые пакеты — разные единицы сборки и общих файлов
// не видят. Ни одной копии внутренности её пакета не требовались: посев
// говорит только с базой. Поэтому общий пакет, который импортируют обе
// стороны, снимает и эту пару без новой копии.
//
// Пакет импортируют только пробы: прод-сборка его не видит.
//
// # Две формы исполнителя
//
// Пробы служб и репозитория держат транзакцию pgx (`Execer`, `Seed`,
// `SeedOpenPath`, `WithWayIn`). Пробы цепочки миграций держат `database/sql`
// и ставят фикстуры на РАЗНЫХ ревизиях (`goose.UpTo`), где инварианта ещё может
// не быть, — для них посев, судящий саму ревизию (`GuardedSQL`, `SeedGuarded`,
// `ExecGuarded`). Это разные предметы, а не параметр одного: на ранней ревизии
// строки способа входа нет вовсе, и посев обязан молчать.
package activewayin

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// fixtureVerifier — материал строки пароля фикстуры: фиксированное значение,
// которым не войти.
const fixtureVerifier = "fixture-password-row-without-a-known-password"

// FixtureSQL — строка пароля каждой личности `ACTIVE`, которую ЭТА транзакция
// завела либо изменила и у которой нет ни строки пароля, ни открытого пути.
// Узнаёт личность по `xmin` строки — то есть по самой транзакции, — поэтому
// фикстуре не нужно перечислять идентификаторы.
const FixtureSQL = `
	INSERT INTO kaname.user_login_methods (user_id, kind, verifier)
	SELECT u.id, 'password', '` + fixtureVerifier + `'
	  FROM kaname.users u
	 WHERE u.xmin = pg_current_xact_id()::xid
	   AND u.invite_status = 'ACTIVE' AND u.recovery_path_opened_at IS NULL
	   AND NOT EXISTS (SELECT 1 FROM kaname.user_login_methods m
	                    WHERE m.user_id = u.id AND m.kind = 'password')`

// OpenPathSQL — для проб, чей предмет сама строка способа входа: личностям
// `ACTIVE` этой транзакции ставится отметка открытого пути (форма «после
// переноса», AWI-11), а строку пароля проба заводит сама.
const OpenPathSQL = `
	UPDATE kaname.users u SET recovery_path_opened_at = now()
	 WHERE u.xmin = pg_current_xact_id()::xid
	   AND u.invite_status = 'ACTIVE' AND u.recovery_path_opened_at IS NULL
	   AND NOT EXISTS (SELECT 1 FROM kaname.user_login_methods m
	                    WHERE m.user_id = u.id AND m.kind = 'password')`

// InviteePasswordSQL — строка пароля ПРИГЛАШЁННОГО (`PENDING`): приглашённый
// заводит пароль регистрацией раньше, чем приглашение активируется
// (kaname#456, Р11 п. 1), и активация не производит ACTIVE без способа входа.
// Параметр `$1` — идентификатор личности.
const InviteePasswordSQL = `INSERT INTO kaname.user_login_methods (user_id, kind, verifier)
	VALUES ($1, 'password', '` + fixtureVerifier + `')`

// GuardedSQL — отметка открытого пути личностям `ACTIVE` текущей транзакции
// без строки пароля, если инвариант в схеме уже стоит; на ревизии без ключа
// `users_active_has_a_way_in_fk` не делает ничего.
//
// Отметка, а не строка пароля: строка пароля сделала бы откат свода способов
// входа невозможным по построению (его страж отказывает на любой строке
// способа), и пробы откатов мерили бы посев, а не предмет.
const GuardedSQL = `
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_active_has_a_way_in_fk') THEN
    EXECUTE $q$
      UPDATE kaname.users u SET recovery_path_opened_at = now()
       WHERE u.xmin = pg_current_xact_id()::xid
         AND u.invite_status = 'ACTIVE' AND u.recovery_path_opened_at IS NULL
         AND NOT EXISTS (SELECT 1 FROM kaname.user_login_methods m
                          WHERE m.user_id = u.id AND m.kind = 'password')$q$;
  END IF;
END
$$`

// Execer — исполнитель оператора открытой транзакции pgx.
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// SQLExecer — исполнитель оператора открытой транзакции `database/sql`.
type SQLExecer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

// WithWayIn оборачивает ОДИН оператор вставки строк личностей, исполняемый вне
// явной транзакции, так, что строка пароля ложится тем же оператором:
// `WITH u AS (<вставка> RETURNING …) INSERT INTO <способы> SELECT … FROM u`.
func WithWayIn(insertUsers string) string {
	return "WITH way_in_people AS (" + strings.TrimSpace(insertUsers) + " RETURNING id, invite_status) " +
		"INSERT INTO kaname.user_login_methods (user_id, kind, verifier) " +
		"SELECT id, 'password', '" + fixtureVerifier + "' FROM way_in_people " +
		"WHERE invite_status = 'ACTIVE'"
}

// Seed заводит строки пароля личностям транзакции перед её фиксацией.
func Seed(t testing.TB, ctx context.Context, tx Execer) {
	t.Helper()
	_, err := tx.Exec(ctx, FixtureSQL)
	require.NoError(t, err, "посев строки пароля личностей фикстуры (kaname#608)")
}

// SeedOpenPath ставит отметку открытого пути личностям транзакции перед её
// фиксацией (см. OpenPathSQL).
func SeedOpenPath(t testing.TB, ctx context.Context, tx Execer) {
	t.Helper()
	_, err := tx.Exec(ctx, OpenPathSQL)
	require.NoError(t, err, "отметка открытого пути личностей фикстуры (kaname#608)")
}

// SeedGuarded — посев перед фиксацией транзакции фикстуры цепочки миграций
// (см. GuardedSQL).
func SeedGuarded(t testing.TB, tx SQLExecer) {
	t.Helper()
	_, err := tx.Exec(GuardedSQL)
	require.NoError(t, err, "посев отметки открытого пути личностей фикстуры (kaname#608)")
}

// ExecGuarded исполняет ОДИН оператор фикстуры цепочки миграций, заводящий
// либо активирующий личность, в своей транзакции с посевом отметки открытого
// пути перед фиксацией: оператор, исполненный вне транзакции, фиксировался бы
// раньше, чем посев успел бы лечь. Исход — как у `db.Exec`.
func ExecGuarded(t testing.TB, db *sql.DB, query string, args ...any) (sql.Result, error) {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.Exec(query, args...)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(GuardedSQL); err != nil {
		return nil, err
	}
	return res, tx.Commit()
}
