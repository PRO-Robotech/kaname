// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

// resource_journal_ntf363_initiator_integration_test.go — строка ресурсного
// журнала без инициатора или без времени базой НЕ принимается.
//
// Приёмка NTF-3 (`docs/specs/sub-phase-NTF-3-kacho-modules-notifications-acceptance.md`
// в репозитории продукта), сценарий NTF3-63, буква «близнец NTF3-62 в дереве
// службы доступа»; форма вставок — NTF3-62: без инициатора, с инициатором без
// типа, без времени, и положительный близнец.
//
// # Инициатор ставится НАСТРОЙКОЙ транзакции, а не колонкой оператора
//
// Проба колонку `initiator` в операторе вставки не называет: значение даёт
// умолчание колонки из настройки `kacho_journal.initiator`, ровно так, как его
// даст помощник транзакции фундамента (`journaltx.SettingInitiator`). Назови
// проба колонку сама, она утверждала бы `NOT NULL` и `CHECK`, но не то, что
// умолчание читает настройку, — и близнец позеленел бы на схеме, где писатель
// обязан называть колонку, то есть на схеме, которую пишущие пути не заполняют.
//
// # Отрицания и близнец отличаются ОДНИМ фактом
//
// Каждая вставка — та же строка того же вида; меняется ровно одно: нет
// настройки; настройка без типа; время `NULL` при годном инициаторе. Близнец —
// годный инициатор и время по умолчанию.

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/journaltx"
)

// ntf363InitiatorColumn — колонка инициатора журнала (Р2, замысел З2).
const ntf363InitiatorColumn = "initiator"

// ntf363Insert — одна строка журнала вида `iam_group`; инициатор берётся
// умолчанием колонки, время — `created_at`, переданным явно лишь там, где его
// отсутствие и есть проверяемый факт.
const (
	ntf363InsertDefaultTime = `INSERT INTO kaname.resource_journal
		  (resource_kind, resource_id, event_type, payload)
		VALUES ('iam_group', $1, 'CREATED', '{}'::jsonb)
		RETURNING sequence_no`
	ntf363InsertNullTime = `INSERT INTO kaname.resource_journal
		  (resource_kind, resource_id, event_type, payload, created_at)
		VALUES ('iam_group', $1, 'CREATED', '{}'::jsonb, NULL)
		RETURNING sequence_no`
)

// ntf363Attempt — исход одной вставки в своей транзакции. setting == "" —
// отсутствие инициатора выставлено пустым значением локально к транзакции.
func ntf363Attempt(t *testing.T, db *sql.DB, setting, stmt, resourceID string) (int64, error) {
	t.Helper()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err, "фикстура: транзакция обязана открыться")
	defer func() { _ = tx.Rollback() }()

	if setting != "" {
		var got string
		require.NoError(t, tx.QueryRowContext(ctx,
			`SELECT set_config($1, $2, true)`, journaltx.SettingInitiator, setting).Scan(&got),
			"фикстура: настройка инициатора обязана выставиться")
		require.Equal(t, setting, got, "фикстура: настройка выставлена не тем значением")
	} else {
		// Отсутствие выставляется ТЕМ ЖЕ оператором, что у открывающего
		// пишущую транзакцию службы (`journalwrite.Begin` без принципала): соединение
		// контейнера проб несёт ролевого инициатора посева, и транзакция,
		// умолчавшая об инициаторе, унаследовала бы его.
		var got sql.NullString
		require.NoError(t, tx.QueryRowContext(ctx,
			`SELECT set_config($1, '', true)`, journaltx.SettingInitiator).Scan(&got),
			"фикстура: отсутствие инициатора обязано выставиться")
		require.NoError(t, tx.QueryRowContext(ctx,
			`SELECT current_setting($1, true)`, journaltx.SettingInitiator).Scan(&got))
		require.True(t, !got.Valid || got.String == "",
			"фикстура: в транзакции «без инициатора» настройка стоит (%q) — "+
				"отказ ниже был бы не о том", got.String)
	}

	var seq int64
	if err := tx.QueryRowContext(ctx, stmt, resourceID).Scan(&seq); err != nil {
		return 0, err
	}
	require.NoError(t, tx.Commit())
	return seq, nil
}

// ntf363PgError — отказ базы из ошибки драйвера; иной отказ — провал пробы с
// текстом, а не молчаливое «не тот код».
func ntf363PgError(t *testing.T, err error) *pgconn.PgError {
	t.Helper()
	var pgErr *pgconn.PgError
	require.True(t, errors.As(err, &pgErr),
		"отказ обязан прийти от базы (SQLSTATE), а пришло: %v", err)
	return pgErr
}

// ntf363ConstraintCoversColumn — ограничение с этим именем стоит на таблице
// журнала и судит названную колонку.
func ntf363ConstraintCoversColumn(t *testing.T, db *sql.DB, constraint, column string) bool {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRowContext(context.Background(), `
		SELECT count(*)
		  FROM pg_constraint c
		  JOIN pg_class r     ON r.oid = c.conrelid
		  JOIN pg_namespace s ON s.oid = r.relnamespace
		  JOIN pg_attribute a ON a.attrelid = r.oid AND a.attnum = ANY (c.conkey)
		 WHERE s.nspname = 'kaname' AND r.relname = 'resource_journal'
		   AND c.contype = 'c' AND c.conname = $1 AND a.attname = $2`,
		constraint, column).Scan(&n))
	return n == 1
}

// TestResourceJournal_NTF363_RowWithoutInitiatorOrTimeIsRefused — NTF3-63,
// близнец NTF3-62 в дереве службы доступа.
func TestResourceJournal_NTF363_RowWithoutInitiatorOrTimeIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)

	// ПРЕДПОСЫЛКА ФИКСТУРЫ — до любого утверждения о предмете: таблица журнала
	// есть, и вид `iam_group` ею принимается. Без этого отказ ниже читался бы
	// как отсутствующая возможность, будучи поломкой фикстуры.
	var tbl sql.NullString
	require.NoError(t, db.QueryRow(`SELECT to_regclass('kaname.resource_journal')::text`).Scan(&tbl))
	require.True(t, tbl.Valid, "фикстура: таблицы kaname.resource_journal после цепи миграций нет")

	usrA := ids.NewID(ids.PrefixUser)
	require.True(t, ids.IsValid(usrA, ids.PrefixUser), "фикстура: id пользователя не той формы")
	initiatorA := "user:" + usrA

	t.Run("без инициатора — 23502 с именем колонки инициатора", func(t *testing.T) {
		_, err := ntf363Attempt(t, db, "", ntf363InsertDefaultTime, "grp-ntf363-noinit")
		require.Error(t, err,
			"строка журнала без инициатора ПРИНЯТА базой: колонки %q с NOT NULL и "+
				"умолчанием из настройки %q нет", ntf363InitiatorColumn, journaltx.SettingInitiator)
		pgErr := ntf363PgError(t, err)
		require.Equal(t, "23502", pgErr.Code, "отказ не тот: %s", pgErr.Message)
		require.Equal(t, ntf363InitiatorColumn, pgErr.ColumnName,
			"отказ NOT NULL обязан назвать колонку инициатора, назвал %q", pgErr.ColumnName)
	})

	t.Run("инициатор без типа — 23514 с именем ограничения на колонке инициатора", func(t *testing.T) {
		_, err := ntf363Attempt(t, db, usrA, ntf363InsertDefaultTime, "grp-ntf363-untyped")
		require.Error(t, err,
			"строка журнала с инициатором без типа (%q) ПРИНЯТА базой: CHECK формы "+
				"инициатора нет", usrA)
		pgErr := ntf363PgError(t, err)
		require.Equal(t, "23514", pgErr.Code, "отказ не тот: %s", pgErr.Message)
		require.NotEmpty(t, pgErr.ConstraintName, "отказ CHECK обязан назвать ограничение")
		require.True(t, ntf363ConstraintCoversColumn(t, db, pgErr.ConstraintName, ntf363InitiatorColumn),
			"отказ назвал ограничение %q, но оно не судит колонку %q таблицы журнала",
			pgErr.ConstraintName, ntf363InitiatorColumn)
	})

	t.Run("без времени — 23502 с именем колонки времени", func(t *testing.T) {
		_, err := ntf363Attempt(t, db, initiatorA, ntf363InsertNullTime, "grp-ntf363-notime")
		require.Error(t, err, "строка журнала без времени ПРИНЯТА базой")
		pgErr := ntf363PgError(t, err)
		require.Equal(t, "23502", pgErr.Code, "отказ не тот: %s", pgErr.Message)
		require.Equal(t, "created_at", pgErr.ColumnName,
			"отказ NOT NULL обязан назвать колонку времени, назвал %q", pgErr.ColumnName)
	})

	t.Run("близнец — годный инициатор и время: строка вставлена и несёт инициатора", func(t *testing.T) {
		seq, err := ntf363Attempt(t, db, initiatorA, ntf363InsertDefaultTime, "grp-ntf363-twin")
		require.NoError(t, err, "строка с инициатором %q и временем обязана вставиться", initiatorA)

		var got sql.NullString
		err = db.QueryRow(
			`SELECT initiator FROM kaname.resource_journal WHERE sequence_no = $1`, seq).Scan(&got)
		require.NoError(t, err,
			"инициатор строки журнала не читается: колонки %q нет", ntf363InitiatorColumn)
		require.Equal(t, initiatorA, got.String,
			"строка несёт инициатора не из настройки транзакции")
	})
}
