// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// baseline_rollback_concurrent_integration_test.go — КОНКУРЕНТНАЯ СЦЕНА, ради
// которой страж заведён.
//
// # Что за окно закрывается
//
// Откатная половина свода — два оператора: перепись живых удостоверений вида
// SECRET и снос схемы. Замка между ними нет, поэтому удостоверение,
// зафиксированное в промежутке, переписью не сосчитано, а сносом уничтожено —
// и откат при этом проходит УСПЕХОМ. Именно это делает окно опасным: у оператора
// нет ни отказа, ни признака.
//
// # Почему сцена детерминированная, а не «попробуем поймать гонку»
//
// Перепись читает снимком и незакоммиченную вставку не видит вовсе, а снос схемы
// обязан взять на таблицу исключительный замок — и ЖДЁТ, пока конкурирующая
// транзакция не зафиксируется. Промежуток между ними поэтому держится столько,
// сколько нужно. Сцена ставится так:
//
//  1. цепочка откатывается ДО СВОДА (`down --target 1`) — штатная форма, которую
//     страж пропускает; после неё единственный оставшийся обратный ход и есть
//     откатная половина свода;
//  2. транзакция B вставляет удостоверение вида SECRET и НЕ фиксируется;
//  3. зовётся обратный ход НИЖЕ свода;
//  4. сцена ждёт, пока он не встанет в ожидание замка: перепись к этому моменту
//     уже отработала и насчитала НОЛЬ — вставка B ей не видна;
//  5. B фиксируется, снос просыпается и уничтожает строку, а откат отвечает
//     УСПЕХОМ.
//
// Шаг 1 несущий, а не косметика. С непустой надстройкой обратный ход упирается в
// замок ВЫШЕ свода (`DROP TRIGGER … ON kaname.service_accounts`: вставка B держит
// на этой таблице разделяемый замок ради проверки ключа), и тогда B фиксируется
// ДО переписи — перепись видит строку, и страж свода честно отказывает. То есть
// без шага 1 сцена меряет не тот промежуток и зеленеет на открытом окне. Это
// измерено, а не выведено: первая редакция сцены была написана без шага 1 и на
// снятом страже дала отказ ПЕРЕПИСИ вместо уничтожения строки.
//
// Шага 4 на починенном дереве не наступает: отказ приходит ДО единого оператора,
// и ждать нечего. Обе стороны различаются ровно этим.
package main

import (
	"database/sql"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// chainUp накатывает цепочку ТЕМ ЖЕ средством, которым её накатывает оператор.
func chainUp(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	_, _, err := runCommandFS(t, migrations.FS, []string{"up", "--dsn", dsn}, nil)
	require.NoError(t, err, "предмет сцены не создан: цепочка обязана накатиться")

	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// seedCredentialOwners — аккаунт, человек и служебная учётка ОДНОЙ транзакцией:
// аккаунт и владелец ссылаются друг на друга, ключи отложены.
func seedCredentialOwners(t *testing.T, db *sql.DB) {
	t.Helper()
	tx, err := db.Begin()
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()

	_, err = tx.Exec(`SET CONSTRAINTS ALL DEFERRED`)
	require.NoError(t, err)
	_, err = tx.Exec(`INSERT INTO kaname.accounts (id, name, owner_user_id)
	                  VALUES ('acc00000000000000mgr', 'migrator-down', 'usr00000000000000mgr')`)
	require.NoError(t, err)
	_, err = tx.Exec(`INSERT INTO kaname.users (id, external_id, email, account_id, invite_status)
	                  VALUES ('usr00000000000000mgr', 'ext-mig', 'mig@example.invalid',
	                          'acc00000000000000mgr', 'ACTIVE')`)
	require.NoError(t, err)
	_, err = tx.Exec(`INSERT INTO kaname.service_accounts (id, account_id, name)
	                  VALUES ('sva00000000000000mgr', 'acc00000000000000mgr', 'migrator-down-sa')`)
	require.NoError(t, err)
	require.NoError(t, tx.Commit())
}

// insertSecretInFlight открывает транзакцию, вставляет удостоверение вида SECRET
// и НЕ фиксирует её: возвращает саму транзакцию, чтобы сцена зафиксировала её в
// нужный момент.
func insertSecretInFlight(t *testing.T, db *sql.DB) *sql.Tx {
	t.Helper()
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i + 7)
	}
	tx, err := db.Begin()
	require.NoError(t, err)
	_, err = tx.Exec(`INSERT INTO kaname.service_account_oauth_clients
	    (id, sva_id, hydra_client_id, created_by_user_id, credential_kind, secret_hash,
	     public_key_pem, key_algorithm, trusted_subjects, expires_at)
	  VALUES ('soc_00000000000000mgr', 'sva00000000000000mgr', NULL, 'usr00000000000000mgr',
	          'SECRET', $1, '', '', '[]'::jsonb, now() + interval '30 days')`, hash)
	require.NoError(t, err, "Given неисполним, если законная строка вида SECRET не пишется")
	return tx
}

// rollbackIsWaitingForALock — встал ли обратный ход в ожидание замка. Это и есть
// наблюдаемый признак того, что он ДОШЁЛ до разрушающих операторов и ждёт
// конкурирующую транзакцию.
//
// Судится ОЖИДАНИЕ, а не текст запроса. Текст назвал бы один оператор из
// восемнадцати откатных половин, и первым в замок упирается не обязательно снос
// схемы: выше свода лежат миграции, трогающие те же таблицы. Проба, ключующаяся
// на «DROP SCHEMA», молчала бы при полностью открытом окне — ровно тот класс,
// который корпус называет слепотой распознавателя.
//
// Фиксирующая транзакция сцены в ожидании НЕ стоит (она idle in transaction), и
// собственное соединение исключено по pid: ждать здесь может только обратный ход.
func rollbackIsWaitingForALock(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var n int
	err := db.QueryRow(`SELECT count(*) FROM pg_stat_activity
	                     WHERE datname = current_database()
	                       AND pid <> pg_backend_pid()
	                       AND wait_event_type = 'Lock'`).Scan(&n)
	require.NoError(t, err)
	return n > 0
}

// TestRollbackBelowTheBaselineIsRefusedWhileACredentialIsInFlight — ОТРИЦАНИЕ.
func TestRollbackBelowTheBaselineIsRefusedWhileACredentialIsInFlight(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	dsn := pgtest.NewEmptyDB(t)
	db := chainUp(t, dsn)
	seedCredentialOwners(t, db)

	// Шаг 1 — штатная форма, которую страж пропускает. Заодно это ЖИВОЙ
	// положительный контроль: страж, отвергающий всё, споткнулся бы здесь.
	_, _, err := runCommandFS(t, migrations.FS, []string{"down", "--target", "1", "--dsn", dsn}, nil)
	require.NoError(t, err, "откат ДО свода — штатная форма, страж её не касается")

	inFlight := insertSecretInFlight(t, db)
	committed := false
	defer func() {
		if !committed {
			_ = inFlight.Rollback()
		}
	}()

	type outcome struct{ err error }
	done := make(chan outcome, 1)
	go func() {
		_, _, err := runCommandFS(t, migrations.FS, []string{"down", "--target", "0", "--dsn", dsn}, nil)
		done <- outcome{err}
	}()

	// Промежуток наблюдается, а не отмеряется временем: ждём ЛИБО ответа наката,
	// ЛИБО его остановки на замке. Второе на починенном дереве не наступает.
	deadline := time.After(90 * time.Second)
	var got outcome
	waiting := false
loop:
	for {
		select {
		case got = <-done:
			break loop
		case <-deadline:
			t.Fatal("накат не ответил и не встал на замок за 90 с — сцена не состоялась")
		default:
			if rollbackIsWaitingForALock(t, db) {
				waiting = true
				require.NoError(t, inFlight.Commit(),
					"фиксируем удостоверение В ПРОМЕЖУТКЕ — ровно то, что стережётся")
				committed = true
				got = <-done
				break loop
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

	require.False(t, waiting,
		"обратный ход встал в ожидание замка — значит он ДОШЁЛ до разрушающих "+
			"операторов, и промежуток между переписью и сносом ОТКРЫТ")
	require.Error(t, got.err, "обратный ход ниже свода обязан быть отвергнут")
	require.Contains(t, got.err.Error(), "baseline version 1",
		"отказ обязан назвать свод, а не прийти о чём-то другом: %v", got.err)

	if !committed {
		require.NoError(t, inFlight.Commit())
		committed = true
	}

	// Схема цела, и удостоверение живо: отказ наступил ДО единого оператора.
	var n int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kaname.service_account_oauth_clients
		  WHERE id = 'soc_00000000000000mgr' AND credential_kind = 'SECRET'`).Scan(&n),
		"схема обязана быть цела")
	require.Equal(t, 1, n, "удостоверение вида SECRET обязано уцелеть")

	var head string
	require.NoError(t, db.QueryRow(
		`SELECT max(version_id)::text FROM goose_db_version WHERE is_applied`).Scan(&head))
	require.NotEqual(t, "0", head, "цепочка обязана остаться применённой")
}

// TestRollbackAboveTheBaselineStillWorks — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ.
//
// Без него отрицание выше выполняется тождественно: страж, отвергающий ВСЯКИЙ
// обратный ход, прошёл бы его и сломал бы штатную процедуру отката выкатки.
func TestRollbackAboveTheBaselineStillWorks(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	dsn := pgtest.NewEmptyDB(t)
	db := chainUp(t, dsn)
	seedCredentialOwners(t, db)

	var before string
	require.NoError(t, db.QueryRow(
		`SELECT max(version_id)::text FROM goose_db_version WHERE is_applied`).Scan(&before))

	_, _, err := runCommandFS(t, migrations.FS,
		[]string{"down", "--target", "20260914091500", "--dsn", dsn}, nil)
	require.NoError(t, err,
		"откат до версии ПОВЕРХ свода — штатная процедура, страж её не касается")

	var after string
	require.NoError(t, db.QueryRow(
		`SELECT max(version_id)::text FROM goose_db_version WHERE is_applied`).Scan(&after))
	require.Equal(t, "20260914091500", after, "обратный ход обязан состояться, а не промолчать")
	require.NotEqual(t, before, after)

	var exists bool
	require.NoError(t, db.QueryRow(`SELECT to_regclass('kaname.accounts') IS NOT NULL`).Scan(&exists))
	require.True(t, exists, "свод обязан остаться применённым")
}

// TestBareStepBackFromTheBaselineIsRefusedAgainstARealDatabase — вторая форма
// обращения, провязанная с НАСТОЯЩИМ читателем головы цепочки.
//
// Пробы с подставным читателем доказывают решение стража, но не то, что команда
// читает голову у базы: подставной читатель отвечает и тогда, когда соединения
// нет вовсе.
func TestBareStepBackFromTheBaselineIsRefusedAgainstARealDatabase(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	dsn := pgtest.NewEmptyDB(t)
	db := chainUp(t, dsn)

	_, _, err := runCommandFS(t, migrations.FS, []string{"down", "--target", "1", "--dsn", dsn}, nil)
	require.NoError(t, err, "откат ДО свода — штатная форма")

	_, _, err = runCommandFS(t, migrations.FS, []string{"down", "--dsn", dsn}, nil)
	require.Error(t, err, "шаг назад от свода снёс бы схему — обязан быть отвергнут")
	require.Contains(t, err.Error(), "baseline version 1",
		"отказ формы без цели обязан назвать свод: %v", err)

	var exists bool
	require.NoError(t, db.QueryRow(`SELECT to_regclass('kaname.accounts') IS NOT NULL`).Scan(&exists))
	require.True(t, exists, "схема обязана уцелеть: отказ наступил до единого оператора")
}
