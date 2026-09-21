// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

// secret_material_statistics_integration_test.go — секретный материал не
// попадает в статистику планировщика (#129).
//
// # Что за предмет
//
// `ANALYZE` кладёт в `pg_statistic` не только числа, но и САМИ ЗНАЧЕНИЯ колонки —
// самые частые и границы гистограммы. Для колонки с секретным материалом это
// вторая копия материала, живущая в каталоге: её не затирает затирание строки,
// не удаляет удаление строки и не видит ни один продуктовый глагол.
//
// # Признак ПЕРЕМЕРЕН, а не взят из задачи
//
// Замер на живой базе (Postgres, свод + `ANALYZE`):
//
//	service_account_oauth_clients.secret_hash, 32 байта   → histogram_bounds НЕСЁТ значения
//	token_signing_keys.private_key_wrapped, 300 байт      → histogram_bounds НЕСЁТ значения
//	token_signing_keys.private_key_wrapped, 2048 байт     → строки статистики НЕТ
//
// Последняя строка — причина, по которой «у нас ключи длинные, и так не попадёт»
// негодный довод: порог ширины у `ANALYZE` — 1024 байта, и попадание решает
// РАЗМЕР значения, то есть выбранный алгоритм и обёртка. Ключ EdDSA короче ключа
// RSA на порядок; свойство, которое держится на длине значения, переживёт свой
// предмет молча.
//
// # Почему исключение ничего не стоит
//
// Ни одна из исключаемых колонок не участвует в отборе: по ним не фильтруют, не
// соединяют и не упорядочивают (перепись по дереву — ноль вхождений в `WHERE` /
// `JOIN` / `ORDER BY`). Единственные индексы по `secret_hash` — ЧАСТИЧНЫЕ
// уникальные, чья избирательность выводится из предиката и уникальности, а не из
// гистограммы значений.

import (
	"database/sql"
	"fmt"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

// secretMaterialKeeps — колонки-кандидаты, которые решено ОСТАВИТЬ в статистике,
// и причина по каждой.
//
// Ведомость истекает сама в ОБЕ стороны: запись, чьей колонки в схеме больше нет,
// — находка (исключению нечего исключать), а кандидат без записи и без исключения
// — тоже находка. Поэтому новая колонка секретного материала не может появиться
// молча: она обязана быть либо исключена, либо названа здесь.
var secretMaterialKeeps = map[string]string{
	"access_bindings.target_digest": "не секретный материал: свёртка ЦЕЛИ выдачи " +
		"(умолчание 'all'), и она входит в ключ уникальности выдачи — " +
		"по ней отбирают, поэтому исключение стоило бы плана",
	"interactive_clients.secret_verifier_set_at": "не секретный материал: МОМЕНТ установки " +
		"проверочного значения, попавший в кандидаты по имени (kaname#313). Значение само " +
		"исключено (SET STATISTICS 0); момент — время, и выборка времён в pg_stats не даёт " +
		"ни одного знака секрета. По нему же отбирают: он предикат согласия пары " +
		"«значение — отметка», и исключение стоило бы плана",
	// Здесь стояла запись о `human_sessions.password_change_required` — колонка
	// снята вместе с полем контракта (kacho#2697, kaname#201), и запись, которой
	// нечего решать, снята тем же изменением: ведомость истекает сама.
}

type statColumn struct {
	table  string
	column string
	typ    string
	target int
}

func (c statColumn) key() string { return c.table + "." + c.column }

// sweepSecretMaterialCandidates — кандидаты ВЫВОДЯТСЯ из применённой схемы, а не
// выписываются: выписанный перечень разошёлся бы с деревом молча.
//
// Предикат кандидата — двойной: любой двоичный столбец (секрет хранится двоичным)
// ЛИБО имя, называющее секретный материал. Оба вида дают ложные попадания —
// на то и ведомость решений: каждое попадание адъюдицируется, а не отбрасывается
// правкой предиката.
func sweepSecretMaterialCandidates(t *testing.T, db *sql.DB) []statColumn {
	t.Helper()
	rows, err := db.Query(`
		SELECT c.relname, a.attname, format_type(a.atttypid, a.atttypmod), a.attstattarget
		  FROM pg_attribute a
		  JOIN pg_class c ON c.oid = a.attrelid
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname = 'kaname' AND c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped
		   AND (format_type(a.atttypid, a.atttypmod) = 'bytea'
		        OR a.attname ~ '(secret|verifier|private|wrapped|password|digest|hash|salt|cipher|nonce)')
		 ORDER BY 1, 2`)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()

	var out []statColumn
	for rows.Next() {
		var c statColumn
		require.NoError(t, rows.Scan(&c.table, &c.column, &c.typ, &c.target))
		out = append(out, c)
	}
	require.NoError(t, rows.Err())
	require.NotEmpty(t, out,
		"обход пуст: кандидатов не найдено НИ ОДНОГО — это отказ, а не чистая схема")
	return out
}

// TestSecretMaterialCandidatesAreAllAdjudicated — по каждому кандидату есть
// решение, и перепись печатается ВСЕГДА.
func TestSecretMaterialCandidatesAreAllAdjudicated(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := baselineUp(t)
	candidates := sweepSecretMaterialCandidates(t, db)

	var excluded, kept, undecided []string
	for _, c := range candidates {
		switch {
		case c.target == 0:
			excluded = append(excluded, c.key())
		case secretMaterialKeeps[c.key()] != "":
			kept = append(kept, c.key())
		default:
			undecided = append(undecided, fmt.Sprintf("%s (%s, attstattarget=%d)", c.key(), c.typ, c.target))
		}
	}
	sort.Strings(undecided)

	t.Logf("ПЕРЕПИСЬ: колонок-кандидатов %d · исключено %d · решено оставить %d · без решения %d",
		len(candidates), len(excluded), len(kept), len(undecided))

	require.Empty(t, undecided,
		"у кандидата нет решения: он либо исключается из статистики (SET STATISTICS 0), "+
			"либо называется в secretMaterialKeeps с причиной: %v", undecided)

	// Ведомость истекает сама: запись, чьей колонки в схеме нет, — находка.
	present := map[string]bool{}
	for _, c := range candidates {
		present[c.key()] = true
	}
	for k := range secretMaterialKeeps {
		require.True(t, present[k],
			"запись ведомости %q потеряла предмет: такой колонки-кандидата в схеме нет", k)
	}
}

// seedSecretRows — строки с РАЗЛИЧНЫМИ значениями секретных колонок: без них
// `ANALYZE` нечего сохранять, и утверждение об отсутствии выполнилось бы
// тождественно.
func seedSecretRows(t *testing.T, db *sql.DB) {
	t.Helper()
	seedSecretCredentialOwners(t, db)

	// По 20 удостоверений на учётку: предел удостоверений на принципала — 24.
	for sa := 0; sa < 6; sa++ {
		svaID := fmt.Sprintf("sva%014d%03d", 0, sa)
		_, err := db.Exec(`INSERT INTO kaname.service_accounts (id, account_id, name)
		                   VALUES ($1, 'acc00000000000000dwn', $2)`, svaID, fmt.Sprintf("stat-sa-%03d", sa))
		require.NoError(t, err)
		for i := 0; i < 20; i++ {
			hash := make([]byte, 32)
			for j := range hash {
				hash[j] = byte(j)
			}
			hash[0], hash[1] = byte(sa), byte(i)
			_, err := db.Exec(`INSERT INTO kaname.service_account_oauth_clients
			    (id, sva_id, hydra_client_id, created_by_user_id, credential_kind, secret_hash,
			     public_key_pem, key_algorithm, trusted_subjects, expires_at)
			  VALUES ($1, $2, NULL, 'usr00000000000000dwn', 'SECRET', $3, '', '', '[]'::jsonb,
			          now() + interval '30 days')`,
				fmt.Sprintf("soc_%014d%03d", i, sa), svaID, hash)
			require.NoError(t, err)
		}
	}

	// Ключ подписи — 300 байт: ИМЕННО тот размер, на котором замер показал
	// попадание. Взять 2048 значило бы написать пробу, зелёную by construction.
	for i := 0; i < 150; i++ {
		blob := make([]byte, 300)
		for j := range blob {
			blob[j] = byte(j)
		}
		blob[0] = byte(i)
		_, err := db.Exec(`INSERT INTO kaname.token_signing_keys
		    (kid, algorithm, state, public_key_pem, private_key_wrapped, not_after)
		  VALUES ($1, 'RS256', 'PUBLISHED', 'pem', $2, now() + interval '30 days')`,
			fmt.Sprintf("kid-%04d", i), blob)
		require.NoError(t, err)
	}
}

func statisticsRowFor(t *testing.T, db *sql.DB, table, column string) (mcv, hist sql.NullString, found bool) {
	t.Helper()
	err := db.QueryRow(`SELECT most_common_vals::text, histogram_bounds::text
	                      FROM pg_stats
	                     WHERE schemaname = 'kaname' AND tablename = $1 AND attname = $2`,
		table, column).Scan(&mcv, &hist)
	if err == sql.ErrNoRows {
		return mcv, hist, false
	}
	require.NoError(t, err)
	return mcv, hist, true
}

// TestSecretMaterialValuesDoNotReachStatisticsAfterAnalyze — ОТРИЦАНИЕ на
// значениях, а не на настройке.
//
// Настройка `attstattarget = 0` — объявление; здесь проверяется ИСХОД: после
// настоящего `ANALYZE` над настоящими строками значений колонки в статистике нет.
func TestSecretMaterialValuesDoNotReachStatisticsAfterAnalyze(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := baselineUp(t)
	seedSecretRows(t, db)

	_, err := db.Exec(`ANALYZE kaname.service_account_oauth_clients,
	                           kaname.token_signing_keys,
	                           kaname.access_bindings`)
	require.NoError(t, err)

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ — первым. Без него отрицание ниже выполняется
	// тождественно на базе, где `ANALYZE` не собрал ничего вовсе.
	_, _, found := statisticsRowFor(t, db, "access_bindings", "target_digest")
	require.True(t, found,
		"контроль: у колонки, решённой к оставлению, статистика обязана БЫТЬ — "+
			"иначе отрицание ниже ничего не утверждает")

	for _, c := range []struct{ table, column string }{
		{"service_account_oauth_clients", "secret_hash"},
		{"token_signing_keys", "private_key_wrapped"},
	} {
		mcv, hist, found := statisticsRowFor(t, db, c.table, c.column)
		if !found {
			continue
		}
		require.False(t, mcv.Valid,
			"значения %s.%s попали в самые частые значения статистики: %s", c.table, c.column, mcv.String)
		require.False(t, hist.Valid,
			"значения %s.%s попали в границы гистограммы статистики: %s", c.table, c.column, hist.String)
	}
}
