// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// limit_export_before_retirement_integration_test.go — назначенные администратором
// величины выгружаемы ДО того, как снятие домена величин их уничтожит
// (задача #2134, приёмка KAN-QUOTA-1 §9 `ПР-3`, сценарий `KAN-Q4-07`).
//
// # Почему проба существует
//
// Величины читаются только маршрутами службы величин, и стадия S4 задачи #2117
// снимает их вместе со службой, а таблицу — новой миграцией. С этой минуты
// прочитать назначенное нечем. Это данные администратора установки, а не наши:
// потеря молча означает, что он узнает о ней по последствиям, а не от продукта.
//
// # Что здесь утверждается, и чего здесь НЕТ намеренно
//
// Здесь — ИСПОЛНИМОСТЬ: запрос, записанный в инструкции обновления, отрабатывает
// против живой схемы и выгружает ровно то, что в таблице лежит. Запрос берётся ИЗ
// ДОКУМЕНТА, а не набирается заново: проба, набравшая его сама, согласилась бы сама
// с собой о форме таблицы, которой документ не называет.
//
// Здесь НЕТ сверки документа с производителем команды (`pkg/dropguard`), и это не
// пропуск. Служба доступа — отдельный модуль Go и собирается против ПИНА фундамента,
// а не против дерева: правка фундамента доезжает сюда только следующим сдвигом пина.
// Проба, позвавшая новый символ фундамента, была бы зелена локально (пространство) и
// красна в конвейере (пин). Сверка живёт на стороне фундамента, где оба конца
// доступны в одном модуле, — `internal/repohygiene`, гейт процедуры выгрузки.
//
// Что psql установлен там, где оператор выполнит команду, проба не утверждает:
// мета-команда `\copy` — часть его оболочки, здесь исполняется её запрос через
// COPY … TO STDOUT. Утверждение об оболочке было бы утверждением о машине оператора.
package migrations_test

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

// limitsTable — предмет процедуры. Одно написание на всю пробу: два написания
// одной таблицы разошлись бы молча, и разошлось бы то, которое не исполняется.
const limitsTable = "kaname.limits"

// installGuide — документ, который читает оператор при обновлении версии. Путь
// относительный: вынесенный репозиторий сменит корень, но не эту связь.
const installGuide = "../../INSTALL.md"

// TestLimitExport_TheDocumentedCommandExportsEveryAssignedValue — условия 1 и 3
// предиката задачи в одном прогоне: команда записана в инструкции обновления и
// выгружает ровно назначенное, с напечатанным числом.
func TestLimitExport_TheDocumentedCommandExportsEveryAssignedValue(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}

	guide, err := os.ReadFile(installGuide)
	require.NoError(t, err, "инструкция обновления обязана существовать: без неё "+
		"процедуре выгрузки негде быть записанной")
	require.NotEmpty(t, guide, "инструкция обновления пуста: прочитано ноль байт, "+
		"и любое утверждение ниже говорило бы не о документе")

	// Запрос БЕРЁТСЯ ИЗ ДОКУМЕНТА. Оператор исполнит ровно его; исполняя копию,
	// проба утверждала бы о копии.
	query := documentedExportQuery(t, string(guide))

	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer db.Close()

	// ТАБЛИЦА НЕПУСТА СВЕРХ ПОСЕЯННЫХ. Предикат задачи требует непустой таблицы:
	// выгрузка, доказанная на одном посеве, ничего не говорит о том, что назначил
	// администратор, — а теряются именно его строки.
	seeded := countLimits(t, db)
	require.Positive(t, seeded, "цепочка не посеяла ни одной величины: выгружать было "+
		"бы нечего, и утверждение ниже зеленело бы, не прочитав ничего")

	const assigned = 8
	seedAssignedLimits(t, db, assigned)
	total := countLimits(t, db)
	require.Equal(t, seeded+assigned, total, "перепись до выгрузки разошлась с ожидаемой")

	// ЧИСЛО ПЕЧАТАЕТСЯ ВСЕГДА: «ноль выгружено» обязано быть отличимо от «не читали».
	exported := copyToCSV(t, db, query)
	rows := csvDataRows(t, exported)
	require.Equal(t, total, rows,
		"выгружено %d строк из %d лежащих: процедура теряет назначенное", rows, total)

	t.Logf("перепись: величин в таблице %d (посеяно умолчаний %d, назначено пробой %d), "+
		"выгружено строк %d, байт %d; запрос из инструкции обновления: %s",
		total, seeded, assigned, rows, len(exported), query)
}

// seedAssignedLimits изображает работу администратора установки: величины,
// назначенные СВЕРХ посеянных умолчаний, на конкретный аккаунт.
//
// Именно они и теряются при сносе таблицы: умолчания цепочка посеет заново на
// любой установке, а эти строки не знает никто, кроме самой установки. Поэтому
// проба назначает их на живой аккаунт, а не подкладывает ещё одно умолчание:
// умолчание прошло бы и без ссылочной проверки, то есть проверяло бы более
// снисходительную форму записи, чем та, которой пользуется администратор.
func seedAssignedLimits(t *testing.T, db *sql.DB, n int) {
	t.Helper()

	tx, err := db.Begin()
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()

	// Ссылки аккаунта и его владельца замкнуты друг на друга, поэтому порядок
	// вставки внутри одной транзакции не определён by construction.
	_, err = tx.Exec(`SET CONSTRAINTS ALL DEFERRED`)
	require.NoError(t, err)

	const accountID = "acc00000000000000lim"
	const ownerID = "usr00000000000000lim"
	_, err = tx.Exec(`
		INSERT INTO kaname.accounts (id, name, owner_user_id)
		VALUES ($1, 'limit-export-probe', $2)`, accountID, ownerID)
	require.NoError(t, err, "посев аккаунта")
	_, err = tx.Exec(`
		INSERT INTO kaname.users (id, external_id, email, account_id, invite_status)
		VALUES ($1, 'ext-limit-export', 'limit-export@example.invalid', $2, 'ACTIVE')`,
		ownerID, accountID)
	require.NoError(t, err, "посев владельца аккаунта")

	for i := 0; i < n; i++ {
		_, err = tx.Exec(`
			INSERT INTO kaname.limits (id, scope, scope_id, kind, limit_value)
			VALUES ($1, 'ACCOUNT', $2, $3, $4)`,
			// Тело идентификатора крокфордово и НЕ пересекается с посеянными:
			// те начинаются нулём, эти девяткой.
			fmt.Sprintf("lim-9%016d", i+1), accountID,
			fmt.Sprintf("probe.assigned%d", i+1), 100+i)
		require.NoError(t, err, "назначение величины администратором обязано проходить")
	}
	require.NoError(t, tx.Commit())
}

// documentedExportQuery достаёт исполнимую половину документированной команды — то,
// что стоит внутри psql-овой `\copy ( … ) TO`.
//
// Отбор идёт по ТАБЛИЦЕ, а не по номеру строки документа: документ правят, и
// привязка к его строению рвалась бы на первой же правке абзаца.
func documentedExportQuery(t *testing.T, guide string) string {
	t.Helper()
	const open = `\copy (`
	const shut = `) TO `

	for _, line := range strings.Split(guide, "\n") {
		i := strings.Index(line, open)
		if i < 0 || !strings.Contains(line, limitsTable) {
			continue
		}
		rest := line[i+len(open):]
		j := strings.LastIndex(rest, shut)
		require.GreaterOrEqual(t, j, 0,
			"в документированной команде нет %q, выгружать некуда: %s", shut, line)
		return strings.TrimSpace(rest[:j])
	}

	t.Fatalf("инструкция обновления не несёт команды выгрузки таблицы %s.\n"+
		"Оператор, встретивший отказ перед сносом, ищет процедуру здесь; не найдя её, "+
		"он оставляет исполнимым единственный названный шаг — разрешить уничтожение строк.",
		limitsTable)
	return ""
}

// copyToCSV исполняет запрос через COPY … TO STDOUT — тем же способом, каким его
// исполнит psql, только без самой оболочки.
func copyToCSV(t *testing.T, db *sql.DB, query string) []byte {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	var buf bytes.Buffer
	require.NoError(t, conn.Raw(func(driverConn any) error {
		pg, ok := driverConn.(*stdlib.Conn)
		require.True(t, ok, "соединение не pgx: выгрузка COPY недоступна")
		_, cerr := pg.Conn().PgConn().CopyTo(ctx, &buf,
			"COPY ("+query+") TO STDOUT WITH (FORMAT csv, HEADER)")
		return cerr
	}), "документированный запрос не отработал против живой схемы")
	return buf.Bytes()
}

// csvDataRows — строк данных, то есть без заголовка столбцов.
func csvDataRows(t *testing.T, csv []byte) int {
	t.Helper()
	lines := strings.Split(strings.TrimRight(string(csv), "\n"), "\n")
	require.NotEmpty(t, lines[0],
		"выгрузка пуста: нет даже заголовка столбцов — без него CSV не прочитать обратно")
	return len(lines) - 1
}

func countLimits(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM `+limitsTable).Scan(&n))
	return n
}
