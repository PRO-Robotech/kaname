// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

// resource_journal_integration_test.go — РЕСУРСНЫЙ ЖУРНАЛ подписки: строка
// пишется в той же транзакции, что ресурсная, и несёт захваченные области.
//
// Приёмка `docs/engineering/acceptance/access-resources-reach-a-narrowed-subscriber.md`,
// сценарии GWT-1, GWT-2, GWT-3, GWT-4 и §3.3 (набор областей). Задача #69.
//
// # Почему эти утверждения живут ЗДЕСЬ, а не у владельца журнала
//
// Их предмет — ТРИГГЕР, то есть свойство схемы: он исполняется в транзакции
// своего оператора, какой бы она ни была, и покрывает пути, которых объявление
// владельца не видит вовсе (посев, применение каталога модулей, применение
// ролей). Проба у владельца утверждала бы про свой вызов, а не про схему.
//
// # Транзакционность проверяется ВИДИМОСТЬЮ, а не счётом после фиксации
//
// Счёт после фиксации зелен и тогда, когда строка написана ВТОРОЙ транзакцией:
// «в той же» и «в какой-то» для него неразличимы. Поэтому строка спрашивается
// ИЗНУТРИ незафиксированной транзакции и СНАРУЖИ неё одновременно — второе
// соединение видит её тогда и только тогда, когда первое зафиксировалось.

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/pressly/goose/v3"

	"github.com/PRO-Robotech/kaname/internal/migrations"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// journalRowsFor — строки журнала по предмету, прочитанные ДАННЫМ исполнителем.
//
// Исполнитель параметром, а не соединением: одна и та же выборка задаётся и
// незафиксированной транзакции, и соединению вне неё, и различие ответов и есть
// предмет пробы.
func journalRowsFor(t *testing.T, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, kind, id string) int {
	t.Helper()
	var n int
	require.NoError(t, q.QueryRowContext(context.Background(),
		`SELECT count(*) FROM kaname.resource_journal
		  WHERE resource_kind = $1 AND resource_id = $2`, kind, id).Scan(&n))
	return n
}

// TestIntegration_JournalRowCommitsWithTheResourceRow — GWT-1.
func TestIntegration_JournalRowCommitsWithTheResourceRow(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	ctx := context.Background()
	db := freshIamSchema(t)
	_, accountID := seedAccountWithOwner(t, db, "gwt1")

	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(ctx,
		`INSERT INTO kaname.groups (id, account_id, name) VALUES ($1, $2, $3)`,
		"grp-gwt1", accountID, "gwt1")
	require.NoError(t, err)

	assert.Equal(t, 1, journalRowsFor(t, tx, "iam_group", "grp-gwt1"),
		"строка журнала обязана быть видна ИЗНУТРИ той же транзакции: "+
			"иначе она написана не ею")
	assert.Equal(t, 0, journalRowsFor(t, db, "iam_group", "grp-gwt1"),
		"снаружи незафиксированной транзакции строки быть не может — "+
			"если она видна, журнал пишется вне транзакции мутации")

	require.NoError(t, tx.Commit())

	assert.Equal(t, 1, journalRowsFor(t, db, "iam_group", "grp-gwt1"),
		"после фиксации строка обязана стать видимой обеим сторонам")
}

// TestIntegration_JournalHasNoRowWhenTheMutationRollsBack — GWT-2.
//
// Положительный близнец — GWT-1 на том же входе: без него «строк ноль» зеленело
// бы и на триггере, не эмитящем никогда.
func TestIntegration_JournalHasNoRowWhenTheMutationRollsBack(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	ctx := context.Background()
	db := freshIamSchema(t)
	_, accountID := seedAccountWithOwner(t, db, "gwt2")

	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx,
		`INSERT INTO kaname.groups (id, account_id, name) VALUES ($1, $2, $3)`,
		"grp-gwt2", accountID, "gwt2")
	require.NoError(t, err)
	require.Equal(t, 1, journalRowsFor(t, tx, "iam_group", "grp-gwt2"),
		"положительный контроль: внутри транзакции строка есть")
	require.NoError(t, tx.Rollback())

	assert.Equal(t, 0, journalRowsFor(t, db, "iam_group", "grp-gwt2"),
		"при отказе мутации события нет ВОВСЕ: наблюдатель не отличит "+
			"«ещё делается» от «упало», и подписка полла операции не заменяет")
}

// TestIntegration_JournalIgnoresAnUpdateThatChangesNothing — GWT-3 с близнецом.
func TestIntegration_JournalIgnoresAnUpdateThatChangesNothing(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	ctx := context.Background()
	db := freshIamSchema(t)
	_, accountID := seedAccountWithOwner(t, db, "gwt3")

	_, err := db.ExecContext(ctx,
		`INSERT INTO kaname.groups (id, account_id, name) VALUES ($1, $2, $3)`,
		"grp-gwt3", accountID, "gwt3")
	require.NoError(t, err)
	require.Equal(t, 1, journalRowsFor(t, db, "iam_group", "grp-gwt3"))

	// Переписывание теми же значениями — то, что делает повторный посев.
	_, err = db.ExecContext(ctx,
		`UPDATE kaname.groups SET name = name WHERE id = $1`, "grp-gwt3")
	require.NoError(t, err)
	assert.Equal(t, 1, journalRowsFor(t, db, "iam_group", "grp-gwt3"),
		"правка, не меняющая существа, события рождать не вправе: "+
			"иначе каждый подъём давал бы шторм правок, в которых ничего не изменилось")

	// ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ в том же прогоне: правка по существу событие рождает.
	_, err = db.ExecContext(ctx,
		`UPDATE kaname.groups SET description = 'изменено' WHERE id = $1`, "grp-gwt3")
	require.NoError(t, err)
	assert.Equal(t, 2, journalRowsFor(t, db, "iam_group", "grp-gwt3"),
		"без этой половины проба зеленела бы на триггере правки, "+
			"не эмитящем никогда")
}

// TestIntegration_JournalDictionariesAreClosed — GWT-4 с близнецом.
func TestIntegration_JournalDictionariesAreClosed(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	ctx := context.Background()
	db := freshIamSchema(t)

	// ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ первым: годная тройка вставляется.
	_, err := db.ExecContext(ctx,
		`INSERT INTO kaname.resource_journal
		   (resource_kind, resource_id, event_type, payload)
		 VALUES ('iam_group', 'grp-ok', 'CREATED', '{"id":"grp-ok"}'::jsonb)`)
	require.NoError(t, err, "годная тройка обязана вставляться: "+
		"иначе отрицания ниже зеленеют на таблице, не принимающей ничего")

	_, err = db.ExecContext(ctx,
		`INSERT INTO kaname.resource_journal
		   (resource_kind, resource_id, event_type, payload)
		 VALUES ('iam_group', 'grp-bad', 'MOVED', '{}'::jsonb)`)
	assert.Error(t, err, "род изменения вне трёх слов вставляться не вправе")

	_, err = db.ExecContext(ctx,
		`INSERT INTO kaname.resource_journal
		   (resource_kind, resource_id, event_type, payload)
		 VALUES ('iam_widget', 'wid-bad', 'CREATED', '{}'::jsonb)`)
	assert.Error(t, err, "вид вне словаря семи вставляться не вправе: "+
		"строка, о видимости которой нельзя спросить модель, не доставляется")

	_, err = db.ExecContext(ctx,
		`INSERT INTO kaname.resource_journal
		   (resource_kind, resource_id, event_type, payload)
		 VALUES ('iam_group', 'grp-arr', 'CREATED', '[]'::jsonb)`)
	assert.Error(t, err, "нагрузка обязана быть объектом")
}

// TestIntegration_RemovalCapturesEveryScopeOfTheSubject — §3.3, набор областей.
//
// Предмет — множественность: человек состоит в НЕСКОЛЬКИХ аккаунтах
// (`memberships_user_account_unique` уникальна по паре, а не по пользователю),
// и захват одной принадлежности из N оставил бы держателей выдач на остальные
// аккаунты без события снятия.
func TestIntegration_RemovalCapturesEveryScopeOfTheSubject(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	ctx := context.Background()
	db := freshIamSchema(t)
	_, accountOne := seedAccountWithOwner(t, db, "one")
	_, accountTwo := seedAccountWithOwner(t, db, "two")

	_, err := db.ExecContext(ctx,
		`INSERT INTO kaname.users (id, external_id, email, account_id)
		 VALUES ('usr-multi', 'usr-multi', 'multi@example.test', $1)`, accountOne)
	require.NoError(t, err)
	// ПЕРВАЯ принадлежность заводится продуктом, а не пробой: триггер
	// `membership_mirrors_user_row` зеркалит аккаунт строки человека в
	// принадлежности. Вписать её здесь значило бы спорить с продуктом — и
	// получить нарушение уникальности пары.
	//
	// Вторая заводится явно: предмет пробы в том, что областей НЕСКОЛЬКО.
	// Идентификатор связан формой (`memberships_id_form_check`), поэтому берётся
	// годным, а не собирается из имени аккаунта.
	_, err = db.ExecContext(ctx,
		`INSERT INTO kaname.memberships (id, user_id, account_id)
		 VALUES ($1, 'usr-multi', $2)`,
		fmt.Sprintf("mbr-%016dq", 2), accountTwo)
	require.NoError(t, err)

	var memberships int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT count(*) FROM kaname.memberships WHERE user_id = 'usr-multi'`).
		Scan(&memberships))
	require.Equal(t, 2, memberships,
		"положительный контроль фикстуры: у человека РОВНО две принадлежности — "+
			"на одной проба не отличила бы набор от значения")

	_, err = db.ExecContext(ctx, `DELETE FROM kaname.users WHERE id = 'usr-multi'`)
	require.NoError(t, err)

	var scopes []byte
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT scope FROM kaname.resource_journal
		  WHERE resource_kind = 'iam_user' AND resource_id = 'usr-multi'
		    AND event_type = 'DELETED'`).Scan(&scopes))

	assert.JSONEq(t,
		`[{"type":"account","id":"`+accountOne+`"},{"type":"account","id":"`+accountTwo+`"}]`,
		string(scopes),
		"захватываются ВСЕ области предмета: одна принадлежность из двух оставила бы "+
			"держателей выдач на второй аккаунт без события снятия, и оставила бы тихо")
}

// TestIntegration_JournalMigrationRollsBack — обратный ход снимает ВСЁ, что
// прямой завёл, и не оставляет висящих триггеров.
//
// Проба нужна не ради самой отмены: применённые триггеры на СЕМИ чужих таблицах
// переживают снятие журнала молча, если их забыли, — и следующее применение
// упало бы на «триггер уже существует», то есть на шаге, который к предмету
// отношения не имеет.
func TestIntegration_JournalMigrationRollsBack(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	ctx := context.Background()
	db := freshIamSchema(t)

	countTriggers := func() int {
		var n int
		require.NoError(t, db.QueryRowContext(ctx,
			`SELECT count(*) FROM pg_trigger t
			   JOIN pg_class c ON c.oid = t.tgrelid
			   JOIN pg_namespace n ON n.oid = c.relnamespace
			  WHERE n.nspname = 'kaname' AND NOT t.tgisinternal
			    AND t.tgname LIKE '%resource_journal%'`).Scan(&n))
		return n
	}

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: прямой ход завёл триггеры, и их СЕМЬ основных
	// (создание, правка, снятие) плюс ТРИ подтаблицы состава плюс пробуждение.
	require.Equal(t, 7*3+3+1, countTriggers(),
		"перепись триггеров журнала: без неё отмена ниже зеленела бы на схеме, "+
			"где их не было вовсе")

	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	goose.SetLogger(goose.NopLogger())
	require.NoError(t, goose.Down(db, "."), "обратный ход обязан пройти целиком")

	assert.Equal(t, 0, countTriggers(),
		"после отмены висящих триггеров журнала не остаётся: забытый пережил бы "+
			"снятие таблицы и уронил бы следующее применение на чужом шаге")

	var exists bool
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT to_regclass('kaname.resource_journal') IS NOT NULL`).Scan(&exists))
	assert.False(t, exists, "таблица журнала снимается вместе с триггерами")

	// Прямой ход применяется ЗАНОВО: отмена, после которой не накатить, есть
	// отмена только по названию.
	require.NoError(t, goose.Up(db, "."), "после отмены цепь обязана накатиться снова")
	assert.Equal(t, 7*3+3+1, countTriggers())
}
