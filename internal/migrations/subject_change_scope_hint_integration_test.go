// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// subject_change_scope_hint_integration_test.go — журнал смены субъекта не
// несёт величин, которых не читает никто (#1462).
//
// # Предмет
//
// Колонки `resource_type`/`resource_id` заполняла КАЖДАЯ мутация выдачи —
// выдача права и его снятие, — а читателя у них не было ни одного: проекция
// чтения (`repo/kacho/pg/subject_change_repo.go`) их не выбирает, контракт
// `InternalIAMService.PollSubjectChanges` их не выставляет, потребитель на крае
// о них не знает. Комментарий рядом с объявлением называл их «optional scope
// hint for future per-resource cache invalidation», то есть подсказкой —
// подсказывать было некому.
//
// Это тот же класс, что величины доставки того же семейства (kacho#917), и
// цена та же: она ложится на путь мутации, а не на путь чтения.
//
// # Почему проба по ЖИВОЙ схеме
//
// Текст миграции говорит, что колонка снята; живая схема говорит, снята ли она
// на самом деле — после проигрывания всей цепи, включая любую позднюю
// миграцию, которая могла бы её вернуть. Первое — намерение, второе — исход.
package migrations_test

import (
	"database/sql"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegration_SubjectChangeJournalCarriesNoUnreadScopeHint — регрессия
// на снятие беспрочтенных величин предмета (#1462).
//
// Утверждается ПАРА, и вторая половина обязательна: без неё «колонки
// resource_type нет» зеленело бы и на снесённом журнале, и на опечатке в имени
// таблицы — то есть ровно там, где вердикт нужен больше всего.
func TestIntegration_SubjectChangeJournalCarriesNoUnreadScopeHint(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)

	columns := columnsOf(t, db, "kacho_iam", "subject_change_outbox")

	t.Logf("перепись: колонок у kacho_iam.subject_change_outbox — %d (%v)",
		len(columns), columns)

	require.NotEmpty(t, columns,
		"перепись пуста: журнала нет вовсе либо запрос к каталогу читает не то — "+
			"на пустой переписи любое отрицание ниже зеленеет, ничего не проверив")

	// Отрицание — предмет #1462.
	assert.NotContains(t, columns, "resource_type",
		"величина предмета снята вместе со своим писателем: её не выбирает проекция "+
			"чтения, не выставляет контракт PollSubjectChanges и не читает потребитель "+
			"на крае — а заполняла её каждая мутация выдачи")
	assert.NotContains(t, columns, "resource_id",
		"величина предмета снята вместе со своим писателем: её не выбирает проекция "+
			"чтения, не выставляет контракт PollSubjectChanges и не читает потребитель "+
			"на крае — а заполняла её каждая мутация выдачи")

	// Положительный контроль на том же запросе, в том же прогоне: величины,
	// у которых читатель ЕСТЬ, обязаны остаться. Без него отрицание выше зеленело
	// бы и на миграции, снёсшей журнал целиком, — а его читает край курсором.
	for _, kept := range []string{"id", "subject_id", "op", "payload", "created_at"} {
		assert.Contains(t, columns, kept,
			"величина, которую читают, обязана остаться: снималась подсказка, "+
				"которой некому подсказывать, а не журнал — его читает край курсором "+
				"по id (InternalIAMService.PollSubjectChanges)")
	}
}

// columnsOf — имена колонок таблицы по ЖИВОЙ схеме, отсортированные.
//
// Читается каталог, а не текст миграций: колонка, снятая поздней миграцией,
// в тексте ранней осталась бы, и предикат по файлам объявил бы живым снятое.
func columnsOf(t *testing.T, db *sql.DB, schema, table string) []string {
	t.Helper()
	rows, err := db.Query(`
		SELECT a.attname
		  FROM pg_attribute a
		  JOIN pg_class c ON c.oid = a.attrelid
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname = $1
		   AND c.relname = $2
		   AND a.attnum > 0
		   AND NOT a.attisdropped`, schema, table)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()

	var out []string
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		out = append(out, name)
	}
	require.NoError(t, rows.Err())
	sort.Strings(out)
	return out
}
