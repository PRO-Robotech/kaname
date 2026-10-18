// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// access_binding_target_form_integration_test.go — ФОРМУ ЦЕЛИ ПРИВЯЗКИ ДЕРЖИТ
// БАЗА, А НЕ ПИСАТЕЛЬ (задача kaname#863, находка ревью kaname#862).
//
// # Что судится
//
// Колонка `access_bindings.target` до испытуемого держала только число
// элементов перечня: корень-массив, `{"resources": null}`, `resources` строкой
// либо объектом база принимала. На таких формах два читателя цели — ветвь
// выдач решения о доступе и материализатор — расходились: первая давала
// отказ, второй читал `null` как всю область либо ломался на загрузке.
//
// Пробы две, и порядок в каждой несущий:
//
//  1. ГОЛОВА КАТАЛОГА отвергает форму вне контракта — вставкой и обновлением,
//     по имени ограничения, SQLSTATE 23514; законный близнец той же строки
//     проходит. До испытуемого проба красная: база форму пропускает.
//  2. ИСПЫТУЕМЫЙ накатывается на базу с живыми строками без отказа: строки
//     посева цепи и строки каждой законной формы. Перепись нарушителей на
//     версии до испытуемого — ноль, и это печатается числом. Близнец — база с
//     одной строкой вне формы: накат отказывает тем же ограничением, то есть
//     ограничение судит лежащие строки, а не только будущие. Откат снимает
//     ограничение, повторный накат проходит.
//
// # Испытуемый ищется по содержанию
//
// Первая по возрастанию версий миграция, чей накат называет ограничение
// `access_bindings_target_form_ck`; «версия до» — старшая ниже него.
package migrations_test

import (
	"database/sql"
	"io/fs"
	"strconv"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// atfConstraint — имя ограничения формы цели, дословно.
const atfConstraint = "access_bindings_target_form_ck"

// atfOutside — формы вне контракта: каждая обязана быть отвергнута базой.
var atfOutside = []string{
	`{"resources": null}`,
	`{"resources": "x"}`,
	`{"resources": {}}`,
	`[]`,
	`"x"`,
}

// atfLegal — законные формы: каждая проходит.
var atfLegal = []string{
	`{"allInScope": true}`,
	`{}`,
	`{"resources": []}`,
	`{"resources": [{"type": "vpc.network", "id": "enp863"}]}`,
}

// atfCatalog — каталог миграций, испытуемый и голова.
type atfCatalog struct {
	versions []int64
	subject  int64
	file     string
}

func (c atfCatalog) head() int64 {
	var best int64
	for _, v := range c.versions {
		if v > best {
			best = v
		}
	}
	return best
}

func (c atfCatalog) preceding() int64 {
	var best int64
	for _, v := range c.versions {
		if (c.subject == 0 || v < c.subject) && v > best {
			best = v
		}
	}
	return best
}

func atfReadCatalog(t *testing.T) atfCatalog {
	t.Helper()
	entries, err := fs.ReadDir(migrations.FS, ".")
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): каталог миграций читается")
	var c atfCatalog
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(name, "_")
		require.True(t, ok, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): имя миграции %s без версии", name)
		v, err := strconv.ParseInt(prefix, 10, 64)
		require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): версия миграции %s", name)
		c.versions = append(c.versions, v)
		body, err := fs.ReadFile(migrations.FS, name)
		require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): тело миграции %s", name)
		if strings.Contains(migrations.MigrationUpSection(string(body)), atfConstraint) &&
			(c.subject == 0 || v < c.subject) {
			c.subject, c.file = v, name
		}
	}
	require.NotEmpty(t, c.versions, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): каталог миграций пуст — судить нечего")
	return c
}

// atfRole — роль из посева цепи: строка выдачи ссылается на неё внешним ключом.
func atfRole(t *testing.T, db *sql.DB) string {
	t.Helper()
	var id string
	require.NoError(t, db.QueryRow(`SELECT id FROM kaname.roles ORDER BY id LIMIT 1`).Scan(&id),
		"НЕ-ВЫПОЛНИЛОСЬ(фикстура): посев цепи несёт хотя бы одну роль")
	return id
}

// atfInsert вставляет выдачу с данной целью; i различает строки.
func atfInsert(db *sql.DB, role string, i int, target string) error {
	tag := strconv.Itoa(8630 + i)
	_, err := db.Exec(`INSERT INTO kaname.access_bindings
	    (id, subject_type, subject_id, role_id, resource_type, resource_id, status, target)
	  VALUES ($1, 'user', $2, $3, 'account', $4, 'ACTIVE', $5::jsonb)`,
		"acbatf"+tag, "usratf"+tag, role, "accatf"+tag, target)
	return err
}

// atfViolators — строк вне формы: то же предложение, что ограничение.
func atfViolators(t *testing.T, db *sql.DB) (total, outside int) {
	t.Helper()
	require.NoError(t, db.QueryRow(`
	  SELECT count(*),
	         count(*) FILTER (WHERE NOT (
	             jsonb_typeof(target) = 'object'
	         AND (NOT target ? 'allInScope' OR jsonb_typeof(target -> 'allInScope') = 'boolean')
	         AND (NOT target ? 'resources'
	              OR (jsonb_typeof(target -> 'resources') = 'array'
	                  AND NOT EXISTS (
	                      SELECT 1 FROM jsonb_array_elements(target -> 'resources') e(v)
	                       WHERE jsonb_typeof(e.v) <> 'object'
	                          OR jsonb_typeof(e.v -> 'type') IS DISTINCT FROM 'string'
	                          OR jsonb_typeof(e.v -> 'id') IS DISTINCT FROM 'string')))))
	    FROM kaname.access_bindings`).Scan(&total, &outside))
	return total, outside
}

// TestAccessBindingTargetForm_HeadRefusesTheFormOutsideTheContract — голова
// каталога отвергает форму цели вне контракта вставкой и обновлением, по имени
// ограничения; законный близнец проходит.
func TestAccessBindingTargetForm_HeadRefusesTheFormOutsideTheContract(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	c := atfReadCatalog(t)
	db := serOpenAt(t, c.head())
	role := atfRole(t, db)

	for i, legal := range atfLegal {
		require.NoError(t, atfInsert(db, role, i, legal), "законная цель %s принимается", legal)
	}
	for i, bad := range atfOutside {
		err := atfInsert(db, role, 100+i, bad)
		if err == nil {
			t.Errorf("вставка: база на версии %d ПРИНЯЛА цель %s вне контракта — форму держит только писатель",
				c.head(), bad)
			continue
		}
		require.Equal(t, atfConstraint, serConstraintOf(err), "вставка %s: отказ даёт ограничение формы: %v", bad, err)
		require.Equal(t, "23514", a458SQLState(err), "вставка %s: SQLSTATE 23514", bad)
	}
	// Обновление: строка законной формы не переводится в форму вне контракта.
	for _, bad := range atfOutside {
		_, err := db.Exec(`UPDATE kaname.access_bindings SET target = $1::jsonb WHERE id = 'acbatf8630'`, bad)
		if err == nil {
			t.Errorf("обновление: база на версии %d ПРИНЯЛА цель %s вне контракта", c.head(), bad)
			continue
		}
		require.Equal(t, atfConstraint, serConstraintOf(err), "обновление %s: отказ даёт ограничение формы: %v", bad, err)
	}
	// Близнец обновления — законная форма.
	_, err := db.Exec(`UPDATE kaname.access_bindings SET target = '{"resources": []}'::jsonb WHERE id = 'acbatf8630'`)
	require.NoError(t, err, "обновление в законную форму проходит")
}

// TestAccessBindingTargetForm_MigrationAppliesOnLiveRows — испытуемый
// накатывается на базу с живыми строками; нарушителей до наката ноль; близнец
// со строкой вне формы отвергается накатом; откат и повторный накат проходят.
func TestAccessBindingTargetForm_MigrationAppliesOnLiveRows(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	c := atfReadCatalog(t)
	if c.subject == 0 {
		t.Fatalf("ИСПЫТУЕМОГО НЕТ: в каталоге из %d миграций (голова %d) нет миграции, чей накат называет %s",
			len(c.versions), c.head(), atfConstraint)
	}

	db := serOpenAt(t, c.preceding())
	role := atfRole(t, db)
	for i, legal := range atfLegal {
		require.NoError(t, atfInsert(db, role, i, legal), "Дано: законная цель %s лежит до наката", legal)
	}
	total, outside := atfViolators(t, db)
	t.Logf("перепись на версии %d: строк выдач %d, из них вне формы %d", c.preceding(), total, outside)
	require.Greater(t, total, len(atfLegal), "Дано: посев цепи несёт свои выдачи сверх строк пробы")
	require.Zero(t, outside, "Дано: нарушителей до наката ноль — обратного заполнения не требуется")

	require.NoError(t, goose.UpTo(db, ".", c.subject), "накат %s на живые строки", c.file)
	after, _ := atfViolators(t, db)
	require.Equal(t, total, after, "накат не трогает ни одной строки")

	require.NoError(t, goose.DownTo(db, ".", c.preceding()), "откат %s", c.file)
	require.NoError(t, atfInsert(db, role, 200, `{"resources": null}`), "после отката ограничения нет")
	_, err := db.Exec(`DELETE FROM kaname.access_bindings WHERE id = 'acbatf8830'`)
	require.NoError(t, err)
	require.NoError(t, goose.UpTo(db, ".", c.subject), "повторный накат")

	// Близнец: та же цепь, одна строка вне формы — накат отказывает.
	twin := serOpenAt(t, c.preceding())
	require.NoError(t, atfInsert(twin, atfRole(t, twin), 300, `{"resources": null}`))
	err = goose.UpTo(twin, ".", c.subject)
	require.Error(t, err, "близнец: строка вне формы останавливает накат")
	require.Contains(t, err.Error(), atfConstraint, "близнец: отказ называет ограничение формы")
}
