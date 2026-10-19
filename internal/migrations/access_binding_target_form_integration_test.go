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
// Пробы три, и порядок в каждой несущий:
//
//  1. ГОЛОВА КАТАЛОГА отвергает форму вне контракта — вставкой и обновлением,
//     по имени ограничения, SQLSTATE 23514; законный близнец той же строки
//     проходит. До испытуемого проба красная: база форму пропускает.
//  2. ЗАВЕДЕНИЕ И ПРОВЕРКА РАЗНЕСЕНЫ по двум миграциям: заведение — `NOT
//     VALID`, проверка лежащих строк — отдельным файлом `VALIDATE CONSTRAINT`
//     без заведения. goose ведёт каждую миграцию своей транзакцией, поэтому
//     проход по таблице идёт под `SHARE UPDATE EXCLUSIVE`, а не под
//     исключительным замком заведения (находка ревью DB-863-2).
//  3. ИСПЫТУЕМЫЕ накатываются на базу с живыми строками без отказа: строки
//     посева цепи и строки каждой законной формы. Перепись нарушителей на
//     версии до испытуемого — ноль, и это печатается числом. Накат проверки
//     держит на таблице `SHARE UPDATE EXCLUSIVE` и не держит исключительного
//     замка — это читается из `pg_locks` транзакции наката. Близнец — база с
//     одной строкой вне формы: заведение ложится, а накат проверки отказывает
//     тем же ограничением, то есть ограничение судит лежащие строки, а не
//     только будущие. Откат проверки возвращает непроверенное ограничение,
//     откат заведения снимает его, повторный накат проходит.
//
// # Испытуемые ищутся по содержанию
//
// Заведение — первая по возрастанию версий миграция, чей накат называет
// ограничение `access_bindings_target_form_ck`; «версия до» — старшая ниже
// него. Проверка — первая миграция, чей накат несёт `VALIDATE CONSTRAINT
// access_bindings_target_form_ck`.
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
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
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

// atfValidate — оператор проверки лежащих строк, дословно.
const atfValidate = "VALIDATE CONSTRAINT " + atfConstraint

// atfCatalog — каталог миграций, испытуемые и голова.
type atfCatalog struct {
	versions []int64
	subject  int64
	file     string
	// subjectUp — исполняемая часть наката заведения.
	subjectUp string
	// validator — миграция проверки лежащих строк; 0 — её нет.
	validator     int64
	validatorFile string
	validatorUp   string
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
		up := migrations.MigrationUpSection(string(body))
		if strings.Contains(up, atfConstraint) && (c.subject == 0 || v < c.subject) {
			c.subject, c.file, c.subjectUp = v, name, up
		}
		if strings.Contains(strings.Join(strings.Fields(up), " "), atfValidate) &&
			(c.validator == 0 || v < c.validator) {
			c.validator, c.validatorFile, c.validatorUp = v, name, up
		}
	}
	require.NotEmpty(t, c.versions, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): каталог миграций пуст — судить нечего")
	return c
}

// atfRole — системная роль владельца аккаунта из посева цепи (та же, что у
// обратного заполнения владельцев): выдача на аккаунт — её законная область.
func atfRole(t *testing.T, db *sql.DB) string {
	t.Helper()
	var id string
	require.NoError(t, db.QueryRow(`SELECT id FROM kaname.roles WHERE id = 'rol' || substr(md5('owner'), 1, 17)`).Scan(&id),
		"НЕ-ВЫПОЛНИЛОСЬ(фикстура): посев цепи несёт роль владельца аккаунта")
	return id
}

// atfInsert вставляет выдачу с данной целью; i различает строки. Субъект —
// живая личность, область — её аккаунт: стражи ссылок выдачи судят обе
// ссылки на вставке, и фикстура строит то, что строит продукт.
func atfInsert(t *testing.T, db *sql.DB, role string, i int, target string) error {
	t.Helper()
	tag := "atf" + strconv.Itoa(8630+i)
	person := serSeedPerson(t, db, tag)
	acc := "acc" + strings.Repeat("0", 17-len(tag)) + tag
	// Выдача и строка её набора — одним оператором, как у продукта: на голове
	// выдачу без набора база отвергает на коммите (kaname#902).
	_, err := db.Exec(bindingset.With(`INSERT INTO kaname.access_bindings
	    (id, subject_type, subject_id, role_id, resource_type, resource_id, status, target)
	  VALUES ($1, 'user', $2, $3, 'account', $4, 'ACTIVE', $5::jsonb)`),
		"acb"+tag, person, role, acc, target)
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
		require.NoError(t, atfInsert(t, db, role, i, legal), "законная цель %s принимается", legal)
	}
	for i, bad := range atfOutside {
		err := atfInsert(t, db, role, 100+i, bad)
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

// atfRequireSplit — заведение и проверка разнесены: заведение несёт `NOT
// VALID` и проверки не несёт, проверка — отдельный файл позже заведения и
// ограничения не заводит.
func atfRequireSplit(t *testing.T, c atfCatalog) {
	t.Helper()
	if c.subject == 0 {
		t.Fatalf("ИСПЫТУЕМОГО НЕТ: в каталоге из %d миграций (голова %d) нет миграции, чей накат называет %s",
			len(c.versions), c.head(), atfConstraint)
	}
	if c.validator == 0 {
		t.Fatalf("ПРОВЕРКИ НЕТ: в каталоге из %d миграций нет наката с %q — проход по таблице "+
			"идёт в транзакции заведения под исключительным замком (%s)", len(c.versions), atfValidate, c.file)
	}
	require.NotEqual(t, c.file, c.validatorFile, "проверка — отдельный файл, а не та же транзакция, что заведение")
	require.Greater(t, c.validator, c.subject, "проверка накатывается после заведения")
	require.Contains(t, strings.Join(strings.Fields(c.subjectUp), " "), "NOT VALID",
		"заведение %s ложится без прохода по таблице — NOT VALID", c.file)
	require.NotContains(t, c.validatorUp, "ADD CONSTRAINT",
		"проверка %s ограничения не заводит — только проверяет лежащие строки", c.validatorFile)
}

// atfLockModes — замки, которые держит на `access_bindings` транзакция,
// исполнившая up; транзакция откатывается.
func atfLockModes(t *testing.T, db *sql.DB, up string) []string {
	t.Helper()
	tx, err := db.Begin()
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(up)
	require.NoError(t, err, "накат исполняется в транзакции пробы")
	rows, err := tx.Query(`SELECT mode FROM pg_locks
	  WHERE locktype = 'relation' AND relation = 'kaname.access_bindings'::regclass
	    AND pid = pg_backend_pid() AND granted ORDER BY mode`)
	require.NoError(t, err)
	defer rows.Close()
	var modes []string
	for rows.Next() {
		var m string
		require.NoError(t, rows.Scan(&m))
		modes = append(modes, m)
	}
	require.NoError(t, rows.Err())
	return modes
}

// atfValidated — проверено ли ограничение формы (`pg_constraint.convalidated`).
func atfValidated(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var ok bool
	require.NoError(t, db.QueryRow(`SELECT convalidated FROM pg_constraint
	  WHERE conrelid = 'kaname.access_bindings'::regclass AND conname = $1`, atfConstraint).Scan(&ok))
	return ok
}

// TestAccessBindingTargetForm_ValidationIsSplitFromTheAddition — заведение
// ограничения и проверка лежащих строк разнесены по двум миграциям.
func TestAccessBindingTargetForm_ValidationIsSplitFromTheAddition(t *testing.T) {
	c := atfReadCatalog(t)
	atfRequireSplit(t, c)
	t.Logf("заведение %s, проверка %s", c.file, c.validatorFile)
}

// TestAccessBindingTargetForm_MigrationAppliesOnLiveRows — испытуемые
// накатываются на базу с живыми строками; нарушителей до наката ноль; проверка
// держит SHARE UPDATE EXCLUSIVE, а не исключительный замок; близнец со строкой
// вне формы отвергается накатом проверки; откат и повторный накат проходят.
func TestAccessBindingTargetForm_MigrationAppliesOnLiveRows(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	c := atfReadCatalog(t)
	atfRequireSplit(t, c)

	db := serOpenAt(t, c.preceding())
	role := atfRole(t, db)
	for i, legal := range atfLegal {
		require.NoError(t, atfInsert(t, db, role, i, legal), "Дано: законная цель %s лежит до наката", legal)
	}
	total, outside := atfViolators(t, db)
	t.Logf("перепись на версии %d: строк выдач %d, из них вне формы %d", c.preceding(), total, outside)
	require.Greater(t, total, len(atfLegal), "Дано: посев цепи несёт свои выдачи сверх строк пробы")
	require.Zero(t, outside, "Дано: нарушителей до наката ноль — обратного заполнения не требуется")

	require.NoError(t, goose.UpTo(db, ".", c.subject), "накат %s на живые строки", c.file)
	require.False(t, atfValidated(t, db), "после заведения ограничение не проверено — NOT VALID")
	require.Error(t, atfInsert(t, db, role, 150, `{"resources": null}`),
		"непроверенное ограничение уже судит новые строки")

	// Замок проверки: проход по таблице — под SHARE UPDATE EXCLUSIVE, без
	// исключительного замка; чтение и запись выдач при этом идут.
	modes := atfLockModes(t, db, c.validatorUp)
	t.Logf("замки наката %s на access_bindings: %v", c.validatorFile, modes)
	require.Contains(t, modes, "ShareUpdateExclusiveLock", "проверка берёт SHARE UPDATE EXCLUSIVE")
	require.NotContains(t, modes, "AccessExclusiveLock", "проверка не берёт исключительного замка")

	require.NoError(t, goose.UpTo(db, ".", c.validator), "накат %s на живые строки", c.validatorFile)
	require.True(t, atfValidated(t, db), "после проверки ограничение проверено")
	after, _ := atfViolators(t, db)
	require.Equal(t, total, after, "накат не трогает ни одной строки")

	require.NoError(t, goose.DownTo(db, ".", c.subject), "откат %s", c.validatorFile)
	require.False(t, atfValidated(t, db), "откат проверки возвращает непроверенное ограничение")
	require.NoError(t, goose.DownTo(db, ".", c.preceding()), "откат %s", c.file)
	require.NoError(t, atfInsert(t, db, role, 200, `{"resources": null}`), "после отката ограничения нет")
	_, err := db.Exec(`DELETE FROM kaname.access_bindings WHERE id = 'acbatf8830'`)
	require.NoError(t, err)
	require.NoError(t, goose.UpTo(db, ".", c.validator), "повторный накат")
	require.True(t, atfValidated(t, db), "повторный накат проверяет ограничение")

	// Близнец: та же цепь, одна строка вне формы — заведение ложится, накат
	// проверки отказывает.
	twin := serOpenAt(t, c.preceding())
	require.NoError(t, atfInsert(t, twin, atfRole(t, twin), 300, `{"resources": null}`))
	require.NoError(t, goose.UpTo(twin, ".", c.subject), "близнец: заведение NOT VALID лежащих строк не читает")
	err = goose.UpTo(twin, ".", c.validator)
	require.Error(t, err, "близнец: строка вне формы останавливает накат проверки")
	require.Contains(t, err.Error(), atfConstraint, "близнец: отказ называет ограничение формы")
}
