// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// access_binding_subject_set_integration_test.go — У ВЫДАЧИ ЕСТЬ ХОТЯ БЫ ОДНА
// СТРОКА НАБОРА СУБЪЕКТОВ, И ДЕРЖИТ ЭТО БАЗА (задача kaname#902).
//
// # Что судится
//
// Решение о доступе и чтения видимости берут субъектов выдачи только из
// `access_binding_subjects`. Выдача без строк набора невидима вердикту: право
// записано и не действует. До испытуемого такую выдачу не запрещало ничего,
// кроме девяти путей записи.
//
// Пробы, и порядок в каждой несущий:
//
//  1. ВСТАВКА выдачи без набора отказывает НА КОММИТЕ (оператор вставки
//     проходит: набор пишется вторым оператором), по имени ограничения,
//     SQLSTATE 23000; законный близнец — выдача с набором той же формы —
//     фиксируется. До испытуемого проба красная: база фиксирует выдачу без
//     набора.
//  2. СНЯТИЕ последней строки набора живой выдачи отказывает; снятие одной из
//     двух — близнец — проходит.
//  3. КОНКУРИРУЮЩИЕ СНЯТИЯ: две транзакции снимают разные строки набора из
//     двух, коммитятся одновременно. Фиксируется ровно одна, вторая отказывает
//     ограничением; у выдачи остаётся одна строка. Одновременность создаёт
//     держатель строки выдачи: обе проверки обязаны встать за ним (это
//     утверждается) и проходят после его отката. Без замка в проверке стороны
//     не ждут держателя, и исход решает порядок коммитов — проба краснеет на
//     этом, а не на случайном исходе гонки.
//  4. СНЯТИЕ ВЫДАЧИ ЦЕЛИКОМ (каскад внешнего ключа на набор) фиксируется.
//  5. НАКАТ на лежащие строки: перепись выдач без набора на цепи посева — ноль
//     (печатается числом), накат проходит. Близнец — база с одной выдачей без
//     набора: накат отказывает тем же ограничением и проверки не заводит;
//     после снятия строки накат проходит, откат снимает проверку, повторный
//     накат проходит.
//
// # Испытуемый ищется по содержанию
//
// Первая по возрастанию версий миграция, чей накат заводит ограничение-триггер
// `access_bindings_carry_a_subject`.
package migrations_test

import (
	"context"
	"database/sql"
	"io/fs"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// absConstraint — имя ограничения-триггера, дословно.
const absConstraint = "access_bindings_carry_a_subject"

// absCreate — оператор заведения, по которому опознаётся испытуемый.
const absCreate = "CREATE CONSTRAINT TRIGGER " + absConstraint

// absWaitBudget — предел ожидания, пока обе проверки встанут за держателем.
const absWaitBudget = 20 * time.Second

type absCatalog struct {
	versions []int64
	subject  int64
	file     string
}

func (c absCatalog) head() int64 {
	var best int64
	for _, v := range c.versions {
		if v > best {
			best = v
		}
	}
	return best
}

func (c absCatalog) preceding() int64 {
	var best int64
	for _, v := range c.versions {
		if (c.subject == 0 || v < c.subject) && v > best {
			best = v
		}
	}
	return best
}

func absReadCatalog(t *testing.T) absCatalog {
	t.Helper()
	entries, err := fs.ReadDir(migrations.FS, ".")
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): каталог миграций читается")
	var c absCatalog
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
		up := strings.Join(strings.Fields(migrations.MigrationUpSection(string(body))), " ")
		if strings.Contains(up, absCreate) && (c.subject == 0 || v < c.subject) {
			c.subject, c.file = v, name
		}
	}
	require.NotEmpty(t, c.versions, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): каталог миграций пуст — судить нечего")
	return c
}

// absBinding — живая выдача владельца на аккаунт личности `tag`, без набора.
// Субъект и область — живые строки: стражи ссылок выдачи судят обе на вставке.
type absBinding struct {
	id     string
	person string
}

// absSeed — личность (с аккаунтом) и роль владельца; строки выдачи не пишет.
func absSeed(t *testing.T, db *sql.DB, tag string) absBinding {
	t.Helper()
	person := serSeedPerson(t, db, tag)
	return absBinding{id: "acb" + strings.Repeat("0", 17-len(tag)) + tag, person: person}
}

// absExecer — исполнитель оператора: база либо открытая транзакция.
type absExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

// absInsertBinding — оператор вставки выдачи на исполнителе `ex`.
func absInsertBinding(ctx context.Context, ex absExecer, b absBinding) error {
	_, err := ex.ExecContext(ctx, `INSERT INTO kaname.access_bindings
	    (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
	  SELECT $1, 'user', u.id, 'rol' || substr(md5('owner'), 1, 17), 'account', u.account_id, 'ACTIVE'
	    FROM kaname.users u WHERE u.id = $2`, b.id, b.person)
	return err
}

// absInsertSubject — строка набора выдачи.
func absInsertSubject(ctx context.Context, ex absExecer, binding, person string, ordinal int) error {
	_, err := ex.ExecContext(ctx, `INSERT INTO kaname.access_binding_subjects
	    (binding_id, subject_type, subject_id, ordinal) VALUES ($1, 'user', $2, $3)`, binding, person, ordinal)
	return err
}

// absWithSet — выдача и её набор одной транзакцией (форма продукта); `extra` —
// личности сверх субъекта пары, по строке набора на каждую.
func absWithSet(t *testing.T, db *sql.DB, b absBinding, extra ...string) {
	t.Helper()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	require.NoError(t, absInsertBinding(ctx, tx, b), "Дано: выдача %s", b.id)
	require.NoError(t, absInsertSubject(ctx, tx, b.id, b.person, 0), "Дано: строка набора %s", b.person)
	for i, p := range extra {
		require.NoError(t, absInsertSubject(ctx, tx, b.id, p, i+1), "Дано: строка набора %s", p)
	}
	require.NoError(t, tx.Commit(), "Дано: выдача с набором фиксируется")
}

func absSetRows(t *testing.T, db *sql.DB, binding string) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.access_binding_subjects WHERE binding_id = $1`, binding).Scan(&n))
	return n
}

func absBindingRows(t *testing.T, db *sql.DB, binding string) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.access_bindings WHERE id = $1`, binding).Scan(&n))
	return n
}

// absBare — перепись выдач без строк набора: то же предложение, что у наката.
func absBare(t *testing.T, db *sql.DB) (total, bare int) {
	t.Helper()
	require.NoError(t, db.QueryRow(`
	  SELECT count(*),
	         count(*) FILTER (WHERE NOT EXISTS (
	             SELECT 1 FROM kaname.access_binding_subjects s WHERE s.binding_id = b.id))
	    FROM kaname.access_bindings b`).Scan(&total, &bare))
	return total, bare
}

// absRequireRefusal — отказ ограничением-триггером, SQLSTATE 23000.
func absRequireRefusal(t *testing.T, err error, what string) {
	t.Helper()
	require.Error(t, err, "%s: ожидается отказ %s", what, absConstraint)
	require.Equal(t, absConstraint, serConstraintOf(err), "%s: отказ даёт ограничение набора: %v", what, err)
	require.Equal(t, "23000", a458SQLState(err), "%s: SQLSTATE 23000: %v", what, err)
}

// TestAccessBindingSubjectSet_BindingWithoutSetIsRefusedAtCommit — проба 1.
func TestAccessBindingSubjectSet_BindingWithoutSetIsRefusedAtCommit(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	c := absReadCatalog(t)
	db := serOpenAt(t, c.head())

	// Близнец: та же выдача той же формы, но с набором — фиксируется.
	twin := absSeed(t, db, "abs9020")
	absWithSet(t, db, twin)
	require.Equal(t, 1, absSetRows(t, db, twin.id), "близнец: строка набора на месте")

	// Предмет: выдача без набора. Оператор вставки проходит — проверка отложена.
	bare := absSeed(t, db, "abs9021")
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	require.NoError(t, absInsertBinding(ctx, tx, bare),
		"оператор вставки выдачи проходит: набор пишется вторым оператором, проверка — на коммите")
	err = tx.Commit()
	if err == nil {
		t.Fatalf("база на версии %d ЗАФИКСИРОВАЛА выдачу %s без строк набора — инвариант держит только писатель",
			c.head(), bare.id)
	}
	absRequireRefusal(t, err, "коммит выдачи без набора")
	require.Equal(t, 0, absBindingRows(t, db, bare.id), "отказанная выдача не осталась в таблице")
}

// TestAccessBindingSubjectSet_LastSetRowIsNotRemoved — проба 2.
func TestAccessBindingSubjectSet_LastSetRowIsNotRemoved(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	c := absReadCatalog(t)
	db := serOpenAt(t, c.head())

	b := absSeed(t, db, "abs9022")
	second := serSeedPerson(t, db, "abs9023")
	absWithSet(t, db, b, second)

	// Близнец: одна из двух строк снимается.
	_, err := db.Exec(`DELETE FROM kaname.access_binding_subjects WHERE binding_id = $1 AND subject_id = $2`, b.id, second)
	require.NoError(t, err, "снятие одной строки из двух проходит")
	require.Equal(t, 1, absSetRows(t, db, b.id))

	// Предмет: последняя строка живой выдачи.
	_, err = db.Exec(`DELETE FROM kaname.access_binding_subjects WHERE binding_id = $1`, b.id)
	if err == nil {
		t.Fatalf("база на версии %d сняла последнюю строку набора выдачи %s — выдача осталась без субъектов",
			c.head(), b.id)
	}
	absRequireRefusal(t, err, "снятие последней строки набора")
	require.Equal(t, 1, absSetRows(t, db, b.id), "строка набора на месте")
}

// TestAccessBindingSubjectSet_ConcurrentRemovalsLeaveOneRow — проба 3.
func TestAccessBindingSubjectSet_ConcurrentRemovalsLeaveOneRow(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	c := absReadCatalog(t)
	db := serOpenAt(t, c.head())

	b := absSeed(t, db, "abs9024")
	second := serSeedPerson(t, db, "abs9025")
	absWithSet(t, db, b, second)

	// Держатель строки выдачи: проверки обеих сторон встают за ним.
	holder, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = holder.Rollback() }()
	_, err = holder.ExecContext(ctx, `SELECT 1 FROM kaname.access_bindings WHERE id = $1 FOR SHARE`, b.id)
	require.NoError(t, err, "Дано: держатель строки выдачи")

	sides := make([]*sql.Tx, 2)
	for i, subject := range []string{b.person, second} {
		tx, err := db.BeginTx(ctx, nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = tx.Rollback() })
		_, err = tx.ExecContext(ctx, `DELETE FROM kaname.access_binding_subjects WHERE binding_id = $1 AND subject_id = $2`, b.id, subject)
		require.NoError(t, err, "сторона %d снимает свою строку набора", i)
		sides[i] = tx
	}

	results := make(chan error, 2)
	for _, tx := range sides {
		go func(tx *sql.Tx) { results <- tx.Commit() }(tx)
	}

	// Обе проверки обязаны встать за держателем. Если коммиты вернулись раньше —
	// проверки нет либо она без замка; исход судится ниже по строкам набора.
	var got []error
	bothWaited := false
	deadline := time.Now().Add(absWaitBudget)
	for len(got) < 2 && time.Now().Before(deadline) {
		select {
		case err := <-results:
			got = append(got, err)
			continue
		default:
		}
		if absLockWaiters(t, db) >= 2 {
			bothWaited = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	returnedBeforeRelease := len(got)
	require.NoError(t, holder.Rollback(), "держатель отпускает строку выдачи")
	for len(got) < 2 {
		select {
		case err := <-results:
			got = append(got, err)
		case <-time.After(absWaitBudget):
			t.Fatalf("коммиты сторон не вернулись за %s после отпускания держателя", absWaitBudget)
		}
	}

	committed, refused := 0, 0
	for _, err := range got {
		if err == nil {
			committed++
			continue
		}
		absRequireRefusal(t, err, "коммит конкурирующего снятия")
		refused++
	}
	rows := absSetRows(t, db, b.id)
	if rows == 0 {
		t.Fatalf("база на версии %d зафиксировала обе конкурирующие транзакции (зафиксировано %d, отказано %d): "+
			"у выдачи %s не осталось ни одной строки набора", c.head(), committed, refused, b.id)
	}
	// Исход держится не совпадением порядка коммитов: обе проверки обязаны были
	// встать за держателем строки выдачи. Без замка в проверке стороны
	// фиксируются, не дожидаясь, и исход решает, чья проверка успела раньше
	// коммита соседки.
	require.True(t, bothWaited,
		"проверки сторон не встали за держателем строки выдачи %s: до его отпускания вернулось коммитов %d из 2 "+
			"— проверка набора не берёт замок строки выдачи, и исход гонки решает порядок, а не база",
		b.id, returnedBeforeRelease)
	require.Equal(t, 1, committed, "фиксируется ровно одна сторона")
	require.Equal(t, 1, refused, "вторая сторона отказывает ограничением набора")
	require.Equal(t, 1, rows, "у выдачи остаётся одна строка набора")
}

// absLockWaiters — сеансов этой базы, ждущих замок.
func absLockWaiters(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM pg_stat_activity
	  WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&n))
	return n
}

// TestAccessBindingSubjectSet_RemovingTheBindingCascades — проба 4.
func TestAccessBindingSubjectSet_RemovingTheBindingCascades(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	c := absReadCatalog(t)
	db := serOpenAt(t, c.head())

	b := absSeed(t, db, "abs9026")
	second := serSeedPerson(t, db, "abs9027")
	absWithSet(t, db, b, second)

	// Снятие выдачи оператором: набор уходит каскадом.
	_, err := db.Exec(`DELETE FROM kaname.access_bindings WHERE id = $1`, b.id)
	require.NoError(t, err, "снятие выдачи целиком фиксируется")
	require.Equal(t, 0, absSetRows(t, db, b.id), "набор снят каскадом")

	// Та же транзакция снимает строку набора и затем выдачу.
	b2 := absSeed(t, db, "abs9028")
	absWithSet(t, db, b2)
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(ctx, `DELETE FROM kaname.access_binding_subjects WHERE binding_id = $1`, b2.id)
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, `DELETE FROM kaname.access_bindings WHERE id = $1`, b2.id)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(), "снятие набора и выдачи одной транзакцией фиксируется")
	require.Equal(t, 0, absBindingRows(t, db, b2.id))
}

// TestAccessBindingSubjectSet_MigrationJudgesLyingRows — проба 5.
func TestAccessBindingSubjectSet_MigrationJudgesLyingRows(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	c := absReadCatalog(t)
	if c.subject == 0 {
		t.Fatalf("ИСПЫТУЕМОГО НЕТ: в каталоге из %d миграций (голова %d) нет миграции, чей накат несёт %q",
			len(c.versions), c.head(), absCreate)
	}

	// Цепь посева: выдач без набора — ноль, накат проходит.
	db := serOpenAt(t, c.preceding())
	total, bare := absBare(t, db)
	t.Logf("перепись на версии %d (до %s): выдач %d, без строк набора %d", c.preceding(), c.file, total, bare)
	require.Positive(t, total, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): посев цепи несёт выдачи — судить есть что")
	require.Zero(t, bare, "посев цепи не несёт выдач без набора")
	require.NoError(t, goose.UpTo(db, ".", c.subject), "накат %s на строках посева", c.file)

	// Близнец: база с выдачей без набора — накат отказывает и проверки не заводит.
	db2 := serOpenAt(t, c.preceding())
	b := absSeed(t, db2, "abs9029")
	require.NoError(t, absInsertBinding(context.Background(), db2, b), "Дано: выдача без набора на версии до испытуемого")
	err := goose.UpTo(db2, ".", c.subject)
	require.Error(t, err, "накат на базе с выдачей без набора отказывает")
	require.Contains(t, err.Error(), absConstraint, "отказ наката называет ограничение")
	got, err := goose.GetDBVersion(db2)
	require.NoError(t, err)
	require.Equal(t, c.preceding(), got, "версия не сдвинулась: проверка не заведена")

	// Строка снята — накат проходит; откат снимает проверку; повторный накат проходит.
	_, err = db2.Exec(`DELETE FROM kaname.access_bindings WHERE id = $1`, b.id)
	require.NoError(t, err)
	require.NoError(t, goose.UpTo(db2, ".", c.subject), "накат после снятия строки")
	require.NoError(t, goose.DownTo(db2, ".", c.preceding()), "откат испытуемого")
	require.NoError(t, absInsertBinding(context.Background(), db2, b), "после отката выдача без набора снова фиксируется")
	_, err = db2.Exec(`DELETE FROM kaname.access_bindings WHERE id = $1`, b.id)
	require.NoError(t, err)
	require.NoError(t, goose.UpTo(db2, ".", c.subject), "повторный накат")
}
