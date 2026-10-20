// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// access_binding_pair_in_set_integration_test.go — ПАРА ВЫДАЧИ — ОДНА ИЗ СТРОК
// ЕЁ НАБОРА СУБЪЕКТОВ, И ДЕРЖИТ ЭТО БАЗА (задача kaname#907, преемник kaname#902).
//
// # Что судится
//
// У выдачи две проекции субъектов: пара строки `access_bindings`
// (`subject_type`, `subject_id`) и набор `access_binding_subjects`. Чтения по
// субъекту спрашивают обе (`bindingNamesSubject`), и пара, которой нет в
// наборе, показывает выдачу субъекту, у которого права по ней нет: вердикт
// берёт субъектов только из набора. До испытуемого связь пары с набором держал
// только писатель (`domain.NormalizeSubjects` сверяет пару с `subjects[0]`), а
// база судила лишь «у выдачи есть строка набора» (kaname#902).
//
// Пробы, каждая — в обход писателя, сырым оператором:
//
//  1. ВСТАВКА выдачи, чья пара не входит в набор, отказывает НА КОММИТЕ по
//     имени ограничения; близнец — та же выдача, пара входит в набор, —
//     фиксируется.
//  2. СНЯТИЕ строки пары из набора живой выдачи отказывает; снятие другой
//     строки — близнец — проходит.
//  3. СМЕНА ПАРЫ на субъекта вне набора отказывает; смена на субъекта набора —
//     близнец — проходит.
//  4. КОНКУРИРУЮЩИЕ ТРАНЗАКЦИИ: одна переводит пару на второго субъекта набора,
//     другая снимает строку этого субъекта; обе операторы исполнены до
//     коммитов, коммиты идут одновременно. Фиксируется ровно одна, вторая
//     отказывает ограничением, взаимной блокировки нет, и пара остаётся в
//     наборе. Без испытуемого обе фиксируются и пара уходит из набора.
//  5. НАКАТ на лежащие строки: перепись выдач, чья пара вне набора, на цепи
//     посева — ноль (печатается числом); близнец — база с такой выдачей: накат
//     отказывает и проверки не заводит.
//  6. ЦЕНА на пути записи: вставка выдачи с набором до и после испытуемого —
//     замер печатается, порог не судится.
//
// # Испытуемый ищется по содержанию
//
// Первая по возрастанию версий миграция, чей накат заводит
// ограничение-триггер `access_bindings_pair_change_carries_a_subject`.
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

// apsCreate — оператор заведения, по которому опознаётся испытуемый.
const apsCreate = "CREATE CONSTRAINT TRIGGER access_bindings_pair_change_carries_a_subject"

// apsWaitBudget — предел ожидания коммитов конкурирующих сторон.
const apsWaitBudget = 20 * time.Second

// apsCostRows — выдач на сторону замера цены.
const apsCostRows = 200

func apsReadCatalog(t *testing.T) absCatalog {
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
		if strings.Contains(up, apsCreate) && (c.subject == 0 || v < c.subject) {
			c.subject, c.file = v, name
		}
	}
	require.NotEmpty(t, c.versions, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): каталог миграций пуст — судить нечего")
	return c
}

// apsRequireSubject — испытуемый обязан существовать: без него пробы ниже
// судили бы голову, на которой проверки нет, и падали бы не на предмете.
func apsRequireSubject(t *testing.T, c absCatalog) {
	t.Helper()
	if c.subject == 0 {
		t.Fatalf("ИСПЫТУЕМОГО НЕТ: в каталоге из %d миграций (голова %d) нет миграции, чей накат несёт %q — "+
			"связь пары выдачи с набором держит только писатель", len(c.versions), c.head(), apsCreate)
	}
}

// apsSetPair — сменить пару выдачи на субъекта-личность `person`.
func apsSetPair(ctx context.Context, ex absExecer, binding, person string) error {
	_, err := ex.ExecContext(ctx, `UPDATE kaname.access_bindings
	    SET subject_type = 'user', subject_id = $2 WHERE id = $1`, binding, person)
	return err
}

// apsDropRow — снять строку набора выдачи по личности.
func apsDropRow(ctx context.Context, ex absExecer, binding, person string) error {
	_, err := ex.ExecContext(ctx, `DELETE FROM kaname.access_binding_subjects
	    WHERE binding_id = $1 AND subject_type = 'user' AND subject_id = $2`, binding, person)
	return err
}

// apsPairInSet — входит ли пара выдачи в её набор.
func apsPairInSet(t *testing.T, db *sql.DB, binding string) bool {
	t.Helper()
	var in bool
	require.NoError(t, db.QueryRow(`SELECT EXISTS (
	    SELECT 1 FROM kaname.access_bindings b
	      JOIN kaname.access_binding_subjects s
	        ON s.binding_id = b.id AND s.subject_type = b.subject_type AND s.subject_id = b.subject_id
	     WHERE b.id = $1)`, binding).Scan(&in))
	return in
}

// apsLying — перепись выдач, чья пара вне набора: то же предложение, что у наката.
func apsLying(t *testing.T, db *sql.DB) (total, lying int) {
	t.Helper()
	require.NoError(t, db.QueryRow(`
	  SELECT count(*),
	         count(*) FILTER (WHERE NOT EXISTS (
	             SELECT 1 FROM kaname.access_binding_subjects s
	              WHERE s.binding_id = b.id AND s.subject_type = b.subject_type AND s.subject_id = b.subject_id))
	    FROM kaname.access_bindings b`).Scan(&total, &lying))
	return total, lying
}

// TestAccessBindingPairInSet_InsertWithAForeignPairIsRefusedAtCommit — проба 1.
func TestAccessBindingPairInSet_InsertWithAForeignPairIsRefusedAtCommit(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	c := apsReadCatalog(t)
	db := serOpenAt(t, c.head())

	other := serSeedPerson(t, db, "aps9070")

	// Близнец: пара входит в набор вместе со вторым субъектом — фиксируется.
	twin := absSeed(t, db, "aps9071")
	absWithSet(t, db, twin, other)
	require.True(t, apsPairInSet(t, db, twin.id), "близнец: пара в наборе")

	// Предмет: набор из одного чужого субъекта, пара в него не входит.
	b := absSeed(t, db, "aps9072")
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	require.NoError(t, absInsertBinding(ctx, tx, b), "оператор вставки выдачи проходит: проверка — на коммите")
	require.NoError(t, absInsertSubject(ctx, tx, b.id, other, 0), "строка набора — не субъект пары")
	err = tx.Commit()
	if err == nil {
		t.Fatalf("база на версии %d ЗАФИКСИРОВАЛА выдачу %s, чья пара не входит в её набор — "+
			"связь держит только писатель", c.head(), b.id)
	}
	absRequireRefusal(t, err, "коммит выдачи с парой вне набора")
	require.Contains(t, err.Error(), "subject pair", "отказ называет пару, а не пустой набор: %v", err)
	require.Equal(t, 0, absBindingRows(t, db, b.id), "отказанная выдача не осталась в таблице")
}

// TestAccessBindingPairInSet_PairRowIsNotRemoved — проба 2.
func TestAccessBindingPairInSet_PairRowIsNotRemoved(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	c := apsReadCatalog(t)
	db := serOpenAt(t, c.head())

	b := absSeed(t, db, "aps9073")
	second := serSeedPerson(t, db, "aps9074")
	third := serSeedPerson(t, db, "aps9075")
	absWithSet(t, db, b, second, third)

	// Близнец: снятие строки, не являющейся парой, проходит.
	require.NoError(t, apsDropRow(ctx, db, b.id, third), "снятие строки вне пары проходит")
	require.Equal(t, 2, absSetRows(t, db, b.id))

	// Предмет: строка пары при живой выдаче и непустом остатке набора.
	err := apsDropRow(ctx, db, b.id, b.person)
	if err == nil {
		t.Fatalf("база на версии %d сняла строку пары выдачи %s — пара осталась вне набора", c.head(), b.id)
	}
	absRequireRefusal(t, err, "снятие строки пары")
	require.True(t, apsPairInSet(t, db, b.id), "пара на месте в наборе")
}

// TestAccessBindingPairInSet_PairMovesOnlyInsideTheSet — проба 3.
func TestAccessBindingPairInSet_PairMovesOnlyInsideTheSet(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	c := apsReadCatalog(t)
	db := serOpenAt(t, c.head())

	b := absSeed(t, db, "aps9076")
	second := serSeedPerson(t, db, "aps9077")
	outsider := serSeedPerson(t, db, "aps9078")
	absWithSet(t, db, b, second)

	// Близнец: пара переходит на второго субъекта набора.
	require.NoError(t, apsSetPair(ctx, db, b.id, second), "смена пары внутри набора проходит")
	require.True(t, apsPairInSet(t, db, b.id))

	// Предмет: пара на субъекта вне набора.
	err := apsSetPair(ctx, db, b.id, outsider)
	if err == nil {
		t.Fatalf("база на версии %d перевела пару выдачи %s на субъекта вне набора", c.head(), b.id)
	}
	absRequireRefusal(t, err, "смена пары на субъекта вне набора")
	require.True(t, apsPairInSet(t, db, b.id), "пара осталась в наборе")
}

// TestAccessBindingPairInSet_ConcurrentPairMoveAndRowRemovalKeepThePairInTheSet — проба 4.
func TestAccessBindingPairInSet_ConcurrentPairMoveAndRowRemovalKeepThePairInTheSet(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	c := apsReadCatalog(t)
	db := serOpenAt(t, c.head())

	b := absSeed(t, db, "aps9079")
	second := serSeedPerson(t, db, "aps9080")
	absWithSet(t, db, b, second)

	mover, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = mover.Rollback() })
	remover, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = remover.Rollback() })

	// Оба оператора исполнены до коммитов: каждая сторона видит набор и пару
	// такими, какими они были до соседки.
	require.NoError(t, apsSetPair(ctx, mover, b.id, second), "сторона пары переводит пару на второго субъекта")
	require.NoError(t, apsDropRow(ctx, remover, b.id, second), "сторона набора снимает строку второго субъекта")

	results := make(chan error, 2)
	for _, tx := range []*sql.Tx{mover, remover} {
		go func(tx *sql.Tx) { results <- tx.Commit() }(tx)
	}
	committed, refused := 0, 0
	for i := 0; i < 2; i++ {
		select {
		case err := <-results:
			if err == nil {
				committed++
				continue
			}
			require.NotEqualf(t, "40P01", a458SQLState(err),
				"конкурирующие стороны разошлись взаимной блокировкой, а не ограничением: %v", err)
			absRequireRefusal(t, err, "коммит конкурирующей стороны")
			refused++
		case <-time.After(apsWaitBudget):
			t.Fatalf("коммиты сторон не вернулись за %s", apsWaitBudget)
		}
	}
	if !apsPairInSet(t, db, b.id) {
		t.Fatalf("база на версии %d зафиксировала обе конкурирующие транзакции (зафиксировано %d, отказано %d): "+
			"пара выдачи %s ушла из набора", c.head(), committed, refused, b.id)
	}
	require.Equal(t, 1, committed, "фиксируется ровно одна сторона")
	require.Equal(t, 1, refused, "вторая сторона отказывает ограничением")
}

// TestAccessBindingPairInSet_MigrationJudgesLyingRows — проба 5.
func TestAccessBindingPairInSet_MigrationJudgesLyingRows(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	c := apsReadCatalog(t)
	apsRequireSubject(t, c)

	// Цепь посева: выдач с парой вне набора — ноль, накат проходит.
	db := serOpenAt(t, c.preceding())
	total, lying := apsLying(t, db)
	t.Logf("перепись на версии %d (до %s): выдач %d, с парой вне набора %d", c.preceding(), c.file, total, lying)
	require.Positive(t, total, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): посев цепи несёт выдачи — судить есть что")
	require.Zero(t, lying, "посев цепи не несёт выдач с парой вне набора")
	require.NoError(t, goose.UpTo(db, ".", c.subject), "накат %s на строках посева", c.file)

	// Близнец: база с выдачей, чья пара вне набора, — накат отказывает.
	db2 := serOpenAt(t, c.preceding())
	b := absSeed(t, db2, "aps9081")
	other := serSeedPerson(t, db2, "aps9082")
	tx, err := db2.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	require.NoError(t, absInsertBinding(ctx, tx, b))
	require.NoError(t, absInsertSubject(ctx, tx, b.id, other, 0))
	require.NoError(t, tx.Commit(), "Дано: до испытуемого выдача с парой вне набора фиксируется")

	err = goose.UpTo(db2, ".", c.subject)
	require.Error(t, err, "накат на базе с выдачей, чья пара вне набора, отказывает")
	require.Contains(t, err.Error(), absConstraint, "отказ наката называет ограничение")
	got, err := goose.GetDBVersion(db2)
	require.NoError(t, err)
	require.Equal(t, c.preceding(), got, "версия не сдвинулась: проверка не заведена")

	// Строка снята — накат проходит; откат возвращает прежнюю проверку; повтор проходит.
	_, err = db2.Exec(`DELETE FROM kaname.access_bindings WHERE id = $1`, b.id)
	require.NoError(t, err)
	require.NoError(t, goose.UpTo(db2, ".", c.subject), "накат после снятия строки")
	require.NoError(t, goose.DownTo(db2, ".", c.preceding()), "откат испытуемого")
	tx2, err := db2.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx2.Rollback() }()
	require.NoError(t, absInsertBinding(ctx, tx2, b))
	require.NoError(t, absInsertSubject(ctx, tx2, b.id, other, 0))
	require.NoError(t, tx2.Commit(), "после отката прежняя проверка судит лишь непустоту набора")
	_, err = db2.Exec(`DELETE FROM kaname.access_bindings WHERE id = $1`, b.id)
	require.NoError(t, err)
	require.NoError(t, goose.UpTo(db2, ".", c.subject), "повторный накат")
}

// TestAccessBindingPairInSet_WritePathCostIsMeasured — проба 6: цена на пути
// записи. Две базы одного сервера: голова (с испытуемым) и версия до него, на
// каждой — одни и те же вставки выдачи с набором, по транзакции на выдачу.
// Порог не судится: замер печатается и идёт в основание выбора формы.
func TestAccessBindingPairInSet_WritePathCostIsMeasured(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	c := apsReadCatalog(t)
	apsRequireSubject(t, c)

	measure := func(version int64) time.Duration {
		db := serOpenAt(t, version)
		people := make([]absBinding, apsCostRows)
		for i := range people {
			people[i] = absSeed(t, db, "apc"+strconv.Itoa(i))
		}
		start := time.Now()
		for _, b := range people {
			absWithSet(t, db, b)
		}
		return time.Since(start)
	}
	withPair := measure(c.head())
	withoutPair := measure(c.preceding())
	t.Logf("цена записи выдачи с набором, %d вставок по транзакции: версия %d (с проверкой пары) %s — "+
		"%.3f мс на выдачу; версия %d (до испытуемого) %s — %.3f мс на выдачу", apsCostRows,
		c.head(), withPair, float64(withPair.Microseconds())/1000/apsCostRows,
		c.preceding(), withoutPair, float64(withoutPair.Microseconds())/1000/apsCostRows)
}
