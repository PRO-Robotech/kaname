// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package bindingset — посев фикстур под инвариант «у выдачи есть хотя бы одна
// строка набора субъектов» (задача PRO-Robotech/kaname#902).
//
// Отложенная проверка `access_bindings_carry_a_subject` отвергает фиксацию
// транзакции, оставившей выдачу без строк `access_binding_subjects`. Фикстура
// не снисходительнее продукта: она заводит то, что заводит продукт, — набор
// той же транзакцией, что строку выдачи. Набор фикстуры — одна строка из пары
// выдачи (`subject_type`, `subject_id`), порядковый номер 0: так пишет каждый
// путь записи продукта для выдачи с одним субъектом (`domain.NormalizeSubjects`
// сводит одиночную пару к набору из одного элемента).
//
// # Почему отдельный пакет
//
// Посев зовут пробы многих пакетов, а `*_test.go` другого пакета импортировать
// нельзя; копия в каждом пакете — вторая редакция одного предмета. Образец —
// `internal/testsupport/activewayin` (тот же класс: отложенная проверка базы и
// фикстуры, писавшие строку без её спутника).
//
// Пакет импортируют только пробы: прод-сборка его не видит.
//
// # Три формы
//
//   - [With] оборачивает ОДИН оператор вставки выдач, исполняемый вне явной
//     транзакции: набор ложится тем же оператором.
//   - [Seed] пишет набор выдачам, которые завела открытая транзакция pgx, перед
//     её фиксацией.
//   - [Insert] — вставка выдачи портом писателя репозитория и запись её набора
//     тем же писателем, как у сценариев службы.
package bindingset

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// SeedSQL — строка набора каждой выдаче, которую ЭТА транзакция завела либо
// изменила и у которой строк набора нет. Выдача узнаётся по `xmin` строки — то
// есть по самой транзакции, — поэтому фикстуре не нужно перечислять
// идентификаторы.
const SeedSQL = `
	INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id, ordinal)
	SELECT b.id, b.subject_type, b.subject_id, 0
	  FROM kaname.access_bindings b
	 WHERE b.xmin = pg_current_xact_id()::xid
	   AND NOT EXISTS (SELECT 1 FROM kaname.access_binding_subjects s WHERE s.binding_id = b.id)`

// Execer — исполнитель оператора открытой транзакции pgx.
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// With оборачивает ОДИН оператор вставки строк выдач так, что строка набора
// каждой вставленной выдачи ложится тем же оператором:
// `WITH bound AS (<вставка> RETURNING …) INSERT INTO <набор> SELECT … FROM bound`.
//
// Область строки набора (`resource_type`, `resource_id`) берётся из
// `RETURNING`, а не триггером заполнения: соседняя часть оператора `WITH` строку
// выдачи ещё не видит, а внешний ключ набора судится в конце оператора, когда
// видна уже обе строки.
func With(insertBindings string) string {
	return "WITH bound AS (" + strings.TrimSpace(insertBindings) +
		" RETURNING id, subject_type, subject_id, resource_type, resource_id) " +
		"INSERT INTO kaname.access_binding_subjects " +
		"(binding_id, subject_type, subject_id, ordinal, resource_type, resource_id) " +
		"SELECT id, subject_type, subject_id, 0, resource_type, resource_id FROM bound"
}

// Seed заводит строки набора выдачам транзакции перед её фиксацией.
func Seed(t testing.TB, ctx context.Context, tx Execer) {
	t.Helper()
	_, err := tx.Exec(ctx, SeedSQL)
	require.NoError(t, err, "посев строки набора субъектов выдач фикстуры (kaname#902)")
}

// Writer — порт записи выдачи и её набора (подмножество
// `access_binding.WriterIface`).
type Writer interface {
	Insert(ctx context.Context, b domain.AccessBinding) (domain.AccessBinding, error)
	InsertSubjects(ctx context.Context, bindingID domain.AccessBindingID, subjects []domain.Subject) error
}

// Insert вставляет выдачу и пишет её набор тем же писателем, то есть в той же
// транзакции. Набор — `b.Subjects`, а без него — одна строка из пары
// вставленной выдачи. Отказ вставки возвращается как есть: набор после
// отказанной вставки не пишется.
func Insert(ctx context.Context, w Writer, b domain.AccessBinding) (domain.AccessBinding, error) {
	out, err := w.Insert(ctx, b)
	if err != nil {
		return out, err
	}
	subjects := b.Subjects
	if len(subjects) == 0 {
		subjects = []domain.Subject{{Type: out.SubjectType, ID: out.SubjectID}}
	}
	return out, w.InsertSubjects(ctx, out.ID, subjects)
}
