// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// pgmaperr_binding_subject_set_test.go — отказ проверки «у выдачи есть строка
// набора субъектов» (`access_bindings_carry_a_subject`, kaname#902) есть дефект
// писателя, а не состояние ресурса.
//
// ПРЕДМЕТ. Запрос без субъектов отвергается до записи (`domain.NormalizeSubjects`),
// и каждый путь записи выдачи пишет набор в той же транзакции. Сработавшая
// проверка значит «служба записала выдачу без набора» — вызывающему исправить
// нечего. Общая ветвь класса 23000 отдала бы FAILED_PRECONDITION с текстом
// «resource state does not permit this operation», то есть обвинила бы
// состояние ресурса вызывающего. Ответ — фиксированный INTERNAL; сообщение
// сервера (в нём идентификатор выдачи) наружу не идёт.
//
// Близнец — безымянный отказ того же класса: он остаётся в общей полосе
// предусловия.

import (
	stderrors "errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

func TestBindingWithoutSubjectSetIsAServiceDefect(t *testing.T) {
	raw := &pgconn.PgError{
		Code:           "23000",
		ConstraintName: "access_bindings_carry_a_subject",
		Message:        "access binding acb00000000000abs9021 carries no subject",
	}
	err := wrapPgErr(raw, "", "")
	require.True(t, stderrors.Is(err, iamerr.ErrInternal), "отказ проверки набора — полоса дефекта службы: %v", err)
	require.False(t, stderrors.Is(err, iamerr.ErrFailedPrecondition), "не полоса предусловия: %v", err)
	require.NotContains(t, err.Error(), "acb00000000000abs9021", "сообщение сервера наружу не идёт")

	// Близнец: безымянный отказ того же класса — общая полоса предусловия.
	twin := wrapPgErr(&pgconn.PgError{Code: "23000"}, "", "")
	require.True(t, stderrors.Is(twin, iamerr.ErrFailedPrecondition), "близнец: общая полоса: %v", twin)
}
