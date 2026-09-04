// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

// pgmaperr_selector_liveness_lane_test.go — отказ СТРАЖА ЖИВОСТИ селектора
// доезжает до арендатора, называя ЭЛЕМЕНТ и РОЛЬ (задача продукта #2011).
//
// # Предмет
//
// Триггер `role_rule_selectors_types_live` (миграция 20260902174500, тело —
// 20260903181000) поднимает `23514` и САМ составляет текст:
//
//	object_types: <элемент> is not a live platform resource (role <роль>)
//
// Обе координаты — это ровно то, чем арендатор чинит своё правило. Приведение
// класса `23514` (`checkText`) ветви на это имя не имело, поэтому обе терялись, и
// вызывающий получал «Illegal argument: value violates a constraint» — отказ, не
// восстанавливающий следующий шаг.
//
// # Почему проба УТВЕРЖДАЕТ РАВЕНСТВО, а не вхождение
//
// Вхождение зеленело бы на реализации, приклеившей к тексту триггера общий хвост
// («… : value violates a constraint»), — то есть на ровно том, от чего уходим.
//
// # Чем это НЕ является
//
// Проба не утверждает, что текст производит база: без базы это недоказуемо
// (`testing.md` §«Гейт на класс», п. 2). Производителя утверждает интеграционная
// проба-сосед; здесь предмет — ПРИВЕДЕНИЕ, и вход ему подаётся синтетический.

import (
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

func TestSelectorLivenessRefusalNamesTheElementAndTheRole(t *testing.T) {
	const produced = "object_types: applierprobe.gone is not a live platform resource " +
		"(role rol00000000000000001)"

	t.Run("текст стража доезжает дословно", func(t *testing.T) {
		err := wrapPgErr(&pgconn.PgError{
			Code:           "23514",
			ConstraintName: "role_rule_selectors_types_live",
			TableName:      "role_rule_selectors",
			Message:        produced,
		}, "", "rol00000000000000001")
		require.Error(t, err)
		require.Equal(t, produced, iamerr.StripSentinel(err),
			"арендатор не видит ни элемента, ни роли — обе координаты потеряны приведением, "+
				"и чинить правило ему нечем")
		require.ErrorIs(t, err, iamerr.ErrInvalidArg,
			"класс отказа сменился: страж живости отвергает ВВОД правила, и код это говорит")
	})

	// Вырожденный вход: производитель без текста. Отдать пустую строку значило бы
	// отказать БЕЗ СООБЩЕНИЯ; ветвь обязана назвать хотя бы поле.
	t.Run("производитель без текста: отказ всё равно называет поле", func(t *testing.T) {
		err := wrapPgErr(&pgconn.PgError{
			Code:           "23514",
			ConstraintName: "role_rule_selectors_types_live",
			TableName:      "role_rule_selectors",
		}, "", "rol00000000000000001")
		require.Error(t, err)
		got := iamerr.StripSentinel(err)
		require.NotEmpty(t, got)
		require.Contains(t, got, "object_types",
			"пустой текст производителя оставил отказ без единого слова о том, что править")
	})

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ №1: ограничение с УЖЕ ОБЪЯВЛЕННЫМ текстом своего
	// текста не теряет. Без него утверждение выше зеленело бы на реализации,
	// эхающей сообщение сервера для ВСЯКОГО `23514`, — то есть на разведке схемы.
	t.Run("контроль: разобранное ограничение отдаёт СВОЙ текст, а не серверный", func(t *testing.T) {
		err := wrapPgErr(&pgconn.PgError{
			Code:           "23514",
			ConstraintName: "users_email_check",
			TableName:      "users",
			Message:        `new row for relation "users" violates check constraint "users_email_check"`,
		}, "", "usr00000000000000001")
		require.Equal(t, "Illegal argument email: invalid format", iamerr.StripSentinel(err))
	})

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ №2: НЕРАЗОБРАННОЕ ограничение по-прежнему отдаёт
	// общий текст и НЕ эхает сообщение сервера — в нём выражение ограничения и
	// значения строки.
	t.Run("контроль: неразобранное ограничение сообщения сервера не эхает", func(t *testing.T) {
		const leak = `new row for relation "secrets" violates check constraint "secrets_shape_ck"`
		err := wrapPgErr(&pgconn.PgError{
			Code:           "23514",
			ConstraintName: "secrets_shape_ck",
			TableName:      "secrets",
			Message:        leak,
		}, "", "")
		require.Equal(t, "Illegal argument: value violates a constraint", iamerr.StripSentinel(err))
		require.NotContains(t, err.Error(), leak)
	})
}
