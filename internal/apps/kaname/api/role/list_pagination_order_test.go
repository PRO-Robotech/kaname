// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package role

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
)

// Форма страницы судится НА ТРАНСПОРТНОЙ ГРАНИЦЕ и ДО всякой работы.
//
// Предмет (#660). Шесть списочных поверхностей сервиса судят форму страницы
// в обработчике, роли судили величину там, а форму курсора — первым
// стейтментом use-case. Порядок «формат до замыкания по личности» при этом
// соблюдался, то есть дефекта поведения не было; предмет в том, что форма
// была ОДНА ИЗ СЕМИ, и следующий, кто заведёт восьмую поверхность,
// скопировал бы ту, на которую посмотрел.
//
// Тройка, а не одиночное утверждение. «Мусорный курсор отвергнут» в одиночку
// зеленело бы и на обработчике, который отвергает всё: рядом стоит
// положительный контроль — законная страница доходит до use-case, — и
// контроль второй оси, величины страницы. Вместе они утверждают «форма
// судится здесь и судится по форме», а не «всё отвергается».
//
// Подставного репозитория здесь нет намеренно: утверждение о ПОРЯДКЕ
// проверяется тем, что отказ приходит раньше, чем обработчику понадобится
// хоть одна зависимость. Нулевой use-case это и показывает: пройди проверка
// формы позже, вызов упал бы разыменованием, а не кодом ответа.
func TestListPaginationFormatCheckedAtTheTransportBoundary(t *testing.T) {
	const garbageToken = "not-a-real-token!!"

	t.Run("мусорный курсор — отказ по формату, до всякой работы", func(t *testing.T) {
		h := NewHandler(nil, nil, nil, nil, nil)

		_, err := h.List(context.Background(), &iamv1.ListRolesRequest{
			PageSize:  100,
			PageToken: garbageToken,
		})

		require.Error(t, err, "форма курсора обязана судиться на границе, а не глубже")
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("величина страницы вне диапазона — тот же рубеж", func(t *testing.T) {
		h := NewHandler(nil, nil, nil, nil, nil)

		_, err := h.List(context.Background(), &iamv1.ListRolesRequest{PageSize: 1001})

		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("законная страница — рубеж пропускает", func(t *testing.T) {
		h := NewHandler(nil, nil, nil, nil, nil)

		// Законный ввод обязан ПРОЙТИ рубеж формы. Что будет дальше — не
		// предмет этой пробы: use-case здесь отсутствует, и исход зависит от
		// его устройства. Предмет — что отказ, если он придёт, будет НЕ о
		// форме: без этого контроля первые два утверждения зеленели бы и на
		// обработчике, отвергающем каждый ввод.
		_, err := h.List(context.Background(), &iamv1.ListRolesRequest{PageSize: 100})

		assert.NotEqual(t, codes.InvalidArgument, status.Code(err),
			"законная страница отвергнута рубежом формы — проба отвергает всё подряд, а не форму")
	})
}
