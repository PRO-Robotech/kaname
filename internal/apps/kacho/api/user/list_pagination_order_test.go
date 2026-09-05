// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	repouser "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/user"
)

// Формат пагинации проверяется ДО замыкания по личности вызывающего.
//
// Предмет. Use-case сначала решает, кто спрашивает: анонимный (в том числе
// непроброшенный принципал, который попадает сюда же) получает пустую страницу
// без ошибки и до репозитория не доходит. Пока формат курсора проверял только
// репозиторий, один и тот же мусорный `page_token` получал разный ответ в
// зависимости от того, опознан ли вызывающий, — то есть проверка ввода зависела
// от прав.
//
// Тройка, а не одиночное утверждение. Проба «анонимный получает InvalidArgument»
// в одиночку зеленела бы и на полностью сломанном use-case, поэтому рядом стоят
// (а) положительный контроль формы — законная первая страница у названного
// вызывающего проходит без ошибки, и (б) контроль сохранности замыкания —
// анонимный с ЗАКОННОЙ пагинацией по-прежнему получает пустую страницу без
// ошибки, а не отказ. Вместе они утверждают «ответ на формат не зависит от
// личности», не подменяя это на «всё отвергается».
func TestListPaginationFormatCheckedBeforeIdentityShortCircuit(t *testing.T) {
	const garbageToken = "not-a-real-token!!"

	t.Run("анонимный вызывающий — отказ по формату курсора", func(t *testing.T) {
		uc := NewListUsersUseCase(&scopeUserRepo{}).WithRelationStore(newUserUnionFGAStub())

		_, _, err := uc.Execute(context.Background(), repouser.ListFilter{PageSize: 100, PageToken: garbageToken})

		require.Error(t, err,
			"пустая страница вместо отказа: замыкание по личности опередило проверку формата")
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("анонимный вызывающий — отказ по page_size вне диапазона", func(t *testing.T) {
		uc := NewListUsersUseCase(&scopeUserRepo{}).WithRelationStore(newUserUnionFGAStub())

		_, _, err := uc.Execute(context.Background(), repouser.ListFilter{PageSize: 1001})

		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("названный вызывающий, законная страница — проходит", func(t *testing.T) {
		uc := NewListUsersUseCase(&scopeUserRepo{}).WithRelationStore(newUserUnionFGAStub())

		_, _, err := uc.Execute(ctxListUser("usr-u1"), repouser.ListFilter{PageSize: 100})

		require.NoError(t, err, "проба обязана отвергать формат, а не всё подряд")
	})

	t.Run("анонимный, законная страница — по-прежнему пустая страница без ошибки", func(t *testing.T) {
		uc := NewListUsersUseCase(&scopeUserRepo{}).WithRelationStore(newUserUnionFGAStub())

		out, next, err := uc.Execute(context.Background(), repouser.ListFilter{PageSize: 100})

		require.NoError(t, err, "замыкание fail-closed обязано уцелеть: это не отказ, а пустая выдача")
		assert.Empty(t, out)
		assert.Empty(t, next)
	})
}
