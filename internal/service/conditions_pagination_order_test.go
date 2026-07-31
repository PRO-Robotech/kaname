// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package service

// conditions_pagination_order_test.go — формат пагинации проверяется ДО решения
// о том, что вызывающему ничего не видно.
//
// Предмет. ConditionsCRUDService.List возвращает пустую страницу в трёх
// случаях: вызывающий анонимен, он просит несуженный список не будучи
// администратором кластера, и он не может читать названный проект. Все три
// стоят ДО обращения к репозиторию, а формат курсора проверял только
// репозиторий. Значит один и тот же мусорный `page_token` получал разный ответ
// в зависимости от того, что вызывающему выдано.

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamserviceerr "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/condition"
)

// TestConditionsList_PaginationFormatCheckedBeforeVisibilityShortCircuit — все
// три полосы «ничего не видно» отвечают на мусорный формат отказом, а не пустой
// страницей.
//
// Положительный контроль стоит рядом и обязателен: без него проба зеленела бы
// на use-case, который отвергает вообще всё.
func TestConditionsList_PaginationFormatCheckedBeforeVisibilityShortCircuit(t *testing.T) {
	const garbageToken = "not-a-real-token!!"

	// Все три полосы, приводящие к пустой странице, — перечислением, не образцом.
	lanes := map[string]struct {
		ctx    context.Context
		filter condition.ListFilter
	}{
		"анонимный вызывающий": {
			ctx:    context.Background(),
			filter: condition.ListFilter{ProjectID: condTestProject, PageToken: garbageToken},
		},
		"несуженный список не администратором кластера": {
			ctx:    condReaderCtx(),
			filter: condition.ListFilter{PageToken: garbageToken},
		},
		"проект недоступен вызывающему": {
			ctx:    condReaderCtx(),
			filter: condition.ListFilter{ProjectID: condTestProject, PageToken: garbageToken},
		},
	}

	for name, lane := range lanes {
		t.Run(name, func(t *testing.T) {
			svc := condSvc(denyingChecker{})

			_, _, err := svc.List(lane.ctx, lane.filter)

			if err == nil {
				t.Fatalf("пустая страница вместо отказа: замыкание по видимости опередило проверку формата")
			}
			if got := status.Code(iamserviceerr.MapRepoErr(err)); got != codes.InvalidArgument {
				t.Fatalf("мусорный курсор обязан быть отвергнут по формату, получено %v (%v)", got, err)
			}
		})
	}

	t.Run("page_size вне диапазона — так же отвергается", func(t *testing.T) {
		svc := condSvc(denyingChecker{})

		_, _, err := svc.List(context.Background(),
			condition.ListFilter{ProjectID: condTestProject, PageSize: 1001})

		if err == nil {
			t.Fatalf("page_size вне диапазона обязан быть отвергнут независимо от видимости")
		}
		if got := status.Code(iamserviceerr.MapRepoErr(err)); got != codes.InvalidArgument {
			t.Fatalf("ожидался InvalidArgument, получено %v (%v)", got, err)
		}
	})

	// Положительный контроль формы: законная пагинация проходит сквозь проверку,
	// и полоса «ничего не видно» остаётся пустой страницей БЕЗ ошибки.
	t.Run("законная страница при отказе в видимости — пусто и без ошибки", func(t *testing.T) {
		svc := condSvc(denyingChecker{})

		out, next, err := svc.List(condReaderCtx(),
			condition.ListFilter{ProjectID: condTestProject, PageSize: 100})

		if err != nil {
			t.Fatalf("проба обязана отвергать формат, а не всё подряд: %v", err)
		}
		if len(out) != 0 || next != "" {
			t.Fatalf("отказ в видимости обязан остаться пустой страницей, получено rows=%d next=%q", len(out), next)
		}
	})
}
