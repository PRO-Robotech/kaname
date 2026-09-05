// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
)

// page_size вне диапазона ОТВЕРГАЕТСЯ на СЫРОМ запросе во ВСЕХ шести
// ListBy*-полосах выдач, а не схлопывается в 0.
//
// Предмет. Narrowing int64→int32 насыщал отрицательное значение в 0, а 0 в
// контракте значит «применить умолчание». Валидатор в use-case'е получал уже 0 и
// пропускал его — проверка стояла и не могла сработать. Канонический List
// (`AccessBindingService.List`) судил СЫРОЕ значение и был прав; шесть его соседей
// делали ровно наоборот, и разницу нельзя было увидеть, читая любой один из них.
//
// Почему проба идёт через хендлер с НЕподключёнными use-case'ами. Именно так
// проверяется, что формат судится ПЕРВЫМ: если да, ни один сотрудник не нужен.
// Проба, построенная от use-case'а, приняла бы уже суженное значение и осталась
// бы зелёной на этом дефекте — им и была.
func TestAccessBindingListsRejectOutOfRangePageSizeOnTheRawRequest(t *testing.T) {
	type probe struct {
		name string
		call func(h *Handler, ctx context.Context, size int64) error
	}
	probes := []probe{
		{"ListByScope", func(h *Handler, ctx context.Context, size int64) error {
			_, err := h.ListByScope(ctx, &iamv1.ListAccessBindingsByScopeRequest{PageSize: size})
			return err
		}},
		{"ListBySubject", func(h *Handler, ctx context.Context, size int64) error {
			_, err := h.ListBySubject(ctx, &iamv1.ListAccessBindingsBySubjectRequest{
				SubjectType: "user", SubjectId: "usr_probe", PageSize: size})
			return err
		}},
		{"ListByAccount", func(h *Handler, ctx context.Context, size int64) error {
			_, err := h.ListByAccount(ctx, &iamv1.ListAccessBindingsByAccountRequest{
				AccountId: "acc_probe", PageSize: size})
			return err
		}},
		{"ListByRole", func(h *Handler, ctx context.Context, size int64) error {
			_, err := h.ListByRole(ctx, &iamv1.ListAccessBindingsByRoleRequest{
				RoleId: "rol_probe", PageSize: size})
			return err
		}},
		{"ListSubjectPrivileges", func(h *Handler, ctx context.Context, size int64) error {
			_, err := h.ListSubjectPrivileges(ctx, &iamv1.ListSubjectPrivilegesRequest{
				SubjectType: "user", SubjectId: "usr_probe", PageSize: size})
			return err
		}},
		{"ListAssignableRoles", func(h *Handler, ctx context.Context, size int64) error {
			_, err := h.ListAssignableRoles(ctx, &iamv1.ListAssignableRolesRequest{
				ScopeType: "iam.account", ScopeId: "acc_probe", PageSize: size})
			return err
		}},
	}

	for _, p := range probes {
		t.Run(p.name, func(t *testing.T) {
			t.Run("отрицательный page_size — InvalidArgument", func(t *testing.T) {
				err := abCallNoPanic(t, func() error { return p.call(&Handler{}, context.Background(), -1) })
				require.Error(t, err, "отрицательный page_size принят: значение схлопнуто в 0 до проверки")
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
				assert.True(t, abNamesField(err, "page_size"), "отказ обязан назвать поле: %v", err)
			})
			t.Run("page_size выше предела — InvalidArgument", func(t *testing.T) {
				err := abCallNoPanic(t, func() error { return p.call(&Handler{}, context.Background(), 1001) })
				require.Error(t, err)
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
				assert.True(t, abNamesField(err, "page_size"), "отказ обязан назвать поле: %v", err)
			})
			t.Run("граница диапазона проходит формат-гейт", func(t *testing.T) {
				err := abCallNoPanicOrReachedCollaborator(func() error {
					return p.call(&Handler{}, context.Background(), 1000)
				})
				abAssertNotRejectedByPageFormat(t, err)
			})
		})
	}
}

// abCallNoPanic — паника означает, что запрос дошёл до НЕподключённого сотрудника,
// то есть формат первым не судился. Это тот же дефект, только громкий.
func abCallNoPanic(t *testing.T, call func() error) (err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("формат не судится первым: запрос дошёл до неподключённого сотрудника (%v)", r)
		}
	}()
	return call()
}

// abCallNoPanicOrReachedCollaborator — для ПОЛОЖИТЕЛЬНОГО контроля: законный ввод
// обязан пройти формат-гейт, а что с ним сделает неподключённый сотрудник — не
// предмет пробы. Паника здесь и есть доказательство прохождения гейта.
func abCallNoPanicOrReachedCollaborator(call func() error) (err error) {
	defer func() { _ = recover() }()
	return call()
}

// abNamesField — отказ по формату обязан НАЗВАТЬ поле. Имя живёт либо в
// google.rpc.BadRequest.field_violations (туда его кладут и платформенный
// validate.PageSize, и shared.InvalidArg), либо в тексте — принимаем оба: предмет
// утверждения «ответ про это поле», а не «ответ такой-то формы».
func abNamesField(err error, field string) bool {
	st := status.Convert(err)
	if strings.Contains(st.Message(), field) {
		return true
	}
	for _, d := range st.Details() {
		br, ok := d.(*errdetails.BadRequest)
		if !ok {
			continue
		}
		for _, v := range br.GetFieldViolations() {
			if v.GetField() == field || strings.Contains(v.GetDescription(), field) {
				return true
			}
		}
	}
	return false
}

// abAssertNotRejectedByPageFormat — положительный контроль: проба обязана отвергать
// формат, а не всё подряд.
func abAssertNotRejectedByPageFormat(t *testing.T, err error) {
	t.Helper()
	if err == nil || status.Convert(err).Code() != codes.InvalidArgument {
		return
	}
	assert.False(t, abNamesField(err, "page_size"),
		"законный page_size отвергнут: проба отвергает всё подряд, а не формат")
	assert.False(t, abNamesField(err, "page_token"),
		"законный page_token отвергнут: проба отвергает всё подряд, а не формат")
}
