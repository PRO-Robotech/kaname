// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package project

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
)

// page_size вне диапазона ОТВЕРГАЕТСЯ на СЫРОМ запросе, а не схлопывается в 0.
//
// Предмет. Narrowing int64→int32 насыщал отрицательное значение в 0, а 0 в
// контракте значит «применить умолчание»: валидатор ниже по потоку получал уже 0
// и пропускал его. Проверка стояла, была верной, задокументированной — и не могла
// сработать ни на одном отрицательном значении.
//
// Проба идёт через ХЕНДЛЕР с НЕподключённым use-case'ом: если формат судится
// первым, ни один сотрудник для ответа не нужен. Проба, построенная от use-case'а,
// приняла бы уже суженное значение и осталась бы зелёной ровно на этом дефекте —
// ею и была.
//
// Тройка, а не одиночное отрицание: рядом стоят положительные контроли — законная
// страница и ГРАНИЦА диапазона обязаны пройти формат-гейт.
func TestProjListRejectsOutOfRangePageSizeOnTheRawRequest(t *testing.T) {
	t.Run("отрицательный page_size — InvalidArgument", func(t *testing.T) {
		err := pageProbecallNoPanic(t, func() error {
			_, e := (&Handler{}).List(context.Background(), &iamv1.ListProjectsRequest{PageSize: -1})
			return e
		})
		require.Error(t, err, "отрицательный page_size принят: значение схлопнуто в 0 до проверки")
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		assert.True(t, pageProbenamesField(err, "page_size"), "отказ обязан назвать поле: %v", err)
	})

	t.Run("page_size выше предела — InvalidArgument", func(t *testing.T) {
		err := pageProbecallNoPanic(t, func() error {
			_, e := (&Handler{}).List(context.Background(), &iamv1.ListProjectsRequest{PageSize: 1001})
			return e
		})
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		assert.True(t, pageProbenamesField(err, "page_size"), "отказ обязан назвать поле: %v", err)
	})

	t.Run("граница диапазона проходит формат-гейт", func(t *testing.T) {
		err := pageProbecallTolerating(func() error {
			_, e := (&Handler{}).List(context.Background(), &iamv1.ListProjectsRequest{PageSize: 1000})
			return e
		})
		pageProbeassertNotRejectedByPageFormat(t, err)
	})

	t.Run("законная страница проходит формат-гейт", func(t *testing.T) {
		err := pageProbecallTolerating(func() error {
			_, e := (&Handler{}).List(context.Background(), &iamv1.ListProjectsRequest{PageSize: 100})
			return e
		})
		pageProbeassertNotRejectedByPageFormat(t, err)
	})
}

// pageProbecallNoPanic — паника значит, что запрос дошёл до НЕподключённого сотрудника,
// то есть формат первым не судился: тот же дефект, только громкий.
func pageProbecallNoPanic(t *testing.T, call func() error) (err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("формат не судится первым: запрос дошёл до неподключённого сотрудника (%v)", r)
		}
	}()
	return call()
}

// pageProbecallTolerating — для ПОЛОЖИТЕЛЬНОГО контроля: законный ввод обязан пройти
// формат-гейт, а что с ним сделает неподключённый сотрудник — не предмет пробы.
func pageProbecallTolerating(call func() error) (err error) {
	defer func() { _ = recover() }()
	return call()
}

// pageProbenamesField — отказ по формату обязан НАЗВАТЬ поле. Имя живёт либо в
// google.rpc.BadRequest.field_violations (платформенный validate.PageSize и
// shared.InvalidArg кладут его туда), либо в тексте — принимаем оба, потому что
// предмет утверждения «ответ про это поле», а не «ответ такой-то формы».
func pageProbenamesField(err error, field string) bool {
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

// pageProbeassertNotRejectedByPageFormat — проба обязана отвергать формат, а не всё подряд.
func pageProbeassertNotRejectedByPageFormat(t *testing.T, err error) {
	t.Helper()
	if err == nil || status.Convert(err).Code() != codes.InvalidArgument {
		return
	}
	assert.False(t, pageProbenamesField(err, "page_size"),
		"законный page_size отвергнут: проба отвергает всё подряд, а не формат")
	assert.False(t, pageProbenamesField(err, "page_token"),
		"законный page_token отвергнут: проба отвергает всё подряд, а не формат")
}
