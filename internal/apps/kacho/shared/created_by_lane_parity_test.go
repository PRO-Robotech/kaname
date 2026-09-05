// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// created_by_lane_parity_test.go — полосы сверяются МЕЖДУ СОБОЙ, а не каждая
// сама с собой (architecture.md §«Параллельные полосы одного механизма обязаны
// сверяться МЕЖДУ СОБОЙ»).
//
// Проба задаёт ОБЕИМ полосам выдачи удостоверения один и тот же вход и требует
// одинакового ответа. Проверка «каждая полоса по отдельности верна» этого
// класса не ловит: обе были верны по отдельности, неверна была их РАЗНИЦА —
// персональный токен принимал присланного ответственного и выбрасывал его
// молча, ключ служебной учётки отвергал явно, и решал это расхождение никто.
//
// Отличие полос ровно одно, и оно НАЗВАНО отдельной пробой ниже, а не оставлено
// на усмотрение читателя.
package shared

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

const (
	parityUserPrincipal = "usr00000000000000007"
	paritySAPrincipal   = "sva00000000000000009"
	parityTargetUser    = "usr00000000000000001"
	parityStranger      = "usr00000000000000099"
)

// parityLane — полоса под пробой. Описатель строится ТЕМИ ЖЕ конструкторами,
// которые зовут обработчики; проба над собственной копией описателя закрепляла
// бы ответ правила, а не полосу продукта.
type parityLane struct {
	name  string
	build func(principal string, callerIsServiceAccount bool) CreatedByLane
}

func parityLanes() []parityLane {
	return []parityLane{
		{
			name: "персональный токен",
			build: func(p string, sa bool) CreatedByLane {
				return CreatedByLaneForUserToken(p, sa, parityTargetUser)
			},
		},
		{
			name: "ключ служебной учётки",
			build: func(p string, sa bool) CreatedByLane {
				return CreatedByLaneForSAKey(p, sa)
			},
		},
	}
}

// TestCreatedByLanes_AnswerTheSameOnTheSameInput — один вход, обе полосы, один
// ответ. Строки «отказ не ожидается» здесь и есть положительный контроль:
// правило, отвергающее всё, зеленело бы на одних отрицаниях.
func TestCreatedByLanes_AnswerTheSameOnTheSameInput(t *testing.T) {
	cases := []struct {
		name                   string
		principal              string
		callerIsServiceAccount bool
		requested              string
		wantRefused            bool
	}{
		{"человек, поле не названо", parityUserPrincipal, false, "", false},
		{"человек, назвал свой принципал", parityUserPrincipal, false, parityUserPrincipal, false},
		{"человек, назвал чужого", parityUserPrincipal, false, parityStranger, true},
		{"машина, поле не названо (посев)", paritySAPrincipal, true, "", false},
		{"машина, назвала третье лицо", paritySAPrincipal, true, parityStranger, true},
		{"машина, назвала себя", paritySAPrincipal, true, paritySAPrincipal, true},
	}

	lanes := parityLanes()
	require.Len(t, lanes, 2, "сверять между собой нечего, если полоса одна")
	require.NotEmpty(t, cases, "пустая таблица зеленеет на любом правиле")

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			verdicts := make(map[string]error, len(lanes))
			for _, l := range lanes {
				verdicts[l.name] = l.build(c.principal, c.callerIsServiceAccount).ValidateRequested(c.requested)
			}
			first := lanes[0]
			for _, l := range lanes[1:] {
				a, b := verdicts[first.name], verdicts[l.name]
				require.Equal(t, a != nil, b != nil,
					"полосы %q и %q ответили по-разному на один и тот же вход", first.name, l.name)
				require.Equal(t, grpcstatus.Code(a), grpcstatus.Code(b),
					"код отказа обязан совпадать: правило одно")
			}
			for _, l := range lanes {
				err := verdicts[l.name]
				if !c.wantRefused {
					require.NoError(t, err, "полоса %q отвергла законный вход", l.name)
					continue
				}
				require.Error(t, err, "полоса %q приняла вход, который не запишет", l.name)
				require.Equal(t, codes.InvalidArgument, grpcstatus.Code(err),
					"неисполнимое поле запроса — INVALID_ARGUMENT (полоса %q)", l.name)
				require.Contains(t, grpcstatus.Convert(err).Message(), "created_by_user_id",
					"отказ обязан назвать поле (полоса %q)", l.name)
			}
		})
	}
}

// TestCreatedByLanes_UserCallerRefusalTextIsIdentical — у вызывающего-человека
// правило не просто одинаковое, а ОДНО, поэтому и текст отказа обязан быть
// дословно один: тон сообщений — часть контракта.
func TestCreatedByLanes_UserCallerRefusalTextIsIdentical(t *testing.T) {
	lanes := parityLanes()
	want := lanes[0].build(parityUserPrincipal, false).ValidateRequested(parityStranger)
	require.Error(t, want)
	for _, l := range lanes[1:] {
		got := l.build(parityUserPrincipal, false).ValidateRequested(parityStranger)
		require.Error(t, got)
		require.Equal(t, grpcstatus.Convert(want).Message(), grpcstatus.Convert(got).Message(),
			"полоса %q произносит своё сообщение там, где правило общее", l.name)
	}
}

// TestCreatedByLanes_TheOneDecidedDifference — единственное отличие полос,
// названное РЕШЕНИЕМ, а не оставленное молчаливым.
//
// Вызывающая машина называет ровно то значение, которое полоса и запишет:
//   - персональный токен — край это значение знает (`user_id` того же запроса),
//     сверяет и ПРИМЕНЯЕТ: отвергать совпавшее значило бы отказывать без
//     предмета и сломать посев, который его шлёт;
//   - ключ служебной учётки — край записываемого значения не знает вовсе (оно
//     резолвится в use-case из владельца аккаунта целевой учётки), сверять
//     нечем, поэтому поле обязано быть пустым.
//
// Проба утверждает ОБЕ стороны: исчезнет отличие — она покраснеет и потребует
// решения, а не молча примет новое поведение.
func TestCreatedByLanes_TheOneDecidedDifference(t *testing.T) {
	tokenLane := CreatedByLaneForUserToken(paritySAPrincipal, true, parityTargetUser)
	require.NoError(t, tokenLane.ValidateRequested(parityTargetUser),
		"край знает записываемое значение и обязан принять совпавшее")
	require.True(t, tokenLane.MachineLaneKnowsRecord,
		"принятие законно ровно потому, что край значение знает")

	keyLane := CreatedByLaneForSAKey(paritySAPrincipal, true)
	require.False(t, keyLane.MachineLaneKnowsRecord,
		"на этой полосе записываемое значение краю недоступно")
	err := keyLane.ValidateRequested(parityTargetUser)
	require.Error(t, err,
		"сверять нечем — значит принимать нечего: непустое значение отвергается")
	require.Equal(t, codes.InvalidArgument, grpcstatus.Code(err))
	require.Contains(t, grpcstatus.Convert(err).Message(), "created_by_user_id")
}
