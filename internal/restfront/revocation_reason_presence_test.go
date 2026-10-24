// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// revocation_reason_presence_test.go — причина отзыва выдачи в теле ответа фронта
// (kaname#963, приёмка unregistration-revokes-its-grants.md, URG-E1 и URG-E2).
//
// Фронт кодирует ответ кодеком маршрутизатора по умолчанию, а он печатает и
// незаданные поля (`EmitUnpopulated`). Поле без присутствия в таком кодеке
// выходит ключом с нулевым значением перечня даже у действующей выдачи, а
// приёмка требует, чтобы у действующей ключа не было вовсе (URG-E2). Проба
// кодирует выдачу ТЕМ кодеком, который фронт выбирает для JSON-запроса, а не
// своей копией настроек: копия разошлась бы с фронтом молча.
package restfront

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/dto"
	_ "github.com/PRO-Robotech/kaname/internal/dto/toproto"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// frontBody — тело ответа фронта на выдачу b: проекция домена в контракт тем же
// реестром, что у обработчиков, и кодек, который фронт выбирает для JSON.
func frontBody(t *testing.T, b domain.AccessBinding) map[string]any {
	t.Helper()
	var pb *iamv1.AccessBinding
	require.NoError(t, dto.Transfer(dto.FromTo(b, &pb)), "проекция выдачи в контракт")
	req := httptest.NewRequest("GET", "/iam/v1/accessBindings/"+string(b.ID), nil)
	req.Header.Set("Accept", "application/json")
	_, out := runtime.MarshalerForRequest(newMux(), req)
	raw, err := out.Marshal(pb)
	require.NoError(t, err, "кодек фронта")
	var body map[string]any
	require.NoError(t, json.Unmarshal(raw, &body), "тело фронта — объект JSON: %s", raw)
	return body
}

func TestFrontBodyCarriesRevocationReasonOnlyWhenTheBindingWasRevokedWithOne(t *testing.T) {
	revokedAt := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name    string
		binding domain.AccessBinding
		want    string // пусто — ключа в теле быть не должно
	}{
		{
			name: "URG-E2: действующая выдача — ключа нет",
			binding: domain.AccessBinding{
				ID: "acb00000000000000act", Status: domain.AccessBindingStatusActive,
			},
		},
		{
			name: "URG-34 R0: отозвана до заведения поля — ключа нет",
			binding: domain.AccessBinding{
				ID: "acb000000000000000r0", Status: domain.AccessBindingStatusRevoked, RevokedAt: &revokedAt,
			},
		},
		{
			// Законный близнец: та же проба на выдаче с причиной обязана видеть ключ,
			// иначе «ключа нет» зеленело бы и на теле, где поле не печатается никогда.
			name: "URG-E1: отозвана снятием регистрации — причина в теле",
			binding: domain.AccessBinding{
				ID: "acb00000000000000urg", Status: domain.AccessBindingStatusRevoked, RevokedAt: &revokedAt,
				RevocationReason: domain.RevocationReasonResourceUnregistered,
			},
			want: "REVOCATION_REASON_RESOURCE_UNREGISTERED",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := frontBody(t, tc.binding)
			got, present := body["revocationReason"]
			if tc.want == "" {
				require.Falsef(t, present, "ключ revocationReason в теле выдачи без причины: %v", got)
				return
			}
			require.Truef(t, present, "ключа revocationReason нет в теле отозванной выдачи: %v", body)
			require.Equal(t, tc.want, got)
		})
	}
}
