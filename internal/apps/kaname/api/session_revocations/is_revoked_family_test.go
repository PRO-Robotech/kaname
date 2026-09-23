// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_revocations

// is_revoked_family_test.go — `IsRevoked` отвечает и об отзыве СЕМЕЙСТВА
// выпуска тем же обращением и в том же ответе (kaname#319, решение К10
// вариант А; приёмка LINE-A-1, сценарий 21).
//
// Запрос и ответ контракта не меняются: вопрос по-прежнему один —
// идентификатор удостоверения, — и ответ по-прежнему один — признак отзыва.
// Меняется то, ЧТО этот признак покрывает: запись отзыва по идентификатору
// ЛИБО отзыв семейства, к которому выпуск принадлежит. Второго обращения за
// семейством у спрашивающего нет и быть не должно: два обращения — два окна
// кэша и две политики на неответ об одном решении.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// TestIsRevoked_LINE_A_1_21_AnswersForTheFamilyOfTheIssuance — записи отзыва
// по идентификатору нет, семейство выпуска отозвано: ответ «отозван».
func TestIsRevoked_LINE_A_1_21_AnswersForTheFamilyOfTheIssuance(t *testing.T) {
	const jti = "tokaaaaaaaaaaaaaaaaa"

	t.Run("T1 близнец: семейство живо — не отозван", func(t *testing.T) {
		r := &fakeReader{families: map[string]bool{jti: false}}
		resp, err := newHandler(&fakeRevoker{}, r).IsRevoked(context.Background(),
			&iamv1.IsRevokedRequest{TokenJti: jti})
		require.NoError(t, err)
		assert.False(t, resp.GetRevoked(), "выпуск живого семейства объявлен отозванным")
	})

	t.Run("семейство отозвано — отозван", func(t *testing.T) {
		r := &fakeReader{families: map[string]bool{jti: true}}
		resp, err := newHandler(&fakeRevoker{}, r).IsRevoked(context.Background(),
			&iamv1.IsRevokedRequest{TokenJti: jti})
		require.NoError(t, err)
		assert.True(t, resp.GetRevoked(),
			"выпуск отозванного семейства назван неотозванным: о семействе не спросили "+
				"(спрошено %v) — край получил бы «жив» о снятом удостоверении", r.familyAsked)
	})

	t.Run("T2 близнец: отозвано другое семейство — не отозван", func(t *testing.T) {
		r := &fakeReader{families: map[string]bool{"tokbbbbbbbbbbbbbbbbb": true}}
		resp, err := newHandler(&fakeRevoker{}, r).IsRevoked(context.Background(),
			&iamv1.IsRevokedRequest{TokenJti: jti})
		require.NoError(t, err)
		assert.False(t, resp.GetRevoked(), "отзыв чужого семейства снял этот выпуск")
	})
}

// TestIsRevoked_FamilyStoreFailureIsAFixedInternal — хранилище семейств не
// ответило: ответа «не отозван» нет, есть отказ с фиксированным текстом без
// текста хранилища.
func TestIsRevoked_FamilyStoreFailureIsAFixedInternal(t *testing.T) {
	r := &fakeReader{familyErr: errors.New("dial tcp 10.0.0.7:5432: connection refused")}
	resp, err := newHandler(&fakeRevoker{}, r).IsRevoked(context.Background(),
		&iamv1.IsRevokedRequest{TokenJti: "tokaaaaaaaaaaaaaaaaa"})
	require.Error(t, err, "сбой хранилища семейств прочитан как «не отозван» (ответ %v)", resp)
	require.Equal(t, codes.Internal, status.Code(err))
	require.Equal(t, "session revocation lookup failed", status.Convert(err).Message(),
		"текст отказа обязан быть фиксированным")
	require.NotContains(t, err.Error(), "10.0.0.7", "текст хранилища утёк наружу")
}
