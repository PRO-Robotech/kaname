// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// revoke_response_whole_seconds_test.go — время в исходе отзыва удостоверения
// человека несётся целыми секундами (kaname#1074): конвенция контракта
// усекает время на проводе до секунды на каждом ресурсе и под-записи, и одно
// сообщение операции не несёт двух времён разной точности (`createdAt`
// операции — целые секунды).
package user_tokens

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

func TestRevokeUserTokenResponse_RevokedAtIsWholeSeconds(t *testing.T) {
	before := time.Now()
	packed, err := revokeUserTokenResponse("uoc_test_1234567890abcd")
	after := time.Now()
	require.NoError(t, err)

	var resp iamv1.RevokeUserTokenResponse
	require.NoError(t, packed.UnmarshalTo(&resp))
	require.Equal(t, "uoc_test_1234567890abcd", resp.GetTokenId(), "эхо идентификатора")
	require.NotNil(t, resp.GetRevokedAt(), "исход отзыва обязан нести момент снятия")

	got := resp.GetRevokedAt().AsTime()
	require.Zerof(t, got.Nanosecond(), "revokedAt несёт дробную часть секунды: %s", got.Format(time.RFC3339Nano))
	require.Falsef(t, got.Before(before.Truncate(time.Second)) || got.After(after),
		"revokedAt %s вне окна вызова [%s, %s]", got, before.Truncate(time.Second), after)
}
