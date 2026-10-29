// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// revoke_response_whole_seconds_test.go — время в исходе отзыва ключа
// сервисной учётной записи несётся целыми секундами (kaname#1074): конвенция
// контракта усекает время на проводе до секунды на каждом ресурсе и под-записи,
// и одно сообщение операции не несёт двух времён разной точности (`createdAt`
// операции — целые секунды).
package sa_keys

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

func TestRevokeSAKeyResponse_RevokedAtIsWholeSeconds(t *testing.T) {
	before := time.Now()
	packed, err := revokeSAKeyResponse("sak_test_1234567890abcd")
	after := time.Now()
	require.NoError(t, err)

	var resp iamv1.RevokeSAKeyResponse
	require.NoError(t, packed.UnmarshalTo(&resp))
	require.Equal(t, "sak_test_1234567890abcd", resp.GetKeyId(), "эхо идентификатора")
	require.NotNil(t, resp.GetRevokedAt(), "исход отзыва обязан нести момент снятия")

	got := resp.GetRevokedAt().AsTime()
	require.Zerof(t, got.Nanosecond(), "revokedAt несёт дробную часть секунды: %s", got.Format(time.RFC3339Nano))
	require.Falsef(t, got.Before(before.Truncate(time.Second)) || got.After(after),
		"revokedAt %s вне окна вызова [%s, %s]", got, before.Truncate(time.Second), after)
}
