// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain_test

// access_key_ceiling_test.go — вид `iam.user.accessKey` стоит в закрытом
// множестве видов посадки, а его подчинённый ресурс `iam.accessKey` анкерен
// таблицей ключей (Ф7 Р8; сценарии Ф7-37, Ф7-38). Таблицу и триггер списания
// на ней сверяет анкер миграций (`credential_ceiling_anchor_test.go`); здесь —
// что словарь домена вид знает и называет ту же таблицу.

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestAccessKey_F7_38_KindIsPostureStated(t *testing.T) {
	require.True(t, domain.IsPostureStatedKind("iam.user.accessKey"))
	require.Contains(t, domain.PostureStatedKinds(), domain.LimitKind("iam.user.accessKey"))
	require.False(t, domain.IsIdentityCarriedKind("iam.user.accessKey"), "ключ считается в человеке, а не в личности")
}

func TestAccessKey_F7_38_SubordinateResourceAnchoredByTheKeysTable(t *testing.T) {
	rec, ok := domain.SubordinateResourceOf("iam.accessKey")
	require.True(t, ok, "подчинённый ресурс ключа обязан быть объявлен: у ключа нет своего типа модели прав")
	require.Equal(t, []domain.LimitKind{"iam.user"}, rec.Parents)
	require.Equal(t, []string{"kaname.user_access_keys"}, rec.Tables)
	require.NotEmpty(t, rec.Why)
	require.Equal(t, domain.LimitKind("iam.accessKey"), domain.LimitKind("iam.user.accessKey").ChildKind())
}
