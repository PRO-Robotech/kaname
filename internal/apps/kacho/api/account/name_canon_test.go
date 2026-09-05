// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package account

// name_canon_test.go — канон имени на пути создания Account (#1279, канон #715).

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/pkg/operations"
)

func createAccountNamed(t *testing.T, name string) *iamv1.Account {
	t.Helper()
	opsRepo := newFakeOpsRepo()
	uc := NewCreateAccountUseCase(newFakeRepo(), opsRepo)

	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr0000000000000abcd"})
	op, err := uc.Execute(ctx, domain.Account{Name: domain.AccountName(name)})
	require.NoError(t, err, "создание с именем %q обязано пройти синхронную проверку", name)
	require.NotNil(t, op)

	wctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(wctx))

	done, err := opsRepo.Get(context.Background(), op.ID)
	require.NoError(t, err)
	require.True(t, done.Done, "операция обязана завершиться")
	require.Nil(t, done.Error, "создание обязано пройти, отказ: %v", done.Error)
	require.NotNil(t, done.Response, "ответ операции обязан нести созданный ресурс")

	var got iamv1.Account
	require.NoError(t, done.Response.UnmarshalTo(&got))
	return &got
}

// TestCreateAccount_EmptyName_WritesIdDerivedDefault — пустое имя означает
// «назови сам» и до записи заменяется именем, производным от идентификатора.
func TestCreateAccount_EmptyName_WritesIdDerivedDefault(t *testing.T) {
	got := createAccountNamed(t, "")
	assert.NotEmpty(t, got.Name, "строка ресурса не может нести пустое имя")
	assert.Equal(t, got.Id, got.Name, "умолчание — сам идентификатор (pkg/validate.NameOrDefault)")
}

// TestCreateAccount_TwoEmptyNames_DistinctNames — оба безымянных создания
// проходят и получают разные имена: `accounts_name_unique` уникально по имени
// на ВЕСЬ кластер, поэтому умолчание, не производное от идентификатора,
// столкнулось бы уже на втором аккаунте платформы.
func TestCreateAccount_TwoEmptyNames_DistinctNames(t *testing.T) {
	first := createAccountNamed(t, "")
	second := createAccountNamed(t, "")
	assert.NotEqual(t, first.Name, second.Name,
		"два безымянных создания обязаны получить разные имена")
}

// TestCreateAccount_CanonNames_Accepted — положительный контроль на осях, где
// прежняя форма iam была УЖЕ канона.
func TestCreateAccount_CanonNames_Accepted(t *testing.T) {
	for _, tc := range []struct{ label, value string }{
		{"цифра первым символом", "9lives"},
		{"один символ", "a"},
		{"обычное имя", "acme-ok"},
	} {
		t.Run(tc.label, func(t *testing.T) {
			got := createAccountNamed(t, tc.value)
			assert.Equal(t, tc.value, got.Name, "присланное имя обязано сохраниться как есть")
		})
	}
}
