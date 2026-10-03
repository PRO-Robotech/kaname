// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// issuance_needs_the_token_endpoint_test.go — ключевая пара человека не
// выдаётся посадкой, где нет токен-эндпоинта (задача kaname#547). Близнец
// `sa_keys/issuance_needs_the_token_endpoint_test.go`.
//
// # Предмет
//
// Ключевую пару человека обменивает только токен-эндпоинт платформы: реестр
// клиентов, доказывающих владение ключом, читает таблицу удостоверений
// человека, и его единственный потребитель — сборка эндпоинта. Выдача на
// посадке без эндпоинта вернула бы ключ, который обменять негде, —
// объявленную возможность, не исполнимую ни при каком входе.
//
// Отказ СИНХРОННЫЙ, после разбора запроса, до всякого чтения и записи, и
// называет ручку — так же, как на пути служебной учётки.
//
// # Законные близнецы
//
//   - та же выдача при объявленном эндпоинте проходит;
//   - секрет (SECRET) обмена не требует и выдаётся без эндпоинта.
package user_tokens

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// clientTokenKnob — ручка, которую обязан назвать отказ.
const clientTokenKnob = "authn.client-token.enabled"

// exchangedKindInputs — виды, которые обмениваются эндпоинтом: названный
// KEYPAIR и неназванный, который разрешается в KEYPAIR.
func exchangedKindInputs() map[string]IssueInput {
	base := IssueInput{UserID: "usr00000000000000001", CreatedByUserID: "usr00000000000000001"}
	named := base
	named.CredentialKind = domain.CredentialKindKeypair
	return map[string]IssueInput{"KEYPAIR": named, "неназванный": base}
}

// TestIssue_WithoutTheTokenEndpoint_ExchangedKindsAreRefusedNamingTheKnob —
// ключевая пара (и неназванный вид) отвергается синхронно, с именем ручки, и
// ничего не пишется и не читается.
func TestIssue_WithoutTheTokenEndpoint_ExchangedKindsAreRefusedNamingTheKnob(t *testing.T) {
	for name, in := range exchangedKindInputs() {
		t.Run(name, func(t *testing.T) {
			repo := &stubUserClientRepo{}
			ops := &stubOpsRepo{}
			op, err := NewIssueUserTokenUseCase(repo, &stubTx{}, ops).Execute(context.Background(), in)
			require.Error(t, err, "выдача ключа, который обменять негде, обязана отказать")
			require.Nil(t, op, "отказ синхронный: операции не заводится")
			require.Equal(t, codes.FailedPrecondition, grpcstatus.Code(err))
			require.Contains(t, grpcstatus.Convert(err).Message(), clientTokenKnob,
				"отказ обязан назвать ручку, которой он снимается")
			require.False(t, ops.created, "отказ до всякой записи: строки операции нет")
			require.Empty(t, repo.inserted.ID, "отказ до всякой записи: строки ключа нет")
			require.Zero(t, repo.accountCalls, "отказ до всякого чтения: владелец не резолвится")
		})
	}
}

// TestIssue_WithoutTheTokenEndpoint_SecretIsIssued — секрет обмена не
// требует: его предъявляют как есть, и выдаётся он без эндпоинта.
func TestIssue_WithoutTheTokenEndpoint_SecretIsIssued(t *testing.T) {
	repo := &stubUserClientRepo{}
	ops := &stubOpsRepo{}
	op, err := NewIssueUserTokenUseCase(repo, &stubTx{}, ops).Execute(context.Background(), IssueInput{
		UserID:          "usr00000000000000001",
		CreatedByUserID: "usr00000000000000001",
		CredentialKind:  domain.CredentialKindSecret,
		TTLSeconds:      int64(time.Hour.Seconds()),
	})
	require.NoError(t, err, "секрет не обменивается и эндпоинта не требует")
	require.NotNil(t, op)
	require.Nil(t, op.Error)
	require.Equal(t, domain.CredentialKindSecret, repo.inserted.CredentialKind)
	require.NotEmpty(t, repo.inserted.ID, "строка секрета обязана быть записана")
}

// TestIssue_WithTheTokenEndpoint_ExchangedKindsAreIssued — законный близнец:
// та же выдача при объявленном эндпоинте проходит.
func TestIssue_WithTheTokenEndpoint_ExchangedKindsAreIssued(t *testing.T) {
	for name, in := range exchangedKindInputs() {
		t.Run(name, func(t *testing.T) {
			repo := &stubUserClientRepo{}
			ops := &stubOpsRepo{}
			_, err := NewIssueUserTokenUseCase(repo, &stubTx{}, ops).WithOwnIssuance().
				Execute(context.Background(), in)
			require.NoError(t, err)
			waitForOp(t, ops)
			require.Nil(t, ops.lastErr, "выдача при объявленном эндпоинте обязана состояться")
			require.Equal(t, domain.CredentialKindKeypair, repo.inserted.CredentialKind)
		})
	}
}
