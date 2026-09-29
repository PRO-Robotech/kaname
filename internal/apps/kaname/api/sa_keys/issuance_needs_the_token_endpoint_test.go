// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// issuance_needs_the_token_endpoint_test.go — ключ, который обменивается
// токен-эндпоинтом платформы, не выдаётся посадкой, где эндпоинта нет
// (задача #362).
//
// # Предмет
//
// Ключ с ключевым материалом и федеративный ключ предъявляются ОБМЕНОМ:
// подписанное утверждение меняется на токен. Обменивает его наш токен-эндпоинт
// (`authn.client-token.enabled`), и другого исполнителя обмена у ключа больше
// нет: запись клиента у прежнего издателя снята вместе со столбцом, где лежало
// его имя. Выдача на посадке без эндпоинта вернула бы ключ, который обменять
// негде, — объявленную возможность, не исполнимую ни при каком входе.
//
// Отказ СИНХРОННЫЙ и называет ручку: запрос сформирован верно, и ответ известен
// до всякой записи. Отказ операции часами позже сказал бы то же самое хуже.
//
// # Законные близнецы
//
//   - та же выдача при объявленном эндпоинте проходит;
//   - секрет (SECRET) обмена не требует — его предъявляют как есть, — и
//     выдаётся без эндпоинта.
package sa_keys

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// clientTokenKnob — ручка, которую обязан назвать отказ.
const clientTokenKnob = "authn.client-token.enabled"

// newEndpointlessIssueUC — выдача на посадке БЕЗ токен-эндпоинта. Утверждения
// ниже одни и те же до правки и после: правка меняет форму сборки (порт
// поставщика снят), а не то, что проверяется.
func newEndpointlessIssueUC(repo *stubSAClientRepo, ops *stubOpsRepo) *IssueSAKeyUseCase {
	return NewIssueSAKeyUseCase(repo, &stubTx{}, ops).
		WithTrustedIssuerWriter(&fakeTrustedIssuers{})
}

func federatedSubjects() []domain.TrustedSubject {
	return []domain.TrustedSubject{{
		Issuer:         "https://idp.example.com",
		SubjectPattern: "^repo:acme/infra$",
		PublicKeyPEM:   testIssuerPublicKeyPEM,
		KeyAlgorithm:   "ES256",
	}}
}

// TestIssue_WithoutTheTokenEndpoint_ExchangedKindsAreRefusedNamingTheKnob —
// ключевая пара и федеративный ключ отвергаются синхронно, с именем ручки, и
// ничего не пишется.
func TestIssue_WithoutTheTokenEndpoint_ExchangedKindsAreRefusedNamingTheKnob(t *testing.T) {
	for name, in := range map[string]IssueInput{
		"KEYPAIR": {ServiceAccountID: "sva_test000000000000", CreatedByUserID: "usr_admin00000000000"},
		"FEDERATED": {ServiceAccountID: "sva_test000000000000", CreatedByUserID: "usr_admin00000000000",
			TrustedSubjects: federatedSubjects()},
	} {
		t.Run(name, func(t *testing.T) {
			repo := &stubSAClientRepo{}
			ops := &stubOpsRepo{}
			op, err := newEndpointlessIssueUC(repo, ops).Execute(context.Background(), in)
			require.Error(t, err, "выдача ключа, который обменять негде, обязана отказать")
			require.Nil(t, op, "отказ синхронный: операции не заводится")
			require.Equal(t, codes.FailedPrecondition, grpcstatus.Code(err))
			require.Contains(t, grpcstatus.Convert(err).Message(), clientTokenKnob,
				"отказ обязан назвать ручку, которой он снимается")
			require.False(t, ops.created, "отказ до всякой записи: строки операции нет")
			require.False(t, repo.insertOK, "отказ до всякой записи: строки ключа нет")
		})
	}
}

// TestIssue_WithTheTokenEndpoint_ExchangedKindsAreIssued — законный близнец:
// та же выдача при объявленном эндпоинте проходит.
func TestIssue_WithTheTokenEndpoint_ExchangedKindsAreIssued(t *testing.T) {
	for name, in := range map[string]IssueInput{
		"KEYPAIR": {ServiceAccountID: "sva_test000000000000", CreatedByUserID: "usr_admin00000000000"},
		"FEDERATED": {ServiceAccountID: "sva_test000000000000", CreatedByUserID: "usr_admin00000000000",
			TrustedSubjects: federatedSubjects()},
	} {
		t.Run(name, func(t *testing.T) {
			repo := &stubSAClientRepo{}
			ops := &stubOpsRepo{}
			_, err := newEndpointlessIssueUC(repo, ops).WithOwnIssuance().Execute(context.Background(), in)
			require.NoError(t, err)
			waitForOp(t, ops)
			require.Nil(t, ops.lastErr, "выдача при объявленном эндпоинте обязана состояться")
			require.True(t, repo.insertOK)
			require.Equal(t, domain.CredentialKind(name), repo.inserted.CredentialKind)
		})
	}
}

// TestIssue_WithoutTheTokenEndpoint_SecretIsIssued — секрет обмена не
// требует: его предъявляют как есть, и выдаётся он без эндпоинта.
func TestIssue_WithoutTheTokenEndpoint_SecretIsIssued(t *testing.T) {
	repo := &stubSAClientRepo{}
	ops := &stubOpsRepo{}
	op, err := newEndpointlessIssueUC(repo, ops).Execute(context.Background(), IssueInput{
		ServiceAccountID: "sva_test000000000000",
		CreatedByUserID:  "usr_admin00000000000",
		CredentialKind:   domain.CredentialKindSecret,
		TTLSeconds:       3600,
	})
	require.NoError(t, err, "секрет не обменивается и эндпоинта не требует")
	require.NotNil(t, op)
	require.Nil(t, op.Error)
	require.True(t, repo.insertOK)
	require.Equal(t, domain.CredentialKindSecret, repo.inserted.CredentialKind)
	require.NotEmpty(t, repo.inserted.ID, "строка секрета обязана быть записана под своим идентификатором")
}
