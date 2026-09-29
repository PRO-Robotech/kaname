// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// credential_kind_wire_test.go — номер вида удостоверения, которого словарь
// выдачи не знает, отвергается с именем поля, а не выпускается ключевой парой
// (задача #362).
//
// # Предмет
//
// Словарь `CredentialKind` закрыт. Номер вне него — не «вид не назван»: вид
// назван, и назван тем, чего нет. Отобразить его в UNSPECIFIED значило бы
// выпустить ключевую пару на запрос, просивший другого, — принять параметр и
// молча его проигнорировать. После снятия вида LEGACY его номер 4 стал ровно
// таким номером: без этой пробы запрос, прежде отвергавшийся с именем поля,
// молча получил бы ключевую пару.
//
// Близнец — номер 0 («вид не назван»): прежнее поведение дословно.
package sa_keys

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/operations"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// TestHandlerIssue_CredentialKindOutsideTheVocabularyIsRefused — номера 4 и 99
// отвергаются синхронно, с именем поля; ничего не пишется.
func TestHandlerIssue_CredentialKindOutsideTheVocabularyIsRefused(t *testing.T) {
	for _, number := range []int32{4, 99} {
		repo := &stubSAClientRepo{}
		ops := &stubOpsRepo{}
		h := NewHandler(newEndpointlessIssueUC(repo, ops).WithOwnIssuance(), nil, nil)
		ctx := operations.WithPrincipal(context.Background(),
			operations.Principal{Type: "user", ID: "usr00000000000000007"})

		_, err := h.Issue(ctx, &iamv1.IssueSAKeyRequest{
			ServiceAccountId: "sva00000000000000001",
			CredentialKind:   iamv1.CredentialKind(number),
		})
		require.Equal(t, codes.InvalidArgument, grpcstatus.Code(err),
			"номер %d вне словаря обязан быть отвергнут, а не выпущен ключевой парой", number)
		require.Contains(t, grpcstatus.Convert(err).Message(), domain.ErrCredentialKindField,
			"номер %d: отказ обязан назвать поле", number)
		require.False(t, ops.created, "номер %d: отказ до всякой записи", number)
		require.False(t, repo.insertOK, "номер %d: строки ключа нет", number)
	}
}

// TestHandlerIssue_CredentialKindUnspecifiedKeepsTheOldBehaviour — близнец:
// «вид не назван» даёт ключевую пару, как прежде.
func TestHandlerIssue_CredentialKindUnspecifiedKeepsTheOldBehaviour(t *testing.T) {
	repo := &stubSAClientRepo{}
	ops := &stubOpsRepo{}
	h := NewHandler(newEndpointlessIssueUC(repo, ops).WithOwnIssuance(), nil, nil)
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr00000000000000007"})

	_, err := h.Issue(ctx, &iamv1.IssueSAKeyRequest{
		ServiceAccountId: "sva00000000000000001",
		CredentialKind:   iamv1.CredentialKind(0),
	})
	require.NoError(t, err)
	waitForOp(t, ops)
	require.Nil(t, ops.lastErr)
	require.Equal(t, domain.CredentialKindKeypair, repo.inserted.CredentialKind)
}
