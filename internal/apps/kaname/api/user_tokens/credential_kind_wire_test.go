// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// credential_kind_wire_test.go — номер вида удостоверения, которого словарь
// выдачи не знает, отвергается с именем поля, а не выпускается ключевой парой
// (задача #362). Довод — в одноимённой пробе ключа служебной учётки: полосы
// выдачи обязаны отвечать на один вход одинаково.
package user_tokens

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
		repo := &stubUserClientRepo{}
		ops := &stubOpsRepo{}
		h := NewHandler(newIssueUCForTest(repo, ops), nil, nil)
		ctx := operations.WithPrincipal(context.Background(),
			operations.Principal{Type: "user", ID: "usr00000000000000001"})

		_, err := h.Issue(ctx, &iamv1.IssueUserTokenRequest{
			UserId:         "usr00000000000000001",
			CredentialKind: iamv1.CredentialKind(number),
		})
		require.Equal(t, codes.InvalidArgument, grpcstatus.Code(err),
			"номер %d вне словаря обязан быть отвергнут, а не выпущен ключевой парой", number)
		require.Contains(t, grpcstatus.Convert(err).Message(), domain.ErrCredentialKindField,
			"номер %d: отказ обязан назвать поле", number)
		require.Empty(t, repo.inserted.ID, "номер %d: строки токена нет", number)
	}
}

// TestHandlerIssue_CredentialKindUnspecifiedKeepsTheOldBehaviour — близнец:
// «вид не назван» даёт ключевую пару, как прежде.
func TestHandlerIssue_CredentialKindUnspecifiedKeepsTheOldBehaviour(t *testing.T) {
	repo := &stubUserClientRepo{}
	ops := &stubOpsRepo{}
	h := NewHandler(newIssueUCForTest(repo, ops), nil, nil)
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr00000000000000001"})

	_, err := h.Issue(ctx, &iamv1.IssueUserTokenRequest{
		UserId:         "usr00000000000000001",
		CredentialKind: iamv1.CredentialKind(0),
	})
	require.NoError(t, err)
	waitForOp(t, ops)
	require.Nil(t, ops.lastErr)
	require.Equal(t, domain.CredentialKindKeypair, repo.inserted.CredentialKind)
}
