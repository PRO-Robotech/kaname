// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// issue_kind_and_lifetime_outcomes_test.go — два исхода выдачи удостоверения
// человека, которые контракт и страница токенов называют словами, а пробы у
// них не было (задачи kaname#507, kaname#516):
//
//   - FEDERATED у личности отвергается СИНХРОННО, с именем поля и до всякой
//     записи: в контракте личности нет поля, которым он задаётся;
//   - KEYPAIR с `ttl_seconds = 0` выдаётся БЕССРОЧНЫМ — в отличие от ключа
//     служебной учётки, где ноль означает умолчание установки.
//
// Каждый исход держится в паре с законным близнецом, отличающимся одним
// фактом: без близнеца проба отказа зеленела бы и на выдаче, отказывающей всем.
package user_tokens

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/momentclock"
)

// federatedRefusalText — отказ, который называет страница токенов и контракт.
const federatedRefusalText = "credential_kind: FEDERATED is not available for this credential — it has no trusted_subjects field"

func TestIssue_FederatedForAPersonIsRefusedSynchronouslyByFieldName(t *testing.T) {
	repo := &stubUserClientRepo{}
	ops := &stubOpsRepo{}
	uc := NewIssueUserTokenUseCase(repo, &stubTx{}, ops).WithIssuanceClock(momentclock.Func(time.Now)).WithOwnIssuance()

	op, err := uc.Execute(context.Background(), IssueInput{
		UserID: "usr00000000000000001", CreatedByUserID: "usr00000000000000001",
		CredentialKind: domain.CredentialKindFederated,
	})
	require.Nil(t, op, "отказ вида обязан прийти до заведения операции")
	st, ok := grpcstatus.FromError(err)
	require.True(t, ok, "ожидался статус gRPC, получено %v", err)
	require.Equal(t, codes.InvalidArgument, st.Code())
	require.Equal(t, federatedRefusalText, st.Message())
	require.Empty(t, repo.inserted.ID, "строка удостоверения записана при отказанном виде")

	// Близнец: тот же запрос с видом KEYPAIR выдаётся.
	twinRepo := &stubUserClientRepo{}
	twinOps := &stubOpsRepo{}
	twin := NewIssueUserTokenUseCase(twinRepo, &stubTx{}, twinOps).WithIssuanceClock(momentclock.Func(time.Now)).WithOwnIssuance()
	twinOp, err := twin.Execute(context.Background(), IssueInput{
		UserID: "usr00000000000000001", CreatedByUserID: "usr00000000000000001",
		CredentialKind: domain.CredentialKindKeypair,
	})
	require.NoError(t, err)
	require.NotNil(t, twinOp)
	waitForOp(t, twinOps)
	require.Nil(t, twinOps.lastErr)
	require.NotEmpty(t, twinRepo.inserted.ID)
}

func TestIssue_KeypairWithZeroTTLIsIssuedWithoutExpiry(t *testing.T) {
	at := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	issue := func(t *testing.T, ttl int64) *stubUserClientRepo {
		t.Helper()
		repo := &stubUserClientRepo{}
		ops := &stubOpsRepo{}
		uc := NewIssueUserTokenUseCase(repo, &stubTx{}, ops).WithIssuanceClock(momentclock.At(at)).WithOwnIssuance()
		_, err := uc.Execute(context.Background(), IssueInput{
			UserID: "usr00000000000000001", CreatedByUserID: "usr00000000000000001",
			CredentialKind: domain.CredentialKindKeypair, TTLSeconds: ttl,
		})
		require.NoError(t, err)
		waitForOp(t, ops)
		require.Nil(t, ops.lastErr)
		return repo
	}

	zero := issue(t, 0)
	require.Nil(t, zero.inserted.ExpiresAt,
		"ключевая пара человека с ttl_seconds=0 получила срок %v — контракт называет её бессрочной",
		zero.inserted.ExpiresAt)

	// Близнец: названный срок применяется дословно.
	named := issue(t, 3600)
	require.NotNil(t, named.inserted.ExpiresAt)
	require.True(t, named.inserted.ExpiresAt.Equal(at.Add(time.Hour)))
}
