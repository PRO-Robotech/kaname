// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// issuance_moment_clock_test.go — момент выдачи удостоверения человека ставит
// поданный источник моментов (общий для всех реплик, kaname#589), а не
// умолчание столбца (задача kaname#388).
// Сквозную сторону — против базы и на каждой полосе правила отсечки — держит
// `one_clock_revoke_all_integration_test.go`; здесь — дешёвый страж без базы.
package user_tokens

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/momentclock"
)

func TestIssue_IssuanceMomentIsTheUseCaseClock(t *testing.T) {
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	for name, kind := range map[string]domain.CredentialKind{
		"SECRET":  domain.CredentialKindSecret,
		"KEYPAIR": domain.CredentialKindKeypair,
	} {
		t.Run(name, func(t *testing.T) {
			repo := &stubUserClientRepo{}
			ops := &stubOpsRepo{}
			uc := NewIssueUserTokenUseCase(repo, &stubTx{}, ops).WithIssuanceClock(momentclock.At(at)).WithOwnIssuance()
			_, err := uc.Execute(context.Background(), IssueInput{
				UserID: "usr00000000000000001", CreatedByUserID: "usr00000000000000001",
				CredentialKind: kind, TTLSeconds: 3600,
			})
			require.NoError(t, err)
			if kind == domain.CredentialKindKeypair {
				waitForOp(t, ops)
				require.Nil(t, ops.lastErr)
			}
			require.True(t, repo.inserted.CreatedAt.Equal(at),
				"момент выдачи %s, а часы варианта использования показывали %s", repo.inserted.CreatedAt, at)
			require.NotNil(t, repo.inserted.ExpiresAt)
			require.True(t, repo.inserted.ExpiresAt.Equal(at.Add(time.Hour)),
				"срок считан не от того же момента: %s", repo.inserted.ExpiresAt)
		})
	}
}
