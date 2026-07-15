// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package user

// internal_on_recovery_test.go — unit-tests (mock-port) for the sync stages of
// InternalUserService.OnRecoveryCompleted. The async writer-tx
// (idempotency / re-enable / revoke / audit) is covered by the testcontainers
// integration tests; here we pin the synchronous gates that must reject BEFORE
// the Operation is spawned (no side-effects), via mock ports.
//
//   - malformed/empty fields → INVALID_ARGUMENT (sync, table-driven).
//   - unknown external_id → NOT_FOUND (sync, no Operation).
//   - email-mismatch → FAILED_PRECONDITION (sync, no Operation).

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// recoveryFakeRepo wraps fakeUserRepo with a FindByExternalIDInStatuses seed.
// existingActive is reused as the identity-row store (the fake reader matches by
// external_id), so a BLOCKED row is also returned by FindByExternalIDInStatuses
// (the fake ignores the status filter — fine for the sync-gate unit tests).
func recoveryUC(rows []domain.User) *OnRecoveryCompletedUseCase {
	repo := newFakeUserRepo()
	repo.existingActive = rows
	return NewOnRecoveryCompletedUseCase(repo, newFakeOpsRepoUser())
}

// malformed/empty fields → INVALID_ARGUMENT, no Operation spawned.
func TestOnRecoveryCompleted_S06_MalformedFields_InvalidArgument(t *testing.T) {
	rows := []domain.User{{
		ID: "usr0000000000valid01", ExternalID: "krt_valid", Email: "valid@example.com",
		InviteStatus: domain.InviteStatusActive,
	}}
	longJTI := strings.Repeat("j", 129)
	longExt := domain.ExternalSubject(strings.Repeat("e", 129))
	longEmail := domain.Email(strings.Repeat("a", 312) + "@example.com") // >320

	cases := map[string]OnRecoveryCompletedInput{
		"a_empty_external_id": {ExternalID: "", RecoveryJTI: "rec1", Email: "valid@example.com"},
		"b_empty_jti":         {ExternalID: "krt_valid", RecoveryJTI: "", Email: "valid@example.com"},
		"c_empty_email":       {ExternalID: "krt_valid", RecoveryJTI: "rec1", Email: ""},
		"d_long_external_id":  {ExternalID: longExt, RecoveryJTI: "rec1", Email: "valid@example.com"},
		"e_long_email":        {ExternalID: "krt_valid", RecoveryJTI: "rec1", Email: longEmail},
		"f_long_jti":          {ExternalID: "krt_valid", RecoveryJTI: longJTI, Email: "valid@example.com"},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			uc := recoveryUC(rows)
			op, err := uc.Execute(context.Background(), in)
			require.Error(t, err)
			assert.Nil(t, op, "no Operation spawned on sync validation failure")
			st, _ := status.FromError(err)
			assert.Equal(t, codes.InvalidArgument, st.Code())
		})
	}
}

// unknown external_id → NOT_FOUND, no Operation.
func TestOnRecoveryCompleted_S03_UnknownExternalID_NotFound(t *testing.T) {
	uc := recoveryUC(nil) // no rows
	op, err := uc.Execute(context.Background(), OnRecoveryCompletedInput{
		ExternalID:  "krt_ghost",
		RecoveryJTI: "rec_flow_003",
		Email:       "ghost@example.com",
	})
	require.Error(t, err)
	assert.Nil(t, op)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.NotFound, st.Code())
}

// email-mismatch → FAILED_PRECONDITION, no Operation.
func TestOnRecoveryCompleted_S04_EmailMismatch_FailedPrecondition(t *testing.T) {
	rows := []domain.User{{
		ID: "usr0000000000carol01", ExternalID: "krt_carol", Email: "carol@example.com",
		InviteStatus: domain.InviteStatusActive,
	}}
	uc := recoveryUC(rows)
	op, err := uc.Execute(context.Background(), OnRecoveryCompletedInput{
		ExternalID:  "krt_carol",
		RecoveryJTI: "rec_flow_004",
		Email:       "attacker@evil.example.com",
	})
	require.Error(t, err)
	assert.Nil(t, op)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
	assert.Contains(t, err.Error(), "recovery email does not match user")
}
