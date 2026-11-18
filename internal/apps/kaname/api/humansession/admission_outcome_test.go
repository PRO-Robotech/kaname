// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package humansession_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/testsupport/momentclock"
	"github.com/stretchr/testify/require"
)

type admissionExhaustedOutcome struct { error }
func (admissionExhaustedOutcome) PreparedAttemptsExhausted() bool { return true }
func (e admissionExhaustedOutcome) Unwrap() error { return e.error }

type admissionCleanupOutcome struct { error }
func (admissionCleanupOutcome) PreparedCleanupFailed() bool { return true }
func (e admissionCleanupOutcome) Unwrap() error { return e.error }

func admissionFailureCases() map[string]error {
	exhausted := admissionExhaustedOutcome{errors.Join(iamerr.ErrAborted, errors.New("private-schema-secret"))}
	return map[string]error{
		"exhausted": exhausted,
		"cancel": errors.Join(exhausted, context.Canceled),
		"deadline": errors.Join(exhausted, context.DeadlineExceeded),
		"unknown-commit": errors.New("private-connection-secret"),
		"cleanup": errors.Join(exhausted, admissionCleanupOutcome{errors.New("private-cleanup-secret")}),
		"legacy-aborted": errors.Join(iamerr.ErrAborted, errors.New("private-legacy-secret")),
	}
}
func assertAdmissionOutcome(t *testing.T, name string, err error) {
	t.Helper()
	if name == "exhausted" {
		require.ErrorIs(t, err, iamerr.ErrAborted)
		require.EqualError(t, err, "aborted: " + iamerr.SerializationConflictSyncText)
		require.NotErrorIs(t, err, humansession.ErrStoreUnavailable)
	} else {
		require.ErrorIs(t, err, humansession.ErrStoreUnavailable)
		require.NotErrorIs(t, err, iamerr.ErrAborted)
	}
	require.NotContains(t, err.Error(), "private-")
}

type admissionOutcomeStore struct {
	*ecStore
	humansession.VerificationStore
	failure error
	calls int
}
func (s *admissionOutcomeStore) Resolve(ctx context.Context, digest domain.BearerDigest, now time.Time) (humansession.Resolved, humansession.NoSessionReason, error) {
	return s.ecStore.Resolve(ctx, digest, now)
}
func (s *admissionOutcomeStore) RunVerificationWrite(context.Context, domain.UserID, func(context.Context, humansession.VerificationWriter) error) error { s.calls++; return s.failure }
func (s *admissionOutcomeStore) RunEmailChangeWrite(context.Context, domain.UserID, func(context.Context, humansession.EmailChangeWriter) error) error { s.calls++; return s.failure }

type recoveryOutcomeStore struct {
	humansession.RecoveryCompletionStore
	failure error
	calls int
}
func (s *recoveryOutcomeStore) RunRecoveryCompletionWrite(context.Context, domain.UserID, func(context.Context, humansession.RecoveryCompletionWriter) error) error { s.calls++; return s.failure }

// Ошибка поступает из завершённого backend executor: UC не повторяет его и
// сохраняет различие исчерпанного abort и неопределённого терминального исхода.
func TestAdmissionUseCasesPreserveTerminalOutcome(t *testing.T) {
	for name, failure := range admissionFailureCases() {
		t.Run(name, func(t *testing.T) {
			for _, confirm := range []bool{false, true} {
				s, bearer := newECStore(t)
				s.resolved.EmailVerified = false
				store := &admissionOutcomeStore{ecStore: s, failure: failure}
				deps := humansession.VerificationDeps{RequirePreparedWrite: true, Store: store, Pace: ecDeps(s).Pace}
				var err error
				if confirm {
					uc, e := humansession.NewConfirmVerificationUseCase(deps)
					require.NoError(t, e)
					_, err = uc.Execute(context.Background(), humansession.ConfirmVerificationInput{Bearer: bearer, Code: "123456"})
				} else {
					uc, e := humansession.NewRequestVerificationUseCase(deps)
					require.NoError(t, e)
					_, err = uc.Execute(context.Background(), bearer)
				}
				assertAdmissionOutcome(t, name, err)
				require.Equal(t, 1, store.calls)
			}
			for _, confirm := range []bool{false, true} {
				s, bearer := newECStore(t)
				store := &admissionOutcomeStore{ecStore: s, failure: failure}
				deps := ecDeps(s)
				deps.Store, deps.RequirePreparedWrite = store, true
				var err error
				if confirm {
					uc, e := humansession.NewConfirmEmailChangeUseCase(deps)
					require.NoError(t, e)
					_, err = uc.Execute(context.Background(), humansession.ConfirmEmailChangeInput{Bearer: bearer, Code: "123456"})
				} else {
					uc, e := humansession.NewRequestEmailChangeUseCase(deps)
					require.NoError(t, e)
					_, err = uc.Execute(context.Background(), humansession.RequestEmailChangeInput{Bearer: bearer, NewEmail: "new@example.invalid"})
				}
				assertAdmissionOutcome(t, name, err)
				require.Equal(t, 1, store.calls)
			}
			h := newHarness(t, nil)
			h.person(t, "usr-outcome", "outcome@example.invalid", "old-password-1", true)
			store := &recoveryOutcomeStore{RecoveryCompletionStore: h.store, failure: failure}
			uc, err := humansession.NewCompleteRecoveryUseCase(humansession.CompleteRecoveryDeps{
				RequirePreparedWrite: true, Store: h.store, Completion: store, Hasher: h.hasher, Rule: h.rule,
				Limits: limits(), TTL: ucTTL, Now: func() time.Time { return ucBase }, CutoffClock: momentclock.Func(func() time.Time { return ucBase }),
			})
			require.NoError(t, err)
			_, err = uc.Execute(context.Background(), humansession.CompleteRecoveryInput{Email: "outcome@example.invalid", Code: "123456", NewPassword: "new-password-2"})
			assertAdmissionOutcome(t, name, err)
			require.Equal(t, 1, store.calls)
		})
	}
}
