// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package humansession_test

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/stretchr/testify/require"
)

type legacyVerificationOnly struct{ humansession.VerificationStore }
type legacyEmailChangeOnly struct{ humansession.EmailChangeStore }
type legacyRecoveryCompletionOnly struct {
	humansession.RecoveryCompletionStore
}

func TestFullAdmissionRequiresPreparedCapability(t *testing.T) {
	for name, construct := range map[string]func() error{
		"request-verification": func() error {
			_, err := humansession.NewRequestVerificationUseCase(humansession.VerificationDeps{RequirePreparedWrite: true, Store: legacyVerificationOnly{}})
			return err
		},
		"confirm-verification": func() error {
			_, err := humansession.NewConfirmVerificationUseCase(humansession.VerificationDeps{RequirePreparedWrite: true, Store: legacyVerificationOnly{}})
			return err
		},
		"request-email-change": func() error {
			_, err := humansession.NewRequestEmailChangeUseCase(humansession.EmailChangeDeps{RequirePreparedWrite: true, Store: legacyEmailChangeOnly{}})
			return err
		},
		"confirm-email-change": func() error {
			_, err := humansession.NewConfirmEmailChangeUseCase(humansession.EmailChangeDeps{RequirePreparedWrite: true, Store: legacyEmailChangeOnly{}})
			return err
		},
		"recovery-completion": func() error {
			_, err := humansession.NewCompleteRecoveryUseCase(humansession.CompleteRecoveryDeps{RequirePreparedWrite: true, Completion: legacyRecoveryCompletionOnly{}})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := construct()
			require.ErrorContains(t, err, "prepared write capability required")
		})
	}
}
