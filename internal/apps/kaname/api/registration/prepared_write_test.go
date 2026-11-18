// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package registration_test

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
	"github.com/stretchr/testify/require"
)

func TestFullRegistrationRequiresPreparedCapability(t *testing.T) {
	_, err := registration.NewRegisterUseCase(registration.Deps{RequirePreparedWrite: true, Store: &unitStore{}})
	require.ErrorContains(t, err, "prepared write capability required")
}
