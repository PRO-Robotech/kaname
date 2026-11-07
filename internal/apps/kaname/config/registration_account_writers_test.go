// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package config

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/stretchr/testify/require"
)

func TestRegistrationWriterDeclarationDistinguishesOmissionAndEmpty(t *testing.T) {
	// Объявление без списка назначений никогда не означает явно пустой план.
	c := Config{RegistrationAccountWriters: &RegistrationAccountWritersConfig{}}
	require.Error(t, c.ValidateRegistrationAccountWriters())
	c.RegistrationAccountWriters.Assignments = []domain.RegistrationAccountWriter{}
	require.NoError(t, c.ValidateRegistrationAccountWriters())
}

func TestRegistrationWriterProductionDeclarationIsRequired(t *testing.T) {
	for _, mode := range []Mode{ModeProduction, ModeProductionStrict} {
		c := Config{AuthN: AuthNConfig{Mode: mode}}
		require.EqualError(t, c.ValidateRegistrationAccountWriters(), "registration-account-writers must be explicitly declared")
		c.RegistrationAccountWriters = &RegistrationAccountWritersConfig{}
		require.EqualError(t, c.ValidateRegistrationAccountWriters(), "registration-account-writers.assignments must be explicitly declared (an empty list disables registrars)")
		c.RegistrationAccountWriters.Assignments = []domain.RegistrationAccountWriter{}
		require.NoError(t, c.ValidateRegistrationAccountWriters())
	}
}
