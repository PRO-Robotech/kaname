// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package config

import (
	"fmt"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// Декларация nil запрещает боевой старт. Присутствующий пустой список assignments
// явно выбирает установку без включённых регистраторов.
type RegistrationAccountWritersConfig struct {
	// Оператор подтверждает, что вход обслуживает лишь редакция с контролем аккаунта.
	RetireClusterWriter bool                                `mapstructure:"retire-cluster-writer"`
	Assignments         []domain.RegistrationAccountWriter  `mapstructure:"assignments"`
	Disabled            []domain.DisabledRegistrationModule `mapstructure:"disabled"`
}

// ValidateRegistrationAccountWriters сохраняет различие пропущенного и явно пустого значения.
func (c Config) ValidateRegistrationAccountWriters() error {
	if c.RegistrationAccountWriters == nil {
		if c.AuthN.Mode.IsProduction() {
			return fmt.Errorf("registration-account-writers must be explicitly declared")
		}
		return nil
	}
	if c.RegistrationAccountWriters.Assignments == nil {
		return fmt.Errorf("registration-account-writers.assignments must be explicitly declared (an empty list disables registrars)")
	}
	return nil
}
