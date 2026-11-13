// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import "fmt"

// kaname#1034: выбор staged participation, не переключатель semantic gates.
// Legacy сохраняет прежних writers; participant не допускает fallback.
type AuthorityProtocolConfig struct {
	Participation string `mapstructure:"participation"`
}

func (c AuthorityProtocolConfig) Validate() error {
	switch c.Participation {
	case "", "legacy", "participant":
		return nil
	default:
		return fmt.Errorf("authority-protocol.participation must be legacy or participant")
	}
}
func (c AuthorityProtocolConfig) Participant() bool { return c.Participation == "participant" }
