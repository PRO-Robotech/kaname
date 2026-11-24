// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package domain

// RegistrationAccountWriter — явное назначение установки, никогда не значение
// по умолчанию при создании аккаунта. ID переживают удаление выдачи в прикладном реестре.
type RegistrationAccountWriter struct {
	AssignmentID string `mapstructure:"assignment_id" yaml:"assignment_id"`
	AccountID    string `mapstructure:"account_id" yaml:"account_id"`
	Module       string `mapstructure:"module" yaml:"module"`
}

// DisabledRegistrationModule хранит решение оператора при первом обновлении для
// существующих объектов, чей модуль намеренно не включён для этого аккаунта.
type DisabledRegistrationModule struct {
	AccountID string `mapstructure:"account_id" yaml:"account_id"`
	Module    string `mapstructure:"module" yaml:"module"`
	Reason    string `mapstructure:"reason" yaml:"reason"`
}
