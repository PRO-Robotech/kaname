// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"fmt"
	"strings"
)

// RoleWriterConfig задаёт отдельную учётную запись для записи ролей
// в основной PostgreSQL. Пустая конфигурация сохраняет общий пул.
type RoleWriterConfig struct {
	User            string `mapstructure:"user"`
	PasswordFromEnv string `mapstructure:"password-from-env"`
	// Ноль наследует предел основного пула.
	MaxConns int `mapstructure:"max-conns"`
}

func (c RoleWriterConfig) Enabled() bool {
	return c.User != "" || c.PasswordFromEnv != "" || c.MaxConns != 0
}

func (c RoleWriterConfig) Validate() error {
	if c.MaxConns < 0 || int64(c.MaxConns) > 1<<31-1 {
		return fmt.Errorf("repository.postgres.role-writer.max-conns must be zero or a positive int32")
	}
	if c.Enabled() && strings.TrimSpace(c.User) == "" {
		return fmt.Errorf("repository.postgres.role-writer.user must name the separate LOGIN")
	}
	return nil
}
