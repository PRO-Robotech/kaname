// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"log/slog"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
)

// bootstrapAdminTask — фоновая задача посева первого администратора.
//
// Строка о старте называет администратора признаком «адрес задан», а не
// адресом (kaname#631): адрес — персональные данные и в журнал не пишется ни
// на каком уровне. Задача вынесена из тела runServe, чтобы этот журнал судила
// проба, а не прочтение кода.
func bootstrapAdminTask(logger *slog.Logger, email string, run func() error) func() error {
	return func() error {
		if email == "" {
			logger.Info("bootstrap admin disabled (KANAME_BOOTSTRAP_ROOT_EMAIL unset)")
			return nil
		}
		logger.Info("bootstrap admin reconciler starting", seed.BootstrapAddressAttr(email))
		// Non-fatal: reconciler errors must not crash the server. It returns
		// nil on convergence / terminal-skip / shutdown by design.
		return run()
	}
}
