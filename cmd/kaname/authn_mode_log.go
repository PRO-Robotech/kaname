// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"log/slog"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// logAuthnMode называет режим authn, в котором поднялась служба.
//
// INFO в обоих боевых режимах (#610): это сообщение о ШТАТНОЙ посадке, а не
// предупреждение. Основание одно на обе строки, поэтому и уровень один. Режим
// разработки строки отсюда не получает — его отклонения называет
// `cfg.InsecureDevWarnings()` уровнем WARN, и там он законен.
func logAuthnMode(logger *slog.Logger, mode config.Mode) {
	switch mode {
	case config.ModeProduction:
		logger.Info("authn.mode=production: anonymous callers will be rejected (fail-closed)")
	case config.ModeProductionStrict:
		logger.Info("authn.mode=production-strict: anonymous rejected + TLS+SSL strictly validated")
	case config.ModeDev:
	}
}
