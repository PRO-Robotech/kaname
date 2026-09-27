// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import (
	"time"

	"github.com/PRO-Robotech/corelib/tokenpolicy"
)

// CeremonyFamilyBound — граница семейства собственной церемонии: меньшее из
// срока сессии, в которой семейство выдано, и потолка семейства фундамента
// (`tokenpolicy.MaxRefreshTokenFamilyTTL`) от его рождения. Семейство кончается
// вместе со своим входом.
//
// Правило названо ЗДЕСЬ один раз: его спрашивают и выдача кода (рождение —
// момент выдачи), и сборка гранта из записи семейства (рождение — отметка
// строки). Сессия без срока (нулевой момент) границы не сужает.
func CeremonyFamilyBound(born, sessionExpiresAt time.Time) time.Time {
	bound := born.Add(tokenpolicy.MaxRefreshTokenFamilyTTL)
	if !sessionExpiresAt.IsZero() && sessionExpiresAt.Before(bound) {
		return sessionExpiresAt
	}
	return bound
}
