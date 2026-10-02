// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import "time"

// CeremonyFamilyBound — граница семейства собственной церемонии: меньшее из
// срока сессии, в которой семейство выдано, и рождения семейства плюс срок
// семейства, названный установкой (`authn.ceremony.refresh-ttl`, kaname#318).
// Семейство кончается вместе со своим входом и не живёт дольше своего срока:
// оборот выпускает преемника, но границы не сдвигает.
//
// Правило названо ЗДЕСЬ один раз: его спрашивают и выдача кода (рождение —
// момент выдачи), и сборка гранта из записи семейства (рождение — отметка
// строки). Сессия без срока (нулевой момент) границы не сужает. Потолок срока
// семейства судит страж старта; здесь срок — уже принятая величина.
func CeremonyFamilyBound(born, sessionExpiresAt time.Time, familyTTL time.Duration) time.Time {
	bound := born.Add(familyTTL)
	if !sessionExpiresAt.IsZero() && sessionExpiresAt.Before(bound) {
		return sessionExpiresAt
	}
	return bound
}
