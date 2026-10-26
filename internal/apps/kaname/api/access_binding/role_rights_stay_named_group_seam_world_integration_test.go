// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// role_rights_stay_named_group_seam_world_integration_test.go — ЕДИНСТВЕННОЕ
// место, где проверка Р3 (PRO-Robotech/kaname#1037) входит в мир Э.
//
// Пробы группы C написаны до реализации и собираются на стволе без неё: тогда
// порта права выдавать у добавления участника в дереве нет, и функция ниже
// отдаёт добавление как есть. Реализация провязывает испытуемого здесь и только
// здесь — теми же частями, что композиционный корень (`cmd/kaname/wiring.go`).

import (
	groupapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/group"
	"github.com/PRO-Robotech/kaname/internal/clients"
)

// escWireGroupAuthority — проверка Р3 в добавление участника мира Э над дверью
// решения `relations` (ESC-25 подставляет дверь, отказывающую ошибкой на
// вопросах об одном субъекте). До реализации порта нет: добавление отдаётся как есть.
func escWireGroupAuthority(_ *escWorld, u *groupapp.AddMemberUseCase, _ clients.RelationStore) *groupapp.AddMemberUseCase {
	return u
}
