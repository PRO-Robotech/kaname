// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// role_rights_stay_named_group_seam_world_integration_test.go — ЕДИНСТВЕННОЕ
// место, где проверка Р3 (PRO-Robotech/kaname#1037) входит в мир Э.
//
// Пробы группы C написаны до реализации и собирались на стволе без неё. Реализация
// провязывает испытуемого здесь и только здесь — теми же частями, что
// композиционный корень (`cmd/kaname/wiring.go`).

import (
	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	groupapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/group"
)

// escWireGroupAuthority — проверка Р3 в добавление участника мира Э над дверью
// решения `relations` (ESC-25 подставляет дверь, отказывающую ошибкой на
// вопросах об одном субъекте).
func escWireGroupAuthority(w *escWorld, u *groupapp.AddMemberUseCase, relations accessbindingapp.GrantAuthorityRelations) *groupapp.AddMemberUseCase {
	return u.WithGrantAuthority(accessbindingapp.NewScopeGrantAuthority(w.repo, relations))
}
