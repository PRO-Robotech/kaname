// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// role_rights_stay_named_seam_world_integration_test.go — ЕДИНСТВЕННОЕ место,
// где проверка Р2 (PRO-Robotech/kaname#1036) входит в мир Э.
//
// Пробы группы B написаны до реализации и собираются на стволе без неё: тогда
// порта права выдавать у правки роли в дереве нет, и функция ниже отдаёт правку
// как есть. Реализация провязывает испытуемого здесь и только здесь — теми же
// частями, что композиционный корень (`cmd/kaname/wiring.go`).

import (
	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
)

// escWireRoleAuthority — проверка Р2 в правку роли мира Э над дверью решения
// `relations` (ESC-14 подставляет дверь, отказывающую ошибкой на вопросах об
// одном субъекте).
func escWireRoleAuthority(w *escWorld, u *roleapp.UpdateRoleUseCase, relations accessbindingapp.GrantAuthorityRelations) *roleapp.UpdateRoleUseCase {
	return u.WithGrantAuthority(accessbindingapp.NewScopeGrantAuthority(w.repo, relations))
}
