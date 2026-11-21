// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmap

import "github.com/PRO-Robotech/kaname/internal/domain"

// BindingScopeRelations — прямые отношения на якоре, которые выдача роли
// выпускает при записи. Это общий выбор ВЕТВИ настоящего buildBindingTuples:
// любая роль с Rules, в том числе *.* на cluster, здесь прав не выпускает;
// роль без правил и без Permissions также ничего не выпускает. Иерархический
// указатель выдачи строится отдельно, он не относится к этим правам.
//
// Непустая прежняя роль без Rules использует существующие производители
// яруса и прямого имени области: на cluster это system_admin/system_viewer.
// Здесь нет нового пути, превращающего wildcard-правило в кластерного админа.
// ScopeSelfVerbs и пообъектная материализация правил — отдельные эффекты;
// отсутствие отношений этой стадии не означает пустого полного эффекта роли.
func BindingScopeRelations(scopeType string, role domain.Role) []Relation {
	if scopeType == "" || len(role.Rules) > 0 || len(role.Permissions) == 0 {
		return nil
	}
	permissions := make([]string, len(role.Permissions))
	for i, permission := range role.Permissions {
		permissions[i] = string(permission)
	}
	return ScopeDirectRelations(scopeType, LegacyScopeTierRelations(scopeType, permissions))
}
