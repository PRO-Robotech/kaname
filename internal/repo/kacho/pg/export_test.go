// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// export_test.go — мост для проб пакета, намеренно УЗКИЙ.
//
// Здесь только то, чего проба не вправе написать своей рукой: ТЕКСТ оператора
// состава и ВЕЛИЧИНА его предела. Проба, переписавшая оператор, замеряла бы
// другой запрос — и осталась бы зелёной ровно тогда, когда предел сняли с
// настоящего.

// MembersOfGroupsSQL — оператор, который исполняет MembersOfGroups.
const MembersOfGroupsSQL = membersOfGroupsSQL

// MaxMembersInGrantSurface — предел состава, возвращаемого одним перечислением.
const MaxMembersInGrantSurface = maxMembersInGrantSurface
