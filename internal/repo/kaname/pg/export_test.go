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

// SweepUnservableSessionsSQL — оператор, который исполняет SweepUnservableSessions.
const SweepUnservableSessionsSQL = sweepUnservableSessionsSQL

// EndSessionsOfSQL — оператор снятия живых записей личности, который исполняет
// EndOtherSessions.
const EndSessionsOfSQL = endSessionsOfSQL

// Операторы выдачи кода (`IssueAuthorizationCode`) — ТЕ САМЫЕ тексты, из
// которых пробы перекрытия собирают контрольные руки: форму «замок одной лишь
// сессии», «только условие» и «только замок» (kaname#369). Рука, переписавшая
// оператор своей рукой, отличалась бы от продукта не одним фактом, а двумя.
const (
	LockUserForKeySQL            = lockUserForKeySQL
	LockCeremonyClientSQL        = lockCeremonyClientSQL
	LockSessionOfCeremonySQL     = lockSessionOfCeremonySQL
	InsertFamilyOnLiveSessionSQL = insertFamilyOnLiveSessionSQL
	SessionCutOffBySubjectSQL    = sessionCutOffBySubjectSQL
)
