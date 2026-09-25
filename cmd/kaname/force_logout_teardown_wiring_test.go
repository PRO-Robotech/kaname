// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// force_logout_teardown_wiring_test.go — ЧЬЮ СЕССИЮ СНИМАЕТ ПРИНУДИТЕЛЬНЫЙ
// ВЫХОД, РЕШАЕТ ПОСАДКА (задача kaname#313).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Снятие сессии входа провязывалось БЕЗУСЛОВНО и вело к внешнему поставщику.
// Под `own` поставщика нет: строитель отдаёт отставленного клиента без адреса,
// снятие отказывает терминально, а отказ снятия делает недоступным ВЕСЬ глагол.
// То есть распорядитель не мог вывести никого.
//
// Здесь судится ВЫБОР корня: ровно один исполнитель на посадку, и «никого»
// выражено ЧИСТЫМ nil — типизированный прошёл бы страж провязки насквозь и
// упал бы на разыменовании вместо честного «снимать здесь нечего».
//
// Поведение самого снятия судится там, где оно наблюдаемо:
// под `own` — `internal/apps/kaname/api/internal_iam/force_logout_own_session_integration_test.go`,
// под `external` — `force_logout_session_test.go` того же пакета.
package main

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// TestCompositionRoot_ForceLogoutTearsDownOurOwnSessionUnderOwnPosture —
// под `own` снимается НАША запись, и чужая дорога не провязывается вовсе.
func TestCompositionRoot_ForceLogoutTearsDownOurOwnSessionUnderOwnPosture(t *testing.T) {
	cfg := roadCfg(config.IdentityProviderOwn, "9097")

	own := forceLogoutOwnSessions(cfg, nil)
	if own == nil {
		t.Fatal("под собственной посадкой снимать нашу запись сессии входа НЕЧЕМ: " +
			"отсечка субъекта её не покрывает — резолв сессии отсечку не применяет " +
			"by construction, и носитель, выданный до выхода, резолвится после него")
	}

	sessions, resolver := forceLogoutProviderSessions(cfg, nil, nil)
	if sessions != nil || resolver != nil {
		t.Errorf("под собственной посадкой провязана дорога к чужому поставщику "+
			"(%T, %T) — её нет, и всякий вызов по ней отказывает терминально, "+
			"делая недоступным весь глагол", sessions, resolver)
	}
}

// TestCompositionRoot_ForceLogoutKeepsTheProviderTeardownUnderExternalPosture —
// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: прежняя посадка снимает сессию там же, где снимала.
//
// Без него отрицания выше зеленели бы на корне, который не провязывает чужую
// дорогу НИКОГДА, — то есть на сломанной прежней посадке, где она и есть
// единственный исполнитель.
func TestCompositionRoot_ForceLogoutKeepsTheProviderTeardownUnderExternalPosture(t *testing.T) {
	cfg := roadCfg(config.IdentityProviderExternal, "9097")

	sessions, resolver := forceLogoutProviderSessions(cfg, nil, nil)
	if sessions == nil {
		t.Fatal("под external снятие сессии у поставщика НЕ провязано — " +
			"поведение прежней посадки эта задача не меняет")
	}
	if resolver == nil {
		t.Fatal("под external не провязано разрешение имени субъекта: снятие идёт " +
			"по имени, которое знает поставщик, а не по нашему users.id")
	}

	if own := forceLogoutOwnSessions(cfg, nil); own != nil {
		t.Errorf("под external провязано снятие НАШИХ записей сессии входа (%T) — "+
			"полоса входа на этой посадке не поднимается вовсе, и записей нет", own)
	}
}
