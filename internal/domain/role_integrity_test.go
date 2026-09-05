// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// role_integrity_test.go — состояние целости роли из пары величин.
//
// Приёмка `services/iam/docs/engineering/acceptance/role-degradation-is-visible-in-get-and-list.md`,
// сценарии IAM-RH-1-01…06, RED-шаг 1 (§9): чистые величины, без базы.
//
// Здесь утверждается ФУНКЦИЯ, а не то, что состояние 513001 в этом дереве
// представимо, — второе утверждает интеграционная проба (шаг 3). Разные
// утверждения, и первое второго не покрывает.

import "testing"

// IAM-RH-1-01 — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ. Без него всякое отрицание ниже зеленело
// бы на реализации, всегда возвращающей «неразрешённых нет».
func TestRoleIntegrity_IAMRH0101_AllSegmentsProjected_IsHealthy(t *testing.T) {
	got := HealthOf(2, 0)
	if got.Health != RoleHealthHealthy {
		t.Fatalf("объявлено 2, неразрешённых 0: состояние %v, ожидалось HEALTHY", got.Health)
	}
	if got.Declared != 2 || got.Unresolved != 0 {
		t.Fatalf("счётчики %d/%d, ожидалось 2/0", got.Unresolved, got.Declared)
	}
}

// IAM-RH-1-02 — форма инцидента 513001: объявлено, не спроецировано НИ ОДНОГО.
// Условие Declared > 0 несущее: без него сценарий проходил бы на роли, которая
// не объявляет ничего.
func TestRoleIntegrity_IAMRH0102_NothingProjected_IsEmpty(t *testing.T) {
	got := HealthOf(2, 2)
	if got.Health != RoleHealthEmpty {
		t.Fatalf("объявлено 2, неразрешённых 2: состояние %v, ожидалось EMPTY", got.Health)
	}
	if got.Declared == 0 {
		t.Fatal("Declared обязан быть > 0, иначе утверждение вырождается")
	}
	if got.Unresolved != got.Declared {
		t.Fatalf("неразрешённых %d, объявлено %d — обязаны совпасть", got.Unresolved, got.Declared)
	}
}

// IAM-RH-1-03 — часть спроецирована, часть нет.
func TestRoleIntegrity_IAMRH0103_PartlyProjected_IsDegraded(t *testing.T) {
	got := HealthOf(2, 1)
	if got.Health != RoleHealthDegraded {
		t.Fatalf("объявлено 2, неразрешённых 1: состояние %v, ожидалось DEGRADED", got.Health)
	}
	if got.Declared != 2 || got.Unresolved != 1 {
		t.Fatalf("счётчики %d/%d, ожидалось 1/2", got.Unresolved, got.Declared)
	}
}

// IAM-RH-1-04 и IAM-RH-1-05 — роль без АДРЕСУЕМЫХ сегментов тревоги не поднимает.
// Прибор, чьи находки ложны, перестают читать: подстановка в модуле и ресурсе
// сегментов не даёт (`RuleRefsOf`), и роль `*.*` обязана читаться здоровой.
func TestRoleIntegrity_IAMRH0104_0105_NothingAddressable_IsHealthyNotEmpty(t *testing.T) {
	got := HealthOf(0, 0)
	if got.Health != RoleHealthHealthy {
		t.Fatalf("объявлено 0: состояние %v, ожидалось HEALTHY (ложная тревога на роли `*.*`)", got.Health)
	}
	if got.Declared != 0 || got.Unresolved != 0 {
		t.Fatalf("счётчики %d/%d, ожидалось 0/0", got.Unresolved, got.Declared)
	}
}

// НОЛЬ СЧЁТЧИКА ОТЛИЧИМ ОТ «НЕ СЧИТАЛИ» — и различает их состояние, а не счётчик.
// Класс §1.3 скила `code-authoring`: ноль есть И законная величина, И признак
// отсутствия. Разводит их перечислимое: невычисленная целость несёт нулевой
// вариант, вычисленная — никогда.
func TestRoleIntegrity_ZeroIsDistinguishableFromNotComputed(t *testing.T) {
	var notComputed RoleIntegrity // нулевое значение — «не вычислено этим путём»
	if notComputed.Health != RoleHealthUnknown {
		t.Fatalf("нулевое значение несёт %v, ожидалось UNKNOWN", notComputed.Health)
	}
	computed := HealthOf(0, 0)
	if computed.Health == RoleHealthUnknown {
		t.Fatal("вычисленная целость роли без сегментов не имеет права быть UNKNOWN: " +
			"иначе «посчитано, терять нечего» неотличимо от «не считали»")
	}
	if notComputed.Declared != computed.Declared || notComputed.Unresolved != computed.Unresolved {
		t.Fatal("предпосылка пробы: у обоих счётчики нулевые — различать обязано состояние")
	}
}
