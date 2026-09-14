// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// ДОРОГА К ВНЕШНЕМУ ПОСТАВЩИКУ НА ПОЛОСЕ `own` НЕ СТРОИТСЯ (задачи #2489,
// `kaname#21`, `kacho#2573`).
//
// # ЗДЕСЬ СТОЯЛО «СЕГОДНЯ КОРЕНЬ СТРОИТ ЕЁ БЕЗУСЛОВНО» — И ЭТО УСТАРЕЛО
//
// Прежняя редакция шапки описывала корень, который строил дорогу без единой
// ветви по посадке личности, и называла требование записанным ВПЕРЁД дефекта.
// Корень с тех пор исправлен: строитель административного клиента первым своим
// оператором спрашивает `providerAdminHopIsBuilt`, и на посадке без внешнего
// поставщика отдаёт отставленного клиента БЕЗ адреса; запись зеркала чужого
// набора ключей публикуется по тому же предикату.
//
// Утверждение пережило свой предмет и продолжало читаться как описание дерева —
// а читается шапка чаще тела. Перемерено вместе с правкой второго читателя
// адреса (`kacho#2573`): чтений резолвера в дереве одно, у строителя.
//
// # ПОЧЕМУ СТРОКА ТАБЛИЦЫ ОСТАЁТСЯ
//
// Предмет строки — ПРОВЯЗКА, а не то, чем она сегодня оказалась. Починка,
// правящая таблицу вместо проводки, сняла бы проверку вместо дефекта; починка,
// снимающая строку после того как проводка исправлена, снимает единственное,
// что удержит её исправной завтра.
//
// Где проверено, что корень СТАВИТ В ЭТИ ПОЛЯ ПРАВДУ, — другой конец предмета и
// другой пакет: `cmd/kaname/lane_provider_road_wiring_test.go`. Здесь судится
// сама строка требования: что заявленная провязка отвергает старт.
//
// Требование — стадии ПРОВЯЗКИ, а не настройки, и это решение. Настройкой оно
// невыразимо by construction: оба резолва деривируют значение из доменного
// имени, поэтому «под own адрес пуст» не выполнимо ни при каком профиле, а
// требование, которого нельзя выполнить, требованием не является.
func TestProviderRoad_OwnLaneRefusesTheAdminHopBeingBuilt(t *testing.T) {
	cfg := laneCfg(config.IdentityProviderOwn)

	w := wiredLane()
	w.ProviderAdminHopBuilt = true

	err := config.ValidateLaneWiring(cfg, w)
	if err == nil {
		t.Fatal("ValidateLaneWiring() = nil; под own собранная административная дорога " +
			"к внешнему поставщику обязана отвергать старт")
	}
	if !strings.Contains(err.Error(), config.IdentityProviderSetting) {
		t.Fatalf("отказ обязан называть поле посадки, получено: %q", err.Error())
	}
}

func TestProviderRoad_OwnLaneRefusesTheKeySetMirrorBeingPublished(t *testing.T) {
	cfg := laneCfg(config.IdentityProviderOwn)

	w := wiredLane()
	w.ProviderKeySetMirrorPublished = true

	err := config.ValidateLaneWiring(cfg, w)
	if err == nil {
		t.Fatal("ValidateLaneWiring() = nil; под own опубликованная запись зеркала чужого " +
			"набора ключей обязана отвергать старт")
	}
	if !strings.Contains(err.Error(), config.IdentityProviderSetting) {
		t.Fatalf("отказ обязан называть поле посадки, получено: %q", err.Error())
	}
}

// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ 1: полоса `own`, на которой ни дороги, ни записи
// зеркала нет, проходит. Без него отрицания выше зеленели бы на проверке,
// отвергающей вообще всё.
func TestProviderRoad_OwnLaneWithoutTheProviderRoadPasses(t *testing.T) {
	cfg := laneCfg(config.IdentityProviderOwn)

	if err := config.ValidateLaneWiring(cfg, wiredLane()); err != nil {
		t.Fatalf("ValidateLaneWiring() = %v; полоса own без дороги к поставщику обязана проходить", err)
	}
}

// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ 2: полосность. На `external` дорога и запись зеркала
// — обязательная часть посадки, и их наличие требованием не нарушает ничего.
func TestProviderRoad_ExternalLaneIsNotAskedToGiveUpTheRoad(t *testing.T) {
	cfg := laneCfg(config.IdentityProviderExternal)

	w := wiredLane()
	w.ProviderAdminHopBuilt = true
	w.ProviderKeySetMirrorPublished = true

	if err := config.ValidateLaneWiring(cfg, w); err != nil {
		t.Fatalf("ValidateLaneWiring() = %v; под external дорога к поставщику законна", err)
	}
}
