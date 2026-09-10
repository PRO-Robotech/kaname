// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// ДОРОГА К ВНЕШНЕМУ ПОСТАВЩИКУ НА ПОЛОСЕ `own` НЕ СТРОИТСЯ (задача #2489).
//
// Сегодня композиционный корень строит её БЕЗУСЛОВНО: строитель
// административного клиента зовётся из четырёх мест без единой ветви по
// посадке личности, а резолв адреса пустого не возвращает никогда — при
// незаданной ручке он выводит адрес из доменного имени. Запись зеркала чужого
// набора ключей добавляется так же безусловно.
//
// На посадке, где внешнего поставщика нет вовсе, процесс держит к нему дорогу
// и публикует запись зеркала на стандартном пути. Живым дефектом это сегодня
// не является — полоса `own` не поднимается по двум другим строкам таблицы, —
// и ровно поэтому требование записывается СТРОКОЙ: иначе оно доедет до той
// самой полосы, ради которой службу выносят, никем не замеченное.
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
