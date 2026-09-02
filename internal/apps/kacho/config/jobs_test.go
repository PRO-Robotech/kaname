// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// jobs_test.go — страж старта секции фоновых заданий (задача #1264).

package config

import (
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
)

const testRegistryTokenTTL = 5 * time.Minute

func goodReclaim() ExpiredCredentialReclaimConfig {
	return ExpiredCredentialReclaimConfig{
		Enabled:   true,
		Interval:  time.Hour,
		Grace:     tokenpolicy.ExpiredCredentialReclaimGrace,
		BatchSize: 200,
	}
}

// Умолчания дерева обязаны проходить собственного стража.
//
// Настройка, которую отвергает её же страж, означает сервис, не поднимающийся
// из коробки, — и узнать об этом можно было бы только запуском.
func TestReclaimDefaultsPassTheirOwnGuard(t *testing.T) {
	if err := goodReclaim().Validate(testRegistryTokenTTL); err != nil {
		t.Fatalf("умолчания обязаны проходить стража: %v", err)
	}
}

// Отсрочка НИЖЕ вычисляемого пола — отказ в старте, а не тихая поправка.
//
// Тихая поправка оставила бы оператора в уверенности, что действует то, что он
// написал; и она же сняла бы единственную защиту от снятия строк, чьи токены ещё
// живы.
func TestReclaimGraceBelowTheComputedFloorRefusesBoot(t *testing.T) {
	floor := tokenpolicy.MinExpiredCredentialReclaimDelay(testRegistryTokenTTL)

	c := goodReclaim()
	c.Grace = floor - time.Second
	err := c.Validate(testRegistryTokenTTL)
	if err == nil {
		t.Fatalf("отсрочка %v под полом %v обязана быть отвергнута при старте", c.Grace, floor)
	}
	// Отказ обязан НАЗЫВАТЬ ручку и причину: сообщение стража — рантайм-диагностика
	// оператору, и без имени ручки стенд не поднять.
	for _, want := range []string{"jobs.expired-credential-reclaim.grace", "floor", "alive"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("отказ обязан содержать %q; получено: %v", want, err)
		}
	}

	// Положительный контроль на той же оси: РОВНО пол проходит. Без него
	// отрицание зеленело бы на страже, отвергающем любую величину.
	c.Grace = floor
	if err := c.Validate(testRegistryTokenTTL); err != nil {
		t.Fatalf("отсрочка ровно в пол обязана проходить: %v", err)
	}
}

// Пол ДВИЖЕТСЯ со сроком докерного токена — он слагаемое, а не константа.
//
// Иначе поднятый срок молча вывел бы отсрочку из-под её же основания: величина,
// проходившая стража вчера, продолжала бы проходить его и тогда, когда перестала
// покрывать живые токены.
func TestReclaimFloorFollowsTheLiveRegistryTokenTTL(t *testing.T) {
	c := goodReclaim()
	c.Grace = tokenpolicy.MinExpiredCredentialReclaimDelay(testRegistryTokenTTL)

	if err := c.Validate(testRegistryTokenTTL); err != nil {
		t.Fatalf("при действующем сроке величина обязана проходить: %v", err)
	}
	// Тот же Grace при БОЛЬШЕМ сроке докерного токена уже не покрывает пол.
	if err := c.Validate(testRegistryTokenTTL + time.Hour); err == nil {
		t.Fatal("пол обязан двигаться со сроком докерного токена — иначе слагаемое не читается")
	}
}

// Неположительный интервал — НЕ «выключено».
//
// Ноль двусмыслен, и различие между «не задано» и «выключено» уже стоило
// продукту отдельного разбора. Выключатель здесь ЯВНЫЙ, поэтому нулевой интервал
// означает петлю, которая никогда не крутится, объявляя себя включённой.
func TestReclaimNonPositiveIntervalIsARefusalNotADisable(t *testing.T) {
	c := goodReclaim()
	c.Interval = 0
	err := c.Validate(testRegistryTokenTTL)
	if err == nil {
		t.Fatal("нулевой интервал обязан быть отвергнут, а не прочитан как «выключено»")
	}
	if !strings.Contains(err.Error(), "jobs.expired-credential-reclaim.interval") {
		t.Fatalf("отказ обязан назвать ручку; получено: %v", err)
	}

	c.BatchSize = 0
	c.Interval = time.Hour
	if err := c.Validate(testRegistryTokenTTL); err == nil {
		t.Fatal("нулевая партия обязана быть отвергнута: партия ограничивает длительность транзакции")
	}
}

// ВЫКЛЮЧЕННЫЙ уборщик стражем не проверяется — и это законно.
//
// Проверять нечего: петля не поднимается. Но молчать о нём нельзя, и об этом
// говорит композиционный корень при старте — молча выключенная уборка
// неотличима от работающей, у которой нечего снимать.
func TestReclaimDisabledIsNotValidated(t *testing.T) {
	c := goodReclaim()
	c.Enabled = false
	c.Interval = 0
	c.Grace = 0
	c.BatchSize = 0
	if err := c.Validate(testRegistryTokenTTL); err != nil {
		t.Fatalf("выключенному уборщику проверять нечего: %v", err)
	}
}

// TestCatalogSnapshot_NonPositiveIntervalRefusesTheStart — страж периода
// обновления снимка каталога (kacho#1816).
//
// Ноль здесь НЕ выключатель: выключенного обновления у снимка не бывает — снимок
// без обновления отстаёт бессрочно и при этом продолжает отвечать, то есть
// снаружи выглядит исправным. Отсюда отказ старта, а не тихое подтягивание к
// умолчанию.
func TestCatalogSnapshot_NonPositiveIntervalRefusesTheStart(t *testing.T) {
	for _, v := range []time.Duration{0, -time.Second} {
		if err := (CatalogSnapshotConfig{RefreshInterval: v}).Validate(); err == nil {
			t.Errorf("период %s принят — снимок, который никогда не обновляется, "+
				"объявлен исправным", v)
		}
	}
	// ЗАКОННЫЙ БЛИЗНЕЦ: без него отрицание выше зеленело бы и на страже,
	// отвергающем ЛЮБУЮ величину.
	if err := (CatalogSnapshotConfig{RefreshInterval: time.Minute}).Validate(); err != nil {
		t.Errorf("положительный период отвергнут: %v", err)
	}
}
