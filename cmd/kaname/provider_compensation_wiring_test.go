// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provider_compensation_wiring_test.go — терпение дренажа компенсаций
// переживает попытку административного клиента целиком.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ (kacho#2490)
//
// Терпение дренажа было 5 с, предел административного клиента — 10 с. Терпение
// ограничивает ОДИН вызов применения, поэтому предел клиента не срабатывал на
// этой полосе НИ РАЗУ: разговор обрывал всегда дренаж. Величина была объявлена
// и не исполнялась никогда — «неисполнимая возможность» на величинах.
//
// Соседняя почтовая полоса называет ровно это ТРЕБОВАНИЕМ и выводит терпение ИЗ
// предела попытки, объясняя вслух то же самое. Здесь соотношение было обратным,
// и никем это не решалось: два места об одном предмете, из которых одно
// объявляет норму, а другое ей противоречит. Своего довода у расхождения не
// было — 5 с суть невыбранное умолчание, поэтому исход выбран первый: терпение
// выводится, а не назначается рядом.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ НА РАЗМАХЕ ВЕЛИЧИН, А НЕ НА ОДНОМ ЗНАЧЕНИИ
//
// Проба, подающая одно значение, совпала бы на умолчании и не удержала бы
// ничего: она была бы зелена и на связи, и на паре независимо выбранных чисел,
// случайно оказавшихся в верном порядке. Связь обязана держаться при ЛЮБОМ
// объявленном пределе.
//
// ─────────────────────────────────────────────────────────────────────────────
// ВТОРАЯ ПОЛОВИНА — ЧТО ПОДАЁТСЯ В ЭТУ СВЯЗЬ
//
// Верная деривация от НЕВЕРНОГО числа даёт тот же дефект. Поэтому рядом стоит
// проба, спрашивающая предел у ПРОИЗВОДИТЕЛЯ — у клиента, которого строит сама
// проводка, — а не у второго написания той же величины.
package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/clients"
)

// Test_ProviderCompensationDrainerConfig_PatienceOutlastsTheAttempt —
// требование, ради которого проводка вынесена отдельной функцией.
func Test_ProviderCompensationDrainerConfig_PatienceOutlastsTheAttempt(t *testing.T) {
	t.Parallel()

	for _, attempt := range []time.Duration{
		time.Second, 5 * time.Second, 10 * time.Second, 30 * time.Second, 2 * time.Minute,
	} {
		got := providerCompensationDrainerConfig(attempt)

		assert.Greater(t, got.ApplyTimeout, attempt,
			"терпение дренажа обязано пережить попытку целиком (предел попытки %s): "+
				"иначе разговор обрывает дренаж, и СВОЙ предел клиента не наблюдается "+
				"ни в одном исходе", attempt)
	}
}

// Test_ProviderCompensationDrainerConfig_PatienceIsDerivedNotAssigned —
// терпение ВЫВОДИТСЯ из предела попытки тем же запасом, что на почтовой полосе.
//
// Без этой пробы требование выше удержалось бы и парой независимо выбранных
// чисел: «строго больше» истинно у любой пары в верном порядке, а разошлись бы
// они молча — ровно тем способом, каким разошлись 5 и 10.
func Test_ProviderCompensationDrainerConfig_PatienceIsDerivedNotAssigned(t *testing.T) {
	t.Parallel()

	const attempt = 9 * time.Second
	got := providerCompensationDrainerConfig(attempt)

	assert.Equal(t, attempt+applyTimeoutHeadroom, got.ApplyTimeout,
		"терпение обязано выводиться из предела попытки тем же запасом, что объявлен "+
			"однажды и применяется обеими полосами")
}

// Test_ProviderCompensationDrainerConfig_AttemptCeilingComesFromTheProducer —
// ВТОРАЯ ПОЛОВИНА: в связь подаётся предел ТОГО клиента, который эту полосу и
// обслуживает.
//
// Верная деривация от неверного числа даёт тот же дефект и выглядит исправной.
// Поэтому величина спрашивается у производителя — у объекта клиента, собранного
// той же проводкой, — а не у второго написания константы.
func Test_ProviderCompensationDrainerConfig_AttemptCeilingComesFromTheProducer(t *testing.T) {
	t.Parallel()

	client := clients.NewHydraAdminClient("http://provider.invalid", "")
	require.NotNil(t, client.HTTPClient, "клиент без предела времени висел бы вечно")

	assert.Equal(t, clients.ProviderAdminHopTimeout, client.HTTPClient.Timeout,
		"предел, из которого выводится терпение, обязан быть пределом ЭТОГО клиента")

	got := providerCompensationDrainerConfig(clients.ProviderAdminHopTimeout)
	assert.Greater(t, got.ApplyTimeout, client.HTTPClient.Timeout,
		"терпение дренажа обязано пережить попытку клиента, который эту полосу обслуживает")
}
