// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package main

// invite_mail_wiring_test.go — проводка очереди писем приглашения.
//
// Утверждается СВЯЗЬ двух величин, а не их наличие: величина, которую нельзя
// наблюдать ни в одном исходе, объявлена и не исполняется — тот же класс, что
// «принято-и-проигнорировано», только заведённый собственными руками.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/outbox/drainer"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
)

// Test_InviteMailDrainerConfig_PatienceOutlastsTheAttempt — требование, ради
// которого проводка вынесена отдельной функцией.
//
// Терпение дренажа обязано быть СТРОГО больше предела попытки отправителя.
// Иначе разговор обрывал бы всегда дренаж, предел отправителя не фигурировал бы
// ни в одном исходе, и MAIL-32 утверждала бы о величине, которой не бывает.
func Test_InviteMailDrainerConfig_PatienceOutlastsTheAttempt(t *testing.T) {
	t.Parallel()

	// Проверяется на РАЗМАХЕ величин, а не на одном значении: связь обязана
	// держаться при любом объявленном пределе, а не совпадать на умолчании.
	for _, attempt := range []time.Duration{
		0, // не задано → берётся умолчание
		time.Second, 5 * time.Second, 20 * time.Second, 2 * time.Minute,
	} {
		cfg := config.InviteMailConfig{AttemptTimeout: attempt}
		got := inviteMailDrainerConfig(cfg)

		assert.Greater(t, got.ApplyTimeout, cfg.AttemptTimeoutOrDefault(),
			"терпение дренажа обязано пережить попытку целиком (предел попытки %s): "+
				"иначе разговор обрывает дренаж, и СВОЙ предел отправителя не наблюдается "+
				"ни в одном исходе", cfg.AttemptTimeoutOrDefault())
	}
}

// Test_InviteMailDrainerConfig_CarriesBothValuesSeparately — величины две, и они
// приезжают из РАЗНЫХ ручек.
//
// Без этой пробы «две величины» держалось бы комментарием: конфигурация, где
// число повторов выводится из предела времени, собиралась бы и выглядела так же.
func Test_InviteMailDrainerConfig_CarriesBothValuesSeparately(t *testing.T) {
	t.Parallel()

	got := inviteMailDrainerConfig(config.InviteMailConfig{
		AttemptTimeout: 9 * time.Second,
		MaxAttempts:    4,
	})
	assert.Equal(t, 4, got.MaxAttempts,
		"число повторов обязано приезжать СВОЕЙ ручкой")
	assert.Equal(t, 9*time.Second+applyTimeoutHeadroom, got.ApplyTimeout,
		"терпение обязано выводиться из предела попытки, а не назначаться рядом")
}

// Test_InviteMailDrainerConfig_OrderingKeyIsNamedOnce — ключ партиции объявлен
// ОДНАЖДЫ и приезжает и в дренаж, и в возврат отравленных.
//
// На разных ключах каждая половина правила порядка сторожила бы партицию,
// которой не видит другая, — и расхождение было бы молчаливым.
func Test_InviteMailDrainerConfig_OrderingKeyIsNamedOnce(t *testing.T) {
	t.Parallel()

	got := inviteMailDrainerConfig(config.InviteMailConfig{})
	require.Equal(t, inviteMailPartitionColumn, got.PartitionColumn,
		"клейм обязан партиционироваться тем же ключом, что объявлен один раз")
	assert.NotEmpty(t, got.PartitionColumn,
		"пустой ключ означал бы «порядка нет» — и уборка доставленных строк стала бы "+
			"невыразимой: общий уборщик платформы отказывает на сборке без ключа")
	assert.Equal(t, drainer.PoisonPermanent, got.PermanentPolicy,
		"MAIL-33: отказ по настройке ограничен числом повторов, а не крутится вечно")
}

// Test_BuildMailRelay_UnconfiguredLaneStillBoots — свойство ПРОИЗВОДСТВЕННОЕ, а
// не удобство: служба поднимается при НЕОБЪЯВЛЕННОЙ почтовой полосе.
//
// Отказ старта по факту необъявленной полосы — предмет стража рендера профиля и
// шага подстановки (Р4а, места С1 и С2), у которых есть доступ к объявлениям
// профиля и к величине из секрета. Здесь такого доступа нет by construction,
// поэтому отказ на этом месте уронил бы КАЖДЫЙ стенд, где полоса ещё не
// объявлена, — и уронил бы по причине, которую он не в состоянии установить.
//
// Что происходит вместо отказа, утверждается соседними пробами: отправитель на
// каждой попытке даёт наблюдаемый исход `misconfigured` — громко, в журнал
// уровнем ошибки и в свою клетку счётчика, — а строка отравляется вместо
// вечного повтора. То есть ненастроенная полоса НАБЛЮДАЕМА, а не тиха.
func Test_BuildMailRelay_UnconfiguredLaneStillBoots(t *testing.T) {
	t.Parallel()

	relay, err := buildMailRelay(config.InviteMailConfig{})
	require.NoError(t, err,
		"сборка отправителя при необъявленной полосе обязана пройти: отказ здесь "+
			"уронил бы каждый стенд, где почта ещё не объявлена")
	assert.Positive(t, relay.AttemptTimeout,
		"предел попытки обязан быть положительным даже у необъявленной полосы: "+
			"непозитивный означал бы попытку без предела")

	// Положительный контроль: НЕГОДНОЕ объявление отказ ДАЁТ. Без него проба
	// зеленела бы на сборке, которая не отказывает никогда, и «поднимается»
	// перестало бы что-либо означать.
	_, err = buildMailRelay(config.InviteMailConfig{
		Relay: "relay.example.invalid:587", CABundleFile: "/nonexistent/anchor.pem",
	})
	require.Error(t, err,
		"якорь доверия, которого нет на диске, — отказ сборки: полоса объявлена "+
			"шифрованной, а проверить сертификат нечем")
}
