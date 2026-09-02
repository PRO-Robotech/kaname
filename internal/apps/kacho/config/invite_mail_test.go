// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package config_test

// invite_mail_test.go — величины НАШЕГО отправителя письма приглашения.
//
// Каждая величина, которую вводит эта фаза, читается пробой ИЗ ОБЪЯВЛЕНИЯ, а не
// выписана в пробе (приёмка ID-MAIL-1, DoD п. 11): выписанное число проверяет
// само себя и остаётся зелёным, когда объявление уедет.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
)

// Test_InviteMail_TwoValuesAreDeclaredAndDistinct — §4.1 замечание В1 круга 6:
// предел времени на попытку и число повторов — РАЗНЫЕ величины.
//
// Проба утверждает именно РАЗЛИЧИЕ, а не наличие: единственная величина, из
// которой выводилась бы вторая, означала бы, что одна из них объявлена и не
// исполняется.
func Test_InviteMail_TwoValuesAreDeclaredAndDistinct(t *testing.T) {
	cfg, err := config.Load("")
	require.NoError(t, err)

	attempt := cfg.InviteMail.AttemptTimeoutOrDefault()
	retries := cfg.InviteMail.MaxAttemptsOrDefault()

	assert.Positive(t, attempt,
		"предел времени на ПОПЫТКУ обязан быть положительным: непозитивный означает "+
			"бесконечное ожидание, то есть ровно тот дефект, который предел снимает")
	assert.Positive(t, retries,
		"число ПОВТОРОВ обязано быть положительным: непозитивное означает, что строка "+
			"не будет предъявлена отправителю ни разу")

	// Величины читаются РАЗНЫМИ ручками — это и есть их различие. Проба задаёт
	// каждую по отдельности и требует, чтобы менялась только она.
	t.Run("предел попытки меняется своей ручкой", func(t *testing.T) {
		t.Setenv("KACHO_IAM_INVITE_MAIL__ATTEMPT_TIMEOUT", "7s")
		c, lerr := config.Load("")
		require.NoError(t, lerr)
		assert.Equal(t, 7*time.Second, c.InviteMail.AttemptTimeoutOrDefault(),
			"ручка предела попытки обязана менять исход загрузки")
		assert.Equal(t, retries, c.InviteMail.MaxAttemptsOrDefault(),
			"и НЕ обязана трогать число повторов — иначе это одна величина под двумя именами")
	})

	t.Run("число повторов меняется своей ручкой", func(t *testing.T) {
		t.Setenv("KACHO_IAM_INVITE_MAIL__MAX_ATTEMPTS", "4")
		c, lerr := config.Load("")
		require.NoError(t, lerr)
		assert.Equal(t, 4, c.InviteMail.MaxAttemptsOrDefault(),
			"ручка числа повторов обязана менять исход загрузки")
		assert.Equal(t, attempt, c.InviteMail.AttemptTimeoutOrDefault(),
			"и НЕ обязана трогать предел попытки")
	})
}

// Test_InviteMail_NoBuiltInDefaultForRelayOrSender — Р3: встроенного умолчания у
// узла, адреса отправителя и удостоверения НЕТ.
//
// Величина, которую построение подставляет молча, предметом стража быть не
// может: он зелен при любом входе, потому что незаданной она не бывает.
func Test_InviteMail_NoBuiltInDefaultForRelayOrSender(t *testing.T) {
	cfg, err := config.Load("")
	require.NoError(t, err)

	assert.Empty(t, cfg.InviteMail.Relay, "у почтового узла встроенного умолчания нет")
	assert.Empty(t, cfg.InviteMail.From, "у адреса отправителя встроенного умолчания нет")
	assert.Empty(t, cfg.InviteMail.UsernameEnv, "у удостоверения встроенного умолчания нет")
	assert.Empty(t, cfg.InviteMail.PasswordEnv, "у удостоверения встроенного умолчания нет")
	assert.False(t, cfg.InviteMail.RelayConfigured(),
		"необъявленная полоса обязана читаться как необъявленная ОДНИМ предикатом — "+
			"тем же, что применяет отправитель")

	// Положительный контроль: объявленная полоса читается как объявленная. Без
	// него отрицания выше зеленели бы на предикате, отвечающем «нет» всегда.
	t.Setenv("KACHO_IAM_INVITE_MAIL__RELAY", "relay.example.invalid:587")
	c, lerr := config.Load("")
	require.NoError(t, lerr)
	assert.True(t, c.InviteMail.RelayConfigured(),
		"положительный контроль: объявленный узел обязан читаться как объявленный")
}

// Test_InviteMail_DegenerateValueCountsAsUnset — Р4: вырожденные значения
// считаются НЕЗАДАННЫМИ, а не «непустыми».
//
// Страж и потребитель обязаны применять ОДИН предикат: разойдясь, они разойдутся
// ровно там, где расхождение опасно — на значении из одних пробелов, чья длина
// ненулевая, а содержания нет.
func Test_InviteMail_DegenerateValueCountsAsUnset(t *testing.T) {
	for _, degenerate := range []string{" ", "   ", "\t"} {
		cfg := config.InviteMailConfig{Relay: degenerate}
		assert.False(t, cfg.RelayConfigured(),
			"вырожденное значение %q обязано читаться как НЕЗАДАННОЕ", degenerate)
		assert.NoError(t, cfg.Validate(),
			"вырожденный узел без прочих объявлений — это «полоса не объявлена», а не расхождение")
	}
}

// Test_InviteMail_HalfDeclaredCredentialsRefuse — Р4: половина настройки хуже
// отсутствия обеих, потому что ВЫГЛЯДИТ настроенной.
func Test_InviteMail_HalfDeclaredCredentialsRefuse(t *testing.T) {
	const relay = "relay.example.invalid:587"
	const from = "kacho@example.invalid"

	t.Run("логин без пароля", func(t *testing.T) {
		err := config.InviteMailConfig{
			Relay: relay, From: from, UsernameEnv: "MAIL_USER",
		}.Validate()
		require.Error(t, err, "объявленная половина пары обязана отказывать")
		assert.Contains(t, err.Error(), "half-declared",
			"текст отказа обязан называть предмет: оператор чинит по нему")
	})

	t.Run("пароль без логина", func(t *testing.T) {
		err := config.InviteMailConfig{
			Relay: relay, From: from, PasswordEnv: "MAIL_PASS",
		}.Validate()
		require.Error(t, err, "зеркальная половина обязана отказывать так же")
	})

	t.Run("узел без отправителя", func(t *testing.T) {
		err := config.InviteMailConfig{Relay: relay}.Validate()
		require.Error(t, err, "у адреса отправителя встроенного умолчания нет (Р3)")
	})

	t.Run("отправитель без узла", func(t *testing.T) {
		err := config.InviteMailConfig{From: from}.Validate()
		require.Error(t, err,
			"объявленный отправитель при необъявленном узле — полоса, которая выглядит "+
				"настроенной и не доставляет ничего")
	})

	// ПОЛОЖИТЕЛЬНЫЕ КОНТРОЛИ. Без них отрицания выше зеленели бы на страже,
	// отвергающем всё, — и «страж работает» не означало бы ничего.
	t.Run("положительный контроль: полная пара принимается", func(t *testing.T) {
		require.NoError(t, config.InviteMailConfig{
			Relay: relay, From: from,
			UsernameEnv: "MAIL_USER", PasswordEnv: "MAIL_PASS",
		}.Validate())
	})

	t.Run("положительный контроль: узел без удостоверения принимается", func(t *testing.T) {
		// Ретранслятор внутри периметра вправе не требовать удостоверения;
		// требовать его здесь значило бы запретить законную посадку.
		require.NoError(t, config.InviteMailConfig{Relay: relay, From: from}.Validate())
	})

	t.Run("положительный контроль: необъявленная полоса не отказ", func(t *testing.T) {
		// «Объявлена ли полоса вообще» судит не этот страж (Р4а, места С1 и С2):
		// у него нет доступа ни к объявлениям профиля, ни к величине из секрета.
		require.NoError(t, config.InviteMailConfig{}.Validate())
	})
}

// Test_InviteMail_TLSModeHasNoPlaintextName — ban #16 на стороне ОБЪЯВЛЕНИЯ.
//
// Незащищённой полосы среди принимаемых имён нет, поэтому оператор не может её
// выбрать, как бы он ни написал значение. Пара к
// `Test_ParseMailTLSMode_NeverYieldsThePlaintextMode` на стороне применителя:
// имена разбираются в двух местах, и они обязаны сходиться.
func Test_InviteMail_TLSModeHasNoPlaintextName(t *testing.T) {
	const relay = "relay.example.invalid:587"
	const from = "kacho@example.invalid"

	for _, attempt := range []string{"none", "plaintext", "off", "disabled", "insecure"} {
		err := config.InviteMailConfig{Relay: relay, From: from, TLSMode: attempt}.Validate()
		require.Error(t, err, "имя %q обязано быть отвергнуто: полоса шифрована на всяком стенде", attempt)
		assert.Equal(t, "starttls",
			config.InviteMailConfig{Relay: relay, From: from, TLSMode: attempt}.TLSModeName(),
			"негодное имя не вправе превращаться в открытую полосу даже как возвращаемое значение")
	}

	// Положительный контроль: два законных имени принимаются и различаются.
	assert.Equal(t, "starttls", config.InviteMailConfig{}.TLSModeName())
	assert.Equal(t, "implicit", config.InviteMailConfig{TLSMode: "implicit"}.TLSModeName())
	require.NoError(t, config.InviteMailConfig{Relay: relay, From: from, TLSMode: "implicit"}.Validate())
}

// Test_InviteMail_NegativeValuesRefuse — непозитивная величина означала бы «не
// ограничиваем», а такого умолчания эта фаза не вводит (DoD п. 12).
func Test_InviteMail_NegativeValuesRefuse(t *testing.T) {
	const relay = "relay.example.invalid:587"
	const from = "kacho@example.invalid"

	require.Error(t, config.InviteMailConfig{
		Relay: relay, From: from, AttemptTimeout: -time.Second,
	}.Validate())
	require.Error(t, config.InviteMailConfig{
		Relay: relay, From: from, MaxAttempts: -1,
	}.Validate())

	// Ноль читается как «не задано» и заменяется объявленным умолчанием — это
	// НЕ то же, что отрицательное значение, которое задано и негодно.
	zero := config.InviteMailConfig{Relay: relay, From: from}
	require.NoError(t, zero.Validate())
	assert.Positive(t, zero.AttemptTimeoutOrDefault())
	assert.Positive(t, zero.MaxAttemptsOrDefault())
}
