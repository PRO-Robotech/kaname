// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

// invite_mail_relay_form_test.go — адрес почтового узла в форме, которую читает
// почтовый процесс поставщика личности.
//
// Решение Р23 приёмки ID-MAIL-1: узел, адрес отправителя и удостоверение
// объявляются ОДНАЖДЫ, и оба отправителя — наш и почтовый процесс поставщика —
// берут их оттуда. Единственное объявление несёт адрес в форме URI
// (`smtp://[имя@]узел:порт/` либо `smtps://…`), потому что это форма второго
// читателя. Значит наш отправитель обязан понимать ту же строку ТАК ЖЕ: схема —
// посадка полосы, часть до «@» — имя пользователя.
//
// До этой правки форма ПРИНИМАЛАСЬ и частью ВЫБРАСЫВАЛАСЬ: транспорт срезал
// схему молча, `smtps://` уходил в STARTTLS, имя пользователя становилось
// частью имени узла, а завершающий `/` — частью порта. Страж старта при этом
// судил другим предикатом, чем транспорт: `smtp://` для него была объявленной
// полосой, для транспорта — незаданной.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// Test_InviteMailRelay_URIFormIsReadAsTheVendorReadsIt — положительная сторона:
// схема задаёт посадку, имя пользователя раскодируется, завершающий `/` законен.
func Test_InviteMailRelay_URIFormIsReadAsTheVendorReadsIt(t *testing.T) {
	t.Parallel()

	for _, c := range []struct {
		raw, hostPort, tls, user string
	}{
		{"smtp://kacho-umbrella-mailpit:1025/", "kacho-umbrella-mailpit:1025", "starttls", ""},
		{"smtp://kacho-umbrella-mailpit:1025", "kacho-umbrella-mailpit:1025", "starttls", ""},
		{"smtps://noreply%40kacho.cloud@relay.example:465", "relay.example:465", "implicit", "noreply@kacho.cloud"},
		{"SMTP://relay.example:587/", "relay.example:587", "starttls", ""},
		{"smtp://noreply@[2001:db8::1]:587/", "[2001:db8::1]:587", "starttls", "noreply"},
	} {
		got, err := config.InviteMailConfig{Relay: c.raw}.RelayCoordinate()
		require.NoError(t, err, "адрес %q обязан разбираться", c.raw)
		assert.Equal(t, c.hostPort, got.HostPort, "узел из %q", c.raw)
		assert.Equal(t, c.tls, got.TLSMode, "посадка из схемы %q", c.raw)
		assert.Equal(t, c.user, got.Username, "имя пользователя из %q", c.raw)
	}
}

// Test_InviteMailRelay_BareFormIsUnchanged — прежняя форма `узел:порт` читается
// как читалась: посадку называет ручка, имя — окружение. Правка расширяет
// смысл формы URI и не трогает соседнюю.
func Test_InviteMailRelay_BareFormIsUnchanged(t *testing.T) {
	t.Parallel()

	for _, c := range []struct{ raw, hostPort string }{
		{"relay.example.invalid:587", "relay.example.invalid:587"},
		{" relay.example.invalid:2525 ", "relay.example.invalid:2525"},
		{"relay.example.invalid", "relay.example.invalid:587"},
		{"[2001:db8::1]:587", "[2001:db8::1]:587"},
	} {
		got, err := config.InviteMailConfig{Relay: c.raw}.RelayCoordinate()
		require.NoError(t, err, "адрес %q обязан разбираться", c.raw)
		assert.Equal(t, c.hostPort, got.HostPort, "узел из %q", c.raw)
		assert.Empty(t, got.TLSMode, "голый адрес посадки не называет — её называет ручка")
		assert.Empty(t, got.Username, "голый адрес имени пользователя не несёт")
	}
}

// relayPasswordProbe — величина-метка удостоверения в адресе. Отличима от
// любого слова объяснения: проба ищет ВЕЛИЧИНУ, а не слово «секрет», которое
// законно стоит в тексте отказа.
const relayPasswordProbe = "pw-4f1c9e-value"

// Test_InviteMailRelay_RefusesWhatItWouldNotHonour — принять и не исполнить
// нельзя: каждая часть адреса, которую отправитель не исполнил бы так же, как
// второй читатель той же строки, отвергается при старте, и отказ называет ключ.
func Test_InviteMailRelay_RefusesWhatItWouldNotHonour(t *testing.T) {
	t.Parallel()

	for _, c := range []struct{ raw, why string }{
		{"smtp://noreply:" + relayPasswordProbe + "@relay.example:587/", "пароль в адресе: удостоверение приезжает из секрета (Р6)"},
		{"smtp://noreply:@relay.example:587/", "пароль в адресе, пусть и пустой"},
		{"smtp://relay.example:587/?disable_starttls=true", "параметр адреса, которого отправитель не исполняет"},
		{"smtp://relay.example:587/?server_name=relay", "параметр адреса, которого отправитель не исполняет"},
		{"smtp://relay.example:587/#frag", "фрагмент адреса"},
		{"smtp://relay.example:587/inbox", "путь в адресе узла"},
		{"smtp://relay.example/", "адрес формы URI без порта: у второго читателя умолчания порта нет"},
		{"smtp://", "схема без узла"},
		{"smtp://:587/", "порт без узла"},
		{"http://relay.example:80/", "схема не почтовая"},
		{":", "двоеточие без узла"},
		{":25", "порт без узла"},
		{"noreply@relay.example:587", "имя пользователя в голом адресе"},
		{"relay.example:587/", "путь в голом адресе"},
	} {
		_, err := config.InviteMailConfig{Relay: c.raw}.RelayCoordinate()
		require.Error(t, err, "%q обязан быть отвергнут: %s", c.raw, c.why)
		assert.Contains(t, err.Error(), "invite-mail.relay", "отказ обязан назвать ключ (%q)", c.raw)
		assert.NotContains(t, err.Error(), relayPasswordProbe,
			"отказ не вправе печатать удостоверение, даже отвергая его (%q)", c.raw)
	}
}

// Test_InviteMailRelay_ContradictionsRefuseAtStart — у величины ОДИН источник.
// Схема и ручка посадки, имя в адресе и имя в окружении — два источника одного
// значения; разошедшиеся, они отвергаются, а совпавшие принимаются.
func Test_InviteMailRelay_ContradictionsRefuseAtStart(t *testing.T) {
	t.Parallel()
	const from = "noreply@kacho.cloud"

	for _, c := range []struct {
		name string
		cfg  config.InviteMailConfig
	}{
		{"схема smtps против ручки starttls",
			config.InviteMailConfig{Relay: "smtps://relay.example:465", From: from, TLSMode: "starttls"}},
		{"схема smtp против ручки implicit",
			config.InviteMailConfig{Relay: "smtp://relay.example:587", From: from, TLSMode: "implicit"}},
		{"имя и в адресе, и в окружении",
			config.InviteMailConfig{Relay: "smtp://noreply@relay.example:587", From: from,
				UsernameEnv: "MAIL_USER", PasswordEnv: "MAIL_PASSWORD"}},
		{"имя в адресе без пароля — половина пары",
			config.InviteMailConfig{Relay: "smtp://noreply@relay.example:587", From: from}},
		{"вырожденный адрес формы URI не «не задан», а негоден",
			config.InviteMailConfig{Relay: "smtp://", From: from}},
	} {
		require.Error(t, c.cfg.Validate(), c.name)
	}

	// Положительный контроль: те же формы без противоречия принимаются. Без него
	// отрицания выше зеленели бы на стороже, отвергающем всякий адрес URI.
	for _, c := range []struct {
		name string
		cfg  config.InviteMailConfig
		tls  string
	}{
		{"smtps без ручки", config.InviteMailConfig{Relay: "smtps://relay.example:465", From: from}, "implicit"},
		{"smtps и совпавшая ручка", config.InviteMailConfig{Relay: "smtps://relay.example:465", From: from, TLSMode: "implicit"}, "implicit"},
		{"smtp без ручки", config.InviteMailConfig{Relay: "smtp://relay.example:587/", From: from}, "starttls"},
		{"имя в адресе и пароль по имени переменной",
			config.InviteMailConfig{Relay: "smtp://noreply@relay.example:587", From: from, PasswordEnv: "MAIL_PASSWORD"}, "starttls"},
		{"адрес без имени, пара в окружении",
			config.InviteMailConfig{Relay: "smtp://relay.example:587", From: from,
				UsernameEnv: "MAIL_USER", PasswordEnv: "MAIL_PASSWORD"}, "starttls"},
		{"голый адрес и ручка", config.InviteMailConfig{Relay: "relay.example:465", From: from, TLSMode: "implicit"}, "implicit"},
	} {
		require.NoError(t, c.cfg.Validate(), c.name)
		assert.Equal(t, c.tls, c.cfg.TLSModeName(), "посадка, которую применит отправитель: %s", c.name)
	}
}
