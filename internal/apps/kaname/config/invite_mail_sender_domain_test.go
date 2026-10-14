// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

// invite_mail_sender_domain_test.go — страж старта отвергает адрес
// отправителя без годной доменной части (задача kaname#642).
//
// Тем доменом отправитель представляется узлу и в нём чеканит Message-ID
// письма. Прежде отсутствие домена обнаруживалось только при ПЕРВОЙ отправке:
// процесс стартовал здоровым, а ни одно письмо — приглашение, подтверждение
// адреса, восстановление — не уходило. Предикат один на стража и на
// отправителя: разойдясь, они разошлись бы ровно на вырожденном значении.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

func Test_InviteMail_SenderWithoutADomainRefusesAtStart(t *testing.T) {
	const relay = "relay.example.invalid:587"

	for _, from := range []string{
		"kacho",                  // доменной части нет вовсе
		"kacho@",                 // разделитель есть, домена нет
		"Kachō <kacho@>",         // то же за отображаемым именем
		"kacho@.example.invalid", // пустая метка в начале
		"kacho@example.invalid.", // пустая метка в конце
		"kacho@example..invalid", // пустая метка внутри
		"kacho@exa mple.invalid", // пробел — не байт домена
		"kacho@[192.0.2.1]",      // скобки — не dot-atom правой части msg-id
	} {
		t.Run(from, func(t *testing.T) {
			err := config.InviteMailConfig{Relay: relay, From: from}.Validate()
			require.Error(t, err, "адрес отправителя без годного домена обязан отказывать на старте")
			require.Contains(t, err.Error(), "invite-mail.from", "отказ называет ручку")
			require.Contains(t, err.Error(), "domain", "отказ называет причину")
		})
	}

	// Законные близнецы: тот же страж, адрес с доменом — молчание. Без них
	// отрицания выше зеленели бы на страже, отвергающем всё.
	for _, from := range []string{
		"kacho@example.invalid",
		"Kachō <kacho@example.invalid>",
		"kacho+mail@sub.example.invalid",
	} {
		t.Run("близнец "+from, func(t *testing.T) {
			require.NoError(t, config.InviteMailConfig{Relay: relay, From: from}.Validate())
		})
	}
}

// Отказ не повторяет значение ручки: адрес отправителя — величина посадки, и
// журнал старта её не размножает.
func Test_InviteMail_SenderDomainRefusalDoesNotEchoTheValue(t *testing.T) {
	err := config.InviteMailConfig{Relay: "relay.example.invalid:587", From: "noreply-642@"}.Validate()
	require.Error(t, err)
	require.False(t, strings.Contains(err.Error(), "noreply-642"), "отказ повторил значение: %v", err)
}
