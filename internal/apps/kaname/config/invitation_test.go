// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

// invitation_test.go — срок приглашения и ограничение частоты писем на адрес:
// обе величины ЧИТАЮТСЯ процессом, умолчание у обеих непусто, а значения,
// означающего «без срока» или «без ограничения», в словаре ручки нет (приёмка
// ID-MAIL-1: Р14, Р24; §10 пп. 13, 22; MAIL-42, MAIL-43 — уровень U).
//
// Величина читается пробой ИЗ ОБЪЯВЛЕНИЯ, а не выписана в пробе: выписанное
// число проверяет само себя и остаётся зелёным, когда объявление уедет.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// MAIL-42 (U): молчащий профиль ограничение НЕ снимает — умолчание действует.
func Test_InviteMailAddressRate_SilentProfileKeepsAPositiveLimit(t *testing.T) {
	cfg, err := config.Load("")
	require.NoError(t, err)
	rate := cfg.InviteMail.AddressRate.Value()
	require.NoError(t, rate.Validate(),
		"умолчание частоты обязано быть годным ограничением: молчащий профиль не вправе означать "+
			"«писем уходит сколько угодно»")
	require.NoError(t, cfg.Validate(), "умолчание обязано проходить страж старта")
}

// MAIL-42 (U), положительный контроль: профиль вправе ИЗМЕНИТЬ величину.
func Test_InviteMailAddressRate_ProfileMayChangeTheValue(t *testing.T) {
	base, err := config.Load("")
	require.NoError(t, err)

	t.Setenv("KANAME_INVITE_MAIL__ADDRESS_RATE__LETTERS", "11")
	t.Setenv("KANAME_INVITE_MAIL__ADDRESS_RATE__WINDOW", "90m")
	cfg, err := config.Load("")
	require.NoError(t, err)
	require.Equal(t, domain.InviteMailAddressRate{Letters: 11, Window: 90 * time.Minute}, cfg.InviteMail.AddressRate.Value(),
		"ручки частоты обязаны менять исход загрузки — иначе величина зашита в код и профилем не читается")
	require.NotEqual(t, base.InviteMail.AddressRate.Value(), cfg.InviteMail.AddressRate.Value())
	require.NoError(t, cfg.Validate())
}

// MAIL-43 (U): снять ограничение профиль не вправе. Ноль и отрицательное
// отвергаются стражем старта, и отказ называет ручку и требование
// положительного значения.
func Test_InviteMailAddressRate_NonPositiveRefusesTheStart(t *testing.T) {
	for _, tc := range []struct{ env, val, knob string }{
		{"KANAME_INVITE_MAIL__ADDRESS_RATE__LETTERS", "0", "invite-mail.address-rate.letters"},
		{"KANAME_INVITE_MAIL__ADDRESS_RATE__LETTERS", "-3", "invite-mail.address-rate.letters"},
		{"KANAME_INVITE_MAIL__ADDRESS_RATE__WINDOW", "0s", "invite-mail.address-rate.window"},
		{"KANAME_INVITE_MAIL__ADDRESS_RATE__WINDOW", "-1h", "invite-mail.address-rate.window"},
	} {
		t.Run(tc.env+"="+tc.val, func(t *testing.T) {
			t.Setenv(tc.env, tc.val)
			cfg, err := config.Load("")
			require.NoError(t, err)
			verr := cfg.Validate()
			require.Error(t, verr, "непозитивная частота обязана отвергаться при старте: она означала бы "+
				"«без ограничения», которого в словаре ручки нет (Р14)")
			require.Contains(t, verr.Error(), tc.knob, "отказ обязан называть ручку")
			require.Contains(t, verr.Error(), "positive", "отказ обязан называть требование")
		})
	}
}

// MAIL-43 (U): слова «выключено» в словаре ручки нет вовсе — разбор отказывает.
func Test_InviteMailAddressRate_NoWordMeansUnlimited(t *testing.T) {
	for _, tc := range []struct{ env, val string }{
		{"KANAME_INVITE_MAIL__ADDRESS_RATE__LETTERS", "off"},
		{"KANAME_INVITE_MAIL__ADDRESS_RATE__WINDOW", "disabled"},
	} {
		t.Run(tc.env+"="+tc.val, func(t *testing.T) {
			t.Setenv(tc.env, tc.val)
			_, err := config.Load("")
			require.Error(t, err, "значение «%s» не число — разбор обязан отказать, а не прочесть его "+
				"как нуль и снять ограничение", tc.val)
		})
	}
}

// MAIL-23 (U): срок приглашения — объявленная величина с непустым умолчанием.
func Test_InvitationTerm_IsDeclaredAndChangeable(t *testing.T) {
	cfg, err := config.Load("")
	require.NoError(t, err)
	require.NoError(t, cfg.Invitation.TermValue().Validate(), "умолчание срока обязано быть годным сроком")

	t.Setenv("KANAME_INVITATION__TERM", "48h")
	changed, err := config.Load("")
	require.NoError(t, err)
	require.Equal(t, domain.InvitationTerm(48*time.Hour), changed.Invitation.TermValue(),
		"ручка срока обязана менять исход загрузки")
	require.NoError(t, changed.Validate())
}

func Test_InvitationTerm_NonPositiveOrUnboundedRefusesTheStart(t *testing.T) {
	for _, val := range []string{"0s", "-1h", (domain.MaxInvitationTerm + time.Hour).String()} {
		t.Run(val, func(t *testing.T) {
			t.Setenv("KANAME_INVITATION__TERM", val)
			cfg, err := config.Load("")
			require.NoError(t, err)
			verr := cfg.Validate()
			require.Error(t, verr, "срок %s обязан отвергаться при старте", val)
			require.Contains(t, verr.Error(), "invitation.term", "отказ обязан называть ручку")
		})
	}
}
