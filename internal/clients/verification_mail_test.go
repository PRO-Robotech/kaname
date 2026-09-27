// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// verification_mail_test.go — EV-26 приёмки
// `access-beyond-login-needs-a-verified-address.md` (kaname#456, Р8): письмо
// подтверждения несёт код, его срок в минутах и адрес экрана подтверждения
// консоли — ровно `<происхождение консоли>/verification`, без параметров и без
// фрагмента (заказ консольной пары), тем же источником настройки, что адрес
// входа в письмах службы; кода ни в одном адресе письма нет. Близнец — письмо
// восстановления тем же применителем: код есть, адреса экрана подтверждения
// нет.
package clients_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/clients"
)

var urlInLetter = regexp.MustCompile(`https?://[^\s]+`)

func TestEV26_VerificationLetterCarriesTheCodeTermAndTheScreenAddress(t *testing.T) {
	relay := clients.MailRelay{From: "noreply@example.invalid", FromName: "Облако", LoginURL: "https://console.example.invalid/login?from=mail"}
	const code = "ABCDE-FGH12"
	body := string(clients.RenderMail(relay, clients.MailEvent{
		Kind: "mail.verification.send", To: "person@example.invalid", Code: code, CodeValidMinutes: 30,
	}))
	require.Contains(t, body, code, "EV-26: тело несёт код")
	require.Contains(t, body, "30 мин.", "EV-26: срок «30 мин.»")
	urls := urlInLetter.FindAllString(body, -1)
	require.Contains(t, urls, "https://console.example.invalid/verification", "EV-26: адрес экрана — происхождение консоли и /verification")
	for _, u := range urls {
		require.NotContains(t, strings.ToUpper(u), strings.ReplaceAll(code, "-", ""), "EV-26: кода в адресе нет: %s", u)
		require.NotContains(t, strings.ToUpper(u), code, "EV-26: кода в адресе нет: %s", u)
		if strings.Contains(u, "/verification") {
			require.Equal(t, "https://console.example.invalid/verification", u, "EV-26: без параметров и без фрагмента")
		}
	}

	recovery := string(clients.RenderMail(relay, clients.MailEvent{
		Kind: clients.EventRecoveryMailSend, To: "person@example.invalid", Code: code, CodeValidMinutes: 5,
	}))
	require.Contains(t, recovery, code, "EV-26 близнец: письмо восстановления несёт код")
	require.NotContains(t, recovery, "/verification", "EV-26 близнец: адреса экрана подтверждения в нём нет")
}
