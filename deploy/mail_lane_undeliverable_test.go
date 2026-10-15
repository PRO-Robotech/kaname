// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// mail_lane_undeliverable_test.go — неотправленное письмо любого вида звонит, а
// заглушка почтового узла боевого профиля не ставится (kaname#733).
//
// Через почтовый узел уходят коды подтверждения адреса, восстановления доступа
// и смены адреса: без них человек застревает на экране подтверждения либо не
// возвращает доступ. Утверждается:
//
//	П1  правило KanameMailUndeliverable считает клетки `transient` и
//	    `misconfigured` ряда `kaname_mail_outcomes_total` КАЖДОГО вида письма — и
//	    разбором выражения, и настоящим движком; клетку `sent` не считает;
//	П2  боевой профиль с оставленной заглушкой узла (зона `.invalid`) не
//	    рендерится, и отказ называет ключ `inviteMail.relay`; то же — у
//	    отправителя с доменом в зоне `.invalid` (`inviteMail.from`);
//	П3  ЗАКОННЫЙ БЛИЗНЕЦ: узел и отправитель установки рендерятся, и имя,
//	    лишь содержащее `invalid`, признаком не является.
//
// Предпосылка П2 — профиль действительно несёт заглушку узла: снятая, она
// сделала бы П2 зелёным на любом чарте.
package deploy_test

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
)

const ruleMailUndeliverable = "KanameMailUndeliverable"

func mailCell(kind, outcome string) cellTerm {
	return cellTerm{series: metrics.MailOutcomesMetric, labels: map[string]string{"kind": kind, "outcome": outcome}}
}

func TestMailUndeliverableRuleReadsEveryLetterKind(t *testing.T) {
	require.NotEmpty(t, clients.MailEventTypes, "перечень видов пуст — судить нечего")
	for _, r := range alertRenders(t) {
		t.Run(r.name, func(t *testing.T) {
			rules, objects := chartAlertRules(t, renderStandaloneChart(t, r.chain, r.sets...))
			require.Equal(t, 1, objects, "объект правил не отрендерился — судить нечего")
			var mail *alertRule
			for i := range rules {
				if rules[i].Alert == ruleMailUndeliverable {
					mail = &rules[i]
				}
			}
			require.NotNilf(t, mail, "правила %s в объекте нет — неотправленное письмо не звонит", ruleMailUndeliverable)
			judged := 0
			for _, kind := range clients.MailEventTypes {
				for _, outcome := range []string{clients.InviteMailOutcomeTransient, clients.InviteMailOutcomeMisconfigured} {
					c := mailCell(kind, outcome)
					// Отбор правила — по исходу, вид — группировка: точной записи
					// клетки в выражении нет, и судит его селектор и движок.
					reads, err := exprCoversCell(mail.Expr, c)
					require.NoError(t, err)
					require.Truef(t, reads, "%s не читает клетку %s", ruleMailUndeliverable, c)
					require.Truef(t, engineReadsCell(t, mail.Expr, c), "движок: %s не звонит на рост %s", ruleMailUndeliverable, c)
					judged++
				}
				sent := mailCell(kind, clients.InviteMailOutcomeSent)
				covered, err := exprCoversCell(mail.Expr, sent)
				require.NoError(t, err)
				require.Falsef(t, covered, "%s считает сданные письма %s — звонил бы на здоровую полосу", ruleMailUndeliverable, sent)
			}
			t.Logf("ПЕРЕПИСЬ (%s): видов %d · клеток отказа осуждено %d", r.name, len(clients.MailEventTypes), judged)
		})
	}
}

// TestShippedProfileCarriesTheRelayPlaceholder — предпосылка П2.
func TestShippedProfileCarriesTheRelayPlaceholder(t *testing.T) {
	raw, err := os.ReadFile("values.prod.yaml")
	require.NoError(t, err)
	var prof struct {
		InviteMail struct {
			Relay string `yaml:"relay"`
			From  string `yaml:"from"`
		} `yaml:"inviteMail"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &prof))
	t.Logf("inviteMail.relay профиля: %q · inviteMail.from: %q", prof.InviteMail.Relay, prof.InviteMail.From)
	require.Contains(t, prof.InviteMail.Relay, ".invalid", "профиль больше не несёт заглушки узла — П2 судил бы пустоту")
	require.True(t, strings.HasSuffix(prof.InviteMail.From, ".invalid"), "профиль больше не несёт заглушки отправителя")
}

// TestRelayPlaceholderIsRefusedAtInstall — П2, П3.
func TestRelayPlaceholderIsRefusedAtInstall(t *testing.T) {
	domain := "authn.domain=" + installDomainForRender
	t.Run("профиль как есть", func(t *testing.T) {
		out, err := renderProdRaw(t, domain)
		require.Errorf(t, err, "профиль с оставленной заглушкой узла отрендерился — установка не узнаёт о ней до первого письма")
		require.Contains(t, out, "inviteMail.relay", "отказ не называет ключа — оператору нечего сделать")
	})
	for _, v := range []string{"RELAY.Example.INVALID:587", "smtp://relay.example.invalid:587/", "smtps://user@mail.invalid.:465/", "invalid:25"} {
		t.Run("узел "+v, func(t *testing.T) {
			out, err := renderProdRaw(t, domain, "inviteMail.relay="+v, "inviteMail.from=kaname@"+installDomainForRender)
			require.Errorf(t, err, "заглушка узла %q прошла рендер", v)
			require.Contains(t, out, "inviteMail.relay")
		})
	}
	t.Run("отправитель в зоне .invalid", func(t *testing.T) {
		out, err := renderProdRaw(t, domain, "inviteMail.relay=mail.kaname.local:587", "inviteMail.from=kaname@access.example.invalid")
		require.Errorf(t, err, "отправитель-заглушка прошёл рендер")
		require.Contains(t, out, "inviteMail.from")
	})
	t.Run("узел и отправитель установки", func(t *testing.T) {
		out, err := renderProdRaw(t, domain, "inviteMail.relay=smtp://mail.kaname.local:587/", "inviteMail.from=kaname@"+installDomainForRender)
		require.NoErrorf(t, err, "узел установки отвергнут:\n%s", out)
	})
	t.Run("имя, лишь содержащее invalid", func(t *testing.T) {
		out, err := renderProdRaw(t, domain, "inviteMail.relay=invalid.kaname.local:587", "inviteMail.from=kaname@invalid.kaname.local")
		require.NoErrorf(t, err, "имя вне зоны .invalid отвергнуто — признак судит строку, а не зону:\n%s", out)
	})
}
