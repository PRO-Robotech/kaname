// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// domain_placeholder_refused_test.go — оставленная заглушка домена отвергается
// установкой, как обещает боевой профиль (kaname#762).
//
// Профиль несёт на месте `authn.domain` имя в зарезервированной зоне `.invalid`
// и обещает: установка, забывшая его заменить, обнаружит это сразу. Рендер и
// старт проходили, и обещание было объявленным и неисполнимым.
//
// Утверждается:
//
//	Р1  профиль как есть, без замены заглушки, не рендерится, и отказ называет
//	    ключ `authn.domain`;
//	Р2  та же заглушка в любой форме записи (регистр, завершающая точка, другая
//	    первая метка) отвергается так же — признак в зоне, а не в строке;
//	Р3  ЗАКОННЫЙ БЛИЗНЕЦ: профиль с доменом установки рендерится, и в карту
//	    настроек уезжает именно он.
//
// Предпосылка Р1 — профиль действительно несёт заглушку: снятая из профиля, она
// сделала бы Р1 зелёным на любом чарте.
package deploy_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// renderProdRaw — рендер боевой цепочки БЕЗ координат установки: исход и вывод.
func renderProdRaw(t *testing.T, sets ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		if os.Getenv(renderGuardLaneEnv) != "" {
			t.Fatalf("helm не в PATH, а полоса рендера объявлена (%s задан)", renderGuardLaneEnv)
		}
		t.Skipf("helm не в PATH — вердикта НЕТ: третья категория (полоса %s)", renderGuardLaneEnv)
	}
	args := []string{"template", "kaname", ".", "--namespace", "kaname", "-f", "values.yaml", "-f", "values.prod.yaml"}
	for _, kv := range sets {
		args = append(args, "--set", kv)
	}
	out, err := exec.Command("helm", args...).CombinedOutput() // #nosec G204 -- фиксированный бинарь, аргументы из дерева
	return string(out), err
}

// installMailSets — узел и отправитель установки: профиль несёт и их заглушки,
// и их отказ (kaname#733) судит `mail_lane_undeliverable_test.go`, а не эти пробы.
var installMailSets = []string{
	"inviteMail.relay=" + installMailRelayForRender,
	"inviteMail.from=" + installMailFromForRender,
}

// TestShippedProfileCarriesTheDomainPlaceholder — предпосылка Р1.
func TestShippedProfileCarriesTheDomainPlaceholder(t *testing.T) {
	raw, err := os.ReadFile("values.prod.yaml")
	require.NoError(t, err)
	var prof struct {
		Authn struct {
			Domain string `yaml:"domain"`
		} `yaml:"authn"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &prof))
	t.Logf("authn.domain профиля: %q", prof.Authn.Domain)
	require.True(t, strings.HasSuffix(prof.Authn.Domain, ".invalid"),
		"профиль больше не несёт заглушки в зоне .invalid — Р1 судил бы пустоту")
}

// TestDomainPlaceholderIsRefusedAtInstall — Р1, Р2, Р3.
func TestDomainPlaceholderIsRefusedAtInstall(t *testing.T) {
	t.Run("профиль как есть", func(t *testing.T) {
		out, err := renderProdRaw(t, installMailSets...)
		require.Errorf(t, err, "профиль с оставленной заглушкой домена отрендерился — обещанного отказа нет")
		require.Contains(t, out, "authn.domain", "отказ не называет ключа — оператору нечего сделать")
	})
	for _, v := range []string{"ACCESS.Example.INVALID", "access.example.invalid.", "kaname.invalid", "invalid"} {
		t.Run("форма "+v, func(t *testing.T) {
			out, err := renderProdRaw(t, append([]string{"authn.domain=" + v}, installMailSets...)...)
			require.Errorf(t, err, "заглушка %q прошла рендер", v)
			require.Contains(t, out, "authn.domain")
		})
	}
	t.Run("домен установки", func(t *testing.T) {
		out, err := renderProdRaw(t, append([]string{"authn.domain=" + installDomainForRender}, installMailSets...)...)
		require.NoErrorf(t, err, "профиль с доменом установки не отрендерился:\n%s", out)
		require.Contains(t, out, `domain: "`+installDomainForRender+`"`, "в карту настроек уехал не домен установки")
	})
	t.Run("имя, лишь содержащее invalid", func(t *testing.T) {
		out, err := renderProdRaw(t, append([]string{"authn.domain=invalid.kaname.local"}, installMailSets...)...)
		require.NoErrorf(t, err, "имя вне зоны .invalid отвергнуто — признак судит строку, а не зону:\n%s", out)
	})
}
