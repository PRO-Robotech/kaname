// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// authn_domain_placeholder_test.go — заглушка домена в зарезервированной зоне
// `.invalid`, поданная мимо чарта переменной процесса, отвергается стражем
// старта (kaname#762).
//
// Чарт отказывает в установке с такой заглушкой, но величина доезжает до
// процесса и в обход чарта — переменной `KANAME_AUTHN__DOMAIN`. Имя в зоне
// `.invalid` не разрешается ни у одной установки (RFC 2606, RFC 6761), а из
// него выводится адресат КАЖДОГО выпущенного удостоверения: старт с ним
// выглядел бы настроенным, будучи ненастроенным.
//
// Утверждается:
//
//	С1  величина, поданная переменной процесса, доезжает до стража и
//	    отвергается; отказ называет поле и переменную;
//	С2  та же заглушка в любой форме записи (регистр, завершающая точка,
//	    другая первая метка, голая зона) отвергается так же — признак в зоне,
//	    а не в строке образца;
//	С3  ЗАКОННЫЕ БЛИЗНЕЦЫ: имя вне зоны, в том числе лишь СОДЕРЖАЩЕЕ метку
//	    `invalid`, старт проходит;
//	С4  образец строки таблицы — заглушка, которую страж отвергает: обещание
//	    «установка, взявшая образец как есть, обнаружит это сразу» исполнимо, а
//	    подстановка домена установки в сборке профиля из таблицы не переживает
//	    своего предмета.
package config_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// TestPlaceholderDomainFromEnvRefusesTheStart — С1.
func TestPlaceholderDomainFromEnvRefusesTheStart(t *testing.T) {
	t.Setenv("KANAME_AUTHN__DOMAIN", "access.example.invalid")

	loaded, err := config.Load("")
	require.NoError(t, err)
	require.Equal(t, "access.example.invalid", loaded.AuthN.Domain,
		"предпосылка: переменная процесса обязана доехать до настройки — иначе страж судил бы не её")

	verdict := domainCfg(loaded.AuthN.Domain).Validate()
	require.Error(t, verdict,
		"заглушка в зоне .invalid, поданная переменной процесса, прошла старт — "+
			"каждое выпущенное удостоверение адресовано имени, которого нет ни у одной установки")
	require.Contains(t, verdict.Error(), "authn.domain", "отказ обязан называть поле")
	require.Contains(t, verdict.Error(), "KANAME_AUTHN__DOMAIN", "отказ обязан называть переменную")
	require.Contains(t, verdict.Error(), ".invalid", "отказ обязан называть причину, а не только поле")
}

// TestPlaceholderDomainIsRefusedInEveryForm — С2 и С3.
func TestPlaceholderDomainIsRefusedInEveryForm(t *testing.T) {
	for _, v := range []string{
		"access.example.invalid",
		"ACCESS.Example.INVALID",
		"access.example.invalid.",
		" kaname.invalid ",
		"invalid",
	} {
		t.Run("заглушка "+v, func(t *testing.T) {
			err := domainCfg(v).Validate()
			require.Errorf(t, err, "заглушка %q прошла старт", v)
			require.Contains(t, err.Error(), "authn.domain")
		})
	}
	for _, v := range []string{"access.example.test", "invalid.kaname.local", "kaname.invalid-zone.test"} {
		t.Run("близнец "+v, func(t *testing.T) {
			require.NoErrorf(t, domainCfg(v).Validate(),
				"имя вне зоны .invalid отвергнуто — признак судит строку, а не зону")
		})
	}
}

// TestDomainSampleIsThePlaceholderTheGuardRefuses — С4.
func TestDomainSampleIsThePlaceholderTheGuardRefuses(t *testing.T) {
	var sample string
	rows := 0
	for _, s := range config.RequiredSettings {
		if s.Key == "authn.domain" {
			sample, rows = s.Sample, rows+1
		}
	}
	require.Equal(t, 1, rows, "строка authn.domain в таблице обязательных величин не одна либо её нет")
	err := domainCfg(sample).Validate()
	require.Errorf(t, err, "образец %q проходит старт — обещание образца не исполнимо, "+
		"а подстановка домена в сборке профиля пережила свой предмет", sample)
	require.Contains(t, err.Error(), "authn.domain")
}
