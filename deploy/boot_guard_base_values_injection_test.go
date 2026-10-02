// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// boot_guard_base_values_injection_test.go — доказательство того, что соседняя
// проба СПОСОБНА упасть, и падает ровно на своём предмете.
//
// ФОРМА ДОКАЗАТЕЛЬСТВА. Вход берётся НАСТОЯЩИЙ — базовые значения этого чарта,
// переложение и таблица стража, — и каждый случай меняет РОВНО ОДИН лист.
// Вердикт случая читается ТОЛЬКО по ключу, который случай тронул: находка у
// соседнего ключа не засчитывается ни в красное, ни в молчание — иначе красное
// могло бы прийти от соседа, а не от внесённого дефекта.
//
// ФОРМЫ ДОКАЗЫВАЮТСЯ ПО ОДНОЙ, и у каждой красной есть законный близнец, на
// котором проба молчит: литерал строкой ↔ пустая строка и снятый ключ;
// поднятый выключатель блока ↔ опущенный; непустой перечень ↔ пустой;
// ненулевое число ↔ ноль (слепая зона — молчит, но считается). Отдельный близнец
// — литерал у ключа, который страж НЕ судит: без него проба ловила бы форму
// («непусто»), а не существо («отменяет ли это стража»).
package deploy_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// realBaseValues — свежая копия базовых значений чарта: каждый случай портит
// свою, и порча одного не доезжает до другого.
func realBaseValues(t *testing.T) map[string]any {
	t.Helper()
	base, err := readChartValues(filepath.Join(serviceRoot(t), "deploy", chartDefaultsFile))
	if err != nil {
		t.Fatalf("фикстура не собрана, базовые значения не читаются: %v", err)
	}
	return base
}

func TestBaseValueSubstitutionInjection(t *testing.T) {
	cases := []struct {
		name      string
		configKey string // ключ стража, о котором случай
		path      []string
		value     any
		remove    bool
		wantRed   bool
		wantBlind bool
	}{
		{name: "литерал строкой у срока ключа подписи", configKey: "authn.token-signing.key-lifetime",
			path: []string{"authn", "tokenSigning", "keyLifetime"}, value: "2160h", wantRed: true},
		{name: "близнец: пустая строка у срока ключа подписи", configKey: "authn.token-signing.key-lifetime",
			path: []string{"authn", "tokenSigning", "keyLifetime"}, value: ""},
		{name: "близнец: пробельная строка у срока ключа подписи", configKey: "authn.token-signing.key-lifetime",
			path: []string{"authn", "tokenSigning", "keyLifetime"}, value: "  "},
		{name: "близнец: срок ключа подписи снят вовсе", configKey: "authn.token-signing.key-lifetime",
			path: []string{"authn", "tokenSigning", "keyLifetime"}, remove: true},
		{name: "литерал строкой у домена доверия", configKey: "authn.trust-domain",
			path: []string{"authn", "trustDomain"}, value: "substituted.example.invalid", wantRed: true},
		{name: "выключатель блока поднят базовыми значениями", configKey: "authn.presented-credential.enabled",
			path: []string{"authn", "presentedCredential", "enabled"}, value: true, wantRed: true},
		{name: "близнец: выключатель блока опущен", configKey: "authn.presented-credential.enabled",
			path: []string{"authn", "presentedCredential", "enabled"}, value: false},
		{name: "непустой перечень", configKey: "authn.trusted-forwarder-sans",
			path: []string{"authn", "trustedForwarderSANs"}, value: []any{"spiffe://substituted.example.invalid/x"}, wantRed: true},
		{name: "близнец: пустой перечень", configKey: "authn.trusted-forwarder-sans",
			path: []string{"authn", "trustedForwarderSANs"}, value: []any{}},
		{name: "ненулевое число у собственного потолка", configKey: "own-ceilings.accounts-per-identity",
			path: []string{"ownCeilings", "accountsPerIdentity"}, value: 5, wantRed: true},
		{name: "близнец: ноль у собственного потолка — слепая зона, молчит и считается",
			configKey: "own-ceilings.accounts-per-identity",
			path:      []string{"ownCeilings", "accountsPerIdentity"}, value: 0, wantBlind: true},
		{name: "близнец: литерал у ключа, который страж НЕ судит", configKey: "authn.token-signing.key-set-path",
			path: []string{"authn", "tokenSigning", "keySetPath"}, value: "/substituted/jwks.json"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := realBaseValues(t)
			_, controlCensus, err := auditBaseValueSubstitution(configBridge, base, config.RequiredSettings)
			if err != nil {
				t.Fatalf("контроль на целой копии не состоялся: %v", err)
			}

			if tc.remove {
				removeAt(base, tc.path)
			} else {
				setAt(base, tc.path, tc.value)
			}

			findings, census, err := auditBaseValueSubstitution(configBridge, base, config.RequiredSettings)
			if err != nil {
				t.Fatalf("обход не состоялся: %v", err)
			}
			var hit *baseValueFinding
			for i := range findings {
				if findings[i].ConfigKey == tc.configKey {
					hit = &findings[i]
				}
			}

			switch {
			case tc.wantRed && hit == nil:
				t.Fatalf("внесённая подстановка %v = %#v не найдена — проба молчит на своём предмете\nперепись: %s",
					tc.path, tc.value, census)
			case !tc.wantRed && hit != nil:
				t.Fatalf("законный близнец дал находку — проба ловит форму, а не существо:\n%s", hit)
			}
			if hit != nil {
				// Находка обязана называть ПРИЧИНУ, а не симптом: ключ стража,
				// лист базовых значений и переменную, которой оператор его задаст.
				row := requiredSettingByKey(t, tc.configKey)
				text := hit.String()
				for _, want := range []string{tc.configKey, row.Env, chartDefaultsFile} {
					if !strings.Contains(text, want) {
						t.Fatalf("находка не называет %q:\n%s", want, text)
					}
				}
			}
			if tc.wantBlind && census.Blind != controlCensus.Blind+1 {
				t.Fatalf("ноль у листа по пути значения обязан лечь в слепую зону ЧИСЛОМ: "+
					"контроль %d, после инъекции %d", controlCensus.Blind, census.Blind)
			}
		})
	}
}

// TestBaseValueSubstitutionEmptyTraversalIsNotGreen — пустой обход по каждому
// из трёх входов — отказ, а не «находок 0».
func TestBaseValueSubstitutionEmptyTraversalIsNotGreen(t *testing.T) {
	base := realBaseValues(t)
	for name, run := range map[string]func() error{
		"пустая таблица стража": func() error {
			_, _, err := auditBaseValueSubstitution(configBridge, base, nil)
			return err
		},
		"пустое переложение": func() error {
			_, _, err := auditBaseValueSubstitution(nil, base, config.RequiredSettings)
			return err
		},
		"пустые базовые значения": func() error {
			_, _, err := auditBaseValueSubstitution(configBridge, map[string]any{}, config.RequiredSettings)
			return err
		},
		"переложение без единого ключа стража": func() error {
			_, _, err := auditBaseValueSubstitution(
				[]bridged{{configKey: "logger.level", valuePath: []string{"logger", "level"}}},
				base, config.RequiredSettings)
			return err
		},
	} {
		if run() == nil {
			t.Errorf("%s: обход вернул вердикт вместо отказа — «ноль находок» стало бы "+
				"неотличимо от «ноль прочитанного»", name)
		}
	}
}

// requiredSettingByKey — строка таблицы стража по ключу. Отсутствие — отказ
// фикстуры: случай про ключ, которого страж не судит, ничего не доказывает.
func requiredSettingByKey(t *testing.T, key string) config.RequiredSetting {
	t.Helper()
	for _, s := range config.RequiredSettings {
		if s.Key == key {
			return s
		}
	}
	t.Fatalf("фикстура беспредметна: в таблице стража нет строки %q", key)
	return config.RequiredSetting{}
}
