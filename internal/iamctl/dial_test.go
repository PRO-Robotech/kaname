// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package iamctl

import (
	"strings"
	"testing"
	"time"
)

// dial_test.go — адрес службы и удостоверение к ней приезжают ПАРОЙ.
//
// Объявить адрес без удостоверения значит завести контроль, который отказывает
// ВСЕГДА и по одной и той же причине, а выглядит настроенным
// (`security.md` §«Контроль, у которого нет МЕХАНИЗМА исполниться»). Поэтому
// половина пары отвергается на разборе вызова, а не на первом обращении к сети.
func TestDialConfigRequiresTheAddressAndTheCredentialTogether(t *testing.T) {
	full := DialConfig{
		Endpoint:   "iam-internal.kacho.svc:9091",
		ServerName: "kaname-internal",
		CAFiles:    []string{"/tls/ca.crt"},
		CertFile:   "/tls/tls.crt",
		KeyFile:    "/tls/tls.key",
		Timeout:    30 * time.Second,
	}

	t.Run("полная пара принимается", func(t *testing.T) {
		if err := full.Validate(); err != nil {
			t.Fatalf("полная пара отвергнута: %v", err)
		}
	})

	for _, tc := range []struct {
		name   string
		mutate func(*DialConfig)
		needs  []string
	}{
		{"адреса нет", func(c *DialConfig) { c.Endpoint = "" }, []string{"-endpoint"}},
		{"имени в сертификате нет", func(c *DialConfig) { c.ServerName = "" }, []string{"-server-name"}},
		{"корня доверия нет", func(c *DialConfig) { c.CAFiles = nil }, []string{"-ca"}},
		{"своего сертификата нет", func(c *DialConfig) { c.CertFile = "" }, []string{"-cert"}},
		{"ключа нет", func(c *DialConfig) { c.KeyFile = "" }, []string{"-key"}},
		{"срок вызова не задан", func(c *DialConfig) { c.Timeout = 0 }, []string{"-timeout"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := full
			tc.mutate(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("половина пары принята: %+v", cfg)
			}
			for _, n := range tc.needs {
				if !strings.Contains(err.Error(), n) {
					t.Fatalf("отказ обязан назвать поле %q, а сказал: %v", n, err)
				}
			}
		})
	}
}

// Незашифрованного пути у инструмента НЕТ, и это не забытая ручка.
//
// Именованный флаг обхода («-insecure», «-plaintext») здесь запрещён: он даёт
// посадку, годную только для стенда, а всякий поднятый стенд работает в
// производственной посадке. Проверяется НЕ отсутствием слова в тексте — а тем,
// что вырожденная посадка не проходит разбора ни при каком входе.
func TestDialConfigHasNoInsecureLane(t *testing.T) {
	bare := DialConfig{Endpoint: "127.0.0.1:9091", Timeout: time.Second}
	if err := bare.Validate(); err == nil {
		t.Fatal("посадка без удостоверения принята — у инструмента появился незашифрованный путь")
	}
}
