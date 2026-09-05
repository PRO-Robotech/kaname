// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// jwks_proxy_caller_test.go — способен ли слушатель набора проверочных ключей
// УСТАНОВИТЬ, кто к нему пришёл.
//
// Вопрос нужен не набору ключей, а соседней поверхности того же слушателя:
// авторитету отзыва, которому присылают предъявленный токен. Обработчик на
// слушателе, который сертификата даже не запрашивает, — контроль, которому
// нечем отказать.
package config

import (
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
)

func TestJWKSProxyVerifiesCaller(t *testing.T) {
	enabled := grpcsrv.TLSServer{Enable: true, CertFile: "c", KeyFile: "k", ClientCAFiles: []string{"ca"}}

	cases := map[string]struct {
		edge grpcsrv.TLSServer
		mode string
		want bool
	}{
		"выключенный слушатель никого не устанавливает": {grpcsrv.TLSServer{}, "mutual", false},
		"server-tls-only не запрашивает сертификат":     {enabled, "server-tls-only", false},
		"пустой режим падает в server-tls-only":         {enabled, "", false},
		"неизвестный режим не считается сужением":       {enabled, "whatever", false},
		"mutual устанавливает":                          {enabled, "mutual", true},
		"optional-mutual устанавливает":                 {enabled, "optional-mutual", true},
	}
	for name, c := range cases {
		m := MTLSConfig{JWKSProxyServerMTLS: c.edge, JWKSProxyClientAuthMode: c.mode}
		if got := m.JWKSProxyVerifiesCaller(); got != c.want {
			t.Fatalf("%s: ожидалось %v, получено %v", name, c.want, got)
		}
	}
}

func TestOptionalMutualRequiresAClientCA(t *testing.T) {
	// Режим, объявленный проверяющим сертификат и не имеющий, ЧЕМ проверять, —
	// та же форма без содержания: он выглядел бы сужением и не сужал бы ничего.
	m := MTLSConfig{
		JWKSProxyServerMTLS:     grpcsrv.TLSServer{Enable: true, CertFile: "c", KeyFile: "k"},
		JWKSProxyClientAuthMode: "optional-mutual",
	}
	if err := m.Validate(); err == nil {
		t.Fatalf("optional-mutual без клиентского удостоверяющего центра принят")
	}

	// Положительный контроль: с удостоверяющим центром режим законен —
	// иначе отрицание зелено на проверке, отвергающей любой режим.
	m.JWKSProxyServerMTLS.ClientCAFiles = []string{"ca"}
	if err := m.Validate(); err != nil {
		t.Fatalf("законный optional-mutual отвергнут: %v", err)
	}
}
