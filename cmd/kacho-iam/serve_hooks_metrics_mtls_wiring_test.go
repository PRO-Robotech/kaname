// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"strings"
	"testing"
)

// TestHooksMetricsMTLS_ServeWiresTLSListeners — P0 hardening wiring guard.
//
// serve.go must wrap the HTTP hooks (:9092) and /metrics (:9095) net.Listen with
// tls.NewListener using a *tls.Config built per-edge from config.LoadMTLS() →
// HooksServerTLSConfig()/MetricsServerTLSConfig(). Default-off: when the *tls.Config
// is nil (enable=false) the listener stays PLAINTEXT (byte-identical to today).
//
// RED-demonstration: remove the tls.NewListener wrap / the per-edge builders from
// serve.go → this test fails before merge.
func TestHooksMetricsMTLS_ServeWiresTLSListeners(t *testing.T) {
	src := readFileT(t, "serve.go")

	// Both per-edge HTTP-listener TLS builders must be invoked in the
	// composition root.
	for _, m := range []string{"HooksServerTLSConfig()", "MetricsServerTLSConfig()"} {
		if !strings.Contains(src, m) {
			t.Errorf("serve.go: нет вызова %s (per-edge HTTP listener mTLS builder)", m)
		}
	}

	// Обёртка слушателя транспортом ЗДЕСЬ БОЛЬШЕ НЕ ИЩЕТСЯ, и это усиление, а не
	// послабление. Прежняя проверка считала вхождения имени функции в ИСХОДНИКЕ:
	// она осталась бы зелёной, напиши кто-нибудь это имя в комментарии, и
	// покраснела бы, переедь обёртка на этаж ниже — что и произошло. Транспорт
	// теперь надевает профиль не-gRPC поверхности, а что объявленный транспорт
	// РЕАЛЬНО доезжает до слушателя, утверждается на проводе:
	// `TestSurfaceDeclaredTLSReachesTheListener` (pkg/servicehost) — открытым
	// текстом до обработчика не достучаться, по TLS ответ штатный.
	//
	// Здесь остаётся то, что принадлежит именно этому корню: транспорт каждой
	// поверхности СОБИРАЕТСЯ своим построителем и ДОВОЗИТСЯ до объявления.
	//
	// Проверяется ПОИМЕННО, а не счётчиком вхождений подстроки «TLS:»: та стоит и
	// в трёх соседних комментариях этого же файла, и счётчик по ней был бы зелен
	// при любой утерянной проводке. Каждое имя ниже — присваивание конкретного
	// собранного транспорта конкретному объявлению, и в прозе оно не встречается.
	for _, want := range []string{
		"TLS: hooksTLSConfig,",
		"TLS: metricsTLSConfig,",
		"TLS: registryTokenTLSConfig,",
		"TLS: jwksProxyTLSConfig,",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("serve.go: собранный транспорт не доехал до объявления поверхности (%q) — "+
				"построитель отработал, а слушатель остался бы открытым", want)
		}
	}

	// MTLSConfig.Validate() must be called so an enabled-but-no-cert edge fails
	// fast at boot (fail-closed).
	if !strings.Contains(src, "mtlsCfg.Validate()") {
		t.Errorf("serve.go: нет mtlsCfg.Validate() — enabled-but-no-cert edge не fail-close'ится на старте")
	}

	// Startup log must reflect the two new per-edge states (observability +
	// audit trail that the listener is/ isn't TLS).
	for _, want := range []string{"hooks_mtls", "metrics_mtls"} {
		if !strings.Contains(src, want) {
			t.Errorf("serve.go: startup log не содержит %q (per-edge HTTP mTLS state)", want)
		}
	}
}
