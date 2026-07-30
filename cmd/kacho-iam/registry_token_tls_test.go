// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
)

// TestRequireRegistryTokenTLS — по слушателю docker-token (`/iam/token`) едет
// HTTP Basic, чей пароль — ПРИВАТНЫЙ КЛЮЧ ключа служебной учётки: сервер его не
// хранит вовсе (сверяет выведенный SPKI с сохранённым публичным), поэтому этот
// хоп — единственное место в системе, где приватный ключ вообще транзитит. Срок
// жизни ключа не ограничен, ротации нет: снятый с провода credential предъявляется
// напрямую и без окна TTL.
//
// Отсюда гейт: в production слушатель либо несёт TLS, либо не поднимается. Молча
// возить бессрочный секрет открытым текстом между подами нельзя — тем более что
// СЛАБЕЙШАЯ соседняя нога (5-минутный bearer на loopback) собственный ack-гейт
// давно получила.
func TestRequireRegistryTokenTLS(t *testing.T) {
	on := grpcsrv.TLSServer{Enable: true, CertFile: "/tls/tls.crt", KeyFile: "/tls/tls.key"}
	off := grpcsrv.TLSServer{}
	cases := []struct {
		name       string
		production bool
		addr       string
		edge       grpcsrv.TLSServer
		wantErr    bool
	}{
		{"dev-plaintext-ok", false, "0.0.0.0:9096", off, false},
		{"prod-listener-disabled-ok", true, "", off, false},
		{"prod-tls-on-ok", true, "0.0.0.0:9096", on, false},
		{"prod-plaintext-rejected", true, "0.0.0.0:9096", off, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var m config.MTLSConfig
			m.RegistryTokenServerMTLS = tc.edge
			err := requireRegistryTokenTLS(tc.production, tc.addr, m)
			if tc.wantErr {
				if err == nil {
					t.Fatal("want refusal, got nil")
				}
				// Оператор обязан узнать из отказа, ЧТО включить.
				if !strings.Contains(err.Error(), "KACHO_IAM_REGISTRYTOKEN_SERVER_MTLS_ENABLE") {
					t.Fatalf("refusal does not name the knob: %q", err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("want nil, got %v", err)
			}
		})
	}
}
