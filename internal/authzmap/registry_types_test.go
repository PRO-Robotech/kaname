// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmap_test

// registry_types_test.go — registry module FGA object-type registration.
//
// kacho-registry владеет двумя FGA-типами: `registry_registry` (namespace) и
// `registry_repository` (per-repo). Оба verb-bearing (полный v_* набор,
// развязанный от tier). object-prefix `registry_` совпадает с именем сервиса
// kacho-registry — словарь имён модулей (pkg/platformmodules) объявляет у него
// обе колонки одинаковыми.

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
)

func TestRegistryObjectTypes(t *testing.T) {
	cases := []struct {
		module, resource, fga string
	}{
		{"registry", "registries", "registry_registry"},
		{"registry", "repositories", "registry_repository"},
	}
	for _, c := range cases {
		got, ok := authzmap.ObjectType(c.module, c.resource)
		if !ok || got != c.fga {
			t.Errorf("ObjectType(%q,%q) = %q,%v; want %q,true", c.module, c.resource, got, ok, c.fga)
		}
		if !authzmap.TypeHasVerbRelations(c.fga) {
			t.Errorf("TypeHasVerbRelations(%q) = false; want true (verb-bearing)", c.fga)
		}
		// reverse index must round-trip so the reconciler tuple-builder and the
		// verify-gate ledger lookup resolve the same dotted key.
		if dotted, ok := authzmap.DottedType(c.fga); !ok || dotted != c.module+"."+c.resource {
			t.Errorf("DottedType(%q) = %q,%v; want %q,true", c.fga, dotted, ok, c.module+"."+c.resource)
		}
	}
}
