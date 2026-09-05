// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain_test

// registry_module_test.go — registry module membership + label-selectability.
//
// `registry` becomes a known platform module; its namespace resource
// `registry.registries` is label-selectable (own-table labels drive authz
// label-scope), while the per-repo `registry.repositories` projection is
// name-selectable only (repos appear via docker push, no labels).

import (
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// Утверждение «registry — модуль платформы» ЗДЕСЬ СНЯТО ВМЕСТЕ С ПРЕДМЕТОМ
// (#1927): домен закрытого набора не объявляет, и проба на `domain.IsKnownModule`
// перестала бы иметь вход, оставшись на вид рабочей. Точный состав набора пинит
// `authzmap/module_set_drift_test.go` — у него есть производитель
// (`authzmap.CatalogSeedModules`), а у домена его нет by construction.

func TestRegistryLabelSelectability(t *testing.T) {
	if !domain.IsLabelSelectableType("registry.registries") {
		t.Error("registry.registries must be label-selectable (label-scoped authz)")
	}
	if domain.IsLabelSelectableType("registry.repositories") {
		t.Error("registry.repositories must NOT be label-selectable (name-selectable only)")
	}
}
