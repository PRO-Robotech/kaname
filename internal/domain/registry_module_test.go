// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain_test

// registry_module_test.go — registry module membership + label-selectability.
//
// `registry` becomes a known platform module; its namespace resource
// `registry.registries` is label-selectable (own-table labels drive authz
// label-scope), while the per-repo `registry.repositories` projection is
// name-selectable only (repos appear via docker push, no labels).

import (
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

func TestRegistryModuleKnown(t *testing.T) {
	if !domain.IsKnownModule("registry") {
		t.Error("domain.IsKnownModule(\"registry\") = false; want true")
	}
}

func TestRegistryLabelSelectability(t *testing.T) {
	if !domain.IsLabelSelectableType("registry.registries") {
		t.Error("registry.registries must be label-selectable (label-scoped authz)")
	}
	if domain.IsLabelSelectableType("registry.repositories") {
		t.Error("registry.repositories must NOT be label-selectable (name-selectable only)")
	}
}
