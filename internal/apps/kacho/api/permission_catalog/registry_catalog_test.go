// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package permission_catalog

// registry_catalog_test.go — backend-driven catalog surfaces the registry
// module after iam-регистрации: resources `registries` (label-selectable,
// has-list) + `repositories` (name-selectable, has-list); verbs get/list/
// create/update/delete; both verb-bearing.

import (
	"testing"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
)

// findModule returns the catalog module by name, or nil.
func findModule(resp *iamv1.ListPermissionCatalogResponse, name string) *iamv1.CatalogModule {
	for _, m := range resp.GetModules() {
		if m.GetModule() == name {
			return m
		}
	}
	return nil
}

func TestListPermissionCatalog_IncludesRegistryModule(t *testing.T) {
	resp := callCatalog(t)

	mod := findModule(resp, "registry")
	if mod == nil {
		t.Fatal("registry module missing from permission catalog")
	}

	want := map[string]struct {
		labelSelectable bool
	}{
		"registries":   {labelSelectable: true},
		"repositories": {labelSelectable: false},
	}
	seen := map[string]bool{}
	for _, r := range mod.GetResources() {
		exp, ok := want[r.GetResource()]
		if !ok {
			t.Errorf("unexpected registry resource %q in catalog", r.GetResource())
			continue
		}
		seen[r.GetResource()] = true
		if !r.GetHasVerbRelations() {
			t.Errorf("registry.%s must be verb-bearing (hasVerbRelations=true)", r.GetResource())
		}
		if !r.GetHasListEndpoint() {
			t.Errorf("registry.%s must have a public List endpoint (hasListEndpoint=true)", r.GetResource())
		}
		if r.GetLabelSelectable() != exp.labelSelectable {
			t.Errorf("registry.%s labelSelectable = %v; want %v",
				r.GetResource(), r.GetLabelSelectable(), exp.labelSelectable)
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("registry resource %q missing from catalog", name)
		}
	}
}
