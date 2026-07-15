// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package permission_catalog — PermissionCatalogService.ListPermissionCatalog
// (RBAC rules-model 2026).
//
// The backend-driven grantable role-rule catalog: a PUBLIC sync read returning
// the grantable-token taxonomy (modules → resources + per-type editor flags),
// the closed verb set, and the wildcard policy. It is a PROJECTION FROM CODE —
// authzmap.Catalog() (the closed objectTypes table) + authzmap.TypeHasVerbRelations
// + domain.ClosedVerbs + a curated hasListEndpoint table — there is NO database,
// NO migration, NO repo/pg layer. The catalog is immutable at runtime; it
// extends only with a new backend release that adds a (module,resource) pair to
// objectTypes (lockstep with fga_model.fga), which then appears automatically
// (the projection is derived, not hand-maintained).
//
// Clean-arch: this use-case imports only `domain` + `authzmap` (both in-process
// projections). It does NOT import grpc/proto — the handler projects the
// use-case output to the proto wire shape.
package permission_catalog

import (
	"context"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// Catalog — the grantable taxonomy projection (use-case DTO; the handler maps
// it to ListPermissionCatalogResponse). Fields mirror the grantable taxonomy
// contract, in their backend-domain form.
type Catalog struct {
	// Modules — ordered grantable modules, each with its grantable resources.
	Modules []Module
	// ClosedVerbs — mirror of domain.ClosedVerbs (fixed order).
	ClosedVerbs []string
	// Wildcard — platform-wide wildcard policy flags.
	Wildcard WildcardPolicy
}

// Module — a grantable module and the resources grantable within it.
type Module struct {
	Module    string
	Resources []Resource
}

// Resource — one grantable (module,resource) token plus the editor flags.
type Resource struct {
	// Resource — the 2nd token segment, spelled exactly as in authzmap.objectTypes.
	Resource string
	// HasVerbRelations — mirror of authzmap.TypeHasVerbRelations(objectType):
	// true for verb-bearing leaves, false for tier-only ancestors (account/project).
	HasVerbRelations bool
	// HasListEndpoint — true iff the type has a PUBLIC per-object filtered List on
	// the api-gateway EXTERNAL listener (curated closed table; Internal-only List
	// does NOT count). Drives the resourceNames picker vs free-text fallback.
	HasListEndpoint bool
	// LabelSelectable — mirror of domain.IsLabelSelectableType("module.resource"):
	// true iff the type is in the label-selectable feed set (mirror-fed types +
	// iam.project/iam.account). The editor must NOT offer a match_labels
	// (ARM_LABELS) arm on a type where this is false — the rule compiler
	// fail-closed-rejects such a rule (e.g. vpc.addressPool is grantable+
	// verb-bearing but NOT label-selectable). ARM_NAMES is NOT feed-gated.
	LabelSelectable bool
}

// WildcardPolicy — the catalog's wildcard policy flags, in parity with the
// rule-compiler enforcement (one source of policy truth).
type WildcardPolicy struct {
	// VerbWildcardAllowedCustom — verb-`*` is grantable in a custom role (bounded
	// "all verbs of the type").
	VerbWildcardAllowedCustom bool
	// ModuleResourceWildcardSystemOnly — module-`*` AND resource-`*` are
	// system-only (custom-role use → INVALID_ARGUMENT).
	ModuleResourceWildcardSystemOnly bool
}

// ListPermissionCatalogUseCase — builds the catalog projection. Stateless (the
// catalog is in-code); constructed once in the composition root.
type ListPermissionCatalogUseCase struct{}

// NewListPermissionCatalogUseCase — builder.
func NewListPermissionCatalogUseCase() *ListPermissionCatalogUseCase {
	return &ListPermissionCatalogUseCase{}
}

// Execute returns the grantable taxonomy. Authenticated-floor: an anonymous
// caller is rejected fail-closed BEFORE any taxonomy is built. The
// catalog is platform-wide metadata — it is NOT scope-filtered per-tenant,
// so every authenticated principal receives the identical full set.
func (u *ListPermissionCatalogUseCase) Execute(ctx context.Context) (Catalog, error) {
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return Catalog{}, err
	}

	// Project authzmap.Catalog() (the closed objectTypes table) into ordered
	// modules → resources. Catalog() is already sorted by the dotted key, so
	// modules and resources both come out deterministically ordered, and a
	// future objectTypes addition appears automatically.
	var modules []Module
	idxByModule := make(map[string]int)
	for _, e := range authzmap.Catalog() {
		fgaType, _ := authzmap.ObjectType(e.Module, e.Resource)
		res := Resource{
			Resource:         e.Resource,
			HasVerbRelations: authzmap.TypeHasVerbRelations(fgaType),
			HasListEndpoint:  hasPublicListEndpoint(e.Module, e.Resource),
			// LabelSelectable — the ARM_LABELS feed-gate, projected straight from
			// the domain source of truth (the dotted key matches authzmap's form).
			LabelSelectable: domain.IsLabelSelectableType(e.Module + "." + e.Resource),
		}
		i, ok := idxByModule[e.Module]
		if !ok {
			i = len(modules)
			idxByModule[e.Module] = i
			modules = append(modules, Module{Module: e.Module})
		}
		modules[i].Resources = append(modules[i].Resources, res)
	}

	// closedVerbs — copy domain.ClosedVerbs (fixed order); never alias the
	// package-level slice so callers cannot mutate the source of truth.
	closedVerbs := make([]string, len(domain.ClosedVerbs))
	copy(closedVerbs, domain.ClosedVerbs)

	return Catalog{
		Modules:     modules,
		ClosedVerbs: closedVerbs,
		Wildcard: WildcardPolicy{
			VerbWildcardAllowedCustom:        true, // verb-`*` bounded.
			ModuleResourceWildcardSystemOnly: true, // module/resource-`*` system-only.
		},
	}, nil
}
