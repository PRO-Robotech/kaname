// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// fga_types.go — closed (module, resource) → fga_object_type table.
//
// RBAC v2. Every concrete-resourceName permission emits a
// direct per-object FGA tuple at the type returned here. Wildcard-
// resourceName permissions emit a tier tuple at the binding's scope
// anchor instead, and the returned ok is false when the pair is unknown
// — the caller falls back to the scope-anchor.
//
// Extending this table requires updating `fga_model.fga` in lockstep
// (kacho-proto). The table is intentionally a closed enumeration: an
// unknown pair must NOT silently land as an arbitrary FGA type.
package authzmap

import (
	"sort"
	"strings"
)

// ObjectType returns the OpenFGA object_type for (module, resource).
// ok=false when the pair is not in the closed table.
func ObjectType(module, resource string) (string, bool) {
	o, ok := objectTypes[module+"."+resource]
	return o, ok
}

// FGAObjectType resolves the OpenFGA object_type for a dotted closed-table key
// ("vpc.securityGroup" → "vpc_security_group", "iam.account" → "account"). It is
// the single canonical dotted→FGA-type mapping (SplitObjectType on the FIRST dot,
// then ObjectType over the closed table) shared by every FGA-object derivation —
// the reconciler's tuple builder and the verify-gate's ledger lookup both route
// through it so their object keys cannot drift. ok=false when the dotted key is not
// in the closed table (callers must NOT fall back to a hand-rolled substitution —
// an unknown type must surface as ok=false, never as an arbitrary FGA type).
func FGAObjectType(dotted string) (string, bool) {
	module, resource, ok := SplitObjectType(dotted)
	if !ok {
		return "", false
	}
	return ObjectType(module, resource)
}

// CatalogEntry — one grantable (module, resource) pair from the closed
// objectTypes table. The dotted key "module.resource" is the canonical token
// form; Module / Resource are its two segments (split on the FIRST dot, same as
// SplitObjectType).
type CatalogEntry struct {
	Module   string
	Resource string
}

// Catalog returns every grantable (module, resource) pair in the closed
// objectTypes table, in a deterministic order (sorted by the dotted
// "module.resource" key). It is the SINGLE exported source of the grantable
// taxonomy — the PermissionCatalogService projects EXACTLY this set
// (no additions, no omissions), so a future objectTypes entry appears in the
// public catalog with no catalog-code change. Pairing it with ObjectType /
// TypeHasVerbRelations gives the per-type FGA object_type and verb-bearing flag.
func Catalog() []CatalogEntry {
	keys := make([]string, 0, len(objectTypes))
	for k := range objectTypes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]CatalogEntry, 0, len(keys))
	for _, k := range keys {
		module, resource, ok := SplitObjectType(k)
		if !ok {
			// objectTypes keys are always well-formed "module.resource"; an
			// unsplittable key would be a table-authoring error. Skip defensively
			// rather than emit a malformed catalog pair.
			continue
		}
		out = append(out, CatalogEntry{Module: module, Resource: resource})
	}
	return out
}

// SplitObjectType splits a dotted "module.resource" key on the FIRST dot
// (the resource segment may itself contain no dot; module never does). ok=false
// when the input has no dot or an empty side. Single source of truth shared by
// the tuple builders in access_binding and access_binding/reconcile (previously
// duplicated in both — unified into one helper so the two paths cannot drift).
func SplitObjectType(typ string) (module, resource string, ok bool) {
	i := strings.IndexByte(typ, '.')
	if i <= 0 || i == len(typ)-1 {
		return "", "", false
	}
	return typ[:i], typ[i+1:], true
}

// DottedType maps an OpenFGA object_type (e.g. "compute_instance") back to the
// dotted closed-table key (e.g. "compute.instance") used by role_rule_selectors
// and resource_mirror.object_type. ok=false when the FGA type is not in the
// closed table — callers may then fall back to the FGA type verbatim (the mirror
// keeps a generic opaque object_type). Reverse of ObjectType.
func DottedType(fgaType string) (string, bool) {
	d, ok := dottedByFGAType[fgaType]
	return d, ok
}

// dottedByFGAType — reverse index of objectTypes, built once at init. Last-wins
// is irrelevant: objectTypes values are unique (each FGA type maps from exactly
// one dotted key).
var dottedByFGAType = func() map[string]string {
	m := make(map[string]string, len(objectTypes))
	for dotted, fga := range objectTypes {
		m[fga] = dotted
	}
	return m
}()

// TypeHasVerbRelations reports whether the FGA object_type carries the closed
// per-verb relation set (v_get/v_list/v_create/v_update/v_delete) in the
// canonical authorization model.
//
// rbac-explicit-model-2026 P3 / D-6 (expand): the hierarchy ancestors
// `account` / `project` are now ALSO verb-bearing — the canonical fga_model.fga
// (P2) defines the full v_* set on both, so a grant of e.g. `iam.account.get`
// materializes `account:<id> # v_get @ subj` (object-level access to the
// account itself, NO cascade to its contents — D-2). This is purely ADDITIVE:
// account/project KEEP their tier relations (admin/editor/viewer, the
// write-authz anchors — D-7) and the scope_grant carrier still operates exactly
// as before. Only the v_* emission gate flips for these two types.
//
// This is the single source of truth the FGA emitter consults before writing a
// per-verb `v_<verb>` tuple or a type-scoped `scope_grant` linking tuple:
// emitting either on a tier-only type is a dangling-relation write that OpenFGA
// rejects → drainer.ErrPermanent → poisoned fga_outbox → partial-grant desync
// (the #177 fail-open class). The set is kept in lockstep with fga_model.fga;
// the CI drift-gate (authzmap/fga_model_drift_test.go) fails the build if this
// set ever diverges from the model.
func TypeHasVerbRelations(fgaType string) bool {
	return verbBearingTypes[fgaType]
}

// verbBearingTypes — the closed set of FGA object_types that define the full
// per-verb relation set in fga_model.fga. Enumerated explicitly (not derived by
// subtraction) so a future objectTypes addition does NOT silently inherit
// verb-bearing status — the drift-gate forces an explicit decision here.
//
// rbac-explicit-model-2026 P3 / D-6: `account` and `project` joined this set —
// they are now verb-bearing (full v_* in the canonical model, P2). They REMAIN
// tier-carrying hierarchy ancestors (admin/editor/viewer write-authz anchors,
// D-7); verb-bearing status is additive on top, not a replacement.
var verbBearingTypes = map[string]bool{
	"compute_instance": true,
	"compute_disk":     true,
	"compute_image":    true,
	"compute_snapshot": true,
	// compute placement / capacity / data-protection resources — each is a
	// first-class by-id authz object (its Get/Update/Delete scope_extractor
	// anchors on the object itself, per kacho-proto per-resource object_type),
	// so the canonical model defines the full closed v_* set on each. host_type
	// is read-only at the service layer (Get/List only) but still verb-bearing
	// in the model (uniform v_* across resource types; read-only-ness is enforced
	// by the absence of mutating RPCs, not by omitting model relations).
	"compute_disk_placement_group":   true,
	"compute_host_group":             true,
	"compute_filesystem":             true,
	"compute_gpu_cluster":            true,
	"compute_placement_group":        true,
	"compute_reserved_instance_pool": true,
	"compute_snapshot_schedule":      true,
	"compute_host_type":              true,
	"vpc_network":                    true,
	"vpc_subnet":                     true,
	"vpc_address":                    true,
	"vpc_security_group":             true,
	"vpc_route_table":                true,
	"vpc_gateway":                    true,
	"vpc_network_interface":          true,
	"vpc_address_pool":               true,
	"vpc_anycast_address_pool":       true,
	"nlb_network_load_balancer":       true,
	"nlb_target_group":                true,
	"nlb_listener":                    true,
	"registry_registry":              true,
	"registry_repository":            true,
	"iam_user":                       true,
	"iam_service_account":            true,
	"iam_group":                      true,
	"iam_role":                       true,
	"iam_access_binding":             true,
	"iam_condition":                  true,
	// rbac-2026 P3 / D-6: account/project are now verb-bearing (additive — they
	// also keep their tier relations as write-authz anchors, D-7).
	"account": true,
	"project": true,
}

// expandableRelations — the closed set of FGA relation names a caller may pass
// to ExpandAccess ("who can do <relation> on <object>"). It is the user-facing
// authorization-decision surface of the canonical fga_model.fga:
//
//   - per-verb leaf relations : v_get / v_list / v_create / v_update / v_delete
//     (the granular CRUD relations every verb-bearing resource type defines).
//   - tier relations          : viewer / editor / admin
//     (the hierarchy-tier relations; admin ⇒ editor ⇒ viewer in the model).
//   - group membership        : member (so "who is a member of group:G" expands).
//
// It deliberately EXCLUDES the model's internal machinery — the scope_grant
// carriers (sg_*), the pull-up resolvers (g_admin_* / g_editor_* / g_vcreate_*),
// and the platform-role relations (system_admin / fga_writer / owner / use / …):
// those are emitter-internal plumbing, not relations a tenant audits "who can do
// X" against. Forwarding an arbitrary string into the FGA Read would let a caller
// probe the model's internal relation graph — ExpandAccess validates against this
// closed set and rejects anything else with INVALID_ARGUMENT. Kept in lockstep
// with fga_model.fga; the drift-gate
// (authzmap/fga_model_drift_test.go) guards the v_* / tier / member names.
var expandableRelations = map[string]bool{
	// per-verb leaf relations
	"v_get":    true,
	"v_list":   true,
	"v_create": true,
	"v_update": true,
	"v_delete": true,
	// tier relations
	"viewer": true,
	"editor": true,
	"admin":  true,
	// group membership
	"member": true,
}

// IsExpandableRelation reports whether `relation` is in the closed set of
// relations ExpandAccess accepts (see expandableRelations). An unknown relation
// must be rejected by the caller with INVALID_ARGUMENT (no probing of
// arbitrary FGA relation strings).
func IsExpandableRelation(relation string) bool {
	return expandableRelations[relation]
}

var objectTypes = map[string]string{
	// compute
	"compute.instance": "compute_instance",
	"compute.disk":     "compute_disk",
	"compute.image":    "compute_image",
	"compute.snapshot": "compute_snapshot",
	// compute placement / capacity / data-protection resources (kacho-proto
	// per-resource object_type). Each is a verb-bearing by-id authz object
	// (see verbBearingTypes above).
	"compute.diskPlacementGroup":   "compute_disk_placement_group",
	"compute.hostGroup":            "compute_host_group",
	"compute.filesystem":           "compute_filesystem",
	"compute.gpuCluster":           "compute_gpu_cluster",
	"compute.placementGroup":       "compute_placement_group",
	"compute.reservedInstancePool": "compute_reserved_instance_pool",
	"compute.snapshotSchedule":     "compute_snapshot_schedule",
	"compute.hostType":             "compute_host_type",

	// vpc
	"vpc.network":            "vpc_network",
	"vpc.subnet":             "vpc_subnet",
	"vpc.address":            "vpc_address",
	"vpc.securityGroup":      "vpc_security_group",
	"vpc.routeTable":         "vpc_route_table",
	"vpc.gateway":            "vpc_gateway",
	"vpc.networkInterface":   "vpc_network_interface",
	"vpc.addressPool":        "vpc_address_pool",
	"vpc.anycastAddressPool": "vpc_anycast_address_pool",

	// load balancer (kacho-nlb)
	"loadbalancer.networkLoadBalancers": "nlb_network_load_balancer",
	"loadbalancer.targetGroups":         "nlb_target_group",
	"loadbalancer.listeners":            "nlb_listener",

	// registry (kacho-registry) — object-prefix `registry_` == service name, so
	// no moduleObjectDomain mapping is required. `registries` is the namespace
	// resource; `repositories` is the per-repo authz object (docker pull/push).
	"registry.registries":   "registry_registry",
	"registry.repositories": "registry_repository",

	// iam — note the hierarchy types `account` and `project` are bare
	// (no `iam_` prefix) because they're shared hierarchy ancestors in
	// the FGA model (cluster ▶ account ▶ project ▶ resource).
	"iam.account":        "account",
	"iam.project":        "project",
	"iam.user":           "iam_user",
	"iam.serviceAccount": "iam_service_account",
	"iam.group":          "iam_group",
	"iam.role":           "iam_role",
	"iam.accessBinding":  "iam_access_binding",
	"iam.condition":      "iam_condition",
}
