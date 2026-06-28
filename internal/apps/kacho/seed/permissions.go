// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package seed — startup-time idempotent seed for kacho-iam.
//
// Provides:
//   - PermissionRegistry: in-memory permissions catalog, loaded via embed
//     from `embedded/permission_catalog.json`. The registry is in-memory and
//     embed-binary self-contained — no DB-table backing it.
//   - BootstrapAdminRunner: creates cluster_admin_grant + fga_outbox when
//     KACHO_IAM_BOOTSTRAP_ROOT_EMAIL env is set.
//
// The composition root (cmd/kacho-iam/main.go) invokes seed.Run() after
// `migrator.Up()` and before the gRPC listener starts.
//
// ─── Bootstrap-state expectation: empty annotation fields ────────────────────
//
// While catalog-generator annotation rollout is incomplete,
// permission_catalog.json ships with **most entries having
// `"permission": ""` and `"required_relation": ""`** — this is the expected
// bootstrap state. Once per-RPC proto annotations are added through the
// catalog-generator pipeline, this expectation flips to "fully populated".
//
// Consequence:
//   - `LookupPermission(...)` for most known permissions returns an empty
//     slice until annotation rollout completes.
//   - `PermissionsForRole("kacho-system.admin")` returns `["*.*.*"]`
//     (hard-coded wildcard, independent of the catalog).
//   - `PermissionsForRole("kacho-system.viewer")` returns an empty slice
//     in the bootstrap state because catalog entries don't yet carry
//     `permission`-strings with read-verbs. The post-rollout catalog will
//     populate viewer-permissions.
//
// The sanity helper `IsPhase1Bootstrap` (preserved as an exported identifier)
// reflects this state and is asserted by integration tests; once annotation
// rollout completes it returns false.
package seed

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
)

// PermissionEntry — one row from permission_catalog.json.
type PermissionEntry struct {
	FQN              string `json:"fqn"`
	Permission       string `json:"permission"`
	RequiredRelation string `json:"required_relation"`
	ScopeExtractor   struct {
		ObjectType       string `json:"object_type"`
		FromRequestField string `json:"from_request_field"`
	} `json:"scope_extractor"`
	RequiredACRMin string `json:"required_acr_min,omitempty"`
}

// permissionCatalogJSON — embedded catalog (primary path: embed).
//
// ⚠️ **MIRROR — NOT runtime source-of-truth.**
// The runtime catalog consumed by the api-gateway authz-interceptor lives in
// `kacho-api-gateway/internal/middleware/embed/permission_catalog.json` and
// is read by api-gateway middleware. This mirror is used ONLY by kacho-iam
// integration tests (verifying JSON-schema and embed-parsing infrastructure);
// it is NOT used by the kacho-iam runtime (there is no per-RPC catalog lookup
// inside the IAM service — that responsibility lives in api-gateway).
//
// The file is committed and embedded directly; the full catalog over the
// transitive set of all domain service.proto is assembled by the api-gateway
// catalog pipeline, and this mirror is refreshed from there as integration-test
// needs demand. Version skew between this mirror and the api-gateway runtime is
// NOT an incident; see kacho-workspace
// docs/architecture/09-permission-catalog-source-of-truth.md.
//
//go:embed embedded/permission_catalog.json
var permissionCatalogJSON []byte

// PermissionRegistry — in-memory registry. Loaded from embed at startup;
// provides lookup-API used by the Check-handler / ListObjects flows.
type PermissionRegistry struct {
	entries []PermissionEntry
	byFQN   map[string]PermissionEntry
	byPerm  map[string][]PermissionEntry // permission → entries (deduped по permission)
}

// LoadPermissionRegistry — embed → registry. Idempotent (the caller may
// invoke it multiple times). Guarantees deterministic ordering (entries
// sorted by FQN).
//
// Catalog source: embedded/permission_catalog.json (committed).
// Planned override env: `KACHO_IAM_PERMISSION_CATALOG_PATH` — ConfigMap
// mount path for emergency hotfix (fallback path); currently embed only.
func LoadPermissionRegistry(ctx context.Context, logger *slog.Logger) (*PermissionRegistry, error) {
	if logger == nil {
		logger = slog.Default()
	}
	var entries []PermissionEntry
	if err := json.Unmarshal(permissionCatalogJSON, &entries); err != nil {
		return nil, fmt.Errorf("seed: unmarshal permission_catalog.json: %w", err)
	}

	// Deterministic ordering: entries sorted by FQN.
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].FQN < entries[j].FQN
	})

	reg := &PermissionRegistry{
		entries: entries,
		byFQN:   make(map[string]PermissionEntry, len(entries)),
		byPerm:  make(map[string][]PermissionEntry, len(entries)),
	}
	for _, e := range entries {
		reg.byFQN[e.FQN] = e
		if e.Permission != "" {
			reg.byPerm[e.Permission] = append(reg.byPerm[e.Permission], e)
		}
	}

	logger.InfoContext(ctx, "permission catalog loaded",
		slog.Int("entries", len(entries)),
		slog.Int("distinct_permissions", len(reg.byPerm)),
	)
	return reg, nil
}

// All — all entries in deterministic order (FQN ascending).
func (r *PermissionRegistry) All() []PermissionEntry {
	out := make([]PermissionEntry, len(r.entries))
	copy(out, r.entries)
	return out
}

// LookupFQN — entry by fully-qualified RPC name.
func (r *PermissionRegistry) LookupFQN(fqn string) (PermissionEntry, bool) {
	e, ok := r.byFQN[fqn]
	return e, ok
}

// LookupPermission — all RPCs annotated with the given permission-string.
func (r *PermissionRegistry) LookupPermission(perm string) []PermissionEntry {
	out := make([]PermissionEntry, len(r.byPerm[perm]))
	copy(out, r.byPerm[perm])
	return out
}

// RequiredACRMin returns the catalog `required_acr_min` for the given RPC FQN
// (e.g. "kacho.cloud.iam.v1.InternalClusterService/GrantAdmin"), or "" if the
// FQN is unknown or carries no acr requirement. Satisfies the
// authzguard.ACRRequirementLookup port for the internal acr-floor.
// (The api-gateway is the runtime catalog source-of-truth on the public path;
// this in-iam lookup gates the gateway-fronted internal RPCs on :9091.)
func (r *PermissionRegistry) RequiredACRMin(fqn string) string {
	if e, ok := r.byFQN[fqn]; ok {
		return e.RequiredACRMin
	}
	return ""
}

// PermissionsForRole — list of permissions semantically assigned to a role.
// kacho-system.admin → ["*.*.*.*"] (no catalog filter needed; runtime does the
// pattern match). kacho-system.viewer → permissions ending in `.read` /
// `.list` / `.get`. The Check-handler uses this function for grant-check.
//
// The strict 4-segment grammar applies; the admin shortcut uses four
// wildcard segments.
func (r *PermissionRegistry) PermissionsForRole(roleName string) []string {
	switch roleName {
	case "kacho-system.admin":
		// Wildcard role: matches anything via Check.
		return []string{"*.*.*.*"}
	case "kacho-system.viewer":
		var perms []string
		seen := make(map[string]struct{})
		for _, e := range r.entries {
			if e.Permission == "" {
				continue
			}
			if !isReadVerb(e.Permission) {
				continue
			}
			if _, ok := seen[e.Permission]; ok {
				continue
			}
			seen[e.Permission] = struct{}{}
			perms = append(perms, e.Permission)
		}
		sort.Strings(perms)
		return perms
	default:
		return nil
	}
}

// IsPhase1Bootstrap — sanity heuristic: returns true if ≥99% of catalog
// entries have an empty `permission` field. This is the expected bootstrap
// state (see package docstring). Once per-RPC annotation rollout completes
// this method will return false; the sanity test inverts in lockstep.
//
// Used by tests to validate the expected bootstrap state.
func (r *PermissionRegistry) IsPhase1Bootstrap() bool {
	if len(r.entries) == 0 {
		return false
	}
	emptyCount := 0
	for _, e := range r.entries {
		if e.Permission == "" {
			emptyCount++
		}
	}
	// 99% threshold: tolerates the 2-3 hard-coded system-role entries
	// (kacho-system.admin "*.*.*"-mapping etc.) if they end up in the catalog.
	return float64(emptyCount)/float64(len(r.entries)) >= 0.99
}

func isReadVerb(perm string) bool {
	// permission format `<domain>.<resource>.<verb>`. Tail-segment after last `.`.
	idx := strings.LastIndexByte(perm, '.')
	if idx < 0 || idx == len(perm)-1 {
		return false
	}
	verb := perm[idx+1:]
	switch verb {
	case "read", "list", "get":
		return true
	default:
		return false
	}
}
