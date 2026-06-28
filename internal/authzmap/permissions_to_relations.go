// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package authzmap maps a role's permissions[] to FGA relations and owns the
// closed (module,resource)→fga_object_type table. Adapter-free (stdlib only):
// consumed from AccessBinding tuple-emission paths without coupling to
// internal/repo or internal/clients.
//
// permissions_to_relations.go — single mapper from a role's permissions[] to
// a deduplicated set of FGA relations.
//
// Replaces the name-based name→relation collapse that lived in
// `internal/apps/kacho/api/access_binding/tuples.go::roleNameToRelation`.
//
// Strategy (conservative — granular FGA model is out of scope for this mapper):
//
//  1. nil / empty permissions       → []Relation{"viewer"} (least privilege).
//
//  2. Group permissions by verb-class (read-only / write / admin), pick the
//     STRONGEST tier present:
//
//     read-only verbs : get | list | view | watch | describe → "viewer"
//     write verbs     : create | update | delete | write | patch | put → "editor"
//     admin / wildcard: admin | * | manage                            → "admin"
//
//  3. If EVERY permission has a registered granular relation in
//     `GranularRelations` (post catalog unification) → return the granular
//     set (no tier fallback). Default deployment has the set empty → tier
//     fallback.
//
// Returned []Relation is stable-ordered (alphabetical) for byte-identical
// fga_outbox payloads on identical inputs (idempotent drainer behaviour).
package authzmap

import (
	"sort"
	"strings"
)

// Relation — typed string for FGA relation names.
type Relation string

// granularRelations — process-wide registry of `<module>.<resource>.<verb>` →
// granular FGA relation (e.g. "vpc_network_get"). Default empty (ship tier-only
// mapping). Future catalog unification will populate this from a generated
// table. Read-only after process startup — registration helpers exist only for
// tests.
var granularRelations = map[string]string{}

// RegisterGranularRelationForTest — test-only helper to add a granular
// permission→relation mapping. Production code MUST NOT call this — the
// future catalog unification will replace it with a generated table loaded at
// startup.
func RegisterGranularRelationForTest(permission, relation string) {
	granularRelations[permission] = relation
}

// ResetGranularRelationsForTest — test-only helper to clear the registry
// between test cases.
func ResetGranularRelationsForTest() {
	granularRelations = map[string]string{}
}

// PermissionsToRelations derives FGA relations from a role's permission list.
//
// See package-level doc-comment for the strategy.
//
// Output is deduplicated, stable-ordered, never nil (always at least one
// relation — viewer fallback for the empty case).
func PermissionsToRelations(permissions []string) []Relation {
	if len(permissions) == 0 {
		return []Relation{"viewer"}
	}

	// Pass 1: are ALL permissions granular-mapped? If so, return granular set
	// (no tier fallback). Order is deterministic via sort below.
	if len(granularRelations) > 0 {
		allGranular := true
		seen := map[string]struct{}{}
		for _, p := range permissions {
			rel, ok := granularRelations[p]
			if !ok {
				allGranular = false
				break
			}
			seen[rel] = struct{}{}
		}
		if allGranular {
			return sortedRelations(seen)
		}
	}

	// Pass 2: tier mapping. Pick the STRONGEST tier present in the permission
	// set (admin > editor > viewer). The strongest tier supersedes the others
	// because the FGA model declares `admin` ⇒ `editor` ⇒ `viewer` via
	// computed relations — emitting all three would just be redundant
	// bookkeeping.
	hasAdmin, hasWrite, hasRead := false, false, false
	for _, p := range permissions {
		switch verbClass(p) {
		case classAdmin:
			hasAdmin = true
		case classWrite:
			hasWrite = true
		case classRead:
			hasRead = true
		}
	}
	switch {
	case hasAdmin:
		return []Relation{"admin"}
	case hasWrite:
		return []Relation{"editor"}
	case hasRead:
		return []Relation{"viewer"}
	default:
		// unrecognised permission shape — least privilege.
		return []Relation{"viewer"}
	}
}

type verbClassKind int

const (
	classUnknown verbClassKind = iota
	classRead
	classWrite
	classAdmin
)

// verbClass — classify a permission string by its trailing verb.
//
// Tier is determined by the VERB (last `.`-segment), not by whether the module
// or resource segment is wildcarded:
//
//   - `vpc.networks.get`       → read   (specific resource, read verb)
//   - `*.*.read`               → read   (global read-only — viewer-tier)
//   - `vpc.networks.create`    → write  (specific resource, write verb)
//   - `vpc.networks.*`         → admin  (verb-position wildcard = full CRUD)
//   - `vpc.*.*`                → admin  (verb-position wildcard, broader scope)
//   - `*.*.*`                  → admin  (global all-verbs = admin-grade)
//   - `iam.accessBindings.admin` → admin
//
// Rule: wildcard ONLY at the verb position escalates to admin; wildcards at
// module/resource positions just broaden scope but keep the verb's tier.
func verbClass(perm string) verbClassKind {
	if perm == "" {
		return classUnknown
	}
	verb := perm
	if i := strings.LastIndexByte(verb, '.'); i >= 0 {
		verb = verb[i+1:]
	}
	verb = strings.ToLower(verb)
	if verb == "*" {
		return classAdmin
	}
	switch verb {
	case "get", "list", "view", "watch", "describe", "viewer", "read",
		// Read-style domain verbs introduced by kacho-nlb.
		// Aliased lowercase: gettargetstates / listoperations.
		"gettargetstates", "listoperations":
		return classRead
	case "create", "update", "delete", "write", "patch", "put", "editor", "edit",
		// Write-style domain verbs (kacho-nlb action RPCs + Move). All mutate
		// state, so they belong in the editor tier.
		"start", "stop", "move",
		"addtargets", "removetargets",
		"attachtargetgroup", "detachtargetgroup",
		"enablezones", "disablezones",
		"addlistener", "removelistener":
		return classWrite
	case "admin", "manage":
		return classAdmin
	}
	return classUnknown
}

func sortedRelations(set map[string]struct{}) []Relation {
	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	res := make([]Relation, len(out))
	for i, r := range out {
		res[i] = Relation(r)
	}
	return res
}
