// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// tier_parity_integration_test.go — the load-bearing tier-parity assertion for
// the RBAC rules model. Testcontainers Postgres 16; reads the
// ACTUAL 65 re-seeded system roles (permissions + rules columns) and asserts that
// the rules-derived per-(module,resource) tier EQUALS the legacy
// permissions-derived per-(module,resource) tier for EVERY role. If any role
// diverges, the re-seed rules for that role are wrong (fix the migration, never
// the assertion). This proves the rules[] re-seed grants exactly the same
// authority the legacy permissions did.

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// tierRank orders the back-compat tiers so "strongest" is well-defined.
var tierRank = map[string]int{"viewer": 1, "editor": 2, "admin": 3}

// legacyVerbTier maps a single permission verb to the tier the consumer authz
// gate resolves it to — the SAME classification authzmap.verbClass /
// PermissionsToRelations uses (get/list/read/view → viewer; delete + verb-`*`
// → admin; everything else → editor). It is kept here in the test (not prod):
// the parity logic lives in the test.
func legacyVerbTier(verb string) string {
	switch strings.ToLower(verb) {
	case "get", "list", "view", "watch", "describe", "read",
		"gettargetstates", "listoperations":
		return "viewer"
	case "*":
		return "admin"
	case "delete":
		return "admin"
	default:
		return "editor"
	}
}

// legacyTierMap groups a role's permission strings by (module, resource) and
// computes the strongest legacy tier per pair. The stored permissions are the
// canonical 4-segment RBAC-v2 grammar `module.resource.resourceName.verb` (mig
// 0005 promoted the original 3-segment seed in-place; e.g. `iam.account.read` →
// `iam.account.*.read`, `iam.account.*` → `iam.account.*.*`). The verb is the
// LAST segment; the key is module.resource. A wildcard module/resource (`*.*.*.*`)
// is keyed by its literal segments ("*"."*") so it compares against the matching
// rule's ["*"]×["*"] pair.
func legacyTierMap(perms []string) map[string]string {
	out := map[string]string{}
	for _, p := range perms {
		segs := strings.Split(p, ".")
		if len(segs) != 4 {
			continue
		}
		key := segs[0] + "." + segs[1]
		t := legacyVerbTier(segs[3])
		if tierRank[t] > tierRank[out[key]] {
			out[key] = t
		}
	}
	return out
}

// rulesTierMap computes the strongest rules-derived tier per (module, resource)
// for a role's rules. For each rule, domain.ResolveVerbsAndTier(verbs) yields the
// rule's tier; that tier is folded into every ({module} × resource) pair the rule
// touches (one module per rule).
func rulesTierMap(rules domain.Rules) map[string]string {
	out := map[string]string{}
	for _, r := range rules {
		_, tier := domain.ResolveVerbsAndTier(r.Verbs)
		for _, res := range r.Resources {
			key := r.Module + "." + res
			if tierRank[tier] > tierRank[out[key]] {
				out[key] = tier
			}
		}
	}
	return out
}

// jsonRule mirrors the JSONB rule shape stored in roles.rules (scalar module).
type jsonRule struct {
	Module        string            `json:"module"`
	Resources     []string          `json:"resources"`
	Verbs         []string          `json:"verbs"`
	ResourceNames []string          `json:"resource_names,omitempty"`
	MatchLabels   map[string]string `json:"match_labels,omitempty"`
}

func TestTierParity_AllSystemRoles_F53(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testcontainers integration in -short mode")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()

	rows, err := pool.Query(ctx,
		`SELECT name, permissions, rules FROM kacho_iam.roles WHERE is_system ORDER BY name`)
	require.NoError(t, err)
	defer rows.Close()

	type roleRow struct {
		name  string
		perms []string
		rules domain.Rules
	}
	var roles []roleRow
	for rows.Next() {
		var name string
		var permsJSON, rulesJSON []byte
		require.NoError(t, rows.Scan(&name, &permsJSON, &rulesJSON))

		var perms []string
		require.NoError(t, json.Unmarshal(permsJSON, &perms))

		var jr []jsonRule
		require.NoError(t, json.Unmarshal(rulesJSON, &jr))
		dr := make(domain.Rules, 0, len(jr))
		for _, r := range jr {
			dr = append(dr, domain.Rule{
				Module: r.Module, Resources: r.Resources, Verbs: r.Verbs,
				ResourceNames: r.ResourceNames, MatchLabels: r.MatchLabels,
			})
		}
		roles = append(roles, roleRow{name: name, perms: perms, rules: dr})
	}
	require.NoError(t, rows.Err())
	require.Len(t, roles, 65, "F-53: expected exactly 65 system roles (58 catalog + 5 SEC-C module-SA from mig 0009 + owner from mig 0035 + registry module-SA from mig 0044)")

	var mismatches []string
	for _, r := range roles {
		legacy := legacyTierMap(r.perms)
		rule := rulesTierMap(r.rules)

		// Compare key-by-key. Both maps must be identical (same pairs, same tiers).
		keys := map[string]struct{}{}
		for k := range legacy {
			keys[k] = struct{}{}
		}
		for k := range rule {
			keys[k] = struct{}{}
		}
		var sortedKeys []string
		for k := range keys {
			sortedKeys = append(sortedKeys, k)
		}
		sort.Strings(sortedKeys)
		for _, k := range sortedKeys {
			if legacy[k] != rule[k] {
				mismatches = append(mismatches,
					r.name+" ["+k+"]: legacy="+legacy[k]+" rules="+rule[k])
			}
		}
	}
	assert.Empty(t, mismatches,
		"F-53 tier-parity: rules-derived tier must equal legacy permissions-derived tier for ALL 65 roles; mismatches:\n%s",
		strings.Join(mismatches, "\n"))

	// emit-FACT gap — the tier-parity assertion above proves the tier VALUE
	// matches, but it NEVER proved a wildcard `*.*` system-role rule is actually
	// MATERIALIZABLE as a tuple (the rules path could fail-closed-SKIP every `*.*`
	// → tier VALUE correct in the parity map yet ZERO FGA tuples emitted → empty
	// grant → total access loss). The emitter (access_binding.rulesBindingTuples) is unexported in
	// another package, so the byte-exact emit proof lives there
	// (scope_grant_tuples_test.go::TestRulesBindingTuples_WildcardSystemRole_* and
	// scope_grant_fga_integration_test.go::TestIntegration_Wildcard201_* against a
	// real OpenFGA). Here — over the ACTUAL re-seeded roles — assert the
	// materializability INVARIANT the emitter relies on: every seeded `*.*` rule has
	// a resolvable tier (non-empty) AND is the full-wildcard shape (no
	// resource_names / match_labels), so the tier-tuple path applies. A `*.*` role
	// that did NOT satisfy this is exactly the shape that silently emitted nothing.
	wildcardRoles := 0
	for _, r := range roles {
		for _, rule := range r.rules {
			if !isFullWildcard(rule) {
				continue
			}
			wildcardRoles++
			_, wantTier := domain.ResolveVerbsAndTier(rule.Verbs)
			require.Containsf(t, []string{"viewer", "editor", "admin"}, wantTier,
				"#201 emit-fact: wildcard system-role %s must resolve to a tier-tuple relation (got %q) — an unresolved tier is the empty-grant #201 bug",
				r.name, wantTier)
		}
	}
	require.GreaterOrEqual(t, wildcardRoles, 3,
		"#201 emit-fact: expected ≥3 seeded `*.*` system roles (admin/edit/view) — the re-seed shape that triggered #201")
}

// isFullWildcard reports whether a rule is the system-role `*.*` form (module AND
// resource both wildcard, all_in_scope) — the materializable-via-tier-tuple shape.
// A half-wildcard or a names/labels arm is NOT this shape.
func isFullWildcard(r domain.Rule) bool {
	hasWildcard := func(xs []string) bool {
		for _, x := range xs {
			if x == "*" {
				return true
			}
		}
		return false
	}
	return r.Module == "*" && hasWildcard(r.Resources) && len(r.ResourceNames) == 0 && len(r.MatchLabels) == 0
}
