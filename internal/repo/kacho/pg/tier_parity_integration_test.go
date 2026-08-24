// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// tier_parity_integration_test.go — the load-bearing tier-parity assertions for
// the RBAC rules model. Testcontainers Postgres 16; reads the system roles the
// migrations actually seeded (permissions + rules columns) and asserts two
// properties over them, plus a census so that "no findings" stays distinguishable
// from "nothing read":
//
//   - CATALOG TIER PARITY — every role family the seed names carries the COMPLETE
//     tier set (admin/edit/view). The expectation is derived from the seeded
//     catalog itself, never written by hand: retiring a resource removes a whole
//     family and the property still holds, while losing a single tier of a family
//     that is still served fails and names the tier.
//   - RULES-VS-PERMISSIONS TIER PARITY — for EVERY role, the rules-derived
//     per-(module,resource) tier EQUALS the legacy permissions-derived one. If any
//     role diverges, the re-seed rules for that role are wrong (fix the migration,
//     never the assertion). This proves the rules[] re-seed grants exactly the same
//     authority the legacy permissions did.
//
// Why no expected total lives here: a hand-written count of seeded roles states
// the wrong thing. It says "the catalog has N members", which is a fact about the
// last migration anyone happened to look at — it goes stale on every deliberate
// retire and has to be re-guessed, and while it is stale the suite is red for a
// reason that has nothing to do with authority. The invariant worth locking is
// that no served resource ends up with a partial tier set; that is what these
// assertions say, and it survives the catalog growing or shrinking.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// tierRank orders the back-compat tiers so "strongest" is well-defined.
var tierRank = map[string]int{"viewer": 1, "editor": 2, "admin": 3}

// catalogTiers is the tier AXIS of the seeded system-role catalog — the suffix
// every catalog family is named over. It is deliberately an axis and not a count:
// retiring a resource removes that resource's whole family and leaves the axis
// untouched, so this list does not go stale when the catalog shrinks or grows.
//
// Not to be confused with tierRank above: that is the authority tier a verb set
// resolves to (viewer/editor/admin); this is the naming suffix the seed uses.
var catalogTiers = []string{"admin", "edit", "view"}

// globalFamily is the display key for the prefix-less family — the three
// cluster-wide roles named by the bare tier (`admin`/`edit`/`view`, seeded as
// "4.1 Wildcards"). It carries the same axis as the per-resource families, so the
// completeness property quantifies over it too rather than exempting it.
const globalFamily = "(global)"

// classifySystemRole splits a seeded system-role name into the catalog family it
// belongs to and the tier it occupies:
//
//	vpc.subnet.edit → ("vpc.subnet", "edit", true)   — per-resource family
//	edit            → ("(global)",   "edit", true)   — prefix-less family
//	owner           → ("",           "",     false)  — non-tiered built-in
//
// The third return says whether the name sits on the tier axis at all. Non-tiered
// built-ins (`owner`, `kacho-system.*`, `loadbalancer.*`, `module.*_sa`) are not
// families and carry no tier by construction — note that `kacho-system.admin`
// ends in a tier word yet is NOT a family member: it is a hand-rolled built-in
// whose sibling is `kacho-system.viewer`, so reading it as a family would demand
// an `edit` tier that was never meant to exist.
func classifySystemRole(name string) (family, tier string, tiered bool) {
	segs := strings.Split(name, ".")
	switch len(segs) {
	case 1:
		if isCatalogTier(segs[0]) {
			return globalFamily, segs[0], true
		}
	case 3:
		if isCatalogTier(segs[2]) {
			return segs[0] + "." + segs[1], segs[2], true
		}
	}
	return "", "", false
}

// tiersTheTypeCanServe — тиры, у которых на этом типе ЕСТЬ содержимое, и признак
// того, что ось у семейства СУЖЕНА относительно полной.
//
// # Зачем это, если ось была полной у всех
//
// Полная ось (`admin`/`edit`/`view`) была верным ожиданием, пока набор глаголов
// был платформенной константой: у каждого типа находился глагол любого тира. С
// набором, ставшим атрибутом ТИПА, это перестало быть верным — у `iam_user` снят
// `update` (#1128), и тир `edit` на нём стал НЕВЫРАЗИМ: роль `iam.user.edit`
// материализовала бы ноль кортежей, а её имя обещало бы правку.
//
// Ожидание поэтому ВЫВОДИТСЯ из набора типа, а не выписывается послаблением:
// перечень исключений устаревал бы молча, а вывод следует за моделью сам.
// Классификация глагола — тем же предикатом, каким её делает соседнее
// утверждение файла (`legacyVerbTier`), чтобы двух вокабуляров не завелось.
//
// Семейство, чей тип не резолвится (префикс-менее `(global)`, имена посева,
// расходящиеся с токеном каталога, — например `iam.service_account` против
// `iam.serviceAccount`), получает ПОЛНУЮ ось: сузить ожидание на непонятом имени
// значило бы выдать незнание за решение.
func tiersTheTypeCanServe(family string) (tiers []string, narrowed bool) {
	module, resource, ok := strings.Cut(family, ".")
	if !ok {
		return catalogTiers, false
	}
	fgaType, known := authzmap.ObjectType(module, resource)
	if !known {
		return catalogTiers, false
	}
	verbs := authzmap.VerbsOfType(fgaType)
	if len(verbs) == 0 {
		return catalogTiers, false
	}
	served := map[string]bool{}
	for _, v := range verbs {
		switch legacyVerbTier(v) {
		case "viewer":
			served["view"] = true
		case "editor":
			served["edit"] = true
		case "admin":
			served["admin"] = true
		}
	}
	for _, t := range catalogTiers {
		if served[t] {
			tiers = append(tiers, t)
		}
	}
	return tiers, len(tiers) < len(catalogTiers)
}

func containsTier(in []string, t string) bool {
	for _, x := range in {
		if x == t {
			return true
		}
	}
	return false
}

func isCatalogTier(s string) bool {
	for _, t := range catalogTiers {
		if s == t {
			return true
		}
	}
	return false
}

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
		_, tier := domain.ResolveVerbsAndTier(r.Verbs, authzmap.CommonVerbVocabulary())
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

	// ── Census. Stated separately so that "no findings" below cannot be read off
	// an empty catalog: every assertion in this test quantifies over `roles`, so a
	// database that was never seeded would satisfy all of them vacuously.
	families := map[string]map[string]string{} // family → tier → role name
	var untiered, offAxis []string
	for _, r := range roles {
		family, tier, tiered := classifySystemRole(r.name)
		if !tiered {
			// A three-segment name whose last segment is not on the axis would be
			// read as "not a family" and quietly escape the completeness property
			// below — the blind spot this bucket exists to expose.
			if strings.Count(r.name, ".") == 2 {
				offAxis = append(offAxis, r.name)
			}
			untiered = append(untiered, r.name)
			continue
		}
		if families[family] == nil {
			families[family] = map[string]string{}
		}
		families[family][tier] = r.name
	}
	t.Logf("census: %d seeded system roles read — %d tier families (%d roles on the tier axis) + %d non-tiered built-ins",
		len(roles), len(families), len(roles)-len(untiered), len(untiered))
	require.NotEmpty(t, families, "census: read %d system roles and ZERO tier families — "+
		"either the migrations did not seed the catalog or the naming convention moved; "+
		"every parity assertion below would be vacuously green", len(roles))
	require.Empty(t, offAxis, "census: system role(s) named <module>.<resource>.<x> with <x> off the %v axis — "+
		"such a name is not read as a family member, so its tier parity is never checked", catalogTiers)

	// ── Property 1: catalog tier parity. Every family the seed names carries the
	// COMPLETE tier axis. Derived from the seeded catalog, so a retire that removes
	// a whole family (as 0074 did for the compute block-storage resources) leaves
	// this green, while dropping one tier of a family that is still served fails
	// here and names the tier — a resource whose catalog offers `admin` and `view`
	// but no `edit` is a grantable surface with a hole in it.
	var tierGaps []string
	narrowedFamilies := 0
	familyNames := make([]string, 0, len(families))
	for f := range families {
		familyNames = append(familyNames, f)
	}
	sort.Strings(familyNames)
	for _, f := range familyNames {
		want, narrowed := tiersTheTypeCanServe(f)
		if narrowed {
			narrowedFamilies++
		}
		for _, tier := range want {
			if _, ok := families[f][tier]; !ok {
				tierGaps = append(tierGaps, fmt.Sprintf(
					"%s: tier %q missing (family has %s)", f, tier, presentTiers(families[f])))
			}
		}
		// Обратная сторона: тир, которому НЕЧЕМ быть, не должен существовать.
		// Без неё сужение оси превратилось бы в послабление: роль, обещающая
		// правку там, где тип правки не объявляет, не даёт ничего.
		for _, tier := range catalogTiers {
			if _, present := families[f][tier]; !present {
				continue
			}
			if !containsTier(want, tier) {
				tierGaps = append(tierGaps, fmt.Sprintf(
					"%s: tier %q посеян, но тип не объявляет ни одного глагола этого тира — "+
						"роль обещает то, чего материализация не даст", f, tier))
			}
		}
	}
	t.Logf("census: families with a NARROWED tier axis (the type declares no verb of some tier): %d of %d",
		narrowedFamilies, len(familyNames))
	assert.Empty(t, tierGaps, "catalog tier parity: every seeded family must carry the tier axis its TYPE can serve; gaps:\n%s",
		strings.Join(tierGaps, "\n"))

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
		"F-53 tier-parity: rules-derived tier must equal legacy permissions-derived tier for all %d seeded system roles; mismatches:\n%s",
		len(roles), strings.Join(mismatches, "\n"))

	// emit-FACT gap — the tier-parity assertion above proves the tier VALUE
	// matches, but it NEVER proved a wildcard `*.*` system-role rule is actually
	// MATERIALIZABLE as a tuple (the rules path could fail-closed-SKIP every `*.*`
	// → tier VALUE correct in the parity map yet ZERO FGA tuples emitted → empty
	// grant → total access loss). Сам сборщик кортежей неэкспортирован и живёт в
	// другом пакете (`access_binding.buildBindingTuples`), поэтому побайтовое
	// доказательство эмиссии принадлежит ему, а не этому файлу. Прежде здесь стояли
	// координаты двух проб, доказывавших это против ЖИВОГО движка; обе сняты вместе
	// с движком, и воспроизводить их имена значило бы посылать читателя в пустоту.
	// Here — над ФАКТИЧЕСКИ пересеянными ролями — assert the
	// materializability INVARIANT the emitter relies on: every seeded `*.*` rule has
	// a resolvable tier (non-empty) AND is the full-wildcard shape (no
	// resource_names / match_labels), so the tier-tuple path applies. A `*.*` role
	// that did NOT satisfy this is exactly the shape that silently emitted nothing.
	wildcardBearers := map[string]bool{}
	for _, r := range roles {
		for _, rule := range r.rules {
			if !isFullWildcard(rule) {
				continue
			}
			wildcardBearers[r.name] = true
			_, wantTier := domain.ResolveVerbsAndTier(rule.Verbs, authzmap.CommonVerbVocabulary())
			require.Containsf(t, []string{"viewer", "editor", "admin"}, wantTier,
				"#201 emit-fact: wildcard system-role %s must resolve to a tier-tuple relation (got %q) — an unresolved tier is the empty-grant #201 bug",
				r.name, wantTier)
		}
	}
	// The floor is DERIVED, not written down: the prefix-less family is the
	// cluster-wide `*.*` trio, so each of its members must be one of the roles the
	// loop above actually walked. Asserting "at least three such roles exist" would
	// pass on any three — including three that are not the trio — and would have to
	// be re-guessed whenever the catalog moves.
	for _, tier := range catalogTiers {
		name, ok := families[globalFamily][tier]
		require.Truef(t, ok, "#201 emit-fact: the %s family has no %q member — checked by the catalog tier parity above",
			globalFamily, tier)
		require.Truef(t, wildcardBearers[name],
			"#201 emit-fact: %s family role %q carries no full-wildcard `*.*` rule — that is the shape which silently emits nothing",
			globalFamily, name)
	}
}

// presentTiers renders the tiers a family does carry, so a gap report says what is
// there as well as what is missing.
func presentTiers(byTier map[string]string) string {
	var have []string
	for _, t := range catalogTiers {
		if _, ok := byTier[t]; ok {
			have = append(have, t)
		}
	}
	if len(have) == 0 {
		return "no tiers"
	}
	return strings.Join(have, ", ")
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
