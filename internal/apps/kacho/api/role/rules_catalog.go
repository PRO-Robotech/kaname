// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package role

// rules_catalog.go — the grantable-token gate for an authored role's rules[].
//
// `domain.Rule.Validate` closes the MODULE segment (domain.IsKnownModule). Ни
// сегмент РЕСУРСА, ни сегмент ГЛАГОЛА словарём НЕ закрыты: оба проверяются лишь
// грамматикой токена (плюс мощность и одиночность подстановки — `validateVerbs`).
// Прежняя редакция этого абзаца утверждала, что сегмент глагола закрыт словарём
// домена, и тем самым ОТВЕЧАЛА читателю на вопрос, идти ли проверять. Словаря там
// не было; он вводится отдельной под-фазой (XC-3 S2), и до тех пор глагол вне
// набора своего типа просто не материализуется — молча, без сигнала автору роли.
//
// Из двух незакрытых сегментов гейт ниже закрывает РЕСУРС. Класс тихого отказа:
//
//	Role.Create(rules=[{module:"compute", resources:["instances"], verbs:["get"]}])
//	  → 200 (grammar-valid token, known module)
//	AccessBinding.Create(role=that, …)
//	  → 200 (the structural RoleCoversType gate compares the target's type against
//	         the SAME typo, so it matches)
//	reconciler → authzmap.FGAObjectType("compute.instances") → ok=false
//	          → tuple emission SKIPPED fail-closed → grantee 403 FOREVER
//
// with no signal on the role, on the binding, or on the Operation. The gate below
// closes it at authoring time: an unknown `(module, resource)` is rejected SYNC with
// INVALID_ARGUMENT naming the token and the public catalog endpoint.
//
// This is a use-case-layer concern by construction — it owns the `authzmap`
// dependency, keeping `domain` free of it (same layering as
// access_binding/reconcile/tuples.go). `authzmap.Catalog()`/`ObjectType` is the ONE
// closed table, so the gate accepts exactly what
// `PermissionCatalogService.ListPermissionCatalog` publishes as grantable — no
// second hand-maintained list that could drift.

import (
	"fmt"

	"go.uber.org/multierr"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// catalogEndpoint — where an author reads the grantable taxonomy. Named in the
// error because the canonical spelling is deliberately NOT uniform across modules
// (compute.instance / iam.serviceAccount singular; storage.volumes /
// registry.registries / loadbalancer.networkLoadBalancers plural), so "guess it"
// is not a viable instruction.
const catalogEndpoint = "GET /iam/v1/permissionCatalog"

// ruleWildcard — the `*` segment. Wildcard module/resource segments are policed by
// domain.Rule.Validate (system-only) and expanded by the rules compiler; they are
// NOT catalog tokens, so the gate skips them rather than double-rejecting (a
// spurious catalog error would mask the real wildcard-policy error).
const ruleWildcard = "*"

// validateRuleCatalog rejects every authored `(module, resource)` pair that is not
// in the published grantable catalog. Errors accumulate (multierr) so an author
// fixing a multi-rule role sees every bad token at once, and are deduplicated so a
// token repeated across rules is reported once. Returns nil when every pair is
// grantable.
//
// systemCtx=true short-circuits to nil. The 58 seeded system roles carry a
// DIFFERENT taxonomy in rules[]: their tokens mirror their permission strings
// VERBATIM for tier-parity (`iam.service_account`, `iam.access_binding`,
// `vpc.security_group`, `vpc.subnetses`, `iam.projectses`, `loadbalancer.operations`,
// `compute.zones`, …), none of which is an authzmap object type. Their authority is
// carried by permissions[]→tier tuples and by the migration-seeded
// role_rule_selectors, not by per-object materialization of those tokens. They are
// also unreachable from this gate in practice — Create forces is_system=false and
// Update rejects a system role sync ("System role is read-only") before validating —
// so the short-circuit is belt-and-braces documentation of the scoping, pinned by
// TestRuleCatalogGate_SystemContextExempt.
func validateRuleCatalog(rules domain.Rules, systemCtx bool) error {
	if systemCtx {
		return nil
	}
	var errs error
	reported := make(map[string]struct{})
	for _, r := range rules {
		if r.Module == ruleWildcard {
			continue
		}
		for _, res := range r.Resources {
			if res == ruleWildcard {
				continue
			}
			if _, ok := authzmap.ObjectType(r.Module, res); ok {
				continue
			}
			key := r.Module + "." + res
			if _, dup := reported[key]; dup {
				continue
			}
			reported[key] = struct{}{}
			errs = multierr.Append(errs, fmt.Errorf(
				"Illegal argument resources (unknown type '%s'; grantable types are published by %s)",
				key, catalogEndpoint))
		}
	}
	return errs
}
