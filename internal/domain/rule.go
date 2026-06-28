// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

// rule.go — RBAC rules-model domain layer.
//
// A Rule is a homogeneous allow-grant `{verbs}` over `{module} × resources`
// (ONE module per rule — `modules []string` collapsed to a scalar
// `Module`), under the owning role's scope, optionally narrowed by a
// resource_names XOR match_labels selector (the "arm" of the rule). A role
// covering several modules uses several rules (one per module). Pure Go: stdlib
// (+ multierr) only (no pgx/grpc/sqlc). Self-validating.
//
// Three arms:
//   - ARM_ANCHOR : neither resource_names nor match_labels → all instances of
//     modules×resources under scope. Compiles to `m.r.*.v`.
//   - ARM_NAMES  : resource_names set → per-id. Compiles to `m.r.<id>.v`.
//   - ARM_LABELS : match_labels set → label-equality selection; reconciler-driven.
//     NOT compiled to permissions.
//
// `Validate(systemCtx)` enforces the wildcard policy, the XOR selector +
// cardinality bounds and the match_labels feed-gate. The
// `systemCtx` flag relaxes the module/resource wildcard to system (seed) roles
// only — custom roles reject `*` in module/resource.

import (
	"fmt"
	"regexp"

	"go.uber.org/multierr"
)

// Rule — one authored grant over ONE module. The element lists are
// validated 1..16 each, the selector is resource_names XOR match_labels.
type Rule struct {
	Module        string // exactly one module per rule
	Resources     []string
	Verbs         []string
	ResourceNames []string
	MatchLabels   map[string]string
}

const (
	wildcard       = "*"
	maxRuleElems   = 16  // resources / verbs per rule
	maxResNames    = 256 // resource_names per rule
	maxMatchLabels = 16  // match_labels keys per rule
	// MaxRules — rules[] cardinality per role.
	MaxRules = 64
	// MaxCompiledPermissions — compiled-permissions cap.
	// Lockstep with DB CHECK + proto (size).
	MaxCompiledPermissions = 1024
)

// rule element token regexes — mirror the compiled-permission 4-segment grammar
// segments (permissionElementRe in types.go) so a compiled token is always valid.
var (
	ruleModuleRe = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	ruleResRe    = regexp.MustCompile(`^[a-z][a-zA-Z0-9_-]*$`)
	ruleVerbRe   = regexp.MustCompile(`^[a-z][a-zA-Z0-9_-]*$`)
	ruleNameRe   = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`) // resource_names element (1..64)
)

// Arm classifies a rule's selector arm.
type Arm int

const (
	ArmAnchor Arm = iota
	ArmNames
	ArmLabels
)

// Arm reports the selector arm of the rule (resource_names XOR match_labels).
func (r Rule) Arm() Arm {
	switch {
	case len(r.ResourceNames) > 0:
		return ArmNames
	case len(r.MatchLabels) > 0:
		return ArmLabels
	default:
		return ArmAnchor
	}
}

// Validate enforces the rule form. systemCtx=true relaxes module/resource
// wildcards to system (seed) roles. Errors carry the stable texts so the API
// contract is preserved.
func (r Rule) Validate(systemCtx bool) error {
	var errs error

	// resource_names XOR match_labels.
	if len(r.ResourceNames) > 0 && len(r.MatchLabels) > 0 {
		errs = multierr.Append(errs, fmt.Errorf(
			"Illegal argument: resourceNames and matchLabels are mutually exclusive"))
	}

	// module — scalar: required + grammar + closed-set membership +
	// wildcard system-only.
	errs = multierr.Append(errs, validateModule(r.Module, systemCtx))
	// element lists — non-empty + cardinality + token grammar.
	errs = multierr.Append(errs, validateRuleList("resources", r.Resources, ruleResRe, systemCtx))
	errs = multierr.Append(errs, validateVerbs(r.Verbs))

	// resource_names — ≤256, opaque-id 1..64, no literal "*".
	if len(r.ResourceNames) > maxResNames {
		errs = multierr.Append(errs, fmt.Errorf(
			"Illegal argument resourceNames (cardinality must be <=%d)", maxResNames))
	}
	for _, n := range r.ResourceNames {
		if n == wildcard {
			errs = multierr.Append(errs, fmt.Errorf(
				"Illegal argument resourceNames (wildcard '*' is not a valid resource name)"))
			continue
		}
		if len(n) < 1 || len(n) > 64 || !ruleNameRe.MatchString(n) {
			errs = multierr.Append(errs, fmt.Errorf(
				"Illegal argument resourceNames (each id must be 1..64 opaque chars)"))
		}
	}

	// match_labels — non-empty when set, ≤16 keys.
	if r.MatchLabels != nil {
		if len(r.MatchLabels) == 0 {
			errs = multierr.Append(errs, fmt.Errorf(
				"Illegal argument matchLabels (must be non-empty when set)"))
		}
		if len(r.MatchLabels) > maxMatchLabels {
			errs = multierr.Append(errs, fmt.Errorf(
				"Illegal argument matchLabels (cardinality must be <=%d keys)", maxMatchLabels))
		}
		for k, v := range r.MatchLabels {
			if err := LabelKey(k).Validate(); err != nil {
				errs = multierr.Append(errs, err)
			}
			if err := LabelVal(v).Validate(); err != nil {
				errs = multierr.Append(errs, err)
			}
		}
	}

	// wildcard + selector combination: any `*` together with a selector
	// is illegal.
	if r.hasAnyWildcard() && (len(r.ResourceNames) > 0 || len(r.MatchLabels) > 0) {
		errs = multierr.Append(errs, fmt.Errorf(
			"Illegal argument: wildcard cannot combine with resourceNames or matchLabels"))
	}

	// feed-availability gate: match_labels only on fed types.
	if len(r.MatchLabels) > 0 {
		errs = multierr.Append(errs, r.validateFeedGate())
	}

	return errs
}

// hasAnyWildcard reports whether the module, or any resource/verb, is `*`.
func (r Rule) hasAnyWildcard() bool {
	if r.Module == wildcard {
		return true
	}
	for _, l := range [][]string{r.Resources, r.Verbs} {
		for _, e := range l {
			if e == wildcard {
				return true
			}
		}
	}
	return false
}

// validateModule validates the scalar module: required non-empty,
// grammar (ruleModuleRe) OR wildcard `*`, and — when grammar-valid and not `*` —
// membership in the closed platform module-set (IsKnownModule). The wildcard `*`
// is system-only (custom role → INVALID_ARGUMENT). Errors carry the stable texts
// (module empty / invalid token / unknown module / wildcard
// system-only). It returns at most ONE module-field violation; the wildcard+selector
// combination is checked independently by Validate, so the two-text case
// (module:"*" + selector in a custom role) still surfaces BOTH texts via Validate's
// multierr accumulation.
func validateModule(module string, systemCtx bool) error {
	if module == "" {
		return fmt.Errorf("Illegal argument module (must be non-empty)")
	}
	if module == wildcard {
		if !systemCtx {
			return fmt.Errorf("Illegal argument module (wildcard '*' is system-only)")
		}
		return nil
	}
	if !ruleModuleRe.MatchString(module) {
		return fmt.Errorf("Illegal argument module (invalid token %q)", module)
	}
	if !IsKnownModule(module) {
		return fmt.Errorf("Illegal argument module (unknown module '%s')", module)
	}
	return nil
}

// validateRuleList validates a resource list: non-empty, ≤16, each token matches
// its grammar OR is the wildcard `*`. The wildcard is system-only: in a
// custom role (systemCtx=false) it is rejected. `*` must be the sole element of
// its list. (The module is scalar — validated by validateModule.)
func validateRuleList(field string, list []string, tokenRe *regexp.Regexp, systemCtx bool) error {
	var errs error
	if len(list) == 0 {
		return fmt.Errorf("Illegal argument %s (must be non-empty)", field)
	}
	if len(list) > maxRuleElems {
		errs = multierr.Append(errs, fmt.Errorf(
			"Illegal argument %s (cardinality must be <=%d)", field, maxRuleElems))
	}
	for _, e := range list {
		if e == wildcard {
			if len(list) != 1 {
				errs = multierr.Append(errs, fmt.Errorf(
					"Illegal argument %s (wildcard '*' must be sole element)", field))
			}
			if !systemCtx {
				errs = multierr.Append(errs, fmt.Errorf(
					"Illegal argument %s (wildcard '*' is system-only)", field))
			}
			continue
		}
		if !tokenRe.MatchString(e) {
			errs = multierr.Append(errs, fmt.Errorf(
				"Illegal argument %s (invalid token %q)", field, e))
		}
	}
	return errs
}

// validateVerbs validates the verbs list. verb `*` is ALLOWED in custom roles:
// it means "all verbs of the type". It still must be the sole element.
func validateVerbs(verbs []string) error {
	var errs error
	if len(verbs) == 0 {
		return fmt.Errorf("Illegal argument verbs (must be non-empty)")
	}
	if len(verbs) > maxRuleElems {
		errs = multierr.Append(errs, fmt.Errorf(
			"Illegal argument verbs (cardinality must be <=%d)", maxRuleElems))
	}
	for _, v := range verbs {
		if v == wildcard {
			if len(verbs) != 1 {
				errs = multierr.Append(errs, fmt.Errorf(
					"Illegal argument verbs (wildcard '*' must be sole element)"))
			}
			continue
		}
		if !ruleVerbRe.MatchString(v) {
			errs = multierr.Append(errs, fmt.Errorf(
				"Illegal argument verbs (invalid token %q)", v))
		}
	}
	return errs
}

// validateFeedGate: a match_labels rule is allowed ONLY on a
// (module,resource) pair in the closed feed-registry (mirror-fed + iam-direct
// project/account). A non-fed type → INVALID_ARGUMENT with the stable text.
func (r Rule) validateFeedGate() error {
	var errs error
	for _, res := range r.Resources {
		if r.Module == wildcard || res == wildcard {
			// wildcard+selector already rejected above; skip feed-gate.
			continue
		}
		typ := r.Module + "." + res
		if !IsLabelSelectableType(typ) {
			errs = multierr.Append(errs, fmt.Errorf(
				"type %s is not selectable (no resource feed)", typ))
		}
	}
	return errs
}

// Rules — a role's authored policy. Cardinality 1..64.
type Rules []Rule

// Validate validates the rule set: cardinality 1..64; each rule self-valid.
func (rs Rules) Validate(systemCtx bool) error {
	if len(rs) == 0 {
		return fmt.Errorf("Illegal argument rules (must be non-empty)")
	}
	if len(rs) > MaxRules {
		return fmt.Errorf("Illegal argument rules (cardinality must be <=%d)", MaxRules)
	}
	var errs error
	for _, r := range rs {
		errs = multierr.Append(errs, r.Validate(systemCtx))
	}
	return errs
}

// CompileRules deterministically compiles authored rules into the INTERNAL
// compiled permission set (4-segment `module.resource.resourceName.verb`),
// for FGA emission/Check-reuse. Pure + deterministic:
//
//   - ARM_ANCHOR  → `m.r.*.v` for each (resource, verb) over the rule's module.
//   - ARM_NAMES   → `m.r.<id>.v` for each (resource, id, verb) over the module.
//   - ARM_LABELS  → NOT compiled (excluded).
//   - verb `*`    → projection keeps the `*` verb segment (`m.r.*.*` / `m.r.<id>.*`),
//     it does NOT expand the closed per-verb set (that is the FGA-emit concern).
//     The projection holds `*`.
//
// The result is de-duplicated (order-preserving over first occurrence) and
// capped at MaxCompiledPermissions; exceeding the cap → INVALID_ARGUMENT
// "compiled permissions exceed 1024" (not silent truncation, not INTERNAL).
//
// The projection is system-context-independent (a system role's `*`-segments are
// authored verbatim into the rules and projected as-is), so CompileRules takes no
// systemCtx flag — the wildcard/system policy is enforced upstream by Rule.Validate.
func CompileRules(rules []Rule) (Permissions, error) {
	out := make(Permissions, 0, len(rules))
	seen := make(map[Permission]struct{})
	add := func(p Permission) error {
		if _, ok := seen[p]; ok {
			return nil
		}
		seen[p] = struct{}{}
		if len(seen) > MaxCompiledPermissions {
			return fmt.Errorf(
				"Illegal argument rules (compiled permissions exceed %d)", MaxCompiledPermissions)
		}
		out = append(out, p)
		return nil
	}
	for _, r := range rules {
		switch r.Arm() {
		case ArmLabels:
			continue // not compiled
		case ArmNames:
			for _, res := range r.Resources {
				for _, id := range r.ResourceNames {
					for _, v := range r.Verbs {
						if err := add(Permission(r.Module + "." + res + "." + id + "." + v)); err != nil {
							return nil, err
						}
					}
				}
			}
		case ArmAnchor:
			for _, res := range r.Resources {
				for _, v := range r.Verbs {
					if err := add(Permission(r.Module + "." + res + "." + wildcard + "." + v)); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	return out, nil
}
