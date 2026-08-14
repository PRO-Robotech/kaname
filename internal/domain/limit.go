// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

import (
	"fmt"
	"strings"
	"time"

	"go.uber.org/multierr"
)

// LimitID — id of a Limit. Hyphen canon `lim-<17>` (ids.PrefixLimitHyphen),
// immutable for the life of the resource and the only externally addressable
// identity (core rule #15).
type LimitID string

// LimitScope — where a ceiling is stated. Three arms, ordered by specificity:
// PROJECT beats ACCOUNT beats DEFAULT.
type LimitScope string

// LimitScope values. Mirrored by a DB CHECK.
const (
	// LimitScopeDefault — platform-wide fallback; exactly one row per kind.
	LimitScopeDefault LimitScope = "DEFAULT"
	// LimitScopeAccount — stated for one account.
	LimitScopeAccount LimitScope = "ACCOUNT"
	// LimitScopeProject — stated for one project; the most specific arm.
	LimitScopeProject LimitScope = "PROJECT"
)

// Specificity — how strongly this scope overrides the others. Higher wins.
//
// It is a METHOD rather than a comparison written at each resolve site: the
// precedence rule is one rule, and three places asserting it independently would
// disagree the first time a fourth scope appeared.
func (s LimitScope) Specificity() int {
	switch s {
	case LimitScopeProject:
		return 3
	case LimitScopeAccount:
		return 2
	case LimitScopeDefault:
		return 1
	default:
		return 0
	}
}

// Validate — the scope is one of the three named arms.
func (s LimitScope) Validate() error {
	if s.Specificity() == 0 {
		return fmt.Errorf("Illegal argument scope: must be DEFAULT, ACCOUNT or PROJECT")
	}
	return nil
}

// LimitKind — a dotted `domain.resource` token naming what is being counted.
type LimitKind string

// Service — the owner service this kind belongs to (`vpc.network` → `vpc`).
//
// Derived from the token rather than stored beside it: two fields naming one
// thing drift, and the dot is the same separator the platform's reference types
// already use.
func (k LimitKind) Service() string {
	if i := strings.IndexByte(string(k), '.'); i > 0 {
		return string(k)[:i]
	}
	return ""
}

// countableKinds — the CLOSED catalogue of kinds a ceiling may be stated on, in
// the order an answer lists them.
//
// WHY CLOSED. A ceiling stated on a kind nobody counts is a field that is
// accepted and never applied: the administrator sees success and the tenant sees
// no effect (api-conventions §«Принято-и-проигнорировано»). So membership is
// checked on the way in, by name.
//
// WHY THIS LIST AND NOT THE EXECUTOR'S VOCABULARY. The vpc arm has EIGHT members,
// not seven. The service's own architecture note derived the tenant's countable
// kinds from the closed dictionary of the data-plane intent projection — and that
// dictionary describes what the executor is told, not what the tenant pays for:
// `vpc.cidrGroup` carries a project, has its own public service and its own authz
// type, but is never projected, because it is a named list of prefixes rather
// than a data-plane entity. Deriving the catalogue from the authorization model
// gives eight; deriving it from the projection loses exactly that one.
//
// The list is guarded, not merely written: authzmap's
// TestLimitKindsAreKnownObjectTypes proves every entry names a real authz object
// type, and TestEveryTenantVpcTypeIsCountable proves no NINTH vpc type can be
// introduced without either a ceiling or a documented exclusion — which is the
// mechanism by which the eighth was lost the first time.
var countableKinds = []LimitKind{
	"vpc.network",
	"vpc.subnet",
	"vpc.address",
	"vpc.networkInterface",
	"vpc.securityGroup",
	"vpc.routeTable",
	"vpc.gateway",
	"vpc.cidrGroup",
	"iam.project",
}

// CountableKinds returns a COPY of the closed catalogue, in catalogue order.
func CountableKinds() []LimitKind {
	out := make([]LimitKind, len(countableKinds))
	copy(out, countableKinds)
	return out
}

// CountableKindsOfService returns the catalogue entries owned by one service, in
// catalogue order. An unknown service yields an empty slice — and the caller must
// treat that as "this service counts nothing", not as "every kind".
func CountableKindsOfService(service string) []LimitKind {
	out := make([]LimitKind, 0, len(countableKinds))
	for _, k := range countableKinds {
		if k.Service() == service {
			out = append(out, k)
		}
	}
	return out
}

// IsCountableKind reports membership in the closed catalogue.
func IsCountableKind(k LimitKind) bool {
	for _, c := range countableKinds {
		if c == k {
			return true
		}
	}
	return false
}

// Validate — membership in the closed catalogue, refused by the field's name.
func (k LimitKind) Validate() error {
	if k == "" {
		return fmt.Errorf("kind: required")
	}
	if !IsCountableKind(k) {
		return fmt.Errorf("Illegal argument kind: %s is not a countable resource kind", k)
	}
	return nil
}

// Limit — the ceiling on how many resources of one kind a tenant may hold.
//
// The triple (Scope, ScopeID, Kind) IS the limit's identity among those in force;
// `Value` is the only mutable field. "Moving" a ceiling to another project or
// another kind is a different ceiling, created and withdrawn explicitly — an
// Update that could change the triple would silently transfer a tenant's headroom
// to a tenant who was never granted it.
type Limit struct {
	ID        LimitID
	CreatedAt time.Time

	Scope   LimitScope
	ScopeID string
	Kind    LimitKind
	Value   int64

	// WithdrawnAt — the moment the ceiling stopped applying. Zero → in force.
	//
	// A withdrawal is a tombstone rather than a deleted row because owner
	// services keep a PROJECTION of these values and refresh it by delta: a delta
	// that only ever reports writes can never drop a projection row, so a
	// withdrawn project override would keep overriding forever.
	WithdrawnAt time.Time

	// Revision — monotonic, assigned by the database. Advances on a change of
	// value or of withdrawal, and stands still when a write restates what was
	// already there.
	Revision int64
}

// Withdrawn reports whether the ceiling has been withdrawn.
func (l Limit) Withdrawn() bool { return !l.WithdrawnAt.IsZero() }

// Validate — self-validating domain entity.
//
// The scope/subject pairing is checked HERE as well as by a DB CHECK, and that is
// not a duplicate rule: the database makes the state inexpressible for every
// writer, and this makes the caller's answer name the FIELD they got wrong
// instead of a constraint they have never heard of.
func (l Limit) Validate() error {
	var errs error
	errs = multierr.Append(errs, l.Scope.Validate())
	errs = multierr.Append(errs, l.Kind.Validate())
	if l.Value < 0 {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument value: must not be negative"))
	}
	switch l.Scope {
	case LimitScopeDefault:
		if l.ScopeID != "" {
			errs = multierr.Append(errs,
				fmt.Errorf("Illegal argument scope_id: must be empty when scope is DEFAULT"))
		}
	case LimitScopeAccount, LimitScopeProject:
		if l.ScopeID == "" {
			errs = multierr.Append(errs,
				fmt.Errorf("scope_id: required when scope is %s", l.Scope))
		}
	}
	return errs
}

// LimitFilter — the three-valued narrowing a List accepts. Empty members mean "do
// not narrow by this"; the vocabulary is closed, so there is no filter grammar
// here and nothing to parse.
type LimitFilter struct {
	Scope   LimitScope
	ScopeID string
	Kind    LimitKind
}

// Validate — a narrowing value that is not a legal value of its dimension is
// refused by the field's NAME rather than silently matching nothing: a filter that
// quietly returns an empty page is indistinguishable from "there is nothing here".
func (f LimitFilter) Validate() error {
	var errs error
	if f.Scope != "" {
		errs = multierr.Append(errs, f.Scope.Validate())
	}
	if f.Kind != "" {
		errs = multierr.Append(errs, f.Kind.Validate())
	}
	return errs
}

// EffectiveLimit — one resolved ceiling plus the scope it was won at.
//
// The source travels with the value because an operator asking "why does this
// project stop at four" cannot otherwise tell a project override from an account
// one from the platform default without re-reading all three scopes by hand.
type EffectiveLimit struct {
	Kind          LimitKind
	Value         int64
	SourceScope   LimitScope
	SourceScopeID string
}

// ResolveEffective folds the limits stated across the three scopes into one row
// per kind of the requested service.
//
// `stated` may contain rows of any scope in any order; only rows whose kind
// belongs to `service` participate. A kind with nothing stated at ANY scope is
// omitted from the answer — the caller must not read a missing row as "no
// ceiling": nothing was said, and inventing a ceiling here would be this
// function's guess rather than the platform's decision.
func ResolveEffective(service string, stated []Limit) []EffectiveLimit {
	winner := make(map[LimitKind]Limit, len(stated))
	for _, l := range stated {
		if l.Withdrawn() || l.Kind.Service() != service {
			continue
		}
		cur, seen := winner[l.Kind]
		if !seen || l.Scope.Specificity() > cur.Scope.Specificity() {
			winner[l.Kind] = l
		}
	}
	out := make([]EffectiveLimit, 0, len(winner))
	// Catalogue order, so two callers reading the same tenant see the same list
	// in the same order — a repeated field whose order is "whatever the map
	// yielded" is read as a fact about the tenant and is not one.
	for _, k := range CountableKindsOfService(service) {
		w, ok := winner[k]
		if !ok {
			continue
		}
		out = append(out, EffectiveLimit{
			Kind:          k,
			Value:         w.Value,
			SourceScope:   w.Scope,
			SourceScopeID: w.ScopeID,
		})
	}
	return out
}
