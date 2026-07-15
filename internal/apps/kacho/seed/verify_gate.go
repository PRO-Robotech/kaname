// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package seed

// verify_gate.go — the continuous, forward-aware verify-gate. This is the
// CONTRACT-PHASE GATE: the contract phase (which removes the FGA derivation
// cascade + scope_grant) is permitted ONLY when this gate reports 100%
// no-access-loss AND a live forward-smoke on a freshly-created resource passes.
//
// Two assertions:
//
//   Verify — for every ACTIVE binding the RECONCILER decided to materialize (it has
//     ≥1 ACTIVE access_binding_target_member — the reconciler's own verdict, not a
//     heuristic), the access_binding_emitted_tuples ledger MUST be non-empty. An
//     ACTIVE member with an empty ledger is a NO-ACCESS-LOSS FAILURE (after the
//     contract phase removes the cascade, that operator would resolve to denied) →
//     the gate reports NoAccessLoss=false and lists the offending binding. A binding
//     the reconciler leaves with no ACTIVE members (a cluster-scoped `*.*.*` super-
//     admin served by the cluster-admin short-circuit, a thin permissions-only role, a
//     selector matching nothing) expects no ledger and is NOT a failure.
//
//   ForwardSmoke — create a synthetic resource matching a selector binding
//     (ARM_ANCHOR/ARM_LABELS on a concrete mirror type, OR the OWNER `*.*.*`
//     wildcard binding) AFTER the backfill, drive the forward path (ReconcileObject
//     on the mirror change), assert that binding's content tuple materialized, then
//     remove the synthetic object. This proves the forward-materialization path is
//     LIVE for BOTH the regular-selector path AND
//     the owner content path. Without it a resource created in the
//     contract window would never get its tuple and its grantee would silently lose
//     access.
//
//     NOTE: the OWNER `*.*.*` role now DOES
//     forward-materialize CONTENT for a BOUNDED scope (ACCOUNT/PROJECT) — the
//     wildcard rule expands to the full materializable type set
//     (domain.MaterializingSelectorsInScope), so the reconciler emits a per-object
//     tuple on every object inside the account. The verify-gate forward-smoke is now
//     run against the OWNER binding too (a POSITIVE owner-content no-access-loss
//     check), not only the regular-selector path: this is the assertion the old gate
//     could NOT make, because owner content never materialized and the
//     active_members-derived Verify always passed it as 0-expected. A GLOBAL/CLUSTER
//     `*.*.*` (cluster super-admin) still does NOT per-object materialize — it is the
//     cluster-admin flat short-circuit, so an owner-content smoke is meaningful ONLY for a
//     bounded-scope owner binding (the contract-phase gate runs it there).
//
// Clean Architecture: depends only on the ReconcileEngine surface + the narrow
// VerifyStore port (implemented by the pg BackfillAdapter). No pgx here.

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// smokeMirrorType / smokeMirrorPrefix — the synthetic mirror object the boot
// forward-smoke creates inside a real account to prove the forward path is live.
// vpc.network is a materializable mirror type covered by the owner `*.*` wildcard
// expansion, so an owner-binding's content tuple must materialize on it; the row is
// seeded and removed by ForwardSmoke so it never lingers in a real account.
const (
	smokeMirrorType   = "vpc.network"
	smokeMirrorPrefix = "net"
)

// VerifyReconcileEngine — the reconcile surface the forward-smoke drives.
type VerifyReconcileEngine interface {
	ReconcileObject(ctx context.Context, objectType, objectID string) error
}

// VerifyRelationChecker — the real-FGA Check port the relation-satisfies-action gate
// uses (Design-B). Implemented by *clients.OpenFGAHTTPClient (the production
// FGA client). nil → the gate is a non-fatal skip (no assertion made), so a
// degraded FGA never crashes boot.
type VerifyRelationChecker interface {
	Check(ctx context.Context, subject, relation, object string) (bool, error)
}

// BindingRelationCheck — one active binding's required-relation Check triple: the
// subject, the enforcement relation the catalog gates the binding's read action on
// (the v_* relation under Design-B), and the FGA object. The gate runs a REAL FGA
// Check on it (relation-satisfies-action), NOT a ledger-presence probe.
type BindingRelationCheck struct {
	BindingID domain.AccessBindingID
	Subject   string // "user:<id>" / "service_account:<id>"
	Relation  string // enforcement relation (v_get / v_list / …)
	Object    string // "<fga_type>:<id>"
}

// BindingMaterialization — one binding's verify facts: its id and whether its role
// is EXPECTED to materialize explicit tuples (scope-self verbs or a materializing
// selector). LedgerCount is the recorded explicit-tuple count.
type BindingMaterialization struct {
	BindingID     domain.AccessBindingID
	ExpectsTuples bool
	LedgerCount   int
}

// VerifyStore — the narrow port the gate needs. Implemented by the pg BackfillAdapter.
type VerifyStore interface {
	// ListActiveBindingMaterialization returns, for every ACTIVE binding, whether it
	// expects explicit materialization and its current ledger-tuple count (one
	// same-DB read; no per-binding round-trip).
	//
	// LIMITATION: ExpectsTuples is derived from the reconciler's OWN
	// verdict (active_members > 0). It therefore detects "ACTIVE member exists but the
	// ledger is empty" (member-without-tuple), NOT "this binding SHOULD have materialized
	// ≥1 member but produced 0" (dropped-membership / wholesale reconcile failure). The
	// latter blind spot is covered for the one class that is computable WITHOUT false
	// positives — ACTIVE account-scoped owner bindings, which always materialize ≥1
	// member — via ListOwnerBindingsMissingMembers below.
	ListActiveBindingMaterialization(ctx context.Context) ([]BindingMaterialization, error)

	// ListOwnerBindingsMissingMembers returns the ids of ACTIVE account-scoped OWNER
	// bindings that have ZERO ACTIVE target members. An owner (`*.*`) role
	// bound at ACCOUNT scope ALWAYS materializes ≥1 member — its scope-self member on
	// account:<A> (the owner role's ScopeSelfVerbs are non-empty and the account is
	// always contained in its own scope). So an owner-binding with 0 ACTIVE members is
	// unambiguously a wholesale-reconcile-failure (the operator silently lost the grant)
	// — a sentinel the active_members-derived Verify cannot otherwise see, computable
	// without false positives (no over-flagging of legitimately-empty bindings).
	ListOwnerBindingsMissingMembers(ctx context.Context) ([]domain.AccessBindingID, error)

	// SeedSmokeMirrorObject / RemoveSmokeMirrorObject create/remove a synthetic
	// resource_mirror row under a project (so a project/account-scoped selector
	// binding's IsContainedIn matches it) for the forward-smoke. The synthetic
	// object is removed after the smoke so it never pollutes real membership.
	SeedSmokeMirrorObject(ctx context.Context, objectType, objectID, parentProject, parentAccount string, labels map[string]string) error
	RemoveSmokeMirrorObject(ctx context.Context, objectType, objectID string) error

	// LedgerHasObject reports whether the binding's ledger records ANY tuple on the
	// given fga-object (e.g. "vpc_network:<id>") — the forward-smoke success check.
	LedgerHasObject(ctx context.Context, bindingID domain.AccessBindingID, fgaObject string) (bool, error)

	// SmokeOwnerBindingCandidate returns ONE ACTIVE account-scoped OWNER binding
	// together with its account id, to drive a live forward-smoke at boot (the
	// contract-phase gate must exercise ForwardSmoke, not only Verify). An
	// owner (`*.*`) binding bound at ACCOUNT scope is the bounded-scope owner-content
	// path the gate doc claims — it forward-materializes per-object content for a
	// fresh resource in the account. ok=false when no owner-binding
	// exists yet (a brand-new cluster) → the caller skips the smoke (non-fatal).
	SmokeOwnerBindingCandidate(ctx context.Context) (bindingID domain.AccessBindingID, accountID string, ok bool, err error)

	// ListActiveBindingRelationChecks returns, for every ACTIVE binding that
	// materialized ≥1 per-object tuple, the (subject, enforcement-relation, object)
	// triples the relation-satisfies-action gate must Check against real FGA.
	// The relation is the v_* enforcement relation the catalog gates the binding's
	// read action on — so the gate proves the materialized tuple actually RESOLVES
	// the relation the cutover will enforce, not merely that the ledger is non-empty
	// (the Design-A class-of-bug blind spot). One same-DB read; no per-binding
	// round-trip.
	ListActiveBindingRelationChecks(ctx context.Context) ([]BindingRelationCheck, error)
}

// VerifyFailure — a binding that expected explicit tuples but has an empty ledger.
type VerifyFailure struct {
	BindingID domain.AccessBindingID
	Reason    string
}

// VerifyReport — the gate verdict.
type VerifyReport struct {
	// NoAccessLoss — true ⇒ every binding that should materialize did (contract OK).
	NoAccessLoss bool
	// BindingsChecked — active bindings inspected.
	BindingsChecked int
	// Failures — bindings that expected explicit tuples but have none.
	Failures []VerifyFailure
}

// VerifyGate — the contract-phase gate.
type VerifyGate struct {
	engine  VerifyReconcileEngine
	store   VerifyStore
	logger  *slog.Logger
	checker VerifyRelationChecker // relation-satisfies-action; nil → skip
}

// NewVerifyGate constructs the gate.
func NewVerifyGate(engine VerifyReconcileEngine, store VerifyStore, logger *slog.Logger) *VerifyGate {
	if logger == nil {
		logger = slog.Default()
	}
	return &VerifyGate{engine: engine, store: store, logger: logger}
}

// WithRelationChecker wires the real-FGA Check port the relation-satisfies-action
// gate uses. nil-safe: an unwired checker makes VerifyRelationSatisfiesAction
// a non-fatal skip (the boot must not crash when FGA is degraded).
func (g *VerifyGate) WithRelationChecker(c VerifyRelationChecker) *VerifyGate {
	g.checker = c
	return g
}

// VerifyRelationSatisfiesAction is the Design-B cutover gate:
// for EVERY active binding's required-relation triple it runs a REAL FGA
// Check(subject, enforcement-relation, object) and reports NoAccessLoss=true ONLY
// when 100% are ALLOW. This closes the blind spot that let the Design-A
// class-of-bug through — the pre-Design-B gate only proved "materialization-
// happened" (ledger non-empty), NOT "the materialized tuple RESOLVES the relation
// the catalog enforces". A historical tier-only ledger (no v_get) → Check(v_get)
// DENIES → the gate FAILS and the catalog flip stays blocked until the reconciler
// backfills v_*.
//
// nil checker (degraded FGA) → non-fatal skip: BindingsChecked=0, NoAccessLoss=true
// (no assertion made); the caller logs and proceeds (parity with the other gate
// methods' best-effort posture).
func (g *VerifyGate) VerifyRelationSatisfiesAction(ctx context.Context) (VerifyReport, error) {
	if g.checker == nil {
		g.logger.InfoContext(ctx, "verify-gate: relation-satisfies-action skipped (no FGA checker wired)")
		return VerifyReport{NoAccessLoss: true}, nil
	}
	checks, err := g.store.ListActiveBindingRelationChecks(ctx)
	if err != nil {
		return VerifyReport{}, fmt.Errorf("verify-gate: list active binding relation checks: %w", err)
	}
	report := VerifyReport{NoAccessLoss: true, BindingsChecked: len(checks)}
	for _, c := range checks {
		allowed, cerr := g.checker.Check(ctx, c.Subject, c.Relation, c.Object)
		if cerr != nil {
			return VerifyReport{}, fmt.Errorf("verify-gate: fga check %s#%s@%s: %w",
				c.Object, c.Relation, c.Subject, cerr)
		}
		if !allowed {
			report.NoAccessLoss = false
			report.Failures = append(report.Failures, VerifyFailure{
				BindingID: c.BindingID,
				Reason: fmt.Sprintf("required relation %q on %s does NOT resolve for %s "+
					"(materialized but relation-not-satisfied — cutover blocked, F-11)",
					c.Relation, c.Object, c.Subject),
			})
		}
	}
	if !report.NoAccessLoss {
		g.logger.WarnContext(ctx, "verify-gate: relation-satisfies-action FAILED — catalog flip BLOCKED",
			slog.Int("failures", len(report.Failures)))
	} else {
		g.logger.InfoContext(ctx, "verify-gate: 100% relation-satisfies-action — catalog flip permitted",
			slog.Int("bindings_checked", report.BindingsChecked))
	}
	return report, nil
}

// Verify asserts no-access-loss: every active binding that should materialize
// explicit tuples has a non-empty ledger. Returns the verdict.
//
// Two complementary checks:
//   - member-without-tuple: an ACTIVE member whose binding ledger is empty (the
//     reconciler activated it but did not emit its tuple).
//   - should-have-members-but-has-none (sentinel): an ACTIVE account-scoped OWNER
//     binding with 0 ACTIVE members — a wholesale-reconcile-failure the active_members-
//     derived check is blind to. Restricted to owner bindings because they ALWAYS
//     materialize ≥1 member, so it never false-flags a legitimately-empty binding.
func (g *VerifyGate) Verify(ctx context.Context) (VerifyReport, error) {
	rows, err := g.store.ListActiveBindingMaterialization(ctx)
	if err != nil {
		return VerifyReport{}, fmt.Errorf("verify-gate: list active binding materialization: %w", err)
	}
	report := VerifyReport{NoAccessLoss: true, BindingsChecked: len(rows)}
	for _, m := range rows {
		if m.ExpectsTuples && m.LedgerCount == 0 {
			report.NoAccessLoss = false
			report.Failures = append(report.Failures, VerifyFailure{
				BindingID: m.BindingID,
				Reason:    "binding expects explicit materialization but its ledger is empty (no-access-loss risk before contract)",
			})
		}
	}
	// Sentinel cross-check: an owner-binding that should have ≥1 member but
	// has none → a dropped-membership regression the active_members heuristic cannot see.
	missing, err := g.store.ListOwnerBindingsMissingMembers(ctx)
	if err != nil {
		return VerifyReport{}, fmt.Errorf("verify-gate: list owner bindings missing members: %w", err)
	}
	for _, bid := range missing {
		report.NoAccessLoss = false
		report.Failures = append(report.Failures, VerifyFailure{
			BindingID: bid,
			Reason:    "owner-binding materialized 0 members but must have ≥1 (scope-self) — wholesale reconcile failure (no-access-loss)",
		})
	}
	if !report.NoAccessLoss {
		g.logger.WarnContext(ctx, "verify-gate: no-access-loss FAILED — contract phase BLOCKED",
			slog.Int("failures", len(report.Failures)))
	} else {
		g.logger.InfoContext(ctx, "verify-gate: 100% no-access-loss — contract phase permitted",
			slog.Int("bindings_checked", report.BindingsChecked))
	}
	return report, nil
}

// ForwardSmokeSpec describes the live forward-smoke: a fresh resource
// matching a REGULAR selector binding. ExpectBinding is the selector binding whose
// ledger MUST gain the content tuple; ObjectType/ObjectID is the synthetic resource;
// ParentProject/ParentAccount place it inside the binding's scope; Labels let it
// match an ARM_LABELS selector (empty for ARM_ANCHOR `all`).
type ForwardSmokeSpec struct {
	ExpectBinding domain.AccessBindingID
	ObjectType    string // dotted mirror type, e.g. "vpc.network"
	ObjectID      string
	ParentProject string
	ParentAccount string
	Labels        map[string]string
}

// ForwardSmoke proves the forward-materialization path is live: it creates the
// synthetic resource, drives the forward path (ReconcileObject), asserts the
// selector binding's content tuple materialized, then removes the synthetic object.
// Returns false (not an error) when the smoke object did not materialize — a
// forward-path regression the contract phase must block on.
func (g *VerifyGate) ForwardSmoke(ctx context.Context, spec ForwardSmokeSpec) (bool, error) {
	if spec.ExpectBinding == "" || spec.ObjectType == "" || spec.ObjectID == "" {
		return false, fmt.Errorf("verify-gate: forward-smoke spec incomplete (binding/type/id required)")
	}
	fgaObject := fgaObjectForSmoke(spec.ObjectType, spec.ObjectID)
	if fgaObject == "" {
		return false, fmt.Errorf("verify-gate: forward-smoke object type %q is not in the closed FGA table", spec.ObjectType)
	}

	if err := g.store.SeedSmokeMirrorObject(ctx, spec.ObjectType, spec.ObjectID,
		spec.ParentProject, spec.ParentAccount, spec.Labels); err != nil {
		return false, fmt.Errorf("verify-gate: seed smoke object: %w", err)
	}
	// Best-effort cleanup so the synthetic object never lingers.
	defer func() {
		if rerr := g.store.RemoveSmokeMirrorObject(ctx, spec.ObjectType, spec.ObjectID); rerr != nil {
			g.logger.WarnContext(ctx, "verify-gate: smoke object cleanup failed",
				slog.String("object_id", spec.ObjectID), slog.Any("err", rerr))
		}
	}()

	if err := g.engine.ReconcileObject(ctx, spec.ObjectType, spec.ObjectID); err != nil {
		return false, fmt.Errorf("verify-gate: forward reconcile smoke object: %w", err)
	}

	materialized, err := g.store.LedgerHasObject(ctx, spec.ExpectBinding, fgaObject)
	if err != nil {
		return false, fmt.Errorf("verify-gate: ledger check smoke object: %w", err)
	}
	if !materialized {
		g.logger.WarnContext(ctx, "verify-gate: forward-smoke FAILED — fresh resource not materialized",
			slog.String("binding_id", string(spec.ExpectBinding)), slog.String("object", fgaObject))
	}
	return materialized, nil
}

// RunBootForwardSmoke drives a single LIVE ForwardSmoke at boot against a real
// ACTIVE owner-binding (the contract-phase gate must actually exercise
// the forward-materialization path, not only the active_members-derived Verify). It
// discovers one account-scoped owner-binding, seeds a synthetic vpc.network mirror
// row inside that account, drives ReconcileObject, and asserts the owner's content
// tuple materialized — the assertion Verify provably cannot make (a resource created
// in the contract window that never materializes its tuple → silent access-loss).
// The synthetic object is removed by ForwardSmoke. Best-effort and non-fatal: when
// no owner-binding exists yet (brand-new cluster) it returns ok=false with no error;
// callers log the verdict and never crash on it (parity with Verify).
func (g *VerifyGate) RunBootForwardSmoke(ctx context.Context) (passed bool, ran bool, err error) {
	bindingID, accountID, ok, err := g.store.SmokeOwnerBindingCandidate(ctx)
	if err != nil {
		return false, false, fmt.Errorf("verify-gate: discover forward-smoke owner-binding: %w", err)
	}
	if !ok {
		return false, false, nil // no owner-binding yet — nothing to smoke (non-fatal)
	}
	smoke, err := g.ForwardSmoke(ctx, ForwardSmokeSpec{
		ExpectBinding: bindingID,
		ObjectType:    smokeMirrorType,
		ObjectID:      ids.NewID(smokeMirrorPrefix),
		ParentAccount: accountID,
	})
	if err != nil {
		return false, true, fmt.Errorf("verify-gate: boot forward-smoke: %w", err)
	}
	return smoke, true, nil
}

// fgaObjectForSmoke builds the FGA object ("<fga_type>:<id>") the forward-smoke
// looks up in the ledger, using the SAME canonical authzmap mapping the reconciler
// uses to WRITE the ledger row (authzmap.FGAObjectType → SplitObjectType on the
// FIRST dot + the closed objectTypes table). This guarantees the lookup key is
// byte-identical to what applyDiff records for EVERY closed-table type — not only
// the ones where a naive `.`→`_` substitution happens to coincide (the
// old hand-rolled byte loop diverged for ~13 of 22 types, e.g. vpc.securityGroup →
// vpc_security_group, iam.account → account). An unknown / multi-dot type returns ""
// (no ledger row can exist for it) so the smoke fails closed rather than fabricating
// an arbitrary FGA object.
func fgaObjectForSmoke(dotted, objectID string) string {
	fgaType, ok := authzmap.FGAObjectType(dotted)
	if !ok {
		return ""
	}
	return fgaType + ":" + objectID
}
