// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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

	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// VerifyReconcileEngine — the reconcile surface the forward-smoke drives.
type VerifyReconcileEngine interface {
	ReconcileObject(ctx context.Context, objectType, objectID string) error
}

// VerifyRelationChecker — the REAL Check port the relation-satisfies-action gate
// uses (Design-B). Implemented by the decision door (internal/authzcascade) over the
// relational form. nil → the gate is a non-fatal skip (no assertion made), so an
// unwired resolver never crashes boot.
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
//
// Relation / Object / Subject НЕ дублируют Reason, а вынимают из него то, по чему
// разбирают журнал. Прежде отказ печатал одно число, а эти три величины жили
// внутри прозы и не выводились никогда — назвать несошедшуюся пару по журналу
// было невозможно (задача #1865). Поля пусты у находок, у которых пары нет by
// construction (пустая ведомость привязки): пустое значение здесь означает
// «пары нет», а не «пара не названа».
type VerifyFailure struct {
	BindingID domain.AccessBindingID
	Reason    string
	Relation  string
	Object    string
	Subject   string
}

// verifyFailureLogCap — сколько пар называется поимённо, прежде чем остаток
// сворачивается в число.
//
// Предел, а не «печатать всё»: страж идёт на старте, и отказ по каждой привязке
// арендатора вылился бы в журнал, который никто не прочтёт. Предел, а не
// «печатать одно число»: остаток называется числом ЯВНО, поэтому усечение видно
// и не выдаёт себя за полный перечень.
const verifyFailureLogCap = 50

// logFailures называет КАЖДУЮ находку отдельной записью с полями.
//
// Поля, а не проза: разбирающий журнал отбирает по полю. Проза остаётся в
// reason — она объясняет, а не адресует.
func (g *VerifyGate) logFailures(ctx context.Context, msg string, report VerifyReport) {
	g.logger.WarnContext(ctx, msg,
		slog.Int("failures", len(report.Failures)),
		slog.Int("bindings_checked", report.BindingsChecked))
	for i, f := range report.Failures {
		if i == verifyFailureLogCap {
			g.logger.WarnContext(ctx, "verify-gate: остаток находок не назван поимённо",
				slog.Int("named", verifyFailureLogCap),
				slog.Int("unnamed", len(report.Failures)-verifyFailureLogCap))
			break
		}
		attrs := []any{
			slog.String("binding_id", string(f.BindingID)),
			slog.String("reason", f.Reason),
		}
		if f.Relation != "" || f.Object != "" || f.Subject != "" {
			attrs = append(attrs,
				slog.String("relation", f.Relation),
				slog.String("object", f.Object),
				slog.String("subject", f.Subject))
		}
		g.logger.WarnContext(ctx, "verify-gate: находка", attrs...)
	}
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
				Relation:  c.Relation,
				Object:    c.Object,
				Subject:   c.Subject,
				Reason: fmt.Sprintf("required relation %q on %s does NOT resolve for %s "+
					"(materialized read tuple does not resolve the enforced relation)",
					c.Relation, c.Object, c.Subject),
			})
		}
	}
	if !report.NoAccessLoss {
		g.logFailures(ctx, "verify-gate: materialized read tuples that do NOT resolve", report)
	} else {
		g.logger.InfoContext(ctx, "verify-gate: every materialized read tuple resolves",
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
		g.logFailures(ctx, "verify-gate: no-access-loss FAILED — contract phase BLOCKED", report)
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
	// УБОРКА СНИМАЕТ ВСЁ, ЧТО ПРОБА ЗАВЕЛА, А НЕ ТОЛЬКО СТРОКУ ЗЕРКАЛА (#119).
	//
	// Строка зеркала — не единственный след: сведение, которым проба и доказывает
	// прямой путь, пишет по её объекту строки ведомости. Снятое зеркало их не
	// уносит, и следующий страж читает ведомость и честно находит
	// материализованное чтение на объекте, которого больше нет. На чистой
	// установке это печатается отказом о СОБСТВЕННОЙ синтетике, неотличимым от
	// поломки.
	//
	// Поэтому уборка: снять зеркало → свести объект ЕЩЁ РАЗ (желаемый набор
	// пуст, сведение снимает написанное) → убедиться, что ведомость его не
	// несёт. Всё три шага best-effort и не роняют старт — но остаток НАЗЫВАЕТСЯ,
	// иначе половинная уборка снова станет невидимой.
	defer func() {
		if rerr := g.store.RemoveSmokeMirrorObject(ctx, spec.ObjectType, spec.ObjectID); rerr != nil {
			g.logger.WarnContext(ctx, "verify-gate: smoke object cleanup failed",
				slog.String("object_id", spec.ObjectID), slog.Any("err", rerr))
			return
		}
		if rerr := g.engine.ReconcileObject(ctx, spec.ObjectType, spec.ObjectID); rerr != nil {
			g.logger.WarnContext(ctx, "verify-gate: smoke object retraction reconcile failed",
				slog.String("object", fgaObject), slog.Any("err", rerr))
			return
		}
		residue, rerr := g.store.LedgerHasObject(ctx, spec.ExpectBinding, fgaObject)
		switch {
		case rerr != nil:
			g.logger.WarnContext(ctx, "verify-gate: smoke object residue check failed",
				slog.String("object", fgaObject), slog.Any("err", rerr))
		case residue:
			g.logger.WarnContext(ctx, "verify-gate: smoke object left ledger rows behind",
				slog.String("binding_id", string(spec.ExpectBinding)),
				slog.String("object", fgaObject))
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
