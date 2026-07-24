// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package reconcile

// reconcile_rules_test.go — unit tests for the role.rules-driven membership reconcile.
//
// The reconciler, when a binding's role carries ARM_LABELS rules, materializes
// membership from role.rules (NOT binding.selector): each ARM_LABELS rule
// (rule_fp) is matched against the mirror/iam-direct feed, matched-and-contained
// objects → ACTIVE per-object tuples derived from the RULE's verbs (per-verb v_*
// + tier), matched-but-not-contained → REJECTED
// (no tuple + audit). Membership is keyed per (rule_fp, object) so a Role.Update
// that removes one rule eager-revokes ONLY that rule's members.
//
// These are use-case unit tests against a fake ReconcileStore (no Postgres — a
// service-layer test requiring Postgres would be adapter leakage).

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// memberKey joins (objectType, objectID) with a NUL separator for the fakeStore's
// deleted-member tracking. NUL never occurs in a dotted closed-table type
// (e.g. "compute.instance") or a crockford-base32 object id, so the join is
// unambiguous. Test-only: production keys members by the full (rule_fp, type, id)
// coordinate (memberRuleKey).
func memberKey(objectType, objectID string) string { return objectType + "\x00" + objectID }

// fakeStore — an in-memory ReconcileStore for the role.rules reconcile slices.
type fakeStore struct {
	scope         domain.ScopeAnchor
	subjectType   string
	subjectID     string
	active        bool
	selectors     []domain.RuleSelector
	mirror        map[string][]domain.MirrorObject // dotted type → objects (MatchSelector source)
	iamDirect     map[string][]domain.MirrorObject // dotted iam.* type → own-table objects (iam-direct feed)
	current       []domain.TargetMember
	upserts       []domain.TargetMember
	deletes       []string // memberKey of deleted members
	writes        [][]domain.MembershipTuple
	tdeletes      [][]domain.MembershipTuple
	recorded      [][]domain.MembershipTuple
	forgotten     [][]domain.MembershipTuple
	audits        []string                 // objectID audited
	ledger        []domain.MembershipTuple // pre-seeded emitted-tuple ledger (revoke source)
	locks         int                      // AcquireBindingLock (EXCLUSIVE) call count
	sharedLocks   int                      // AcquireBindingLockShared (SHARE) call count (forward path)
	unlockedLoads int                      // LoadBindingUnlocked call count (forward path)

	// ReconcileObject fan-out fixtures (deadlock-class lock-ordering test). When set,
	// BindingsForObject / SelectorBindingsMatchingObject return these (possibly
	// overlapping, intentionally UNSORTED) id sets; lockOrder records the order in
	// which AcquireBindingLock is invoked across the fan-out so the test can assert a
	// globally-consistent (sorted ASC) acquisition order.
	bindingsForObject []domain.AccessBindingID
	selectorBindings  []domain.AccessBindingID
	// iamDirectSelectorBindings is the iam-direct fast-path source
	// (IAMDirectSelectorBindingsMatchingObject). Kept SEPARATE from selectorBindings
	// so a forward pass over an iam.* object exercises the iam-direct branch (own-table
	// getter + iam-direct fan-out) without disturbing the mirror-fed forward tests.
	iamDirectSelectorBindings []domain.AccessBindingID
	lockOrder                 []domain.AccessBindingID
}

func (f *fakeStore) AcquireBindingLock(ctx context.Context, id domain.AccessBindingID) error {
	f.locks++
	f.lockOrder = append(f.lockOrder, id)
	return nil
}

// AcquireBindingLockShared records the SHARE-mode advisory lock the forward fast-path
// takes. It is counted SEPARATELY from the EXCLUSIVE `locks` so a forward unit test can
// assert f.locks==0 (never the serializing EXCLUSIVE lock) while f.sharedLocks>=1.
func (f *fakeStore) AcquireBindingLockShared(ctx context.Context, id domain.AccessBindingID) error {
	f.sharedLocks++
	return nil
}

func (f *fakeStore) LoadBinding(ctx context.Context, id domain.AccessBindingID) (BindingScope, bool, error) {
	return BindingScope{
		BindingID:   id,
		Scope:       f.scope,
		SubjectType: f.subjectType,
		SubjectID:   f.subjectID,
		Selectors:   f.selectors,
		Active:      f.active,
	}, true, nil
}

// LoadBindingUnlocked mirrors LoadBinding but records that the forward path took NO
// advisory lock: the test asserts f.locks stays 0 across a forward pass (the throughput-
// critical property). unlockedLoads counts the no-lock loads so a forward unit test can
// prove it read the binding without AcquireBindingLock.
func (f *fakeStore) LoadBindingUnlocked(ctx context.Context, id domain.AccessBindingID) (BindingScope, bool, error) {
	f.unlockedLoads++
	return BindingScope{
		BindingID:   id,
		Scope:       f.scope,
		SubjectType: f.subjectType,
		SubjectID:   f.subjectID,
		Selectors:   f.selectors,
		Active:      f.active,
	}, true, nil
}

func (f *fakeStore) MatchSelector(ctx context.Context, types []string, ml map[string]string) ([]domain.MirrorObject, error) {
	var out []domain.MirrorObject
	for _, t := range types {
		for _, o := range f.mirror[t] {
			if o.MatchesLabels(ml) {
				out = append(out, o)
			}
		}
	}
	return out, nil
}

func (f *fakeStore) MatchIAMDirect(ctx context.Context, types []string, ml map[string]string) ([]domain.MirrorObject, error) {
	var out []domain.MirrorObject
	for _, t := range types {
		for _, o := range f.iamDirect[t] {
			if o.MatchesLabels(ml) {
				out = append(out, o)
			}
		}
	}
	return out, nil
}

// MatchAllInScope models the LOOSEST valid superset: it returns EVERY seeded object of the
// types and ignores `scope`. This is deliberate — the production adapter pushes a proven
// scope superset into SQL, but the reconciler's IsContainedIn re-verify is the authoritative
// containment gate; the fake over-returns so the unit tests prove IsContainedIn rejects
// foreign-scope objects even when the store hands back an over-broad candidate set.
func (f *fakeStore) MatchAllInScope(ctx context.Context, types []string, scope domain.ScopeAnchor) ([]domain.MirrorObject, error) {
	var out []domain.MirrorObject
	for _, t := range types {
		out = append(out, f.mirror[t]...)
	}
	return out, nil
}

func (f *fakeStore) MatchByIDs(ctx context.Context, types, ids []string) ([]domain.MirrorObject, error) {
	want := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		want[id] = struct{}{}
	}
	var out []domain.MirrorObject
	for _, t := range types {
		for _, o := range f.mirror[t] {
			if _, ok := want[o.ObjectID]; ok {
				out = append(out, o)
			}
		}
	}
	return out, nil
}

// MatchAllInScopeIAMDirect models the LOOSEST valid superset for the iam-direct feed:
// every seeded object of the types, ignoring scope (the reconciler's IsContainedIn
// re-verify is the authoritative containment gate — parity with MatchAllInScope).
func (f *fakeStore) MatchAllInScopeIAMDirect(ctx context.Context, types []string, scope domain.ScopeAnchor) ([]domain.MirrorObject, error) {
	var out []domain.MirrorObject
	for _, t := range types {
		out = append(out, f.iamDirect[t]...)
	}
	return out, nil
}

func (f *fakeStore) MatchByIDsIAMDirect(ctx context.Context, types, ids []string) ([]domain.MirrorObject, error) {
	want := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		want[id] = struct{}{}
	}
	var out []domain.MirrorObject
	for _, t := range types {
		for _, o := range f.iamDirect[t] {
			if _, ok := want[o.ObjectID]; ok {
				out = append(out, o)
			}
		}
	}
	return out, nil
}

func (f *fakeStore) GetMirrorObject(ctx context.Context, ot, oid string) (domain.MirrorObject, bool, error) {
	// Search the seeded mirror for the single object (forward fast-path source).
	for _, o := range f.mirror[ot] {
		if o.ObjectID == oid {
			return o, true, nil
		}
	}
	return domain.MirrorObject{}, false, nil
}

// GetIAMDirectObject is the iam-direct analogue of GetMirrorObject: it returns the
// seeded own-table projection (parents + labels) for one iam.* object. The forward
// fast-path uses it for a brand-new iam-direct object (which never lives in the mirror).
func (f *fakeStore) GetIAMDirectObject(ctx context.Context, ot, oid string) (domain.MirrorObject, bool, error) {
	for _, o := range f.iamDirect[ot] {
		if o.ObjectID == oid {
			return o, true, nil
		}
	}
	return domain.MirrorObject{}, false, nil
}

func (f *fakeStore) CurrentMembers(ctx context.Context, id domain.AccessBindingID) ([]domain.TargetMember, error) {
	return f.current, nil
}
func (f *fakeStore) BindingsForObject(ctx context.Context, ot, oid string) ([]domain.AccessBindingID, error) {
	return f.bindingsForObject, nil
}
func (f *fakeStore) SelectorBindingsMatchingObject(ctx context.Context, ot, oid string) ([]domain.AccessBindingID, error) {
	return f.selectorBindings, nil
}
func (f *fakeStore) IAMDirectSelectorBindingsMatchingObject(ctx context.Context, ot, oid string) ([]domain.AccessBindingID, error) {
	return f.iamDirectSelectorBindings, nil
}
func (f *fakeStore) UpsertMember(ctx context.Context, m domain.TargetMember) error {
	f.upserts = append(f.upserts, m)
	return nil
}
func (f *fakeStore) DeleteMember(ctx context.Context, id domain.AccessBindingID, ruleFP, ot, oid string) error {
	f.deletes = append(f.deletes, memberKey(ot, oid))
	return nil
}
func (f *fakeStore) LedgerTuplesForObject(ctx context.Context, id domain.AccessBindingID, object string) ([]domain.MembershipTuple, error) {
	// The fake ledger = pre-seeded rows + anything recorded this pass.
	var out []domain.MembershipTuple
	for _, t := range f.ledger {
		if t.Object == object {
			out = append(out, t)
		}
	}
	for _, batch := range f.recorded {
		for _, t := range batch {
			if t.Object == object {
				out = append(out, t)
			}
		}
	}
	return out, nil
}

// TuplesStillClaimedByOtherBindings — the fake models a SINGLE binding (no cross-
// binding siblings), so no tuple is ever still-claimed by another binding → empty set.
// The cross-binding suppression is exercised by the pg integration test
// (reconcile_cross_binding_revoke_integration_test.go) with two real bindings.
func (f *fakeStore) TuplesStillClaimedByOtherBindings(ctx context.Context, exclude domain.AccessBindingID, ts []domain.MembershipTuple) (map[domain.MembershipTuple]struct{}, error) {
	return map[domain.MembershipTuple]struct{}{}, nil
}
func (f *fakeStore) EmitTupleWrite(ctx context.Context, ts []domain.MembershipTuple) error {
	f.writes = append(f.writes, ts)
	return nil
}
func (f *fakeStore) EmitTupleDelete(ctx context.Context, ts []domain.MembershipTuple) error {
	f.tdeletes = append(f.tdeletes, ts)
	return nil
}
func (f *fakeStore) RecordEmittedTuples(ctx context.Context, id domain.AccessBindingID, ts []domain.MembershipTuple) error {
	f.recorded = append(f.recorded, ts)
	return nil
}
func (f *fakeStore) ForgetEmittedTuples(ctx context.Context, id domain.AccessBindingID, ts []domain.MembershipTuple) error {
	f.forgotten = append(f.forgotten, ts)
	return nil
}
func (f *fakeStore) EmitContainmentAudit(ctx context.Context, id domain.AccessBindingID, ot, oid string, s domain.ScopeAnchor) error {
	f.audits = append(f.audits, oid)
	return nil
}
func (f *fakeStore) RevokeExpiredBinding(ctx context.Context, id domain.AccessBindingID) (bool, error) {
	return false, nil
}

// fakeRunner hands the reconciler the fake store within a "tx".
type fakeRunner struct{ s ReconcileStore }

func (r fakeRunner) WithTx(ctx context.Context, fn func(ctx context.Context, s ReconcileStore) error) error {
	return fn(ctx, r.s)
}

func allWrites(f *fakeStore) []domain.MembershipTuple {
	var out []domain.MembershipTuple
	for _, batch := range f.writes {
		out = append(out, batch...)
	}
	return out
}

func hasTuple(ts []domain.MembershipTuple, relation, object string) bool {
	for _, t := range ts {
		if t.Relation == relation && t.Object == object {
			return true
		}
	}
	return false
}

// ── matchLabels per-object, no anchor; only matched objects ─────────

func TestReconcileRules_MatchLabels_PerObjectOnly_NoAnchor(t *testing.T) {
	fp := domain.Rule{
		Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get", "create"},
		MatchLabels: map[string]string{"env": "prod"},
	}.Fingerprint()
	f := &fakeStore{
		scope:       domain.ScopeAnchor{Type: "project", ID: "prj-1"},
		subjectType: "user", subjectID: "usr-1", active: true,
		selectors: []domain.RuleSelector{{
			Arm: domain.ArmLabels, RuleFP: fp,
			ObjectTypes: []string{"compute.instance"},
			MatchLabels: map[string]string{"env": "prod"},
			Verbs:       []string{"get", "create"},
		}},
		mirror: map[string][]domain.MirrorObject{
			"compute.instance": {
				{ObjectType: "compute.instance", ObjectID: "i-prod", ParentProjectID: "prj-1", Labels: map[string]string{"env": "prod"}},
				{ObjectType: "compute.instance", ObjectID: "i-stg", ParentProjectID: "prj-1", Labels: map[string]string{"env": "staging"}},
			},
		},
	}
	rec := New(fakeRunner{s: f}, nil)
	require.NoError(t, rec.ReconcileBinding(context.Background(), "acb-1"))

	// Only i-prod is materialized ACTIVE.
	require.Len(t, f.upserts, 1, "exactly one matched object materialized")
	assert.Equal(t, "i-prod", f.upserts[0].ObjectID)
	assert.Equal(t, domain.VerificationActive, f.upserts[0].VerificationStatus)
	assert.Equal(t, fp, f.upserts[0].RuleFP, "member keyed by rule_fp")

	w := allWrites(f)
	// Per-object tuples on the CONCRETE object — never a broad anchor (no scope_grant,
	// no tuple on project:prj-1). v_get + v_create + tier (viewer→editor: create⇒editor).
	assert.True(t, hasTuple(w, "v_get", "compute_instance:i-prod"), "v_get on matched object")
	assert.True(t, hasTuple(w, "v_create", "compute_instance:i-prod"), "v_create on matched object")
	assert.True(t, hasTuple(w, "editor", "compute_instance:i-prod"), "back-compat tier on matched object")
	// NO tuple on the non-matching object, NO anchor/scope_grant.
	for _, tup := range w {
		assert.NotContains(t, tup.Object, "i-stg", "no tuple on non-matched object")
		assert.NotContains(t, tup.Object, "scope_grant:", "matchLabels never emits a scope_grant anchor (fix #8)")
		assert.NotEqual(t, "project:prj-1", tup.Object, "no broad anchor tuple")
	}
}

// ── containment unit: matched-but-foreign-scope → REJECTED, no tuple ──────

func TestReconcileRules_MatchLabels_ForeignScope_Rejected(t *testing.T) {
	fp := domain.Rule{
		Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"env": "prod"},
	}.Fingerprint()
	f := &fakeStore{
		scope:       domain.ScopeAnchor{Type: "project", ID: "prj-1"},
		subjectType: "user", subjectID: "usr-1", active: true,
		selectors: []domain.RuleSelector{{
			Arm: domain.ArmLabels, RuleFP: fp, ObjectTypes: []string{"compute.instance"},
			MatchLabels: map[string]string{"env": "prod"}, Verbs: []string{"get"},
		}},
		mirror: map[string][]domain.MirrorObject{
			"compute.instance": {
				// matches labels but lives under a foreign project
				{ObjectType: "compute.instance", ObjectID: "i-foreign", ParentProjectID: "prj-OTHER", Labels: map[string]string{"env": "prod"}},
			},
		},
	}
	rec := New(fakeRunner{s: f}, nil)
	require.NoError(t, rec.ReconcileBinding(context.Background(), "acb-1"))

	require.Len(t, f.upserts, 1)
	assert.Equal(t, domain.VerificationRejected, f.upserts[0].VerificationStatus, "foreign scope → REJECTED")
	assert.Empty(t, allWrites(f), "REJECTED → no write tuple")
	assert.Contains(t, f.audits, "i-foreign", "REJECTED → containment audit (not silent)")
}

// ── a removed rule eager-revokes ONLY its rule_fp members ───────────

func TestReconcileRules_RuleRemoved_EagerRevokeByRuleFP(t *testing.T) {
	fpKept := domain.Rule{
		Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"team": "a"},
	}.Fingerprint()
	fpGone := domain.Rule{
		Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"team": "b"},
	}.Fingerprint()
	f := &fakeStore{
		scope:       domain.ScopeAnchor{Type: "project", ID: "prj-1"},
		subjectType: "user", subjectID: "usr-1", active: true,
		// the role NOW only has the "team=a" rule (the "team=b" rule was removed).
		selectors: []domain.RuleSelector{{
			Arm: domain.ArmLabels, RuleFP: fpKept, ObjectTypes: []string{"compute.instance"},
			MatchLabels: map[string]string{"team": "a"}, Verbs: []string{"get"},
		}},
		mirror: map[string][]domain.MirrorObject{
			"compute.instance": {
				{ObjectType: "compute.instance", ObjectID: "i-a", ParentProjectID: "prj-1", Labels: map[string]string{"team": "a"}},
				{ObjectType: "compute.instance", ObjectID: "i-b", ParentProjectID: "prj-1", Labels: map[string]string{"team": "b"}},
			},
		},
		// CURRENT materialized members: i-a under fpKept (stays), i-b under fpGone (must revoke).
		current: []domain.TargetMember{
			{BindingID: "acb-1", RuleFP: fpKept, ObjectType: "compute.instance", ObjectID: "i-a", VerificationStatus: domain.VerificationActive},
			{BindingID: "acb-1", RuleFP: fpGone, ObjectType: "compute.instance", ObjectID: "i-b", VerificationStatus: domain.VerificationActive},
		},
		// The emitted-tuple ledger holds what was emitted for each member (the
		// revoke source for a fell-out role.rules member whose rule verbs are gone).
		ledger: []domain.MembershipTuple{
			{User: "user:usr-1", Relation: "v_get", Object: "compute_instance:i-a"},
			{User: "user:usr-1", Relation: "viewer", Object: "compute_instance:i-a"},
			{User: "user:usr-1", Relation: "v_get", Object: "compute_instance:i-b"},
			{User: "user:usr-1", Relation: "viewer", Object: "compute_instance:i-b"},
		},
	}
	rec := New(fakeRunner{s: f}, nil)
	require.NoError(t, rec.ReconcileBinding(context.Background(), "acb-1"))

	// i-b (the removed rule's member) is deleted + its tuple eager-revoked.
	assert.Contains(t, f.deletes, memberKey("compute.instance", "i-b"), "removed-rule member deleted")
	var revoked []domain.MembershipTuple
	for _, batch := range f.tdeletes {
		revoked = append(revoked, batch...)
	}
	assert.True(t, hasTuple(revoked, "v_get", "compute_instance:i-b"), "removed-rule member tuple eager-revoked")
	// i-a (the kept rule's member) is NOT revoked (unchanged ACTIVE → idempotent skip).
	assert.False(t, hasTuple(revoked, "v_get", "compute_instance:i-a"), "kept-rule member NOT revoked")
}

// ── ACTIVE→REJECTED transition revokes the SAVED tuple via the ledger ──────────
//
// A label-matched object that was ACTIVE then moves OUT of scope (parent change /
// label-tampering) transitions ACTIVE→REJECTED. The stale tuple MUST be
// eager-revoked from the SAVED ledger (the rule verbs are still present, but the
// revoke source is the ledger, not d.Tuples which is empty for a REJECTED member).
func TestReconcileRules_ActiveToRejected_RevokesViaLedger(t *testing.T) {
	fp := domain.Rule{
		Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"env": "prod"},
	}.Fingerprint()
	f := &fakeStore{
		scope:       domain.ScopeAnchor{Type: "project", ID: "prj-1"},
		subjectType: "user", subjectID: "usr-1", active: true,
		selectors: []domain.RuleSelector{{
			Arm: domain.ArmLabels, RuleFP: fp, ObjectTypes: []string{"compute.instance"},
			MatchLabels: map[string]string{"env": "prod"}, Verbs: []string{"get"},
		}},
		mirror: map[string][]domain.MirrorObject{
			"compute.instance": {
				// the object STILL matches labels but has MOVED to a foreign project.
				{ObjectType: "compute.instance", ObjectID: "i-moved", ParentProjectID: "prj-OTHER", Labels: map[string]string{"env": "prod"}},
			},
		},
		// CURRENT: i-moved is ACTIVE under fp (was granted while in-scope).
		current: []domain.TargetMember{
			{BindingID: "acb-1", RuleFP: fp, ObjectType: "compute.instance", ObjectID: "i-moved", VerificationStatus: domain.VerificationActive},
		},
		// ledger holds the previously-emitted tuple for i-moved (the revoke source).
		ledger: []domain.MembershipTuple{
			{User: "user:usr-1", Relation: "v_get", Object: "compute_instance:i-moved"},
			{User: "user:usr-1", Relation: "viewer", Object: "compute_instance:i-moved"},
		},
	}
	rec := New(fakeRunner{s: f}, nil)
	require.NoError(t, rec.ReconcileBinding(context.Background(), "acb-1"))

	// Member flips to REJECTED + audited; the stale tuple is eager-revoked via ledger.
	require.Len(t, f.upserts, 1)
	assert.Equal(t, domain.VerificationRejected, f.upserts[0].VerificationStatus, "moved-out object → REJECTED")
	assert.Contains(t, f.audits, "i-moved", "REJECTED → audit")
	var revoked []domain.MembershipTuple
	for _, batch := range f.tdeletes {
		revoked = append(revoked, batch...)
	}
	assert.True(t, hasTuple(revoked, "v_get", "compute_instance:i-moved"),
		"ACTIVE→REJECTED eager-revokes the saved tuple from the ledger (no standing orphan)")
}

// ── ARM_ANCHOR(all) materializes per-object, no anchor/scope_grant ─────

func TestReconcileRules_AnchorAll_PerObject_AllInScope(t *testing.T) {
	fp := domain.Rule{
		Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get", "list"},
	}.Fingerprint()
	f := &fakeStore{
		scope:       domain.ScopeAnchor{Type: "project", ID: "prj-1"},
		subjectType: "user", subjectID: "usr-1", active: true,
		selectors: []domain.RuleSelector{{
			Arm: domain.ArmAnchor, RuleFP: fp,
			ObjectTypes: []string{"vpc.network"},
			Verbs:       []string{"get", "list"},
		}},
		mirror: map[string][]domain.MirrorObject{
			"vpc.network": {
				{ObjectType: "vpc.network", ObjectID: "n1", ParentProjectID: "prj-1"},
				{ObjectType: "vpc.network", ObjectID: "n2", ParentProjectID: "prj-1"},
				// n3 is in a foreign project → not contained → REJECTED.
				{ObjectType: "vpc.network", ObjectID: "n3", ParentProjectID: "prj-OTHER"},
			},
		},
	}
	rec := New(fakeRunner{s: f}, nil)
	require.NoError(t, rec.ReconcileBinding(context.Background(), "acb-1"))

	// The advisory lock is taken exactly once per pass.
	assert.Equal(t, 1, f.locks, "AcquireBindingLock taken once per reconcile pass")

	// n1 + n2 ACTIVE; n3 REJECTED (foreign scope).
	byID := map[string]domain.VerificationStatus{}
	for _, u := range f.upserts {
		byID[u.ObjectID] = u.VerificationStatus
	}
	assert.Equal(t, domain.VerificationActive, byID["n1"])
	assert.Equal(t, domain.VerificationActive, byID["n2"])
	assert.Equal(t, domain.VerificationRejected, byID["n3"], "out-of-scope object REJECTED, not granted")

	w := allWrites(f)
	assert.True(t, hasTuple(w, "v_get", "vpc_network:n1"), "v_get on n1")
	assert.True(t, hasTuple(w, "v_list", "vpc_network:n2"), "v_list on n2")
	for _, tup := range w {
		assert.NotContains(t, tup.Object, "scope_grant:", "ARM_ANCHOR never emits a scope_grant (D-4)")
		assert.NotEqual(t, "project:prj-1", tup.Object, "no bare-anchor tier tuple")
		assert.NotContains(t, tup.Object, "n3", "no tuple on out-of-scope object")
	}
}

// ── ARM_NAMES materializes only the named objects ─────────────────────

func TestReconcileRules_Names_OnlyNamed(t *testing.T) {
	fp := domain.Rule{
		Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"},
		ResourceNames: []string{"n1"},
	}.Fingerprint()
	f := &fakeStore{
		scope:       domain.ScopeAnchor{Type: "project", ID: "prj-1"},
		subjectType: "user", subjectID: "usr-1", active: true,
		selectors: []domain.RuleSelector{{
			Arm: domain.ArmNames, RuleFP: fp,
			ObjectTypes:   []string{"vpc.network"},
			ResourceNames: []string{"n1"},
			Verbs:         []string{"get"},
		}},
		mirror: map[string][]domain.MirrorObject{
			"vpc.network": {
				{ObjectType: "vpc.network", ObjectID: "n1", ParentProjectID: "prj-1"},
				{ObjectType: "vpc.network", ObjectID: "n2", ParentProjectID: "prj-1"},
			},
		},
	}
	rec := New(fakeRunner{s: f}, nil)
	require.NoError(t, rec.ReconcileBinding(context.Background(), "acb-1"))

	require.Len(t, f.upserts, 1, "only the named object materialized")
	assert.Equal(t, "n1", f.upserts[0].ObjectID)
	assert.Equal(t, domain.VerificationActive, f.upserts[0].VerificationStatus)
	w := allWrites(f)
	assert.True(t, hasTuple(w, "v_get", "vpc_network:n1"))
	for _, tup := range w {
		assert.NotContains(t, tup.Object, "n2", "unnamed object never materialized")
		assert.NotContains(t, tup.Object, "scope_grant:", "names never emits scope_grant")
	}
}

// ── deadlock-class: ReconcileObject fan-out acquires advisory locks in a globally
//
//	consistent (sorted ASC) order ────────────────────────────────────────────────
//
// ReconcileObject fans out over the union of (a) bindings that
// already reference the object and (b) bindings whose selector now matches it, taking
// pg_advisory_xact_lock(hashtext(binding_id)) per binding inside ONE writer-tx. If the
// union is locked in source/append order, two concurrent ReconcileObject passes on
// DIFFERENT objects with OVERLAPPING binding-sets can grab the locks in DIFFERENT
// orders → classic ABBA deadlock (Postgres 40P01). The fix sorts+dedupes the union so
// every pass acquires shared bindings in the SAME global order, which is deadlock-free.
//
// This is a pure use-case test: the underlying queries return intentionally UNSORTED,
// overlapping id sets; the assertion is that the reconciler acquires the locks in a
// deterministic sorted order regardless of arrival order (without the sort the
// union would be locked in append order: c, a, b).
func TestReconcileObject_FanOut_DeterministicLockOrder(t *testing.T) {
	f := &fakeStore{
		scope:       domain.ScopeAnchor{Type: "project", ID: "prj-1"},
		subjectType: "user", subjectID: "usr-1", active: true,
		// No selectors ⇒ each fanned-out binding is a thin recompute (no membership
		// writes); we only care about lock-acquisition ORDER here.
		selectors: nil,
		// Intentionally UNSORTED, OVERLAPPING id sets across the two fan-out sources.
		// Union (deduped) = {acb-a, acb-b, acb-c}; a globally-consistent order is the
		// sorted ASC sequence acb-a, acb-b, acb-c.
		bindingsForObject: []domain.AccessBindingID{"acb-c", "acb-a"},
		selectorBindings:  []domain.AccessBindingID{"acb-b", "acb-a"},
	}
	rec := New(fakeRunner{s: f}, nil)
	require.NoError(t, rec.ReconcileObject(context.Background(), "vpc.network", "nX"))

	// Each distinct binding is locked exactly once (dedup) ...
	assert.Equal(t, []domain.AccessBindingID{"acb-a", "acb-b", "acb-c"}, f.lockOrder,
		"fan-out must acquire advisory locks in a globally-consistent (sorted ASC, deduped) order to be deadlock-free")
}
