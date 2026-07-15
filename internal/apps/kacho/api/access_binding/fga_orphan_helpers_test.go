// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// fga_orphan_helpers_test.go — test scaffolding for the orphan-tuple
// regression suite (fga_orphan_test.go): fake-repo extensions for the persisted
// emitted-tuple store + active-by-role listing, a fake Role writer, and the
// Role.Update use-case wiring (real UpdateRoleUseCase + real RoleTupleReconciler
// over the fake repo).

import (
	"context"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	roleapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/role"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	ab_repo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
)

// ─── ordered, deduped emitted-tuple store ────────────────────────────────────

// orderedTupleSet models the access_binding_emitted_tuples ledger of ONE binding
// in the fake repo: set semantics (PK on the natural key ⇒ dedupe) WITH
// insertion order preserved on read-back. The real pg SelectEmittedTuples returns
// a deterministic `ORDER BY relation, object, fga_user`; the fake returns
// insertion order. Both are valid for the SET-based symmetric-revoke contract
// (the drainer applies a set to OpenFGA), but a raw `map[tuple]struct{}` iterates
// in RANDOM order, which makes TestFGASymmetric's require.Equal(written, deleted)
// flaky/failing. Insertion order is deterministic AND matches the order in which
// create.go captured the write-set (it feeds the SAME `tuples` slice to both
// EmitRelationWrite and InsertEmittedTuples), so the round-trip is byte-stable.
type orderedTupleSet struct {
	order []ab_repo.RelationTuple            // insertion order, deduped
	seen  map[ab_repo.RelationTuple]struct{} // membership for dedupe
}

func newOrderedTupleSet() *orderedTupleSet {
	return &orderedTupleSet{seen: map[ab_repo.RelationTuple]struct{}{}}
}

// add appends a tuple if not already present (ON CONFLICT DO NOTHING parity).
func (s *orderedTupleSet) add(t ab_repo.RelationTuple) {
	if _, dup := s.seen[t]; dup {
		return
	}
	s.seen[t] = struct{}{}
	s.order = append(s.order, t)
}

// list returns a copy in insertion order.
func (s *orderedTupleSet) list() []ab_repo.RelationTuple {
	out := make([]ab_repo.RelationTuple, len(s.order))
	copy(out, s.order)
	return out
}

// ─── fake-repo extensions ────────────────────────────────────────────────────

// setRolePermissions mutates the backing role's permissions (simulates a
// Role.Update of the role's permissions between grant and revoke).
func (r *abFakeRepo) setRolePermissions(p domain.Permissions) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rolePermissions = p
}

// setRoleRules marks the backing role as a RULES-role (RBAC rules-model) so the
// create + reconcile exercise the type-scoped scope_grant emit
// path (rulesBindingTuples) instead of the legacy whole-role anchor collapse.
func (r *abFakeRepo) setRoleRules(rules domain.Rules) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.roleRules = rules
}

// setRoleCustom marks the backing role as a CUSTOM role owned by accountID so
// the Role.Update account-owner authority + assignability gates pass.
func (r *abFakeRepo) setRoleCustom(accountID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.roleIsCustom = true
	r.accountID = accountID
}

// InsertEmittedTuples — fake of the persisted exact emitted-set co-commit. Set
// semantics (PK on the natural key) — repeated inserts of the same tuple are a
// no-op (ON CONFLICT DO NOTHING parity); insertion order is preserved on
// read-back so the round-trip is deterministic (orderedTupleSet doc).
func (w *fakeABWtr) InsertEmittedTuples(_ context.Context, id domain.AccessBindingID, tuples []ab_repo.RelationTuple) error {
	w.repo.mu.Lock()
	defer w.repo.mu.Unlock()
	if w.repo.emittedTuples == nil {
		w.repo.emittedTuples = map[domain.AccessBindingID]*orderedTupleSet{}
	}
	if w.repo.emittedTuples[id] == nil {
		w.repo.emittedTuples[id] = newOrderedTupleSet()
	}
	for _, t := range tuples {
		w.repo.emittedTuples[id].add(t)
	}
	return nil
}

// ReplaceEmittedTuples — fake of the reconcile wholesale-replace (delete-all +
// insert the new set) inside the writer-tx. The new set keeps the supplied
// insertion order.
func (w *fakeABWtr) ReplaceEmittedTuples(_ context.Context, id domain.AccessBindingID, tuples []ab_repo.RelationTuple) error {
	w.repo.mu.Lock()
	defer w.repo.mu.Unlock()
	if w.repo.emittedTuples == nil {
		w.repo.emittedTuples = map[domain.AccessBindingID]*orderedTupleSet{}
	}
	set := newOrderedTupleSet()
	for _, t := range tuples {
		set.add(t)
	}
	w.repo.emittedTuples[id] = set
	return nil
}

// SelectEmittedTuples — fake of the stored-set read on the reader side
// (revoke / reconcile diff base). Returns the exact persisted set in insertion
// order (deterministic; the real pg repo orders by relation,object,fga_user —
// both are valid for the set-based symmetric-revoke contract).
func (rd *fakeABRdr) SelectEmittedTuples(_ context.Context, id domain.AccessBindingID) ([]ab_repo.RelationTuple, error) {
	rd.repo.mu.Lock()
	defer rd.repo.mu.Unlock()
	if set := rd.repo.emittedTuples[id]; set != nil {
		return set.list(), nil
	}
	return nil, nil
}

// ListActiveByRole — fake of the Role.Update fan-out lister: ACTIVE bindings of
// a role. The fake stores a single binding (sufficient for the unit tests); it
// is returned when its RoleID matches and it is not REVOKED.
func (rd *fakeABRdr) CountActiveByRole(_ context.Context, _ domain.RoleID) (int, error) {
	return 0, nil
}

func (rd *fakeABRdr) ListActiveByRole(_ context.Context, roleID domain.RoleID) ([]domain.AccessBinding, error) {
	rd.repo.mu.Lock()
	defer rd.repo.mu.Unlock()
	if rd.repo.ab == nil || rd.repo.ab.RoleID != roleID {
		return nil, nil
	}
	if rd.repo.ab.Status == domain.AccessBindingStatusRevoked {
		return nil, nil
	}
	cp := *rd.repo.ab
	return []domain.AccessBinding{cp}, nil
}

// SelectEmittedTuplesBySource — the fake stores only binding-level emitted tuples
// (no ARM_LABELS members in these unit tests), so it returns the full stored set
// regardless of source (the real pg repo filters by the `source` column).
func (rd *fakeABRdr) SelectEmittedTuplesBySource(ctx context.Context, id domain.AccessBindingID, _ string) ([]ab_repo.RelationTuple, error) {
	return rd.SelectEmittedTuples(ctx, id)
}

// ─── multi-subject fake extensions (subjects[] + ListByRole) ─────────────────

// ListByRole — fake of the audit lister: ACTIVE (non-revoked) binding of a
// role. The fake stores one binding (sufficient for unit tests); returns it when
// its RoleID matches and it is not REVOKED (unless IncludeRevoked).
func (rd *fakeABRdr) ListByRole(_ context.Context, roleID domain.RoleID, f ab_repo.ListByRoleFilter) ([]domain.AccessBinding, string, error) {
	rd.repo.mu.Lock()
	defer rd.repo.mu.Unlock()
	if rd.repo.ab == nil || rd.repo.ab.RoleID != roleID {
		return nil, "", nil
	}
	if !f.IncludeRevoked && rd.repo.ab.Status == domain.AccessBindingStatusRevoked {
		return nil, "", nil
	}
	cp := *rd.repo.ab
	return []domain.AccessBinding{cp}, "", nil
}

// ListSubjects — fake of the multi-subject read. Returns the per-binding
// subjects recorded by InsertSubjects (insertion order preserved).
func (rd *fakeABRdr) ListSubjects(_ context.Context, id domain.AccessBindingID) ([]domain.Subject, error) {
	rd.repo.mu.Lock()
	defer rd.repo.mu.Unlock()
	subs := rd.repo.abSubjects[id]
	out := make([]domain.Subject, len(subs))
	copy(out, subs)
	return out, nil
}

// ListSubjectsForBindings — batch fake.
func (rd *fakeABRdr) ListSubjectsForBindings(_ context.Context, ids []domain.AccessBindingID) (map[domain.AccessBindingID][]domain.Subject, error) {
	rd.repo.mu.Lock()
	defer rd.repo.mu.Unlock()
	out := map[domain.AccessBindingID][]domain.Subject{}
	for _, id := range ids {
		if subs := rd.repo.abSubjects[id]; len(subs) > 0 {
			cp := make([]domain.Subject, len(subs))
			copy(cp, subs)
			out[id] = cp
		}
	}
	return out, nil
}

// InsertSubjects — fake of the per-subject child-table persist (idempotent set).
func (w *fakeABWtr) InsertSubjects(_ context.Context, id domain.AccessBindingID, subjects []domain.Subject) error {
	w.repo.mu.Lock()
	defer w.repo.mu.Unlock()
	if w.repo.abSubjects == nil {
		w.repo.abSubjects = map[domain.AccessBindingID][]domain.Subject{}
	}
	existing := w.repo.abSubjects[id]
	seen := map[domain.Subject]struct{}{}
	for _, s := range existing {
		seen[s] = struct{}{}
	}
	for _, s := range subjects {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		existing = append(existing, s)
	}
	w.repo.abSubjects[id] = existing
	return nil
}

// DeleteSubject — fake of the per-subject revoke.
func (w *fakeABWtr) DeleteSubject(_ context.Context, id domain.AccessBindingID, subject domain.Subject) (bool, error) {
	w.repo.mu.Lock()
	defer w.repo.mu.Unlock()
	subs := w.repo.abSubjects[id]
	out := subs[:0:0]
	found := false
	for _, s := range subs {
		if s == subject {
			found = true
			continue
		}
		out = append(out, s)
	}
	w.repo.abSubjects[id] = out
	return found, nil
}

// ─── fake Role writer ────────────────────────────────────────────────────────

// fakeRoleWtr — minimal role.WriterIface for the Role.Update doUpdate path.
type fakeRoleWtr struct{ repo *abFakeRepo }

func (w *fakeRoleWtr) Insert(_ context.Context, r domain.Role) (domain.Role, error) {
	return r, nil
}

func (w *fakeRoleWtr) Update(_ context.Context, r domain.Role, _ []string) (domain.Role, error) {
	w.repo.mu.Lock()
	defer w.repo.mu.Unlock()
	// Persist the new permissions AND rules into the fake's backing store so a
	// subsequent Roles().Get reflects the update (the reconcile reads the role back).
	w.repo.rolePermissions = r.Permissions
	w.repo.roleRules = r.Rules
	return r, nil
}

func (w *fakeRoleWtr) UpdateCAS(ctx context.Context, r domain.Role, mask []string, _ string) (domain.Role, error) {
	// The fake ignores the OCC token (single-threaded unit tests) — the xmin-CAS is
	// exercised by the role_occ integration test against real Postgres.
	return w.Update(ctx, r, mask)
}

func (w *fakeRoleWtr) Delete(_ context.Context, _ domain.RoleID) error { return nil }

func (w *fakeRoleWtr) ReplaceRuleSelectors(_ context.Context, _ domain.RoleID, _ []domain.RuleSelector) error {
	return nil
}

// ─── Role.Update use-case wiring ─────────────────────────────────────────────

// newRoleUpdateUseCaseForTest builds the REAL UpdateRoleUseCase with the REAL
// RoleTupleReconciler (the role-update fan-out) over the fake repo, so the test
// exercises the production reconcile path. fga is wired for backwards-compat
// surface parity (not used sync).
func newRoleUpdateUseCaseForTest(repo *abFakeRepo, opsRepo operations.Repo, _ *recordingFGA) *roleapp.UpdateRoleUseCase {
	return roleapp.NewUpdateRoleUseCase(repo, opsRepo).
		WithTupleReconciler(NewRoleTupleReconciler())
}

// roleUpdateInput builds an UpdateRoleInput that changes only the role's rules
// (update_mask=["rules"]). The use-case recompiles rules→permissions, so the
// reconcile fan-out diffs against the new compiled set just as before. `rules`
// is the rules-model 2026 authored input (replaces the legacy permissions input).
func roleUpdateInput(roleID string, rules domain.Rules) roleapp.UpdateRoleInput {
	return roleapp.UpdateRoleInput{
		ID:         domain.RoleID(roleID),
		Rules:      rules,
		UpdateMask: []string{"rules"},
	}
}
