// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// fga_orphan_test.go — F3 / PRO-Robotech/kacho-iam#178 regression suite.
//
// The bug: AccessBinding revoke and Role.Update were NOT symmetric to the FGA
// grant emission, so a role mutation between grant and revoke left ORPHAN FGA
// tuples = standing privilege.
//
//   - delete.go RE-DERIVED the revoke tuple-set from the binding's CURRENT role
//     instead of the persisted emitted-set → if the role changed, the wrong
//     tuples were deleted and the originally-granted ones leaked.
//   - role/update.go (doUpdate) on a permissions change emitted ONLY an audit
//     event and did NOT reconcile the FGA tuples of the role's active bindings →
//     a dropped permission left its tuple standing.
//
// The fix: a persisted exact emitted-set per binding
// (access_binding_emitted_tuples), co-committed with the grant emit; revoke
// SELECTs it (no re-derive); Role.Update diffs stored-old vs derive-from-new and
// emits the delta — all in the writer-tx.
//
// These tests drive the REAL use-cases (Create / Delete / Role.Update) over the
// in-memory fake repo, asserting the NET FGA tuple effect (writes minus deletes)
// is empty after a revoke and tier-correct after a Role.Update. They are RED
// against the pre-fix code (orphan `admin` survives) and GREEN after.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	ab_repo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
)

// Well-formed 20-char crockford-base32 role ids (shared.ValidateResourceID in
// Role.Update checks prefix + length == domain.ShortIDLen).
const (
	roleID178a = "rol00000000000dyn01a"
	roleID178b = "rol00000000000dyn01b"
	roleID178c = "rol00000000000dyn01c"
)

// netTuples computes the residual FGA tuple set after applying a sequence of
// writes and deletes: a tuple present in writes but not cancelled by an equal
// delete is "still live in OpenFGA". An orphan tuple is a write with no matching
// delete. The drainer is idempotent, so multiplicity does not matter — set
// semantics on (User, Relation, Object).
func netTuples(written, deleted []ab_repo.RelationTuple) map[ab_repo.RelationTuple]int {
	net := map[ab_repo.RelationTuple]int{}
	for _, w := range written {
		net[w]++
	}
	for _, d := range deleted {
		net[d]--
	}
	for k, v := range net {
		if v <= 0 {
			delete(net, k)
		}
	}
	return net
}

// awaitOpDone polls a SPECIFIC operation to completion via the ops repo
// (deterministic per-op wait — the process-global operations.Wait is unreliable
// across interleaved test workers because it keys on a shared WaitGroup that can
// transiently hit zero between a grant's Done and the next op's Add).
func awaitOpDone(t *testing.T, opsRepo operations.Repo, opID string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		op, err := opsRepo.Get(context.Background(), opID)
		require.NoError(t, err)
		if op.Done {
			if op.Error != nil {
				t.Fatalf("operation %s failed: %v", opID, op.Error)
			}
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("operation %s did not complete within deadline", opID)
}

// ─── RED-1 — revoke under role mutation leaves ZERO residual tuples ───────────

// TestFGAOrphan_178_RevokeAfterRoleDowngrade_NoResidualTuple — grant a role at
// admin tier, MUTATE the role admin→viewer, then revoke the binding. The revoke
// MUST delete the exact tuples that were emitted at grant (the persisted
// emitted-set), regardless of the role's current permissions, so no FGA tuple
// survives. Pre-fix, delete.go re-derived from the now-viewer role and emitted
// EmitRelationDelete(viewer); the admin role-relation tuple emitted at grant was
// orphaned (standing admin = privilege escalation).
func TestFGAOrphan_178_RevokeAfterRoleDowngrade_NoResidualTuple(t *testing.T) {
	const (
		subjectID  = "usr_sub_178a"
		resourceID = "prj_target_178a"
		ownerID    = "usr_owner_178a"
		accountID  = "acc_178a"
	)
	repo := newABFakeRepo(ownerID, accountID, resourceID, roleID178a, "admin",
		domain.Permissions{"iam.access_bindings.admin"})
	opsRepo := newFakeOpsRepo()
	fga := newRecordingFGA()
	ctx := newOwnerContext(ownerID)

	createUC := NewCreateAccessBindingUseCase(repo, opsRepo).WithRelationStore(fga, nil)
	opCreate, err := createUC.Execute(ctx, domain.AccessBinding{
		SubjectType:  "user",
		SubjectID:    domain.SubjectID(subjectID),
		RoleID:       domain.RoleID(roleID178a),
		ResourceType: "project",
		ResourceID:   resourceID,
	})
	require.NoError(t, err)
	awaitOpDone(t, opsRepo, opCreate.ID)

	written := repo.drainFGAWritten()
	require.NotEmpty(t, written, "Create must emit grant tuples")
	adminTuple := ab_repo.RelationTuple{
		User: "user:" + subjectID, Relation: "admin", Object: "project:" + resourceID,
	}
	require.Contains(t, written, adminTuple, "grant emitted the admin role-relation tuple")

	// MUTATE the backing role admin→viewer (simulates a Role.Update between grant
	// and revoke). The persisted emitted-set must still drive the revoke.
	repo.setRolePermissions(domain.Permissions{"iam.access_bindings.get"})

	abID := repo.lastInsertedID()
	deleteUC := NewDeleteAccessBindingUseCase(repo, opsRepo).WithRelationStore(fga, nil)
	opDelete, err := deleteUC.Execute(newOwnerContext(subjectID), abID)
	require.NoError(t, err)
	awaitOpDone(t, opsRepo, opDelete.ID)

	deleted := repo.drainFGADeleted()

	residual := netTuples(written, deleted)
	assert.Empty(t, residual,
		"revoke after role downgrade must leave ZERO residual FGA tuples (orphan = standing privilege); residual=%v", residual)
}

// NOTE (RBAC explicit-model 2026 P4 / D-4): the former
// TestFGAOrphan_178_RoleUpdateDowngrade_ReconcilesActiveBindingTuples asserted the
// BINDING-TIME scope_grant emission/revoke on a RULES-role Role.Update. That path is
// REMOVED in P4 (binding-time scope_grant emission dropped wholesale; the unified
// reconciler now materializes DIRECT per-object v_*/tier tuples). The Role.Update
// reconcile of a rules-role's per-object membership is covered by the reconciler
// suites instead — TestC20C21_RuleRemoved_EagerRevokeByRuleFP (integration) and
// TestReconcileRules_RuleRemoved_EagerRevokeByRuleFP (unit). The two
// permissions-only-role orphan tests below remain valid (legacy tier-on-anchor path).

// ─── RED-3 — granular permission removal between grant and revoke ─────────────

// TestFGAOrphan_178_GranularPermissionRemoved_NoResidual — a role granting
// [read, write] emits the editor-tier tuple (write supersedes read). After the
// role drops write (Role.Update [read,write]→[read], tier editor→viewer) and the
// binding is revoked, the residual MUST be empty: the revoke deletes the
// persisted emitted-set (editor), not the re-derived viewer. Pre-fix, the editor
// tuple was orphaned.
func TestFGAOrphan_178_GranularPermissionRemoved_NoResidual(t *testing.T) {
	const (
		subjectID = "usr_sub_178c"
		ownerID   = "usr_owner_178c"
		accountID = "acc_178c"
	)
	resourceID := accountID // account-scoped custom role bound on its own account
	repo := newABFakeRepo(ownerID, accountID, resourceID, roleID178c, "granular",
		domain.Permissions{"iam.role.read", "iam.role.write"})
	repo.setRoleCustom(accountID)
	opsRepo := newFakeOpsRepo()
	fga := newRecordingFGA()
	ownerCtx := newOwnerContext(ownerID)

	createUC := NewCreateAccessBindingUseCase(repo, opsRepo).WithRelationStore(fga, nil)
	opCreate, err := createUC.Execute(ownerCtx, domain.AccessBinding{
		SubjectType:  "user",
		SubjectID:    domain.SubjectID(subjectID),
		RoleID:       domain.RoleID(roleID178c),
		ResourceType: "account",
		ResourceID:   resourceID,
	})
	require.NoError(t, err)
	awaitOpDone(t, opsRepo, opCreate.ID)
	written := repo.drainFGAWritten()
	require.GreaterOrEqual(t, len(written), 2, "editor role-relation tuple + hierarchy")
	editorTuple := ab_repo.RelationTuple{
		User: "user:" + subjectID, Relation: "editor", Object: "account:" + resourceID,
	}
	require.Contains(t, written, editorTuple, "grant emitted the editor role-relation tuple")

	// Role drops the write permission (tier editor→viewer).
	repo.setRolePermissions(domain.Permissions{"iam.role.read"})

	abID := repo.lastInsertedID()
	deleteUC := NewDeleteAccessBindingUseCase(repo, opsRepo).WithRelationStore(fga, nil)
	opDelete, err := deleteUC.Execute(newOwnerContext(subjectID), abID)
	require.NoError(t, err)
	awaitOpDone(t, opsRepo, opDelete.ID)
	deleted := repo.drainFGADeleted()

	residual := netTuples(written, deleted)
	assert.Empty(t, residual,
		"revoke after granular permission removal must leave ZERO residual tuples; residual=%v", residual)
}
