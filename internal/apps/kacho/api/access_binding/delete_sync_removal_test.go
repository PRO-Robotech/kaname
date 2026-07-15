// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// delete_sync_removal_test.go — синхронное удаление FGA-tuples на Delete.
//
// Контракт (паритет латентности revoke ≈ grant): после того как Operation
// Delete'а сообщает done, revoke-набор (persisted emitted-set) уже удален из
// OpenFGA СИНХРОННО через RelationStore.DeleteTuples — зеркало post-commit
// FGA-материализации grant'а. Async EmitRelationDelete + drainer остаются
// at-least-once backstop, но deny не должен ждать outbox-drain.
//
// До фикса doDelete только заэнкьюивал EmitRelationDelete (async drain) и НЕ
// звал DeleteTuples — поэтому recordingFGA.deleted оставался пуст (RED).

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// TestDeleteAccessBinding_SyncTupleRemoval_RemovesGrantedTuplesAtOpDone — после
// Delete-Operation done revoke-набор удален из OpenFGA синхронно (sync DeleteTuples),
// а не только заэнкьюен в async fga_outbox. Зеркало grant'а, который материализует
// tuples сразу после commit. Проверяет: (1) sync-удаленный набор непуст;
// (2) он содержит КАЖДЫЙ tuple, эмитнутый grant'ом; (3) async backstop тоже эмитнут.
func TestDeleteAccessBinding_SyncTupleRemoval_RemovesGrantedTuplesAtOpDone(t *testing.T) {
	const (
		roleID     = "rol_viewer_sync_001"
		roleName   = "kacho.view"
		subjectID  = "usr_sync_subject"
		resourceID = "prj_sync_project"
		ownerID    = "usr_sync_owner"
		accountID  = "acc_sync_account"
	)

	perms := domain.Permissions{"iam.access_bindings.get", "iam.access_bindings.list"}
	repo := newABFakeRepo(ownerID, accountID, resourceID, roleID, roleName, perms)
	opsRepo := newFakeOpsRepo()
	fga := newRecordingFGA()
	ctx := newOwnerContext(ownerID)

	// ── Grant ───────────────────────────────────────────────────────────────
	createUC := NewCreateAccessBindingUseCase(repo, opsRepo).WithRelationStore(fga, nil)
	binding := domain.AccessBinding{
		SubjectType:  "user",
		SubjectID:    domain.SubjectID(subjectID),
		RoleID:       domain.RoleID(roleID),
		ResourceType: "project",
		ResourceID:   resourceID,
	}
	_, err := createUC.Execute(ctx, binding)
	require.NoError(t, err, "Create.Execute must succeed")

	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx), "async Create worker must complete")

	written := repo.drainFGAWritten()
	require.GreaterOrEqual(t, len(written), 2,
		"Create must emit ≥2 fga_outbox tuples (role-relation + hierarchy)")
	// Sanity: grant НЕ зовет sync FGA через relations в unit-обвязке (reconciler не
	// подключен) — sync-write идет через reconciler.applyAfterCommit, не через relations.
	require.Empty(t, fga.drainWritten(),
		"Create must not call relations.WriteTuples in this wiring (reconciler unwired)")

	abID := repo.lastInsertedID()
	require.NotEmpty(t, abID)

	// ── Revoke ──────────────────────────────────────────────────────────────
	deleteUC := NewDeleteAccessBindingUseCase(repo, opsRepo).WithRelationStore(fga, nil)
	_, err = deleteUC.Execute(newOwnerContext(subjectID), abID)
	require.NoError(t, err, "Delete.Execute must succeed")

	waitCtx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	require.NoError(t, operations.Wait(waitCtx2), "async Delete worker must complete")

	// CORE: sync removal — после op-done revoke-набор УЖЕ удален из OpenFGA
	// синхронно (RED до фикса: doDelete не звал DeleteTuples).
	syncDeleted := fga.drainDeleted()
	require.NotEmpty(t, syncDeleted,
		"Delete must SYNCHRONOUSLY remove the granted tuples from OpenFGA "+
			"(relations.DeleteTuples), so the deny is observable at Operation-done — "+
			"not only enqueued for the async fga_outbox drain")

	for _, w := range written {
		assert.Contains(t, syncDeleted, clients.RelationTuple{User: w.User, Relation: w.Relation, Object: w.Object},
			"sync revoke must remove tuple {User:%q Relation:%q Object:%q} granted at Create",
			w.User, w.Relation, w.Object)
	}
	require.Equal(t, len(written), len(syncDeleted),
		"sync revoke set must be byte-symmetric to the granted set")

	// Backstop preserved: async fga_outbox revoke is still enqueued in the writer-tx.
	asyncDeleted := repo.drainFGADeleted()
	require.Equal(t, len(written), len(asyncDeleted),
		"async EmitRelationDelete backstop must still enqueue the same revoke set")
}
