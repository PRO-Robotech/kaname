// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// delete_sync_removal_retry_test.go — устойчивость синхронного revoke к
// транзиентному сбою OpenFGA.
//
// Контракт (паритет надежности revoke ≈ grant): grant материализует FGA-tuples
// надежно (reconciler sync-write). Revoke обязан быть ему симметричен — одиночный
// best-effort DeleteTuples под нагрузкой мог транзиентно упасть, и тогда deny ждал
// отставший async fga_outbox drain (revoke-deny convergence > bounded poll на
// нагруженном CI). Revoke-worker РЕТРАИТ синхронное удаление на транзиентной ошибке,
// поэтому deny наблюдается к моменту Operation done.
//
// До фикса doDelete звал DeleteTuples ОДИН раз: первая ошибка → удаляемый набор не
// применен синхронно (RED — flakyDeleteFGA.deleted пуст).

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// flakyDeleteFGA — RelationStore, чей DeleteTuples падает первые failN вызовов
// транзиентной ошибкой, затем успешно записывает удаляемый набор. Моделирует
// транзиентный сбой OpenFGA-write под нагрузкой. Check/WriteTuples — no-op (sync
// grant-write в этой обвязке идет не через этот клиент).
type flakyDeleteFGA struct {
	mu       sync.Mutex
	failN    int
	attempts int
	deleted  []clients.RelationTuple
}

func (f *flakyDeleteFGA) Check(context.Context, string, string, string) (bool, error) {
	return true, nil
}

func (f *flakyDeleteFGA) WriteTuples(context.Context, []clients.RelationTuple) error { return nil }

func (f *flakyDeleteFGA) DeleteTuples(_ context.Context, tuples []clients.RelationTuple) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts++
	if f.attempts <= f.failN {
		return errors.New("openfga delete: status 503: transient")
	}
	f.deleted = append(f.deleted, tuples...)
	return nil
}

func (f *flakyDeleteFGA) drainDeleted() []clients.RelationTuple {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]clients.RelationTuple, len(f.deleted))
	copy(out, f.deleted)
	return out
}

func (f *flakyDeleteFGA) attemptCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attempts
}

var _ clients.RelationStore = (*flakyDeleteFGA)(nil)

// TestDeleteAccessBinding_SyncTupleRemoval_RetriesTransientFGAFailure — revoke-worker
// ретраит синхронное удаление tuples мимо двух транзиентных сбоев OpenFGA и доводит
// удаляемый набор до OpenFGA к моменту Operation done. Зеркало надежности grant'а:
// deny не откладывается на отставший async fga_outbox drain.
func TestDeleteAccessBinding_SyncTupleRemoval_RetriesTransientFGAFailure(t *testing.T) {
	const (
		roleID     = "rol_viewer_retry_001"
		roleName   = "kacho.view"
		subjectID  = "usr_retry_subject"
		resourceID = "prj_retry_project"
		ownerID    = "usr_retry_owner"
		accountID  = "acc_retry_account"
	)

	perms := domain.Permissions{"iam.access_bindings.get", "iam.access_bindings.list"}
	repo := newABFakeRepo(ownerID, accountID, resourceID, roleID, roleName, perms)
	opsRepo := newFakeOpsRepo()
	ctx := newOwnerContext(ownerID)

	// ── Grant ────────────────────────────────────────────────────────────────
	createUC := NewCreateAccessBindingUseCase(repo, opsRepo).WithRelationStore(newRecordingFGA(), nil)
	_, err := createUC.Execute(ctx, domain.AccessBinding{
		SubjectType:  "user",
		SubjectID:    domain.SubjectID(subjectID),
		RoleID:       domain.RoleID(roleID),
		ResourceType: "project",
		ResourceID:   resourceID,
	})
	require.NoError(t, err, "Create.Execute must succeed")

	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx), "async Create worker must complete")

	written := repo.drainFGAWritten()
	require.GreaterOrEqual(t, len(written), 2,
		"Create must emit ≥2 fga_outbox tuples (role-relation + hierarchy)")
	abID := repo.lastInsertedID()
	require.NotEmpty(t, abID)

	// ── Revoke with a transiently-failing FGA ─────────────────────────────────
	flaky := &flakyDeleteFGA{failN: 2}
	deleteUC := NewDeleteAccessBindingUseCase(repo, opsRepo).WithRelationStore(flaky, nil)
	_, err = deleteUC.Execute(newOwnerContext(subjectID), abID)
	require.NoError(t, err, "Delete.Execute must succeed")

	waitCtx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()
	require.NoError(t, operations.Wait(waitCtx2), "async Delete worker must complete")

	// CORE: revoke worker RETRIED past the two transient failures and applied the
	// removal synchronously (RED before the fix: single best-effort call → deleted empty).
	syncDeleted := flaky.drainDeleted()
	require.NotEmpty(t, syncDeleted,
		"revoke worker must RETRY the synchronous FGA tuple-removal past a transient failure, "+
			"so the deny is observable at Operation-done instead of waiting on the lagging async drain")
	require.GreaterOrEqual(t, flaky.attemptCount(), 3,
		"revoke worker must retry the sync removal (≥3 attempts: 2 transient failures + 1 success)")
	for _, w := range written {
		assert.Contains(t, syncDeleted, clients.RelationTuple{User: w.User, Relation: w.Relation, Object: w.Object},
			"sync revoke (after retry) must remove tuple {User:%q Relation:%q Object:%q} granted at Create",
			w.User, w.Relation, w.Object)
	}
}
