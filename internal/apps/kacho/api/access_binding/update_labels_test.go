// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// update_labels_test.go — unit-тесты UpdateAccessBindingUseCase для own-resource
// labels (T3.3 unify IAM label-scope, chunk 2 / T3.3-IMM-01).
//
// AB mutable-набор расширен до {deletion_protection, labels}. Любой ИНОЙ путь
// mask (role_id / subject / scope / resource_*) → sync INVALID_ARGUMENT (immutable
// набор НЕ ослаблен — добавлен только labels). Изменение labels co-commit'ит
// reconcile-event "iam.accessBinding" в writer-tx (D-6 catalog-видимость).
//
// Реальный round-trip + iam-direct материализация — в integration
// (pg/access_binding_labels_integration_test.go).

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// T3.3-IMM-01 happy: Update(update_mask=["labels"]) sets labels and co-commits a
// reconcile event on iam.accessBinding.
func TestAccessBinding_Update_T33IMM01_LabelsMutable(t *testing.T) {
	const ownerID, accountID, roleID = "usr_acct_owner", "acc_t33_lbl", "rol_viewer_test_001"
	repo := newABFakeRepo(ownerID, accountID, "", roleID, "kacho.view", nil)
	id := seedAccountBinding(repo, accountID, roleID, false)

	uc := NewUpdateAccessBindingUseCase(repo, newFakeOpsRepo()).WithRelationStore(newRecordingFGA(), nil)
	op, err := uc.Execute(newOwnerContext(ownerID), id,
		[]string{"labels"}, false, domain.Labels{"stage": "prod"})
	require.NoError(t, err)
	require.NotNil(t, op)
	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx))

	repo.mu.Lock()
	gotLabels := repo.ab.Labels
	repo.mu.Unlock()
	assert.Equal(t, domain.Labels{"stage": "prod"}, gotLabels, "labels applied via UpdateLabels")
	assert.Contains(t, repo.drainReconcileObjects(), string(id),
		"labels change co-commits a reconcile-event on iam.accessBinding")
}

// T3.3-IMM-01 negative: role_id in update_mask → sync INVALID_ARGUMENT (immutable
// set NOT weakened — only labels was added).
func TestAccessBinding_Update_T33IMM01_RoleIDImmutable(t *testing.T) {
	const ownerID, accountID, roleID = "usr_acct_owner", "acc_t33_imm", "rol_viewer_test_001"
	repo := newABFakeRepo(ownerID, accountID, "", roleID, "kacho.view", nil)
	id := seedAccountBinding(repo, accountID, roleID, true)

	uc := NewUpdateAccessBindingUseCase(repo, newFakeOpsRepo()).WithRelationStore(newRecordingFGA(), nil)
	op, err := uc.Execute(newOwnerContext(ownerID), id,
		[]string{"role_id"}, false, nil)
	require.Error(t, err)
	assert.Nil(t, op)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code(),
		"role_id in update_mask → INVALID_ARGUMENT (immutable)")
}

// deletion_protection remains mutable alongside labels (set not weakened).
func TestAccessBinding_Update_T33IMM01_DeletionProtectionStillMutable(t *testing.T) {
	const ownerID, accountID, roleID = "usr_acct_owner", "acc_t33_dp", "rol_viewer_test_001"
	repo := newABFakeRepo(ownerID, accountID, "", roleID, "kacho.view", nil)
	id := seedAccountBinding(repo, accountID, roleID, true)

	uc := NewUpdateAccessBindingUseCase(repo, newFakeOpsRepo()).WithRelationStore(newRecordingFGA(), nil)
	op, err := uc.Execute(newOwnerContext(ownerID), id,
		[]string{"deletion_protection"}, false, nil)
	require.NoError(t, err)
	require.NotNil(t, op)
	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx))

	repo.mu.Lock()
	got := repo.ab.DeletionProtection
	repo.mu.Unlock()
	assert.False(t, got, "deletion_protection cleared (still mutable alongside labels)")
}
