// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// update_labelclear_test.go — очистка labels AccessBinding через
// update_mask=["labels"] с пустым телом. Единственный сигнал «очистить» — labels
// в update_mask (proto3-map без presence). Без фикса очистка была silent no-op,
// из-за чего label-selectable грант нельзя было отозвать снятием метки.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

func TestAccessBinding_Update_LabelClearViaMask(t *testing.T) {
	const ownerID, accountID, roleID = "usr_acct_owner", "acc_lblclear", "rol_viewer_test_001"
	repo := newABFakeRepo(ownerID, accountID, "", roleID, "kacho.view", nil)
	id := seedAccountBinding(repo, accountID, roleID, false)
	repo.mu.Lock()
	repo.ab.Labels = domain.Labels{"stage": "prod"} // у binding есть метки
	repo.mu.Unlock()

	uc := NewUpdateAccessBindingUseCase(repo, newFakeOpsRepo()).WithRelationStore(newRecordingFGA(), nil)
	op, err := uc.Execute(newOwnerContext(ownerID), id,
		[]string{"labels"}, false, nil) // пустое тело labels (proto3-map ⇒ nil)
	require.NoError(t, err)
	require.NotNil(t, op)

	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx))

	repo.mu.Lock()
	gotLabels := repo.ab.Labels
	repo.mu.Unlock()
	assert.Empty(t, gotLabels,
		"update_mask=labels + пустое тело очищает labels AccessBinding (был silent no-op)")
	assert.Contains(t, repo.drainReconcileObjects(), string(id),
		"очистка labels co-commit'ит reconcile-event на iam.accessBinding (eager отзыв)")
}
