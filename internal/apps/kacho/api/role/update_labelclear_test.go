// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package role

// update_labelclear_test.go — очистка labels Role через update_mask=["labels"] с
// пустым телом. Единственный сигнал «очистить» — labels в update_mask (proto3-map
// без presence). Без фикса очистка была silent no-op.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

func TestUpdateRole_LabelClearViaMask(t *testing.T) {
	repo := newRlUpdRepo(domain.Labels{"team": "billing"})
	uc := NewUpdateRoleUseCase(repo, newRlFakeOps())

	_, err := uc.Execute(ownerCtx(), UpdateRoleInput{
		ID:         rlUpdRoleID,
		Labels:     nil, // пустое тело labels (proto3-map ⇒ nil)
		UpdateMask: []string{"labels"},
	})
	require.NoError(t, err)
	waitOps(t)

	assert.Empty(t, repo.labelsSnapshot(),
		"update_mask=labels + пустое тело очищает labels Role (был silent no-op)")
}
