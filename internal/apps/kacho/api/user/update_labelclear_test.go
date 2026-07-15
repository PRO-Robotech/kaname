// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package user

// update_labelclear_test.go — очистка labels через update_mask=["labels"] с
// пустым телом. proto3-map не несет presence: пустой `labels:{}` и отсутствующий
// labels неотличимы (оба nil), поэтому единственный сигнал «очистить» — labels в
// update_mask. Без фикса очистка была silent no-op (label-scoped грант нельзя было
// отозвать снятием метки).

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

func TestUpdateUser_LabelClearViaMask(t *testing.T) {
	repo := newUpdUserRepo()
	repo.user.Labels = domain.Labels{"team": "sec"} // у пользователя есть метки

	uc := NewUpdateUserUseCase(repo, newUpdOpsRepo())
	op, err := uc.Execute(ownerCtx(), UpdateUserInput{
		ID:         domain.UserID(updUserID),
		Labels:     nil, // пустое тело labels (proto3-map ⇒ nil)
		UpdateMask: []string{"labels"},
	})
	require.NoError(t, err)
	require.NotNil(t, op)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(ctx))

	assert.Empty(t, repo.labelsSnapshot(),
		"update_mask=labels + пустое тело очищает labels (был silent no-op)")
	assert.Empty(t, repo.user.Labels, "запись пользователя без меток после очистки")
}
