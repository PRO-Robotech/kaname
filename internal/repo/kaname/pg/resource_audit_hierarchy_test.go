// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/stretchr/testify/require"
)

func TestResourceCleanupAuditDoesNotRequireCurrentParentGraph(t *testing.T) {
	c := parentCaptureFixture(t)
	parentCaptureObject(t, c, "item", "item-a", "project-a", domain.WritePolicy{})
	parentCaptureProject(t, c, "project-a", "account-a")
	// Новая policy не объявляет прежний pointer. Аудит снятия сохраняет записанную
	// область, хотя новая регистрация через этот же контейнер неполна.
	h, found, err := c.auditHierarchy(context.Background(), "item:item-a")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, domain.ParentHierarchy{Links: []string{"item:item-a", "project:project-a", "account:account-a"}, ProjectID: "project-a", AccountID: "account-a"}, h)
	_, _, err = c.hierarchies(context.Background(), "item:item-a")
	require.ErrorIs(t, err, domain.ErrParentHierarchyIncomplete)
}
