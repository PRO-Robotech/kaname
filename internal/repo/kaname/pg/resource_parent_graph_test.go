// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/stretchr/testify/require"
)

func TestResourceCapturedHierarchyPreservesIntermediateContainer(t *testing.T) {
	c := parentCaptureFixture(t)
	parentCaptureObject(t, c, "item", "item-a", "project-a", domain.WritePolicy{Pointers: []domain.ParentPointer{{Name: "box", Type: "box"}}})
	parentCaptureObject(t, c, "box", "box-a", "project-a", domain.WritePolicy{Pointers: []domain.ParentPointer{{Name: "project", Type: "project"}}})
	parentCaptureProject(t, c, "project-a", "account-a")
	parentCaptureRows(t, c, resourceSourceKey{kind: resourceSourcePointerFacts, typ: "item", id: "item-a"}, map[string]any{"subject": "box:box-a", "relation": "box"})
	parentCaptureRows(t, c, resourceSourceKey{kind: resourceSourcePointerFacts, typ: "box", id: "box-a"}, map[string]any{"subject": "project:project-a", "relation": "project"})
	policy := domain.WritePolicy{ObjectType: "tag", Pointers: []domain.ParentPointer{{Name: "item", Type: "item"}}}
	claim := domain.ParentClaim{ProjectID: "project-a", AccountID: "account-a", Chain: []string{"item:item-a", "box:box-a", "project:project-a", "account:account-a"}}
	hierarchies, scopes, err := c.derive(context.Background(), "item:item-a", "item", "tag:tag-a", policy, claim)
	require.NoError(t, err)
	require.Equal(t, []domain.ParentHierarchy{{Links: claim.Chain, ProjectID: "project-a", AccountID: "account-a"}}, hierarchies)
	require.Equal(t, []domain.ContainerScope{{Registered: true, ProjectID: "project-a", AccountID: "account-a"}}, scopes)
	// Полный граф читается и проверяется раньше фильтра по присланной цепи.
	parentCaptureRows(t, c, resourceSourceKey{kind: resourceSourcePointerFacts, typ: "box", id: "box-a"})
	_, _, err = c.derive(context.Background(), "item:item-a", "item", "tag:tag-a", policy, domain.ParentClaim{})
	require.ErrorIs(t, err, domain.ErrParentHierarchyIncomplete)
}

func TestResourceCapturedHierarchyDoesNotPromotePointerToMissingCeiling(t *testing.T) {
	c := parentCaptureFixture(t)
	parentCaptureObject(t, c, "item", "item-a", "", domain.WritePolicy{Pointers: []domain.ParentPointer{{Name: "box", Type: "box"}}})
	// Цель pointer намеренно не захвачена: DP14 не разрешает читать её как H.
	parentCaptureRows(t, c, resourceSourceKey{kind: resourceSourcePointerFacts, typ: "item", id: "item-a"}, map[string]any{"subject": "box:box-a", "relation": "box"})
	hierarchies, found, err := c.hierarchies(context.Background(), "item:item-a")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, []domain.ParentHierarchy{{Links: []string{"item:item-a"}}}, hierarchies)
	_, touched := c.catalogs["box"]
	require.False(t, touched)
}
