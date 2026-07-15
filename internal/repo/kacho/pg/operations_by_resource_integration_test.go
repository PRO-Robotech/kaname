// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// operations_by_resource_integration_test.go — integration test for the
// per-resource operation listing that backs RoleService/GroupService/
// ProjectService/ServiceAccountService.ListOperations.
//
// Coverage:
//   - TestOperationsByResource_FilterAndIsolation — operations whose metadata
//     carries a `<resource>_id` are denormalized into the resource_id column
//     (corelib operations.Repo) and List(ListFilter{ResourceID}) returns ONLY
//     that resource's operations (cross-resource isolation).
//   - TestOperationsByResource_Pagination — (created_at, id) cursor pagination
//     with page_size cap; the opaque next_page_token yields the next page.
//
// Backs the bug fix: the four ListOperations handlers were hand-written no-ops
// returning an empty list. The schema (operations.resource_id, denormalized by
// extractResourceID from the Create*Metadata first `_id` field) already supports
// this query — these tests prove it.
//
// Skip under `testing.Short()` (Docker required) — same convention as the other
// integration tests in this package.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

func newOpWithRoleMeta(t *testing.T, roleID string, createdAt time.Time) operations.Operation {
	t.Helper()
	op, err := operations.New(
		domain.PrefixOperationIAM,
		"Create role "+roleID,
		&iamv1.CreateRoleMetadata{RoleId: roleID},
	)
	require.NoError(t, err)
	op.CreatedAt = createdAt
	op.ModifiedAt = createdAt
	return op
}

func TestOperationsByResource_FilterAndIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	opsRepo := operations.NewRepo(pool, "kacho_iam")

	roleA := ids.NewID(domain.PrefixRole)
	roleB := ids.NewID(domain.PrefixRole)

	base := time.Now().UTC().Truncate(time.Microsecond)
	// 2 operations for roleA, 1 for roleB.
	require.NoError(t, opsRepo.Create(ctx, newOpWithRoleMeta(t, roleA, base)))
	require.NoError(t, opsRepo.Create(ctx, newOpWithRoleMeta(t, roleA, base.Add(time.Second))))
	require.NoError(t, opsRepo.Create(ctx, newOpWithRoleMeta(t, roleB, base.Add(2*time.Second))))

	got, next, err := opsRepo.List(ctx, operations.ListFilter{ResourceID: roleA})
	require.NoError(t, err)
	assert.Empty(t, next, "single page expected for 2 ops")
	assert.Len(t, got, 2, "only roleA operations must be returned (isolation)")
	for _, op := range got {
		// Metadata round-trips the role_id; confirm it is roleA, never roleB.
		md := &iamv1.CreateRoleMetadata{}
		require.NoError(t, op.Metadata.UnmarshalTo(md))
		assert.Equal(t, roleA, md.GetRoleId(), "no roleB operation may leak into roleA list")
	}

	// roleB sees exactly its own single operation.
	gotB, _, err := opsRepo.List(ctx, operations.ListFilter{ResourceID: roleB})
	require.NoError(t, err)
	assert.Len(t, gotB, 1)
}

func TestOperationsByResource_Pagination(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	opsRepo := operations.NewRepo(pool, "kacho_iam")

	roleID := ids.NewID(domain.PrefixRole)
	base := time.Now().UTC().Truncate(time.Microsecond)
	const total = 3
	for i := 0; i < total; i++ {
		require.NoError(t, opsRepo.Create(ctx, newOpWithRoleMeta(t, roleID, base.Add(time.Duration(i)*time.Second))))
	}

	// page_size=2 → first page of 2 + non-empty next token.
	page1, next, err := opsRepo.List(ctx, operations.ListFilter{ResourceID: roleID, PageSize: 2})
	require.NoError(t, err)
	assert.Len(t, page1, 2)
	require.NotEmpty(t, next, "next_page_token expected when more rows exist")

	// second page via the opaque token → remaining 1, no further token.
	page2, next2, err := opsRepo.List(ctx, operations.ListFilter{ResourceID: roleID, PageSize: 2, PageToken: next})
	require.NoError(t, err)
	assert.Len(t, page2, 1)
	assert.Empty(t, next2)

	// no overlap between pages.
	seen := map[string]bool{}
	for _, op := range append(page1, page2...) {
		assert.False(t, seen[op.ID], "operation %s appeared twice across pages", op.ID)
		seen[op.ID] = true
	}
	assert.Len(t, seen, total)
}
