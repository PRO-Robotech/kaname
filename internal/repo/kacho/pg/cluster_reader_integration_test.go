// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// cluster_reader_integration_test.go — integration test for
// ClusterReader.Get (singleton `cluster_kacho_root` seeded by migration).
//
// Get happy path (sync read, no Operation envelope).

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// TestGet_Singleton — `cluster_kacho_root` row seeded by migration 0001
// section 3 (squashed baseline). Reader.Get returns it.
func TestGet_Singleton(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	r := kachopg.NewClusterReader(pool)
	c, err := r.Get(ctx)
	require.NoError(t, err)

	require.Equal(t, domain.ClusterID(domain.ClusterSingletonID), c.ID)
	require.Equal(t, domain.ClusterName("kacho-root"), c.Name)
	require.NotEmpty(t, c.Description)
	require.False(t, c.CreatedAt.IsZero())
}
