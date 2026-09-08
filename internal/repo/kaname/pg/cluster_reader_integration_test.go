// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// cluster_reader_integration_test.go — integration test for
// ClusterReader.Get (singleton `cluster_root` seeded by migration).
//
// Get happy path (sync read, no Operation envelope).

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// TestGet_Singleton — `cluster_root` row seeded by migration 0001
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

	r := kanamepg.NewClusterReader(pool)
	c, err := r.Get(ctx)
	require.NoError(t, err)

	require.Equal(t, domain.ClusterID(domain.ClusterSingletonID), c.ID)
	require.Equal(t, domain.ClusterName("kacho-root"), c.Name)
	require.NotEmpty(t, c.Description)
	require.False(t, c.CreatedAt.IsZero())
}
