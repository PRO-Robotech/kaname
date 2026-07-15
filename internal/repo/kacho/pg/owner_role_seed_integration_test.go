// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// owner_role_seed_integration_test.go — TDD integration-тест: миграция 0035
// сидит net-new system-роль `owner` (RBAC explicit-model).
//
// owner cluster-scoped system-role, rules `[{*,*,*}, selector all]`.
//   - is_system = true, account_id NULL, cluster_id = cluster_kacho_root.
//   - детерминированный id (`rol||md5('owner')[:17]`), идемпотентно на re-apply.
//   - rules плоско-материализуемы: ScopeSelfVerbs(account) непуст (verb-bearing
//     self), MaterializingSelectors непуст (ARM_ANCHOR forward на содержимое).

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

func TestOwnerRole_P6_Seeded(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (needs Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	role, err := rd.Roles().Get(ctx, domain.OwnerRoleID)
	require.NoError(t, err, "owner system-role must be seeded by migration 0035 (id=%s)", domain.OwnerRoleID)

	assert.True(t, role.IsSystem, "owner is a system role")
	assert.Empty(t, role.AccountID, "system role has NULL account_id")
	assert.Equal(t, "owner", string(role.Name))

	// D-8a flat-materializability: owner (`*.*.*` selector all) must yield a
	// non-empty scope-self verb set on the account itself (verb-bearing self) AND
	// non-empty materializing selectors (forward per-object on content).
	assert.NotEmpty(t, role.Rules.ScopeSelfVerbs("account"),
		"owner rules must grant scope-self verbs on account (verb-bearing self, C-01)")
	assert.NotEmpty(t, role.Rules.MaterializingSelectors(),
		"owner rules must carry ARM_ANCHOR materializing selector (forward content, C-01b)")
}
