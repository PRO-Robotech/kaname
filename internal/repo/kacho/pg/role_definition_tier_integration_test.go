// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// role_definition_tier_integration_test.go — redesign-2026 F4 (IAM-1-10/11) DB side.
//
// Migration 0056 renames the exactly-one-anchor XOR CHECK roles_scope_xor →
// roles_definition_tier_xor and makes is_system a GENERATED derivation of the tier
// (cluster_id present ⇔ system role) rather than a stored bool. Asserts:
//   - roles_definition_tier_xor exists; roles_scope_xor is gone (rename landed).
//   - is_system is a STORED generated column (pg_attribute.attgenerated='s').
//   - the production repo Insert (which no longer writes is_system) round-trips a
//     custom account-scoped role with is_system=false and the derived tier.
//   - an explicit INSERT of is_system is rejected (generated columns are not
//     directly insertable) — the derivation cannot be forged.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

func TestRole_IAM_1_10_DefinitionTierXorRenamedAndIsSystemGenerated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	// (1) roles_definition_tier_xor exists; roles_scope_xor is gone.
	var newExists, oldExists bool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM pg_constraint WHERE conname = 'roles_definition_tier_xor')`).Scan(&newExists))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM pg_constraint WHERE conname = 'roles_scope_xor')`).Scan(&oldExists))
	assert.True(t, newExists, "roles_definition_tier_xor CHECK must exist after 0056")
	assert.False(t, oldExists, "roles_scope_xor CHECK must be renamed away by 0056")

	// (2) is_system is a STORED generated column.
	var attgenerated string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT attgenerated FROM pg_attribute
		   WHERE attrelid = 'kacho_iam.roles'::regclass AND attname = 'is_system'`).Scan(&attgenerated))
	assert.Equal(t, "s", attgenerated, "is_system must be a STORED generated column (derived from the tier)")

	// (3) Production Insert round-trips a custom account-scoped role — is_system
	// evaluates to false (cluster_id NULL) and the derived definition tier reads back.
	repo := kachopg.New(pool, nil)
	owner := mustSeedUser(t, ctx, pool, "f4dt")
	acc := seedAccount(t, ctx, repo, "acc-f4dt", owner)

	r := domain.Role{
		ID:          domain.RoleID(ids.NewID(domain.PrefixRole)),
		AccountID:   acc.ID,
		Name:        domain.RoleName("app_deployer_f4"),
		Description: domain.Description("account-scoped custom role"),
		Rules:       domain.Rules{{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"}}},
		IsSystem:    true, // intentionally wrong — the generated column ignores it.
	}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	inserted, err := w.RolesW().Insert(ctx, r)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	assert.False(t, inserted.IsSystem, "is_system generated from cluster_id (NULL ⇒ false)")
	assert.False(t, inserted.IsSystemDerived())
	assert.Equal(t, domain.ScopeTypeAccountDotted, inserted.DefinitionTierType())
	assert.Equal(t, string(acc.ID), inserted.DefinitionTierID())

	// (4) An explicit INSERT into the generated is_system column is rejected.
	_, err = pool.Exec(ctx,
		`INSERT INTO kacho_iam.roles (id, account_id, name, description, permissions, rules, is_system, created_at, labels)
		 VALUES ($1, $2, $3, '', '[]'::jsonb, '[]'::jsonb, true, now(), '{}'::jsonb)`,
		ids.NewID(domain.PrefixRole), string(acc.ID), "forge_is_system_f4")
	require.Error(t, err, "cannot insert a non-DEFAULT value into the generated is_system column")
}
