// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// access_binding_role_assignable_integration_test.go — a binding cannot carry a role
// that is not assignable on its scope, whichever writer inserts it.
//
// The rule had exactly one enforcement point: the AccessBinding create path. It is
// not the only writer of the table — the invitation flow builds a binding from a
// caller-supplied role and inserts it directly — so the invariant was, in effect,
// optional. What that costs the role's owner is the role's LIFECYCLE, not access: the
// role reference is ON DELETE RESTRICT, so a binding created elsewhere pins the role
// for ever, while the listing that would explain why filters that row out because it
// sits in a scope the owner holds no authority over.
//
// These assertions run against the DATABASE, deliberately: a check that lives in one
// caller is a convention, and the next writer inherits nothing from it.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// seedAccountRole — INSERT an account-scoped custom role directly.
func seedAccountRole(t *testing.T, ctx context.Context, pool *pgxpool.Pool, acc domain.AccountID, name string) domain.RoleID {
	t.Helper()
	rid := domain.RoleID(ids.NewID(domain.PrefixRole))
	_, err := pool.Exec(ctx, `
		INSERT INTO roles (id, account_id, name, description, permissions)
		VALUES ($1, $2, $3, $4, '["iam.users.*.read"]'::jsonb)`,
		string(rid), string(acc), name, "account role "+name)
	require.NoError(t, err, "seed account-scoped role")
	return rid
}

// insertBinding writes a binding the way a writer that skipped the service gate
// would: a plain INSERT of the columns, nothing else.
func insertBinding(ctx context.Context, pool *pgxpool.Pool, role domain.RoleID, subject domain.UserID, resourceType, resourceID string) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO access_bindings
		    (id, subject_type, subject_id, role_id, resource_type, resource_id, created_at, status)
		VALUES ($1, 'user', $2, $3, $4, $5, $6, 'ACTIVE')`,
		ids.NewID(domain.PrefixAccessBinding), string(subject), string(role),
		resourceType, resourceID, time.Now().UTC())
	return err
}

// A custom role defined by ANOTHER account cannot be bound, however the row is
// written. This is the case the single service-level gate did not cover.
func TestAccessBinding_ForeignAccountRole_IsRefusedByTheDatabase(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	ownerA := mustSeedUser(t, ctx, pool, "assign-a")
	ownerB := mustSeedUser(t, ctx, pool, "assign-b")
	accA := seedAccount(t, ctx, repo, "acc-assign-a", ownerA)
	accB := seedAccount(t, ctx, repo, "acc-assign-b", ownerB)
	roleOfB := seedAccountRole(t, ctx, pool, accB.ID, "b_only_role")
	projectOfA := seedProject(t, ctx, repo, accA.ID, "prj-assign-a")

	err = insertBinding(ctx, pool, roleOfB, ownerA, "account", string(accA.ID))
	require.Error(t, err, "a role of another account must not be bindable on this account")
	require.Contains(t, strings.ToLower(err.Error()), "not assignable")

	err = insertBinding(ctx, pool, roleOfB, ownerA, "project", string(projectOfA.ID))
	require.Error(t, err, "a role of another account must not be bindable on this account's project either")

	// Control, so the refusal is about the ACCOUNT BOUNDARY and not about custom
	// roles generally: the same role on its OWN account is accepted.
	require.NoError(t, insertBinding(ctx, pool, roleOfB, ownerB, "account", string(accB.ID)),
		"a role must remain bindable inside the account that defined it")
}

// The legitimate shapes must all still pass — a boundary check that refuses valid
// bindings would be found by an outage, not by a test.
func TestAccessBinding_AssignableRoles_AreAccepted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "assign-ok")
	acc := seedAccount(t, ctx, repo, "acc-assign-ok", owner)
	prj := seedProject(t, ctx, repo, acc.ID, "prj-assign-ok")

	accountRole := seedAccountRole(t, ctx, pool, acc.ID, "own_account_role")
	projectRole := seedProjectRole(t, ctx, pool, prj.ID, "own_project_role")

	require.NoError(t, insertBinding(ctx, pool, accountRole, owner, "account", string(acc.ID)),
		"account role on its own account")
	// The single hierarchy-down case: an account-tier role on a project nested in it.
	require.NoError(t, insertBinding(ctx, pool, accountRole, owner, "project", string(prj.ID)),
		"account role on a project of its own account")
	require.NoError(t, insertBinding(ctx, pool, projectRole, owner, "project", string(prj.ID)),
		"project role on its own project")

	// A system role is assignable anywhere, including on the cluster.
	var systemRole string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT id FROM roles WHERE is_system = true LIMIT 1`).Scan(&systemRole))
	require.NoError(t, insertBinding(ctx, pool, domain.RoleID(systemRole), owner, "account", string(acc.ID)),
		"system role on an account")
	require.NoError(t, insertBinding(ctx, pool, domain.RoleID(systemRole), owner, "cluster", "cluster_root"),
		"system role on the cluster")
}

// No custom role is assignable on the cluster — the scope that grants everything.
func TestAccessBinding_CustomRoleOnCluster_IsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "assign-cl")
	acc := seedAccount(t, ctx, repo, "acc-assign-cl", owner)
	role := seedAccountRole(t, ctx, pool, acc.ID, "cluster_attempt_role")

	err = insertBinding(ctx, pool, role, owner, "cluster", "cluster_root")
	require.Error(t, err, "a custom role must not be bindable on the cluster scope")
}
