// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// operations_account_id_integration_test.go — integration test (testcontainers
// PG16) for the account_id denormalization that backs
// AccountService.ListAllOperations and InternalOperationsService.ListIamOperations.
//
// Proves the IAM-side of the corelib account_id change end-to-end against the
// real kacho_iam.operations schema (migration 0016 adds the account_id column +
// partial index):
//   - category-(I) metadata carrying account_id (Project/Group/SA/Account/
//     AddGroupMember/User-Delete/account-scoped AccessBinding) → corelib
//     extractAccountID denormalizes into the account_id column → List(AccountID)
//     returns the account-scoped set and isolates other accounts.
//   - resource_id denormalization is NOT broken by the additive account_id field
//     — per-resource List(ResourceID) still returns the same op.
//   - category-(II) metadata WITHOUT account_id (Role / SAKey / Condition /
//     project-scoped AccessBinding) → account_id IS NULL → excluded from the
//     account-scoped list, still visible per-resource and cluster-wide
//     (no AccountID filter → returns everything).
//   - back-compat: a non-IAM op with no account_id metadata writes
//     account_id IS NULL and does not leak into any account-scoped list.
//
// Skip under testing.Short() (Docker required).

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"google.golang.org/protobuf/proto"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// opMeta builds an IAM operation carrying the given metadata message.
func opMeta(t *testing.T, desc string, meta proto.Message, createdAt time.Time) operations.Operation {
	t.Helper()
	op, err := operations.New(domain.PrefixOperationIAM, desc, meta)
	require.NoError(t, err)
	op.CreatedAt = createdAt
	op.ModifiedAt = createdAt
	return op
}

func TestOperationsAccountID_DenormalizationAndIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	opsRepo := operations.NewRepo(pool, "kacho_iam")

	accX := ids.NewID(domain.PrefixAccount)
	accOther := ids.NewID(domain.PrefixAccount)
	prjY := ids.NewID(domain.PrefixProject)
	svaZ := ids.NewID(domain.PrefixServiceAccount)
	grpG := ids.NewID(domain.PrefixGroup)
	base := time.Now().UTC().Truncate(time.Microsecond)

	mk := func(op operations.Operation) {
		require.NoError(t, opsRepo.Create(ctx, op))
	}

	// category-(I): account_id stamped → in accX scope.
	mk(opMeta(t, "create account", &iamv1.CreateAccountMetadata{AccountId: accX}, base))
	mk(opMeta(t, "create project", &iamv1.CreateProjectMetadata{ProjectId: prjY, AccountId: accX}, base.Add(time.Second)))
	mk(opMeta(t, "create sa", &iamv1.CreateServiceAccountMetadata{ServiceAccountId: svaZ, AccountId: accX}, base.Add(2*time.Second)))
	mk(opMeta(t, "add group member", &iamv1.AddGroupMemberMetadata{GroupId: grpG, MemberId: "usr0000000000000mmmm", AccountId: accX}, base.Add(3*time.Second)))
	// other account — isolation.
	mk(opMeta(t, "create project other", &iamv1.CreateProjectMetadata{ProjectId: ids.NewID(domain.PrefixProject), AccountId: accOther}, base.Add(4*time.Second)))

	// account-scoped list of accX includes only its 4 ops, none of accOther.
	gotX, _, err := opsRepo.List(ctx, operations.ListFilter{AccountID: accX, PageSize: 100})
	require.NoError(t, err)
	assert.Len(t, gotX, 4, "accX list must aggregate its 4 category-I ops (1.2-11)")

	gotOther, _, err := opsRepo.List(ctx, operations.ListFilter{AccountID: accOther, PageSize: 100})
	require.NoError(t, err)
	assert.Len(t, gotOther, 1, "accOther isolated to its own op (account_id column isolation)")

	// per-resource resource_id filter still works (additive account_id did not
	// break the first-_id resource_id denormalization).
	gotPrj, _, err := opsRepo.List(ctx, operations.ListFilter{ResourceID: prjY})
	require.NoError(t, err)
	assert.Len(t, gotPrj, 1, "project op visible per-resource by resource_id=prj-…")
	gotGrp, _, err := opsRepo.List(ctx, operations.ListFilter{ResourceID: grpG})
	require.NoError(t, err)
	assert.Len(t, gotGrp, 1, "add-member op visible per-resource by resource_id=grp-…")
}

func TestOperationsAccountID_CategoryII_NullExcludedFromAccountList(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	opsRepo := operations.NewRepo(pool, "kacho_iam")

	accX := ids.NewID(domain.PrefixAccount)
	roleR := ids.NewID(domain.PrefixRole)
	svaZ := ids.NewID(domain.PrefixServiceAccount)
	base := time.Now().UTC().Truncate(time.Microsecond)

	// One category-I op (in accX) + category-II ops (account_id NULL).
	require.NoError(t, opsRepo.Create(ctx, opMeta(t, "create account", &iamv1.CreateAccountMetadata{AccountId: accX}, base)))
	require.NoError(t, opsRepo.Create(ctx, opMeta(t, "create role", &iamv1.CreateRoleMetadata{RoleId: roleR}, base.Add(time.Second))))                          // cluster-global, no account_id
	require.NoError(t, opsRepo.Create(ctx, opMeta(t, "issue sa key", &iamv1.IssueSAKeyMetadata{ServiceAccountId: svaZ, KeyId: "k1"}, base.Add(2*time.Second)))) // narrow-scope (II)

	// account-scoped list of accX contains ONLY the category-I account op.
	gotX, _, err := opsRepo.List(ctx, operations.ListFilter{AccountID: accX, PageSize: 100})
	require.NoError(t, err)
	assert.Len(t, gotX, 1, "category-II ops (Role / SAKey, account_id NULL) excluded from account-scoped list (1.2-11f)")

	// cluster-wide (no AccountID filter) returns ALL 3 ops, including the NULL ones.
	all, _, err := opsRepo.List(ctx, operations.ListFilter{PageSize: 100})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(all), 3, "cluster-wide Internal list aggregates category-II + Internal-only ops (1.2-12)")

	// SAKey op still visible per-resource by resource_id=sva-….
	gotSva, _, err := opsRepo.List(ctx, operations.ListFilter{ResourceID: svaZ})
	require.NoError(t, err)
	assert.Len(t, gotSva, 1, "SAKey-Issue op visible per-resource by resource_id=sva-…")
}

func TestOperationsAccountID_Pagination(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	opsRepo := operations.NewRepo(pool, "kacho_iam")
	accX := ids.NewID(domain.PrefixAccount)
	base := time.Now().UTC().Truncate(time.Microsecond)
	const total = 3
	for i := 0; i < total; i++ {
		require.NoError(t, opsRepo.Create(ctx, opMeta(t, "p",
			&iamv1.CreateProjectMetadata{ProjectId: ids.NewID(domain.PrefixProject), AccountId: accX},
			base.Add(time.Duration(i)*time.Second))))
	}
	page1, next, err := opsRepo.List(ctx, operations.ListFilter{AccountID: accX, PageSize: 2})
	require.NoError(t, err)
	assert.Len(t, page1, 2)
	require.NotEmpty(t, next, "cursor next_page_token expected (account_id partial index)")

	page2, next2, err := opsRepo.List(ctx, operations.ListFilter{AccountID: accX, PageSize: 2, PageToken: next})
	require.NoError(t, err)
	assert.Len(t, page2, 1)
	assert.Empty(t, next2)
}
