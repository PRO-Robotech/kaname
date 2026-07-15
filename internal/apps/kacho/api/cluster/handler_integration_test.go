// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package cluster_test

// handler_integration_test.go — integration tests for the
// InternalClusterService handler.
//
// Handler-level scenarios:
//
//	Get singleton cluster.
//	GrantAdmin happy-path (fresh INSERT → Operation returned).
//	GrantAdmin idempotent (second call → same grant id in metadata).
//	GrantAdmin reactivate (Grant→Revoke→Grant → active again).
//	GrantAdmin unknown subject_type → InvalidArgument.
//	GrantAdmin subject_id missing → InvalidArgument.
//	GrantAdmin subject_id bad format → InvalidArgument.
//	RevokeAdmin self-revoke → FailedPrecondition.
//	RevokeAdmin last-admin → FailedPrecondition.
//	RevokeAdmin never-admin → NotFound.
//	RevokeAdmin already-revoked → NotFound.
//	RevokeAdmin happy-path → Operation returned.
//	ListAdmins → list of active admins with denormalised user fields.
//	GrantAdmin user-not-in-DB → InvalidArgument.
//
// All tests use testcontainers-go Postgres + real migrations.
// Principal injection is done via operations.WithPrincipal context helper.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"

	clusterapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/cluster"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
)

// ── test helpers ────────────────────────────────────────────────────────────

// buildHandler wires the full handler stack against a real pool.
func buildHandler(t *testing.T, dsn string) *clusterapp.Handler {
	t.Helper()
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	opsRepo := operations.NewRepo(pool, "kacho_iam")

	clusterReader := kachopg.NewClusterReader(pool)
	grantWriter := kachopg.NewClusterAdminGrantWriter(pool)
	grantReader := kachopg.NewClusterAdminGrantReader(pool)
	fgaEmitter := kachopg.NewFGAOutboxEmitter()
	txb := kachopg.NewPoolTxBeginner(pool)

	userChecker := kachopg.NewUserExistenceChecker(pool)

	// Allowing ReBAC checker: these integration tests exercise the SQL CAS /
	// outbox path (the principal is the caller seeded per-test). The
	// defense-in-depth system_admin gate has its own unit tests in
	// admin_authz_test.go; here it is satisfied so the DB behaviour is reached.
	adminChecker := &fakeAdminChecker{allow: true}

	// durable audit_outbox emitter, atomic in the grant/revoke tx.
	auditEmitter := kachopg.NewAuditOutboxEmitter(pool)

	getUC := clusterapp.NewGetClusterUseCase(clusterReader)
	grantUC := clusterapp.NewGrantAdminUseCase(grantWriter, grantReader, fgaEmitter, txb, opsRepo).
		WithUserChecker(userChecker).
		WithAdminChecker(adminChecker).
		WithAuditEmitter(auditEmitter)
	revokeUC := clusterapp.NewRevokeAdminUseCase(grantWriter, fgaEmitter, txb, opsRepo).
		WithAdminChecker(adminChecker).
		WithAuditEmitter(auditEmitter)
	listUC := clusterapp.NewListAdminsUseCase(grantReader)

	return clusterapp.NewHandler(getUC, grantUC, revokeUC, listUC)
}

// withPrincipal injects a principal into ctx so operations.PrincipalFromContext
// returns a known user identity.
func withPrincipal(ctx context.Context, userID string) context.Context {
	return operations.WithPrincipal(ctx, operations.Principal{Type: "user", ID: userID})
}

// extractGrantMeta — unpacks GrantClusterAdminMetadata from an Operation.
func extractGrantMeta(t *testing.T, op *operationpb.Operation) *iamv1.GrantClusterAdminMetadata {
	t.Helper()
	require.NotNil(t, op.GetMetadata())
	meta := &iamv1.GrantClusterAdminMetadata{}
	require.NoError(t, op.GetMetadata().UnmarshalTo(meta))
	return meta
}

// ── Get ────────────────────────────────────────────────────────────────

func TestCluster_6_00_GetSingleton(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	h := buildHandler(t, dsn)

	resp, err := h.Get(ctx, &iamv1.GetClusterRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, domain.ClusterSingletonID, resp.GetId())
}

// ── GrantAdmin happy-path ──────────────────────────────────────────────

func TestCluster_6_01_GrantAdmin_HappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	caller := mustSeedUser(t, ctx, pool, "caller")
	target := mustSeedUser(t, ctx, pool, "target")

	h := buildHandler(t, dsn)
	pctx := withPrincipal(ctx, string(caller))

	op, err := h.GrantAdmin(pctx, &iamv1.GrantClusterAdminRequest{
		SubjectType: iamv1.ClusterGrantSubjectType_USER,
		SubjectId:   string(target),
	})
	require.NoError(t, err)
	require.NotNil(t, op)
	require.NotEmpty(t, op.GetId())
}

// ── GrantAdmin idempotent ──────────────────────────────────────────────

func TestCluster_6_02_GrantAdmin_Idempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	caller := mustSeedUser(t, ctx, pool, "caller")
	target := mustSeedUser(t, ctx, pool, "target")

	h := buildHandler(t, dsn)
	pctx := withPrincipal(ctx, string(caller))

	req := &iamv1.GrantClusterAdminRequest{
		SubjectType: iamv1.ClusterGrantSubjectType_USER,
		SubjectId:   string(target),
	}

	op1, err := h.GrantAdmin(pctx, req)
	require.NoError(t, err)

	op2, err := h.GrantAdmin(pctx, req)
	require.NoError(t, err)

	meta1 := extractGrantMeta(t, op1)
	meta2 := extractGrantMeta(t, op2)
	require.Equal(t, meta1.GetClusterAdminGrantId(), meta2.GetClusterAdminGrantId(),
		"idempotent grant must produce same ClusterAdminGrant id in metadata")
}

// ── GrantAdmin reactivate (grant→revoke→grant) ────────────────────────

func TestCluster_6_03_GrantAdmin_Reactivate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	caller := mustSeedUser(t, ctx, pool, "caller")
	target := mustSeedUser(t, ctx, pool, "target")
	// second admin so last-admin guard doesn't fire during Revoke
	other := mustSeedUser(t, ctx, pool, "other")
	seedClusterAdmin(t, ctx, pool, other)

	h := buildHandler(t, dsn)
	pctx := withPrincipal(ctx, string(caller))

	// Grant
	_, err = h.GrantAdmin(pctx, &iamv1.GrantClusterAdminRequest{
		SubjectType: iamv1.ClusterGrantSubjectType_USER,
		SubjectId:   string(target),
	})
	require.NoError(t, err)

	// Revoke
	_, err = h.RevokeAdmin(pctx, &iamv1.RevokeClusterAdminRequest{
		SubjectType: iamv1.ClusterGrantSubjectType_USER,
		SubjectId:   string(target),
	})
	require.NoError(t, err)

	// Grant again — must reactivate
	op, err := h.GrantAdmin(pctx, &iamv1.GrantClusterAdminRequest{
		SubjectType: iamv1.ClusterGrantSubjectType_USER,
		SubjectId:   string(target),
	})
	require.NoError(t, err)
	require.NotNil(t, op)

	// After reactivation target should appear in ListAdmins
	listResp, err := h.ListAdmins(ctx, &iamv1.ListClusterAdminsRequest{})
	require.NoError(t, err)
	found := false
	for _, e := range listResp.GetAdmins() {
		if e.GetSubjectId() == string(target) {
			found = true
		}
	}
	require.True(t, found, "reactivated admin must appear in ListAdmins")
}

// ── GrantAdmin unknown subject_type ────────────────────────────────────

func TestCluster_6_04_GrantAdmin_BadSubjectType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	h := buildHandler(t, dsn)

	// authz is enforced FIRST (defense-in-depth — see GrantAdminUseCase.Execute):
	// a negative subject-validation case must still pass the system_admin gate
	// (authorized principal + fakeAdminChecker.allow) to reach the InvalidArgument
	// branch, otherwise it short-circuits at PermissionDenied.
	_, err := h.GrantAdmin(withPrincipal(ctx, "usr0000000000000000a"), &iamv1.GrantClusterAdminRequest{
		SubjectType: iamv1.ClusterGrantSubjectType_CLUSTER_GRANT_SUBJECT_TYPE_UNSPECIFIED,
		SubjectId:   "usr_00000000000000000",
	})
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument, status.Code(err),
		"unspecified subject_type must return InvalidArgument")
}

// ── GrantAdmin subject_id missing ──────────────────────────────────────

func TestCluster_6_05_GrantAdmin_MissingSubjectID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	h := buildHandler(t, dsn)

	// authz is enforced FIRST (defense-in-depth — see GrantAdminUseCase.Execute):
	// a negative subject-validation case must still pass the system_admin gate
	// (authorized principal + fakeAdminChecker.allow) to reach the InvalidArgument
	// branch, otherwise it short-circuits at PermissionDenied.
	_, err := h.GrantAdmin(withPrincipal(ctx, "usr0000000000000000a"), &iamv1.GrantClusterAdminRequest{
		SubjectType: iamv1.ClusterGrantSubjectType_USER,
		SubjectId:   "",
	})
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument, status.Code(err),
		"empty subject_id must return InvalidArgument")
}

// ── GrantAdmin bad subject_id format ───────────────────────────────────

func TestCluster_6_06_GrantAdmin_BadSubjectIDFormat(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	h := buildHandler(t, dsn)

	// authz is enforced FIRST (defense-in-depth — see GrantAdminUseCase.Execute):
	// a negative subject-validation case must still pass the system_admin gate
	// (authorized principal + fakeAdminChecker.allow) to reach the InvalidArgument
	// branch, otherwise it short-circuits at PermissionDenied.
	_, err := h.GrantAdmin(withPrincipal(ctx, "usr0000000000000000a"), &iamv1.GrantClusterAdminRequest{
		SubjectType: iamv1.ClusterGrantSubjectType_USER,
		SubjectId:   "not-a-valid-user-id",
	})
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument, status.Code(err),
		"malformed subject_id must return InvalidArgument")
}

// ── RevokeAdmin self-revoke ────────────────────────────────────────────

func TestCluster_6_07_RevokeAdmin_SelfRevoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	// Two admins — last-admin guard won't fire.
	self := mustSeedUser(t, ctx, pool, "self")
	other := mustSeedUser(t, ctx, pool, "other")
	seedClusterAdmin(t, ctx, pool, self)
	seedClusterAdmin(t, ctx, pool, other)

	h := buildHandler(t, dsn)
	pctx := withPrincipal(ctx, string(self))

	_, err = h.RevokeAdmin(pctx, &iamv1.RevokeClusterAdminRequest{
		SubjectType: iamv1.ClusterGrantSubjectType_USER,
		SubjectId:   string(self),
	})
	require.Error(t, err)
	require.Equal(t, codes.FailedPrecondition, status.Code(err),
		"self-revoke must return FailedPrecondition")
	require.Contains(t, status.Convert(err).Message(),
		"cannot revoke own cluster admin grant")
}

// ── RevokeAdmin last-admin ────────────────────────────────────────────

func TestCluster_6_08a_RevokeAdmin_LastAdmin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	// ONE admin only.
	admin := mustSeedUser(t, ctx, pool, "admin")
	caller := mustSeedUser(t, ctx, pool, "caller") // separate caller to avoid self-revoke
	seedClusterAdmin(t, ctx, pool, admin)

	h := buildHandler(t, dsn)
	pctx := withPrincipal(ctx, string(caller))

	_, err = h.RevokeAdmin(pctx, &iamv1.RevokeClusterAdminRequest{
		SubjectType: iamv1.ClusterGrantSubjectType_USER,
		SubjectId:   string(admin),
	})
	require.Error(t, err)
	require.Equal(t, codes.FailedPrecondition, status.Code(err),
		"last-admin revoke must return FailedPrecondition")
	require.Contains(t, status.Convert(err).Message(),
		"cannot revoke last active cluster admin")
}

// ── RevokeAdmin never-admin ────────────────────────────────────────────

func TestCluster_6_09_RevokeAdmin_NeverAdmin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	admin := mustSeedUser(t, ctx, pool, "admin")
	admin2 := mustSeedUser(t, ctx, pool, "admin2")
	seedClusterAdmin(t, ctx, pool, admin)
	seedClusterAdmin(t, ctx, pool, admin2) // so count > 1
	never := mustSeedUser(t, ctx, pool, "never")

	h := buildHandler(t, dsn)
	pctx := withPrincipal(ctx, string(admin))

	_, err = h.RevokeAdmin(pctx, &iamv1.RevokeClusterAdminRequest{
		SubjectType: iamv1.ClusterGrantSubjectType_USER,
		SubjectId:   string(never),
	})
	require.Error(t, err)
	require.Equal(t, codes.NotFound, status.Code(err),
		"revoke never-admin must return NotFound")
}

// ── RevokeAdmin already-revoked ──────────────────────────────────────

func TestCluster_6_09b_RevokeAdmin_AlreadyRevoked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	admin := mustSeedUser(t, ctx, pool, "admin")
	admin2 := mustSeedUser(t, ctx, pool, "admin2")
	seedClusterAdmin(t, ctx, pool, admin)
	seedClusterAdmin(t, ctx, pool, admin2)
	revoked := mustSeedUser(t, ctx, pool, "revoked")
	seedRevokedClusterAdmin(t, ctx, pool, revoked)

	h := buildHandler(t, dsn)
	pctx := withPrincipal(ctx, string(admin))

	_, err = h.RevokeAdmin(pctx, &iamv1.RevokeClusterAdminRequest{
		SubjectType: iamv1.ClusterGrantSubjectType_USER,
		SubjectId:   string(revoked),
	})
	require.Error(t, err)
	require.Equal(t, codes.NotFound, status.Code(err),
		"revoke already-revoked must return NotFound (D-12)")
}

// ── RevokeAdmin happy-path ─────────────────────────────────────────────

func TestCluster_6_10_RevokeAdmin_HappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	caller := mustSeedUser(t, ctx, pool, "caller")
	target := mustSeedUser(t, ctx, pool, "target")
	other := mustSeedUser(t, ctx, pool, "other")
	seedClusterAdmin(t, ctx, pool, target)
	seedClusterAdmin(t, ctx, pool, other) // ensure count > 1

	h := buildHandler(t, dsn)
	pctx := withPrincipal(ctx, string(caller))

	op, err := h.RevokeAdmin(pctx, &iamv1.RevokeClusterAdminRequest{
		SubjectType: iamv1.ClusterGrantSubjectType_USER,
		SubjectId:   string(target),
	})
	require.NoError(t, err)
	require.NotNil(t, op)
	require.NotEmpty(t, op.GetId())
}

// ── ListAdmins ─────────────────────────────────────────────────────────

func TestCluster_6_11_ListAdmins(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	a1 := mustSeedUser(t, ctx, pool, "a1")
	a2 := mustSeedUser(t, ctx, pool, "a2")
	revoked := mustSeedUser(t, ctx, pool, "rv")
	seedClusterAdmin(t, ctx, pool, a1)
	seedClusterAdmin(t, ctx, pool, a2)
	seedRevokedClusterAdmin(t, ctx, pool, revoked)

	h := buildHandler(t, dsn)

	resp, err := h.ListAdmins(ctx, &iamv1.ListClusterAdminsRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Len(t, resp.GetAdmins(), 2, "only active admins must be returned")

	subjectIDs := map[string]bool{}
	for _, e := range resp.GetAdmins() {
		subjectIDs[e.GetSubjectId()] = true
		require.NotEmpty(t, e.GetSubjectEmail(), "subject_email must be populated")
	}
	require.True(t, subjectIDs[string(a1)])
	require.True(t, subjectIDs[string(a2)])
	require.False(t, subjectIDs[string(revoked)])
}

// ── GrantAdmin user not in DB ──────────────────────────────────────

func TestCluster_6_12_GrantAdmin_UserNotInDB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	caller := mustSeedUser(t, ctx, pool, "caller")
	h := buildHandler(t, dsn)
	pctx := withPrincipal(ctx, string(caller))

	// Valid format but not seeded — user does not exist in users table.
	ghost := "usr_aaaaaaaaaaaaaaaaa"
	_, err = h.GrantAdmin(pctx, &iamv1.GrantClusterAdminRequest{
		SubjectType: iamv1.ClusterGrantSubjectType_USER,
		SubjectId:   ghost,
	})
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument, status.Code(err),
		"subject not in users table must return InvalidArgument (D-9)")
}

// anypb is used via extractGrantMeta; keep the import alive.
var _ = (*anypb.Any)(nil)
