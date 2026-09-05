// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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

	clusterapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/cluster"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"

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

	subjectState := kachopg.NewSubjectStateReader(pool)

	// Allowing ReBAC checker: these integration tests exercise the SQL CAS /
	// outbox path (the principal is the caller seeded per-test). The
	// defense-in-depth system_admin gate has its own unit tests in
	// admin_authz_test.go; here it is satisfied so the DB behaviour is reached.
	adminChecker := &fakeAdminChecker{allow: true}

	// durable audit_outbox emitter, atomic in the grant/revoke tx.
	auditEmitter := kachopg.NewAuditOutboxEmitter(pool)

	getUC := clusterapp.NewGetClusterUseCase(clusterReader)
	grantUC := clusterapp.NewGrantAdminUseCase(grantWriter, grantReader, fgaEmitter, txb, opsRepo).
		WithSubjectStateReader(subjectState).
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

	// ONE active grant in the whole table: the migration-seeded bootstrap-SA
	// grant is decommissioned first, because the last-admin guard counts EVERY
	// active grant — with the seed intact, `admin` is not the last one and the
	// revoke legitimately succeeds (pinned by the repo-level
	// TestRevoke_LastUserAdmin_BootstrapSAKeepsClusterAdministrable).
	admin := mustSeedUser(t, ctx, pool, "admin")
	caller := mustSeedUser(t, ctx, pool, "caller") // separate caller to avoid self-revoke
	decommissionBootstrapSeedGrant(t, ctx, pool)
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
	seedSubject := bootstrapSeedSubject(t, ctx, pool)

	h := buildHandler(t, dsn)

	resp, err := h.ListAdmins(ctx, &iamv1.ListClusterAdminsRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp)

	bySubject := map[string]*iamv1.ClusterAdminEntry{}
	for _, e := range resp.GetAdmins() {
		bySubject[e.GetSubjectId()] = e
	}
	require.NotContains(t, bySubject, string(revoked),
		"only active admins must be returned")

	// The response is the whole active-admin population: the two user admins
	// seeded here plus the bootstrap ServiceAccount granted cluster
	// system_admin by migration 0058. Assert both halves exactly.
	require.Len(t, resp.GetAdmins(), 3, "two seeded user admins + the bootstrap-SA grant")
	require.Contains(t, bySubject, string(a1))
	require.Contains(t, bySubject, string(a2))
	require.Contains(t, bySubject, seedSubject, "bootstrap-SA grant must be listed")

	for _, id := range []string{string(a1), string(a2)} {
		e := bySubject[id]
		require.Equal(t, iamv1.ClusterGrantSubjectType_USER, e.GetSubjectType())
		require.NotEmpty(t, e.GetSubjectEmail(), "subject_email must be populated")
	}

	// The ServiceAccount grant must be reported AS a service account: the entry
	// carries the stored subject_type, never a hard-coded USER. Mis-typing it
	// would tell an operator that `sva…` is a human user.
	sa := bySubject[seedSubject]
	require.Equal(t, iamv1.ClusterGrantSubjectType_SERVICE_ACCOUNT, sa.GetSubjectType(),
		"service_account grant must not be reported as USER")
	require.Empty(t, sa.GetSubjectEmail(),
		"a ServiceAccount has no users-row to denormalise an email from")
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

// ── machine-subject grants: visible AND revocable ───────────────────────────

// TestCluster_6_20_RevokeAdmin_BootstrapServiceAccountGrant — the permanent
// cluster-admin grant migration 0058 seeds for the bootstrap-admin
// ServiceAccount must be revocable through the RPC.
//
// This is the observable proof for the whole machine-subject fix: it does not
// construct the grant, it revokes the one the PLATFORM issues. Before the fix
// the use-case answered InvalidArgument ("only 'user' supported") and, even had
// it not, every write statement was pinned to `subject_type='user'` and would
// have matched no row — granted authority that could not be taken back.
func TestCluster_6_20_RevokeAdmin_BootstrapServiceAccountGrant(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	// The migration-seeded machine admin, and a human admin so the last-admin
	// guard (count > 1) is satisfied and cannot mask the result.
	sva := bootstrapSeedSubject(t, ctx, pool)
	caller := mustSeedUser(t, ctx, pool, "revoker")
	seedClusterAdmin(t, ctx, pool, caller)

	h := buildHandler(t, dsn)
	pctx := withPrincipal(ctx, string(caller))

	// Precondition: the machine grant is VISIBLE on the admin list.
	before, err := h.ListAdmins(pctx, &iamv1.ListClusterAdminsRequest{})
	require.NoError(t, err)
	require.True(t, containsAdminSubject(before.GetAdmins(), sva),
		"the seeded bootstrap-SA grant must be visible before revoke")

	// Revoke it.
	op, err := h.RevokeAdmin(pctx, &iamv1.RevokeClusterAdminRequest{
		SubjectType: iamv1.ClusterGrantSubjectType_SERVICE_ACCOUNT,
		SubjectId:   sva,
	})
	require.NoError(t, err,
		"the machine cluster-admin grant the platform seeds must be revocable")
	require.True(t, op.GetDone())

	// The row is actually revoked (not merely reported as such).
	var active int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.cluster_admin_grants
		  WHERE subject_id = $1 AND granted_until IS NULL`, sva).Scan(&active))
	require.Zero(t, active, "the seeded machine grant must no longer be active")

	// It disappears from the admin list.
	after, err := h.ListAdmins(pctx, &iamv1.ListClusterAdminsRequest{})
	require.NoError(t, err)
	require.False(t, containsAdminSubject(after.GetAdmins(), sva),
		"a revoked machine grant must not be listed as an active cluster admin")

	// And the relation removal names the MACHINE subject — a `user:<sva…>`
	// delete would remove a tuple that never existed, leaving the relation
	// backend still granting cluster-admin while the DB says revoked.
	var tuples int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox
		  WHERE event_type = 'fga.tuple.delete'
		    AND payload->>'user'     = $1
		    AND payload->>'relation' = 'system_admin'
		    AND payload->>'object'   = $2`,
		"service_account:"+sva, "cluster:"+domain.ClusterSingletonID).Scan(&tuples))
	require.Equal(t, 1, tuples,
		"exactly one system_admin tuple removal must be queued for the machine subject")
}

// TestCluster_6_21_RevokeAdmin_HumanPathUnaffected — regression: widening the
// accepted subject type must not disturb the human path. A user grant is still
// revoked, and still removes a `user:<id>` tuple.
func TestCluster_6_21_RevokeAdmin_HumanPathUnaffected(t *testing.T) {
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
	seedClusterAdmin(t, ctx, pool, caller)
	seedClusterAdmin(t, ctx, pool, target)

	h := buildHandler(t, dsn)
	pctx := withPrincipal(ctx, string(caller))

	op, err := h.RevokeAdmin(pctx, &iamv1.RevokeClusterAdminRequest{
		SubjectType: iamv1.ClusterGrantSubjectType_USER,
		SubjectId:   string(target),
	})
	require.NoError(t, err)
	require.True(t, op.GetDone())

	var active int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.cluster_admin_grants
		  WHERE subject_id = $1 AND granted_until IS NULL`, string(target)).Scan(&active))
	require.Zero(t, active)

	var tuples int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox
		  WHERE event_type = 'fga.tuple.delete'
		    AND payload->>'user'   = $1
		    AND payload->>'object' = $2`,
		"user:"+string(target), "cluster:"+domain.ClusterSingletonID).Scan(&tuples))
	require.Equal(t, 1, tuples)
}

// TestCluster_6_22_RevokeAdmin_MachineGrant_NotReachableAsUser — the type is
// part of the address, not decoration: asking to revoke the machine subject
// under subject_type=USER must not silently hit the service_account row.
func TestCluster_6_22_RevokeAdmin_MachineGrant_NotReachableAsUser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	sva := bootstrapSeedSubject(t, ctx, pool)
	caller := mustSeedUser(t, ctx, pool, "caller")
	seedClusterAdmin(t, ctx, pool, caller)

	h := buildHandler(t, dsn)
	pctx := withPrincipal(ctx, string(caller))

	_, err = h.RevokeAdmin(pctx, &iamv1.RevokeClusterAdminRequest{
		SubjectType: iamv1.ClusterGrantSubjectType_USER,
		SubjectId:   sva,
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err),
		"an sva… id under subject_type=USER is malformed, not a shortcut to the machine row")

	var active int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.cluster_admin_grants
		  WHERE subject_id = $1 AND granted_until IS NULL`, sva).Scan(&active))
	require.Equal(t, 1, active, "the machine grant must be untouched by the rejected call")
}

// containsAdminSubject reports whether the listed admins include subjectID.
func containsAdminSubject(admins []*iamv1.ClusterAdminEntry, subjectID string) bool {
	for _, a := range admins {
		if a.GetSubjectId() == subjectID {
			return true
		}
	}
	return false
}

// TestCluster_6_23_GrantAdmin_ServiceAccountSubject — the grant direction for a
// machine subject, including the per-type existence guard.
//
// Grant and Revoke must accept the same subject types: an asymmetric pair
// (grantable but not revocable, or the reverse) is how an unrevocable grant is
// manufactured in the first place. This drives the SERVICE_ACCOUNT branch of the
// existence guard (kacho_iam.service_accounts, not kacho_iam.users — subject_id
// is polymorphic and no FK can cover it).
func TestCluster_6_23_GrantAdmin_ServiceAccountSubject(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	sva := bootstrapSeedSubject(t, ctx, pool)
	caller := mustSeedUser(t, ctx, pool, "granter")
	seedClusterAdmin(t, ctx, pool, caller)

	h := buildHandler(t, dsn)
	pctx := withPrincipal(ctx, string(caller))

	// Revoke the seeded machine grant, then grant it back — the reactivate path
	// for a machine subject, which the subject_type-pinned writer could not reach.
	_, err = h.RevokeAdmin(pctx, &iamv1.RevokeClusterAdminRequest{
		SubjectType: iamv1.ClusterGrantSubjectType_SERVICE_ACCOUNT,
		SubjectId:   sva,
	})
	require.NoError(t, err)

	op, err := h.GrantAdmin(pctx, &iamv1.GrantClusterAdminRequest{
		SubjectType: iamv1.ClusterGrantSubjectType_SERVICE_ACCOUNT,
		SubjectId:   sva,
	})
	require.NoError(t, err, "a machine subject must be re-grantable after revoke")
	require.True(t, op.GetDone())

	var active int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.cluster_admin_grants
		  WHERE subject_id = $1 AND subject_type = 'service_account'
		    AND granted_until IS NULL`, sva).Scan(&active))
	require.Equal(t, 1, active, "the machine grant must be active again")

	// The write-tuple must name the machine subject (mirror of the revoke case).
	var tuples int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox
		  WHERE event_type = 'fga.tuple.write'
		    AND payload->>'user'   = $1
		    AND payload->>'object' = $2`,
		"service_account:"+sva, "cluster:"+domain.ClusterSingletonID).Scan(&tuples))
	require.GreaterOrEqual(t, tuples, 2,
		"granting a machine subject must queue a service_account: tuple. TWO, not one: "+
			"the bootstrap seed already writes exactly this row for this very subject "+
			"(migration 0058), so a floor of one is satisfied by the seed alone and the "+
			"assertion would hold even if the emitter always wrote user:")
}

// TestCluster_6_24_GrantAdmin_UnknownServiceAccount_Rejected — the existence
// guard must read the SERVICE_ACCOUNTS table for a machine subject. Checking
// kacho_iam.users for an `sva…` id would never match, turning a well-formed
// request into a confusing failure; skipping the check entirely would let a
// cluster-admin grant be written for a subject that does not exist.
func TestCluster_6_24_GrantAdmin_UnknownServiceAccount_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	caller := mustSeedUser(t, ctx, pool, "granter")
	seedClusterAdmin(t, ctx, pool, caller)

	h := buildHandler(t, dsn)
	pctx := withPrincipal(ctx, string(caller))

	const absentSA = "sva0000000000000000z"
	_, err = h.GrantAdmin(pctx, &iamv1.GrantClusterAdminRequest{
		SubjectType: iamv1.ClusterGrantSubjectType_SERVICE_ACCOUNT,
		SubjectId:   absentSA,
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err),
		"a cluster-admin grant must not be written for a ServiceAccount that does not exist")
	require.Contains(t, status.Convert(err).Message(), "ServiceAccount",
		"the message must name the subject type actually looked up")

	var rows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.cluster_admin_grants WHERE subject_id = $1`,
		absentSA).Scan(&rows))
	require.Zero(t, rows, "no grant row may exist for a rejected subject")
}
