// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package cluster_test

// operation_contract_integration_test.go — the Operation envelope of
// GrantAdmin / RevokeAdmin, asserted where a CLIENT can see it.
//
// The contract these tests pin (api-conventions.md «мутации возвращают
// Operation», internal_cluster_service.proto):
//
//	GrantAdmin  → metadata: GrantClusterAdminMetadata,  response: ClusterAdminGrant
//	RevokeAdmin → metadata: RevokeClusterAdminMetadata, response: ClusterAdminGrant
//
// and the client protocol: poll OperationService.Get(id) until done=true.
//
// WHY THESE ARE NOT «op.GetDone() == true» ASSERTIONS
// ---------------------------------------------------
// `op.GetDone()` on the handler's return value reads a field the use-case set
// in memory a line earlier — it is true no matter what reached Postgres. Both
// paths passed that assertion while the row a poller reads said `done=f,
// response_data=NULL`, i.e. while a client following the documented contract
// polled forever. So every assertion here reads either the persisted row or the
// repo a poll goes through, never the in-memory struct alone.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
)

// pollOperationToDone — the client protocol, executed: read the operation the
// way OperationService.Get does, until done=true or the budget runs out.
// Exhausting the budget is the observable form of "the client polls forever".
func pollOperationToDone(t *testing.T, ctx context.Context, repo operations.Repo, id string) *operations.Operation {
	t.Helper()
	const attempts = 10
	for i := 0; i < attempts; i++ {
		got, err := repo.Get(ctx, id)
		require.NoError(t, err, "a returned operation id must be queryable")
		if got.Done {
			return got
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("operation %s never reached done=true in %d polls — "+
		"a client following the documented contract polls forever", id, attempts)
	return nil
}

// activeGrantID — the id of the subject's active cluster_admin_grants row,
// read from the table itself, so the metadata is compared against the ROW and
// not against another copy of whatever the use-case happened to produce.
func activeGrantID(t *testing.T, ctx context.Context, pool *pgxpool.Pool, subjectID string) string {
	t.Helper()
	var id string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT id FROM kacho_iam.cluster_admin_grants
		  WHERE subject_id = $1 AND granted_until IS NULL`, subjectID).Scan(&id))
	return id
}

// revokedGrantID — mirror of activeGrantID for the soft-revoked row.
func revokedGrantID(t *testing.T, ctx context.Context, pool *pgxpool.Pool, subjectID string) string {
	t.Helper()
	var id string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT id FROM kacho_iam.cluster_admin_grants
		  WHERE subject_id = $1 AND granted_until IS NOT NULL`, subjectID).Scan(&id))
	return id
}

// opRow — the three columns a poller's answer is built from.
func opRow(t *testing.T, ctx context.Context, pool *pgxpool.Pool, opID string) (done bool, metadata, response []byte) {
	t.Helper()
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT done, metadata_data, response_data FROM kacho_iam.operations WHERE id = $1`,
		opID).Scan(&done, &metadata, &response))
	return done, metadata, response
}

// ── GrantAdmin ──────────────────────────────────────────────────────────────

func TestClusterGrantAdmin_OperationCarriesGrantIdAndCompletesInDB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)

	caller := mustSeedUser(t, ctx, pool, "caller")
	target := mustSeedUser(t, ctx, pool, "target")

	h := buildHandler(t, dsn)
	pctx := withPrincipal(ctx, string(caller))

	op, err := h.GrantAdmin(pctx, &iamv1.GrantClusterAdminRequest{
		SubjectType: iamv1.ClusterGrantSubjectType_USER,
		SubjectId:   string(target),
	})
	require.NoError(t, err)

	grantID := activeGrantID(t, ctx, pool, string(target))

	// (1) The envelope the caller gets back without polling. The proto declares
	// cluster_admin_grant_id ON THE METADATA — a client correlating the
	// operation with the grant row reads it here.
	meta := extractGrantMeta(t, op)
	require.Equal(t, grantID, meta.GetClusterAdminGrantId(),
		"Operation.metadata must name the cluster_admin_grants row that was written")
	require.Equal(t, string(target), meta.GetSubjectId())

	// (2) The persisted row — done and response, as stored.
	done, metaData, respData := opRow(t, ctx, pool, op.GetId())
	require.True(t, done, "the operations row must be terminal, not merely reported as terminal")
	require.NotEmpty(t, metaData, "metadata must be persisted")
	require.NotEmpty(t, respData, "response must be persisted")

	// (3) The poll path, end to end.
	polled := pollOperationToDone(t, ctx, operations.NewRepo(pool, "kacho_iam"), op.GetId())

	polledMeta := &iamv1.GrantClusterAdminMetadata{}
	require.NotNil(t, polled.Metadata)
	require.NoError(t, polled.Metadata.UnmarshalTo(polledMeta))
	require.Equal(t, grantID, polledMeta.GetClusterAdminGrantId(),
		"the polled operation must carry the grant id the contract promises")
	require.Equal(t, string(target), polledMeta.GetSubjectId())

	polledResp := &iamv1.ClusterAdminGrant{}
	require.NotNil(t, polled.Response, "GrantAdmin declares response: ClusterAdminGrant")
	require.NoError(t, polled.Response.UnmarshalTo(polledResp),
		"the response must be the declared ClusterAdminGrant")
	require.Equal(t, grantID, polledResp.GetId())
	require.Equal(t, string(target), polledResp.GetSubjectId())
	require.Equal(t, iamv1.ClusterGrantSubjectType_USER, polledResp.GetSubjectType())
	require.Equal(t, string(caller), polledResp.GetGrantedByUserId())
}

// The idempotent re-grant must report the id of the row that already exists.
// Comparing the two metadata ids to each other passes when both are empty; the
// comparison is therefore against the row.
func TestClusterGrantAdmin_IdempotentRegrantReportsTheExistingGrantId(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)

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

	grantID := activeGrantID(t, ctx, pool, string(target))
	require.NotEmpty(t, grantID)

	require.Equal(t, grantID, extractGrantMeta(t, op1).GetClusterAdminGrantId(),
		"first grant must report the row it inserted")
	require.Equal(t, grantID, extractGrantMeta(t, op2).GetClusterAdminGrantId(),
		"idempotent re-grant must report the SAME, already-existing row")
}

// ── RevokeAdmin ─────────────────────────────────────────────────────────────

func TestClusterRevokeAdmin_OperationCompletesInDBAndCarriesResponse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)

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

	grantID := revokedGrantID(t, ctx, pool, string(target))

	// (1) The envelope the caller gets back.
	require.NotNil(t, op.GetMetadata())
	meta := &iamv1.RevokeClusterAdminMetadata{}
	require.NoError(t, op.GetMetadata().UnmarshalTo(meta))
	require.Equal(t, grantID, meta.GetClusterAdminGrantId())
	require.Equal(t, string(target), meta.GetSubjectId())

	// (2) The persisted row. This is the defect verbatim: the RPC answered
	// done:true while the row said done=f, response_data=NULL.
	done, metaData, respData := opRow(t, ctx, pool, op.GetId())
	require.True(t, done,
		"RevokeAdmin returned done:true — the row a poller reads must agree")
	require.NotEmpty(t, metaData, "metadata must be persisted")
	require.NotEmpty(t, respData, "response must be persisted")

	// (3) The poll path, end to end.
	polled := pollOperationToDone(t, ctx, operations.NewRepo(pool, "kacho_iam"), op.GetId())

	polledMeta := &iamv1.RevokeClusterAdminMetadata{}
	require.NotNil(t, polled.Metadata)
	require.NoError(t, polled.Metadata.UnmarshalTo(polledMeta))
	require.Equal(t, grantID, polledMeta.GetClusterAdminGrantId())
	require.Equal(t, string(target), polledMeta.GetSubjectId())

	polledResp := &iamv1.ClusterAdminGrant{}
	require.NotNil(t, polled.Response, "RevokeAdmin declares response: ClusterAdminGrant")
	require.NoError(t, polled.Response.UnmarshalTo(polledResp))
	require.Equal(t, grantID, polledResp.GetId())
	require.Equal(t, string(target), polledResp.GetSubjectId())
	require.Equal(t, iamv1.ClusterGrantSubjectType_USER, polledResp.GetSubjectType())
}

// A refused revoke must leave no half-written operation behind: the row is
// terminal with an error, never a `done=false` row nobody will ever finish.
func TestClusterRevokeAdmin_RefusedRevokeLeavesNoUnfinishedOperation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)

	caller := mustSeedUser(t, ctx, pool, "caller")
	target := mustSeedUser(t, ctx, pool, "target")
	seedClusterAdmin(t, ctx, pool, caller)

	h := buildHandler(t, dsn)
	pctx := withPrincipal(ctx, string(caller))

	// target was never an admin → NotFound, surfaced synchronously.
	_, err := h.RevokeAdmin(pctx, &iamv1.RevokeClusterAdminRequest{
		SubjectType: iamv1.ClusterGrantSubjectType_USER,
		SubjectId:   string(target),
	})
	require.Error(t, err)

	var unfinished int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.operations
		  WHERE done = false
		    AND description LIKE 'Revoke cluster admin%'`).Scan(&unfinished))
	require.Zero(t, unfinished,
		"a refused revoke must not leave a never-completing operation row")

	// And the subject really is untouched.
	var rows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.cluster_admin_grants WHERE subject_id = $1`,
		string(target)).Scan(&rows))
	require.Zero(t, rows)
}
