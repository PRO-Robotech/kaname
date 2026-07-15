// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// resource_mirror_t31_g3_integration_test.go — cross-service
// ARM_LABELS revoke on label change, IAM-side G-3 confirmation test.
//
// G-3 contract: full label removal (labels → {}) on a LIVE resource emits
// RegisterResource (mirror.upsert) with an EMPTY labels-map — NOT
// UnregisterResource. The mirror row must therefore SURVIVE with labels={}
// (not be DELETEd as Unregister would do): the resource still exists in its
// source, so its owner-tuple / containment registration (parent_project_id /
// parent_account_id) stays intact; only the label-selectors stop matching.
// UnregisterResource remains reserved for actual resource Delete.
//
// This test asserts the SQL-side G-3 invariant directly on kacho_iam.resource_mirror
// after a RegisterResource(labels={}) with a newer source_version:
//   - the row is PRESENT (count==1), labels='{}'::jsonb (FULL-REPLACE)
//   - parent_project_id / parent_account_id are PRESERVED
//   - source_version advanced (monotonic upsert applied)
//   - it is an UPSERT, not a DELETE (Unregister would have removed the row).
//
// Expectation (G-6): GREEN against the current iam mirror emitter (upsert is
// FULL-REPLACE, source_version-monotonic). RED here would be an IAM-side finding.
//
// TEST-ONLY (ban #13): no production code is touched.
// Run: `make test` (testcontainers + Docker). Skipped under -short.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/internal_iam"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// readMirrorRowT31 reads the full tenant-facing projection of a mirror row.
// found=false when the row is absent (i.e. it was Unregister-DELETEd).
func readMirrorRowT31(t *testing.T, ctx context.Context, pool *pgxpool.Pool, objType, objID string) (found bool, parentPrj, parentAcc, labelsText string, sourceVersion time.Time) {
	t.Helper()
	err := pool.QueryRow(ctx,
		`SELECT parent_project_id, parent_account_id, labels::text, source_version
		   FROM kacho_iam.resource_mirror WHERE object_type=$1 AND object_id=$2`,
		objType, objID).Scan(&parentPrj, &parentAcc, &labelsText, &sourceVersion)
	if err != nil {
		return false, "", "", "", time.Time{}
	}
	return true, parentPrj, parentAcc, labelsText, sourceVersion
}

// ── T3.1-G3-01: upsert {} on label removal — mirror row stays (NOT Unregister) ─

func TestNetworkRepo_T31G301_UpsertNotUnregister_MirrorRowStays(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()

	uc := internal_iam.NewRegisterResourceUseCase(
		kachopg.NewFGAOutboxEmitter(),
		kachopg.NewResourceMirrorEmitter(),
		kachopg.NewPoolTxBeginner(pool),
	)

	const objType, objID = "vpc.network", "net-g3"
	const prj, acc = "prj-g3", "acc-g3"

	// Given: a network registered with a label (Create-time emit) at v0.
	v0 := time.Now().Add(-time.Minute)
	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId:       "project:" + prj,
		Relation:        "parent",
		Object:          "vpc_network:" + objID,
		Labels:          map[string]string{"network": "treska"},
		ParentProjectId: prj,
		ParentAccountId: acc,
		SourceVersion:   timestamppb.New(v0),
	}))

	found0, prj0, acc0, labels0, srcV0 := readMirrorRowT31(t, ctx, pool, objType, objID)
	require.True(t, found0, "mirror row present after Create-time register")
	require.Equal(t, prj, prj0)
	require.Equal(t, acc, acc0)
	require.JSONEq(t, `{"network":"treska"}`, labels0)

	// When: the label is fully removed → consumer (#113 fix) re-emits
	// RegisterResource (mirror.upsert) with labels={} and a NEWER source_version
	// (G-3: upsert {}, NOT UnregisterResource).
	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId:       "project:" + prj,
		Relation:        "parent",
		Object:          "vpc_network:" + objID,
		Labels:          map[string]string{}, // empty — full removal
		ParentProjectId: prj,
		ParentAccountId: acc,
		SourceVersion:   timestamppb.New(v0.Add(time.Minute)),
	}))

	// Then (G-3): the row is STILL PRESENT (upsert, not Unregister-DELETE) ...
	found1, prj1, acc1, labels1, srcV1 := readMirrorRowT31(t, ctx, pool, objType, objID)
	require.True(t, found1,
		"mirror row MUST survive full label removal (G-3: upsert {}, not UnregisterResource DELETE)")

	// ... with labels FULL-REPLACED to {} ...
	assert.JSONEq(t, `{}`, labels1, "labels fully replaced with {} (selectors stop matching)")

	// ... parent scope PRESERVED (owner-tuple / containment registration alive) ...
	assert.Equal(t, prj, prj1, "parent_project_id preserved (registration not torn down)")
	assert.Equal(t, acc, acc1, "parent_account_id preserved (registration not torn down)")

	// ... and source_version ADVANCED (monotonic upsert applied, not a no-op).
	assert.True(t, srcV1.After(srcV0),
		"source_version advanced (monotonic upsert applied the newer label-removal)")

	// Exactly one row by the (object_type, object_id) PK — no duplicate / split.
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.resource_mirror WHERE object_type=$1 AND object_id=$2`,
		objType, objID).Scan(&n))
	assert.Equal(t, 1, n, "single mirror row (PK upsert, no split)")
}
