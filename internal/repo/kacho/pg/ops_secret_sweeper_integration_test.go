// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ops_secret_sweeper_integration_test.go — the one-shot credential is cleaned even
// when nothing in this process is left to clean it.
//
// The credential is staged in the operation response ON PURPOSE: the client polls
// the operation to collect it, and it is handed over exactly once. Removing it
// afterwards was the job of a goroutine detached from the request — and a detached
// goroutine is what a rollout, an eviction or an OOM kill ends. The pod that comes
// back has no memory of the pending clean-up; the operation is done=true, so the
// orphan reconciler's claim (done = false) cannot see it by construction; and
// nothing in the tree ages operations out. Every branch that logs "key material may
// remain" runs inside the goroutine that no longer exists, so nothing says a word.
//
// So the clean-up needs a backstop that survives a restart, and the backstop has to
// say out loud when it fires: one that quietly does the work of a broken fast path
// is indistinguishable from one that has never had to.
package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
)

// stageIssuedKey persists a done operation whose response carries a plaintext
// private key, and back-dates it so the sweeper's settle window has elapsed.
func stageIssuedKey(t *testing.T, ctx context.Context, pool *pgxpool.Pool, opsRepo operations.Repo, opID, pem string, age time.Duration) {
	t.Helper()
	require.NoError(t, opsRepo.Create(ctx, operations.Operation{
		ID:          opID,
		Description: "Issue SA key for sva_test",
		CreatedAt:   time.Now().UTC().Truncate(time.Second),
		ModifiedAt:  time.Now().UTC().Truncate(time.Second),
		Principal:   operations.SystemPrincipal(),
	}))
	respAny, err := anypb.New(&iamv1.IssueSAKeyResponse{
		Key: &iamv1.ServiceAccountOAuthClient{
			Id:            "soc_sweeper_test01",
			SvaId:         "sva_test",
			HydraClientId: "hydra_client_sweeper",
			CreatedAt:     timestamppb.Now(),
		},
		ClientId:      "hydra_client_sweeper",
		PrivateKeyPem: pem,
	})
	require.NoError(t, err)
	require.NoError(t, opsRepo.MarkDone(ctx, opID, respAny))

	if age > 0 {
		_, err := pool.Exec(ctx,
			`UPDATE kacho_iam.operations SET modified_at = now() - $2::interval WHERE id = $1`,
			opID, age.String())
		require.NoError(t, err)
	}
}

func readPEM(t *testing.T, ctx context.Context, opsRepo operations.Repo, opID string) string {
	t.Helper()
	op, err := opsRepo.Get(ctx, opID)
	require.NoError(t, err)
	require.NotNil(t, op)
	require.NotNil(t, op.Response)
	out := &iamv1.IssueSAKeyResponse{}
	require.NoError(t, op.Response.UnmarshalTo(out))
	return out.PrivateKeyPem
}

func saKeySweepTargets(t *testing.T) []kachopg.SecretSweepTarget {
	t.Helper()
	a, err := anypb.New(&iamv1.IssueSAKeyResponse{})
	require.NoError(t, err)
	return []kachopg.SecretSweepTarget{{
		ResponseType: a.TypeUrl,
		Fields:       []string{"private_key_pem", "client_secret"},
	}}
}

// The strand: the process ended before the fast path ran. The backstop clears the
// key and REPORTS that it had to — that report is the only evidence anyone gets
// that the fast path did not run.
func TestSweepStrandedSecrets_ClearsWhatTheDetachedCleanupNeverGotTo(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupRedactorPG(t))
	require.NoError(t, err)
	defer pool.Close()
	opsRepo := operations.NewRepo(pool, "kacho_iam")

	const secret = "-----BEGIN PRIVATE KEY-----stranded-----END PRIVATE KEY-----"
	stageIssuedKey(t, ctx, pool, opsRepo, "iop_sweep_stranded", secret, 10*time.Minute)
	require.Equal(t, secret, readPEM(t, ctx, opsRepo, "iop_sweep_stranded"),
		"baseline: the credential is staged in the response, as the hand-over requires")

	sw := kachopg.NewOpsResponseRedactor(pool, "kacho_iam")
	spec := kachopg.SecretSweepSpec{
		Targets: saKeySweepTargets(t), Settled: time.Minute, Window: 24 * time.Hour, Limit: 100,
	}
	res, err := sw.SweepStrandedSecrets(ctx, spec)
	require.NoError(t, err)
	assert.Equal(t, 1, res.Redacted, "the backstop must report the stranded credential it cleared")
	assert.Empty(t, readPEM(t, ctx, opsRepo, "iop_sweep_stranded"), "the credential must be gone from the response")

	// Second pass: nothing left to do, and the report says so. A backstop that keeps
	// reporting work is how a permanently broken fast path becomes visible.
	res2, err := sw.SweepStrandedSecrets(ctx, spec)
	require.NoError(t, err)
	assert.Equal(t, 0, res2.Redacted, "an already-clean response must not be counted as a strand")
}

// The other direction: inside the settle window the credential is UNTOUCHED. The
// client is still polling for it, and a backstop that raced the fast path would
// hand out an empty string for a key that was issued once and cannot be reissued.
func TestSweepStrandedSecrets_LeavesTheGraceWindowAlone(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupRedactorPG(t))
	require.NoError(t, err)
	defer pool.Close()
	opsRepo := operations.NewRepo(pool, "kacho_iam")

	const secret = "-----BEGIN PRIVATE KEY-----fresh-----END PRIVATE KEY-----"
	stageIssuedKey(t, ctx, pool, opsRepo, "iop_sweep_fresh", secret, 0)

	sw := kachopg.NewOpsResponseRedactor(pool, "kacho_iam")
	res, err := sw.SweepStrandedSecrets(ctx, kachopg.SecretSweepSpec{
		Targets: saKeySweepTargets(t), Settled: 10 * time.Minute, Window: 24 * time.Hour, Limit: 100,
	})
	require.NoError(t, err)
	assert.Equal(t, 0, res.Redacted, "a response inside the grace window must not be swept")
	assert.Equal(t, secret, readPEM(t, ctx, opsRepo, "iop_sweep_fresh"),
		"the client must still be able to collect the key it is polling for")
}

// Only credential-bearing response types are read at all: scanning the rest would
// make the cost of the backstop the size of the operations table, for rows that
// never held a secret.
func TestSweepStrandedSecrets_ReadsOnlyCredentialBearingResponses(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupRedactorPG(t))
	require.NoError(t, err)
	defer pool.Close()
	opsRepo := operations.NewRepo(pool, "kacho_iam")

	stageIssuedKey(t, ctx, pool, opsRepo, "iop_sweep_typed",
		"-----BEGIN PRIVATE KEY-----x-----END PRIVATE KEY-----", 10*time.Minute)

	// A done operation of an unrelated type, also outside the settle window.
	require.NoError(t, opsRepo.Create(ctx, operations.Operation{
		ID: "iop_sweep_other", Description: "unrelated",
		CreatedAt: time.Now().UTC(), ModifiedAt: time.Now().UTC(), Principal: operations.SystemPrincipal(),
	}))
	other, err := anypb.New(&iamv1.Account{Id: "acc_sweep_other"})
	require.NoError(t, err)
	require.NoError(t, opsRepo.MarkDone(ctx, "iop_sweep_other", other))
	_, err = pool.Exec(ctx,
		`UPDATE kacho_iam.operations SET modified_at = now() - interval '10 minutes' WHERE id = $1`,
		"iop_sweep_other")
	require.NoError(t, err)

	sw := kachopg.NewOpsResponseRedactor(pool, "kacho_iam")
	res, err := sw.SweepStrandedSecrets(ctx, kachopg.SecretSweepSpec{
		Targets: saKeySweepTargets(t), Settled: time.Minute, Window: 24 * time.Hour, Limit: 100,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Scanned, "only the credential-bearing response type may be read")
}
