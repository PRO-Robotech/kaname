// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// ops_response_redactor_integration_test.go — end-to-end redactor proof.
//
// Full Issue → MarkDone → redact integration test against a real Postgres
// testcontainer. Proves that:
//
//  1. After operations.Repo.MarkDone stores the IssueSAKeyResponse with the
//     plaintext client_secret in response_data BYTEA,
//  2. OpsResponseRedactor.RedactResponseField("client_secret") rewrites
//     response_data so the secret is no longer present, and
//  3. The redacted operation, when read back through operations.Repo.Get,
//     surfaces an IssueSAKeyResponse with ClientSecret == "" (the proto
//     default for cleared fields) — client_id and key remain intact.
//
// Without this redactor (e.g. the older jsonb_set-on-non-existent-column
// attempt), the secret would survive in response_data after MarkDone.
package pg_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// sqlOpen — narrow wrapper around database/sql.Open used by goose migration
// driver. testcontainer DSN already includes search_path so we don't need
// session-level GUCs here.
func sqlOpen(t *testing.T, dsn string) (*sql.DB, error) {
	t.Helper()
	return sql.Open("pgx", dsn)
}

// setupRedactorPG разворачивает Postgres 16 в testcontainer и применяет
// миграции схемы kacho_iam. Возвращает coredb.Pool, готовый под Operations.Repo.
func setupRedactorPG(t *testing.T) string {
	t.Helper()
	ctx := context.Background()

	pgc, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("kacho_iam_test"),
		postgres.WithUsername("iam"),
		postgres.WithPassword("iam"),
		postgres.BasicWaitStrategies(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pgc.Terminate(ctx) })

	dsn, err := pgc.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	dsn += "&search_path=kacho_iam,public&options=-c%20search_path%3Dkacho_iam%2Cpublic"

	// Run migrations via stdlib sql.DB then close it.
	{
		db, err := sqlOpen(t, dsn)
		require.NoError(t, err)
		goose.SetBaseFS(migrations.FS)
		require.NoError(t, goose.SetDialect("postgres"))
		require.NoError(t, goose.Up(db, "."))
		_ = db.Close()
	}
	return dsn
}

// TestKAC164_RedactSAKeyClientSecret_FullFlow — closeout proof.
func TestKAC164_RedactSAKeyClientSecret_FullFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupRedactorPG(t)

	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	opsRepo := operations.NewRepo(pool, "kacho_iam")

	// 1. Persist an un-resolved Operation.
	op := operations.Operation{
		ID:          "iop_kac164_redact_test",
		Description: "Issue SA key for sva_test",
		CreatedAt:   time.Now().UTC().Truncate(time.Second),
		ModifiedAt:  time.Now().UTC().Truncate(time.Second),
		Principal:   operations.SystemPrincipal(),
	}
	require.NoError(t, opsRepo.Create(ctx, op))

	// 2. Build an IssueSAKeyResponse with a plaintext client_secret.
	resp := &iamv1.IssueSAKeyResponse{
		Key: &iamv1.ServiceAccountOAuthClient{
			Id:            "soc_kac164test01",
			SvaId:         "sva_test",
			HydraClientId: "hydra_client_kac164",
			CreatedAt:     timestamppb.Now(),
		},
		ClientId:     "hydra_client_kac164",
		ClientSecret: "topsecret_plaintext_should_be_redacted",
	}
	respAny, err := anypb.New(resp)
	require.NoError(t, err)

	// 3. MarkDone — corelib stores response_type + response_data.
	require.NoError(t, opsRepo.MarkDone(ctx, op.ID, respAny))

	// Sanity: read back BEFORE redact — ClientSecret must still be plaintext.
	got, err := opsRepo.Get(ctx, op.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.True(t, got.Done)
	require.NotNil(t, got.Response)
	{
		out := &iamv1.IssueSAKeyResponse{}
		require.NoError(t, got.Response.UnmarshalTo(out))
		assert.Equal(t, "topsecret_plaintext_should_be_redacted", out.ClientSecret,
			"pre-redact baseline: secret present")
		assert.Equal(t, "hydra_client_kac164", out.ClientId,
			"pre-redact baseline: client_id present")
	}

	// 4. Redact.
	redactor := kachopg.NewOpsResponseRedactor(pool, "kacho_iam")
	require.NoError(t, redactor.RedactResponseField(ctx, op.ID,
		[]string{"client_secret"}))

	// 5. Read back AFTER redact — ClientSecret must be empty; other fields kept.
	got, err = opsRepo.Get(ctx, op.ID)
	require.NoError(t, err)
	require.NotNil(t, got.Response)
	{
		out := &iamv1.IssueSAKeyResponse{}
		require.NoError(t, got.Response.UnmarshalTo(out))
		assert.Empty(t, out.ClientSecret,
			"post-redact: client_secret must be cleared")
		assert.Equal(t, "hydra_client_kac164", out.ClientId,
			"post-redact: client_id must be unchanged")
		require.NotNil(t, out.Key)
		assert.Equal(t, "soc_kac164test01", out.Key.Id,
			"post-redact: key.id must be unchanged")
	}

	// 6. Idempotent re-redact — second call must not error and must not flip
	//    anything else.
	require.NoError(t, redactor.RedactResponseField(ctx, op.ID,
		[]string{"client_secret"}))
	got, err = opsRepo.Get(ctx, op.ID)
	require.NoError(t, err)
	{
		out := &iamv1.IssueSAKeyResponse{}
		require.NoError(t, got.Response.UnmarshalTo(out))
		assert.Empty(t, out.ClientSecret, "idempotent")
		assert.Equal(t, "hydra_client_kac164", out.ClientId, "idempotent")
	}
}

// TestKAC164_RedactSAKey_NonExistentOp_NoError — redact against a missing
// id is defensive: returns nil so a racing GC of the operations row doesn't
// produce log noise.
func TestKAC164_RedactSAKey_NonExistentOp_NoError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupRedactorPG(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	redactor := kachopg.NewOpsResponseRedactor(pool, "kacho_iam")
	err = redactor.RedactResponseField(ctx, "iop_does_not_exist",
		[]string{"client_secret"})
	require.NoError(t, err, "missing op must not error")
}

// TestKAC164_RedactSAKey_OpWithoutResponse_NoError — when MarkError ran (no
// response_data was written) the redact must no-op cleanly.
func TestKAC164_RedactSAKey_OpWithoutResponse_NoError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupRedactorPG(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	opsRepo := operations.NewRepo(pool, "kacho_iam")

	op := operations.Operation{
		ID:          "iop_kac164_noresp",
		Description: "marked-error before MarkDone",
		CreatedAt:   time.Now().UTC().Truncate(time.Second),
		ModifiedAt:  time.Now().UTC().Truncate(time.Second),
		Principal:   operations.SystemPrincipal(),
	}
	require.NoError(t, opsRepo.Create(ctx, op))
	// Leave it without MarkDone/MarkError → response_type='' and response_data=NULL.

	redactor := kachopg.NewOpsResponseRedactor(pool, "kacho_iam")
	err = redactor.RedactResponseField(ctx, op.ID,
		[]string{"client_secret"})
	require.NoError(t, err, "op without response must no-op")
}
