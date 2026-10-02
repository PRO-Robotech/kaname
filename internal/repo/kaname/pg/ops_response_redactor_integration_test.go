// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/pgtest"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// setupRedactorPG отдаёт вызывающему СОБСТВЕННУЮ базу схемы kaname на общем
// Postgres пакета. Возвращает DSN, готовый под coredb.NewPool → Operations.Repo.
//
// Раньше на каждый вызов поднимался отдельный контейнер и заново проигрывалась
// вся цепочка миграций. Теперь база клонируется из шаблона, смигрированного
// TestMain'ом один раз, — состояние и изоляция те же (см. pkg/pgtest).
func setupRedactorPG(t *testing.T) string {
	t.Helper()
	return pgtest.NewDB(t)
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

	opsRepo := operations.NewRepo(pool, "kaname")

	// 1. Persist an un-resolved Operation.
	op := operations.Operation{
		ID:          "iop_kac164_redact_test",
		Description: "Issue SA key for sva_test",
		CreatedAt:   time.Now().UTC().Truncate(time.Second),
		ModifiedAt:  time.Now().UTC().Truncate(time.Second),
		Principal:   operations.SystemPrincipal(),
	}
	require.NoError(t, opsRepo.Create(ctx, op))

	// 2. Build an IssueSAKeyResponse with a plaintext client_secret — in the
	//    shape a response was STORED in before kaname#362: the key still
	//    carries field 3 (the provider's client name), which the regenerated
	//    contract has reserved. The stored bytes are read by a reader that no
	//    longer knows the field, and it must stay an unknown field rather than
	//    fail the read or the redaction.
	key := &iamv1.ServiceAccountOAuthClient{
		Id:        "soc_kac164test01",
		SvaId:     "sva_test",
		CreatedAt: timestamppb.Now(),
	}
	key.ProtoReflect().SetUnknown(protowire.AppendString(
		protowire.AppendTag(nil, 3, protowire.BytesType), "provider_client_kac164"))
	resp := &iamv1.IssueSAKeyResponse{
		Key:          key,
		ClientId:     "provider_client_kac164",
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
		assert.Equal(t, "provider_client_kac164", out.ClientId,
			"pre-redact baseline: client_id present")
	}

	// 4. Redact.
	redactor := kanamepg.NewOpsResponseRedactor(pool, "kaname")
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
		assert.Equal(t, "provider_client_kac164", out.ClientId,
			"post-redact: client_id must be unchanged")
		require.NotNil(t, out.Key)
		assert.Equal(t, "soc_kac164test01", out.Key.Id,
			"post-redact: key.id must be unchanged")
		// The reserved field of the stored response survives as unknown bytes:
		// the redaction rewrote the row and neither dropped nor rejected them.
		assert.Contains(t, string(out.Key.ProtoReflect().GetUnknown()), "provider_client_kac164",
			"post-redact: a field reserved after the row was stored stays readable as unknown bytes")
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
		assert.Equal(t, "provider_client_kac164", out.ClientId, "idempotent")
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

	redactor := kanamepg.NewOpsResponseRedactor(pool, "kaname")
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
	opsRepo := operations.NewRepo(pool, "kaname")

	op := operations.Operation{
		ID:          "iop_kac164_noresp",
		Description: "marked-error before MarkDone",
		CreatedAt:   time.Now().UTC().Truncate(time.Second),
		ModifiedAt:  time.Now().UTC().Truncate(time.Second),
		Principal:   operations.SystemPrincipal(),
	}
	require.NoError(t, opsRepo.Create(ctx, op))
	// Leave it without MarkDone/MarkError → response_type='' and response_data=NULL.

	redactor := kanamepg.NewOpsResponseRedactor(pool, "kaname")
	err = redactor.RedactResponseField(ctx, op.ID,
		[]string{"client_secret"})
	require.NoError(t, err, "op without response must no-op")
}
