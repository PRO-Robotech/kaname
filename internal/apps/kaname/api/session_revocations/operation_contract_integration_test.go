// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_revocations_test

// operation_contract_integration_test.go — the Operation envelope of
// InternalSessionRevocationsService.Revoke, asserted where a CLIENT can see it.
//
// The contract these tests pin (api-conventions.md «мутации возвращают
// Operation», session_revocations_service.proto):
//
//	Revoke → metadata: RevokeMetadata, response: SessionRevocation
//
// and the client protocol: poll OperationService.Get(id) until done=true.
//
// WHY THESE ARE NOT «op.GetDone() == true» ASSERTIONS
// ---------------------------------------------------
// `op.GetDone()` on the returned envelope reads a field the use-case set in
// memory a line earlier — it is true no matter what reached Postgres. Revoke
// passed that assertion while NO operations row existed at all: a client
// following the documented contract got NotFound for the id it was just handed,
// forever, and the operation appeared in no list and no audit. So every
// assertion here reads either the persisted row or the repo a poll goes
// through, never the in-memory struct alone.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	sessionrev "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/session_revocations"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

const revokeTestAdminID = "usr0000000000000admin"

// newRevokeHandler wires the REAL use-case over a real pool, exactly as the
// composition root does.
func newRevokeHandler(t *testing.T) (*sessionrev.Handler, *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	adapter := kanamepg.NewSessionRevocationsAdapter(pool)
	h := sessionrev.NewHandler(
		sessionrev.NewRevokeUseCase(adapter, operations.NewRepo(pool, "kaname")),
		adapter,
	)
	return h, pool
}

// principalCtx — an authenticated caller, as the internal listener supplies one.
func principalCtx() context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: revokeTestAdminID})
}

// seedRevokeUser inserts the user (+ owning account) the revocation targets.
// user_token_revocations carries an FK to users, so the bulk path needs a real
// row. users↔accounts reference each other, so both rows go in ONE transaction
// (the FKs are DEFERRABLE INITIALLY DEFERRED — order-independent on commit).
func seedRevokeUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool) domain.UserID {
	t.Helper()
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	accID := domain.AccountID(ids.NewID(domain.PrefixAccount))

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
		string(uid), string(accID),
		"ext-"+string(uid), fmt.Sprintf("u-%s@example.com", uid), "Revoke Target")
	require.NoError(t, err, "seed user")

	_, err = tx.Exec(ctx, `
		INSERT INTO kaname.accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		string(accID), "seed-acc-"+string(accID)[len(accID)-6:], string(uid))
	require.NoError(t, err, "seed account")

	require.NoError(t, tx.Commit(ctx), "commit seed")
	return uid
}

// pollRevokeOperationToDone — the client protocol, executed: read the operation
// the way OperationService.Get does, until done=true or the budget runs out.
// Exhausting the budget is the observable form of "the client polls forever".
func pollRevokeOperationToDone(t *testing.T, ctx context.Context, repo operations.Repo, id string) *operations.Operation {
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

// revokeOpRow — the three columns a poller's answer is built from.
func revokeOpRow(t *testing.T, ctx context.Context, pool *pgxpool.Pool, opID string) (done bool, metadata, response []byte) {
	t.Helper()
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT done, metadata_data, response_data FROM kaname.operations WHERE id = $1`,
		opID).Scan(&done, &metadata, &response),
		"the operation id handed to the caller must name a persisted row")
	return done, metadata, response
}

// ── Revoke: per-jti ─────────────────────────────────────────────────────────

func TestSessionRevoke_OperationIsPersistedAndCompletes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	h, pool := newRevokeHandler(t)
	uid := seedRevokeUser(t, ctx, pool)
	jti := "jti-" + ids.NewUID()

	op, err := h.Revoke(principalCtx(), &iamv1.RevokeRequest{
		TokenJti: jti,
		UserId:   string(uid),
		Reason:   "user-logout",
	})
	require.NoError(t, err)
	require.NotEmpty(t, op.GetId())

	// (1) The persisted row. This is the defect verbatim: Revoke answered
	// done:true while no operations row was ever written.
	done, metaData, respData := revokeOpRow(t, ctx, pool, op.GetId())
	require.True(t, done, "the operations row must be terminal, not merely reported as terminal")
	require.NotEmpty(t, metaData, "metadata must be persisted")
	require.NotEmpty(t, respData, "response must be persisted")

	// (2) The poll path, end to end.
	polled := pollRevokeOperationToDone(t, ctx, operations.NewRepo(pool, "kaname"), op.GetId())

	polledMeta := &iamv1.RevokeMetadata{}
	require.NotNil(t, polled.Metadata)
	require.NoError(t, polled.Metadata.UnmarshalTo(polledMeta))
	require.Equal(t, string(uid), polledMeta.GetUserId())
	require.Equal(t, int32(1), polledMeta.GetRevokedCount(),
		"one session_revocations row was written — the metadata must say so")

	polledResp := &iamv1.SessionRevocation{}
	require.NotNil(t, polled.Response, "Revoke declares response: SessionRevocation")
	require.NoError(t, polled.Response.UnmarshalTo(polledResp),
		"the response must be the declared SessionRevocation")
	require.Equal(t, jti, polledResp.GetTokenJti())
	require.Equal(t, string(uid), polledResp.GetUserId())
	require.Equal(t, "user-logout", polledResp.GetReason())

	// (3) The response must describe the row that actually landed.
	var rowReason string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT reason FROM kaname.session_revocations WHERE token_jti = $1`,
		jti).Scan(&rowReason))
	require.Equal(t, rowReason, polledResp.GetReason())
}

// ── Revoke: user-level revoke-all ───────────────────────────────────────────

func TestSessionRevoke_BulkPathOperationIsPersistedAndCompletes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	h, pool := newRevokeHandler(t)
	uid := seedRevokeUser(t, ctx, pool)

	op, err := h.Revoke(principalCtx(), &iamv1.RevokeRequest{
		UserId:              string(uid),
		RevokeAllUserTokens: true,
	})
	require.NoError(t, err)

	done, metaData, respData := revokeOpRow(t, ctx, pool, op.GetId())
	require.True(t, done)
	require.NotEmpty(t, metaData)
	require.NotEmpty(t, respData,
		"a revoke-all is a real revocation — its operation must carry the declared response")

	polled := pollRevokeOperationToDone(t, ctx, operations.NewRepo(pool, "kaname"), op.GetId())
	polledMeta := &iamv1.RevokeMetadata{}
	require.NoError(t, polled.Metadata.UnmarshalTo(polledMeta))
	require.Equal(t, string(uid), polledMeta.GetUserId())
	require.Equal(t, int32(1), polledMeta.GetRevokedCount())

	polledResp := &iamv1.SessionRevocation{}
	require.NoError(t, polled.Response.UnmarshalTo(polledResp))
	require.Equal(t, string(uid), polledResp.GetUserId())
	require.Empty(t, polledResp.GetTokenJti(),
		"the revoke-all cutoff is user-level — it names no single token")
}

// The operation is the caller's only handle on the mutation, so it must be
// durable BEFORE the mutation: a refused write must leave a terminal error row,
// never a row nobody will ever finish and never no row at all.
func TestSessionRevoke_FailedWriteLeavesTerminalErrorOperation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	h, pool := newRevokeHandler(t)

	// No user row → user_token_revocations FK refuses the bulk write.
	_, err := h.Revoke(principalCtx(), &iamv1.RevokeRequest{
		UserId:              string(ids.NewID(domain.PrefixUser)),
		RevokeAllUserTokens: true,
	})
	require.Error(t, err, "a refused revoke must surface as an error, never silent success")

	var unfinished int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.operations
		  WHERE done = false AND description LIKE 'Revoke session%'`).Scan(&unfinished))
	require.Zero(t, unfinished,
		"a refused revoke must not leave a never-completing operation row")

	var terminalErrors int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.operations
		  WHERE done = true AND error_code <> 0 AND description LIKE 'Revoke session%'`).Scan(&terminalErrors))
	require.Equal(t, 1, terminalErrors,
		"the failure must be readable by a poller, not invisible")
}
