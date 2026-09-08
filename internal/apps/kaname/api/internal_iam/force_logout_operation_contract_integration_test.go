// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam_test

// force_logout_operation_contract_integration_test.go — the Operation envelope
// of InternalIAMService.ForceLogout, asserted where a CLIENT can see it.
//
// The contract these tests pin (api-conventions.md «мутации возвращают
// Operation», internal_iam_service.proto):
//
//	ForceLogout → metadata: ForceLogoutMetadata, response: ForceLogoutResult
//
// and the client protocol: poll OperationService.Get(id) until done=true.
//
// `op.GetDone()` on the returned envelope proves nothing: ForceLogout passed it
// while no operations row existed at all, so the id the admin was handed
// answered NotFound forever and the force-logout appeared in no operation list.
// Every assertion here therefore reads the persisted row or the repo a poll
// goes through.

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

	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

const forceLogoutAdminID = "usr0000000000000admin"

// allowAdmin — an allowing ReBAC checker. These tests exercise the Operation
// contract, not the authZ gate (gate cases live in force_logout_authz_test.go).
type allowAdmin struct{}

func (allowAdmin) Check(_ context.Context, _, _, _ string) (bool, error) { return true, nil }

func newForceLogoutHandler(t *testing.T) (*internaliam.Handler, *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	h := internaliam.NewHandler(internaliam.NewLookupSubjectUseCase(nil), nil).
		WithSessionRevoker(kanamepg.NewSessionRevocationsAdapter(pool)).
		WithAdminChecker(allowAdmin{}).
		WithOperations(operations.NewRepo(pool, "kaname"))
	return h, pool
}

func forceLogoutAdminCtx() context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: forceLogoutAdminID})
}

// seedForceLogoutUser inserts the target user (+ owning account);
// user_token_revocations carries an FK to users. users↔accounts reference each
// other, so both rows go in ONE transaction (the FKs are DEFERRABLE INITIALLY
// DEFERRED — order-independent on commit).
func seedForceLogoutUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool) domain.UserID {
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
		"ext-"+string(uid), fmt.Sprintf("u-%s@example.com", uid), "Force Logout Target")
	require.NoError(t, err, "seed user")

	_, err = tx.Exec(ctx, `
		INSERT INTO kaname.accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		string(accID), "seed-acc-"+string(accID)[len(accID)-6:], string(uid))
	require.NoError(t, err, "seed account")

	require.NoError(t, tx.Commit(ctx), "commit seed")
	return uid
}

func pollForceLogoutOperationToDone(t *testing.T, ctx context.Context, repo operations.Repo, id string) *operations.Operation {
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

func TestForceLogout_OperationIsPersistedAndCompletes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	h, pool := newForceLogoutHandler(t)
	uid := seedForceLogoutUser(t, ctx, pool)

	op, err := h.ForceLogout(forceLogoutAdminCtx(), &iamv1.ForceLogoutRequest{
		UserId: string(uid),
		Reason: "admin-force-logout",
	})
	require.NoError(t, err)
	require.NotEmpty(t, op.GetId())

	// (1) The persisted row. The defect verbatim: ForceLogout answered done:true
	// while no operations row was ever written.
	var done bool
	var metaData, respData []byte
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT done, metadata_data, response_data FROM kaname.operations WHERE id = $1`,
		op.GetId()).Scan(&done, &metaData, &respData),
		"the operation id handed to the admin must name a persisted row")
	require.True(t, done, "the operations row must be terminal, not merely reported as terminal")
	require.NotEmpty(t, metaData, "metadata must be persisted")
	require.NotEmpty(t, respData, "response must be persisted")

	// (2) The poll path, end to end.
	polled := pollForceLogoutOperationToDone(t, ctx, operations.NewRepo(pool, "kaname"), op.GetId())

	polledMeta := &iamv1.ForceLogoutMetadata{}
	require.NotNil(t, polled.Metadata)
	require.NoError(t, polled.Metadata.UnmarshalTo(polledMeta))
	require.Equal(t, string(uid), polledMeta.GetUserId())

	polledResp := &iamv1.ForceLogoutResult{}
	require.NotNil(t, polled.Response, "ForceLogout declares response: ForceLogoutResult")
	require.NoError(t, polled.Response.UnmarshalTo(polledResp),
		"the response must be the declared ForceLogoutResult")
	require.Equal(t, int32(1), polledResp.GetRevokedCount(),
		"one revocation record was committed — the response must say so, not report an inert 0")

	// (3) The cutoff really landed — the operation describes a committed change.
	var cutoffs int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.user_token_revocations WHERE user_id = $1`,
		string(uid)).Scan(&cutoffs))
	require.Equal(t, 1, cutoffs)
}

// A refused force-logout must leave a terminal error row a poller can read —
// not an unfinished row, and not nothing at all.
func TestForceLogout_FailedWriteLeavesTerminalErrorOperation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	h, pool := newForceLogoutHandler(t)

	// No user row → user_token_revocations FK refuses the write.
	_, err := h.ForceLogout(forceLogoutAdminCtx(), &iamv1.ForceLogoutRequest{
		UserId: string(ids.NewID(domain.PrefixUser)),
	})
	require.Error(t, err, "a refused force-logout must surface as an error, never silent success")

	var unfinished int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.operations
		  WHERE done = false AND description LIKE 'Force logout%'`).Scan(&unfinished))
	require.Zero(t, unfinished,
		"a refused force-logout must not leave a never-completing operation row")

	var terminalErrors int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.operations
		  WHERE done = true AND error_code <> 0 AND description LIKE 'Force logout%'`).Scan(&terminalErrors))
	require.Equal(t, 1, terminalErrors,
		"the failure must be readable by a poller, not invisible")
}

// An unwired operation repository must fail closed: handing back an id that
// names no row is exactly the defect these tests exist for, so it must not be
// reachable by a wiring omission either.
func TestForceLogout_UnwiredOperationRepo_FailsClosed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	uid := seedForceLogoutUser(t, ctx, pool)

	h := internaliam.NewHandler(internaliam.NewLookupSubjectUseCase(nil), nil).
		WithSessionRevoker(kanamepg.NewSessionRevocationsAdapter(pool)).
		WithAdminChecker(allowAdmin{})
	// deliberately no WithOperations

	_, err = h.ForceLogout(forceLogoutAdminCtx(), &iamv1.ForceLogoutRequest{UserId: string(uid)})
	require.Error(t, err, "without an operation repository the RPC must refuse, not answer with an unqueryable id")

	var cutoffs int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.user_token_revocations WHERE user_id = $1`,
		string(uid)).Scan(&cutoffs))
	require.Zero(t, cutoffs, "the refusal must precede the mutation")
}
