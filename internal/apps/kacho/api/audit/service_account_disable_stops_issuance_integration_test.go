// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit_test

// service_account_disable_stops_issuance_integration_test.go — the whole loop,
// end to end, against a real database: an enabled account is issued a
// credential; the account is disabled through the ACTION; the same request is
// refused; the account is enabled again; the request works again.
//
// WHY THIS EXISTS ALONGSIDE THE OTHER TWO FILES. The sibling tests prove the
// writer reaches the column and the readers report it. Neither proves what the
// reader is FOR. This one drives the actual issuance use-case — the same code
// that runs in production, over the same repository adapters — so what is
// asserted is the product behaviour a person cares about: a disabled machine
// identity does not get handed new credentials. If the writer, the column and
// the gate ever stop lining up, this is the test that says so in one sentence.
//
// Only the OAuth provider is faked. Everything between the action and the
// verdict — use-cases, transactions, both repository adapters, the real
// Postgres schema — is the production path.
//
// This file lives in this package because this is where the full-service
// Postgres harness lives; it is not about the audit trail (the sibling file
// covers that).
//
// Run: `go test ./internal/apps/kacho/api/audit/... -run DisabledServiceAccount`. Skipped with -short.

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/sa_keys"
	service_account "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/service_account"
	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
)

// fakeOAuthProvider stands in for the external authorization server — the ONE
// thing that cannot run in a test container here. It always succeeds, so a
// refusal observed below can only have come from our own decision, never from
// the provider being unavailable.
//
// Each registration gets a DISTINCT client id, because the real one does and the
// schema holds it unique. A constant here made the second issuance collide, and
// the collision surfaced only as "one key where two were expected" — a fixture
// defect wearing the clothes of the product defect under test.
type fakeOAuthProvider struct{ created int }

func (f *fakeOAuthProvider) CreateOAuthClient(context.Context, clients.CreateOAuthClientRequest) (clients.HydraOAuthClient, error) {
	f.created++
	return clients.HydraOAuthClient{ClientID: fmt.Sprintf("fake-client-id-%d", f.created)}, nil
}
func (f *fakeOAuthProvider) DeleteOAuthClient(context.Context, string) error { return nil }

func TestDisabledServiceAccount_IsRefusedACredential_AndWorksAgainAfterEnable(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	owner, accID := seedUserAccount(t, ctx, env.pool, "saiss")

	_, err := service_account.NewCreateServiceAccountUseCase(env.repo, env.opsRepo).Execute(
		withPrincipal(owner), domain.ServiceAccount{
			AccountID: accID,
			Name:      domain.SvcAccountName("ci-bot-issuance"),
		})
	require.NoError(t, err)
	awaitWorkers(t)
	saID := domain.ServiceAccountID(singleID(t, ctx, env,
		`SELECT id FROM kacho_iam.service_accounts WHERE name = $1 AND account_id = $2`,
		"ci-bot-issuance", string(accID)))

	provider := &fakeOAuthProvider{}
	issue := sa_keys.NewIssueSAKeyUseCase(
		kachopg.NewSAOAuthClientRepo(env.pool),
		kachopg.NewPoolTxBeginner(env.pool),
		provider,
		env.opsRepo,
	)
	issueOnce := func(name string) error {
		_, ierr := issue.Execute(withPrincipal(owner), sa_keys.IssueInput{
			ServiceAccountID: saID,
			CreatedByUserID:  string(owner),
			Name:             name,
		})
		return ierr
	}
	// requireEveryOperationSucceeded — every Operation this test started is done
	// and carries no error. Without it, an async failure shows up only as a row
	// count that is off by one, and the reader is left guessing whether the
	// product refused something or the fixture tripped over itself.
	requireEveryOperationSucceeded := func() {
		t.Helper()
		rows, qerr := env.pool.Query(ctx,
			`SELECT id, description, done, coalesce(error_message, '') FROM kacho_iam.operations ORDER BY created_at`)
		require.NoError(t, qerr)
		defer rows.Close()
		for rows.Next() {
			var id, desc, errMsg string
			var done bool
			require.NoError(t, rows.Scan(&id, &desc, &done, &errMsg))
			require.True(t, done, "operation %s (%s) never finished", id, desc)
			require.Empty(t, errMsg, "operation %s (%s) failed", id, desc)
		}
		require.NoError(t, rows.Err())
	}
	keysOnRecord := func() int {
		var n int
		require.NoError(t, env.pool.QueryRow(ctx,
			`SELECT count(*) FROM kacho_iam.service_account_oauth_clients WHERE sva_id = $1`,
			string(saID)).Scan(&n))
		return n
	}

	// ── 1. Enabled: the credential is issued. ──────────────────────────────────
	//
	// The control case, and it comes first on purpose. `enabled` is false in
	// every zero value, so a gate reading a field nothing loaded would refuse
	// EVERY account — and a test that only checked the refusal would call that
	// a pass while machine access was dead platform-wide.
	require.NoError(t, issueOnce("key-before"), "an enabled account is issued a credential")
	awaitWorkers(t)
	requireEveryOperationSucceeded()
	require.Equal(t, 1, keysOnRecord(), "and the key is on record")

	// ── 2. Disable through the ACTION. ─────────────────────────────────────────
	_, err = service_account.NewDisableServiceAccountUseCase(env.repo, env.opsRepo).
		Execute(withPrincipal(owner), saID)
	require.NoError(t, err)
	awaitWorkers(t)

	// ── 3. Disabled: the same request is refused. ──────────────────────────────
	err = issueOnce("key-while-disabled")
	require.Error(t, err, "a disabled account must not be issued a new credential")
	require.Equal(t, codes.FailedPrecondition, status.Code(err),
		"the request is well-formed; it is the account's state that does not permit it")
	require.Contains(t, status.Convert(err).Message(), "is disabled and cannot be issued a key")
	awaitWorkers(t)
	require.Equal(t, 1, keysOnRecord(),
		"and nothing was written — a refusal that still left a usable key behind would be no "+
			"refusal at all, only a slower one")
	require.Equal(t, 1, provider.created,
		"nor was a client registered with the provider: the refusal happens before anything "+
			"outside this service is asked for")

	// ── 4. Enable: the same request works again. ───────────────────────────────
	_, err = service_account.NewEnableServiceAccountUseCase(env.repo, env.opsRepo).
		Execute(withPrincipal(owner), saID)
	require.NoError(t, err)
	awaitWorkers(t)

	require.NoError(t, issueOnce("key-after"),
		"an account brought back into service is issued credentials again — otherwise Disable "+
			"is a one-way door and nobody will use it")
	awaitWorkers(t)
	requireEveryOperationSucceeded()
	require.Equal(t, 2, keysOnRecord())
}
