// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit_test

// service_account_disable_audit_integration_test.go — taking a machine identity
// out of service is an EVENT, and it has an OBSERVABLE consequence.
//
// Two things are asserted together on purpose, because either one alone is the
// defect this file exists to rule out:
//
//   - the audit trail records WHO did it, TO WHOM and WHEN, as an event of its
//     own rather than a diff of some field. "Disabled the CI bot" and "renamed
//     the CI bot" must not read the same in the log a year from now;
//   - the state actually reaches the reader that gates issuance. A test that
//     stopped at "the row was written" would pass just as happily if the write
//     went somewhere nothing consults — which is the shape of the whole
//     original defect: a column read by five callers, decided on by four, and
//     written by none.
//
// Idempotence is asserted, not assumed: the safe direction of a control must
// not be the one that fails when it is repeated.
//
// Run: `go test ./internal/apps/kaname/api/audit/... -run ServiceAccountDisable`. Skipped with -short.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	service_account "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/service_account"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

func TestServiceAccountDisable_RecordsTheEventAndReachesTheIssuanceGate(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	owner, accID := seedUserAccount(t, ctx, env.pool, "sadis")

	_, err := service_account.NewCreateServiceAccountUseCase(env.repo, env.opsRepo).Execute(
		withPrincipal(owner), domain.ServiceAccount{
			AccountID: accID,
			Name:      domain.SvcAccountName("ci-bot-disable"),
		})
	require.NoError(t, err)
	awaitWorkers(t)
	saID := singleID(t, ctx, env,
		`SELECT id FROM kaname.service_accounts WHERE name = $1 AND account_id = $2`,
		"ci-bot-disable", string(accID))

	// The gate that decides whether this account may be handed a credential.
	// Read directly, so what is proven is the state the ISSUANCE PATH sees, not
	// the state some convenient reader in this test happens to report.
	gate := kanamepg.NewSAOAuthClientRepo(env.pool)
	_, mayAuth, err := gate.AccountForServiceAccount(ctx, domain.ServiceAccountID(saID))
	require.NoError(t, err)
	require.True(t, mayAuth, "a freshly created service account may authenticate — the control case")

	// ── Disable ────────────────────────────────────────────────────────────────
	disable := service_account.NewDisableServiceAccountUseCase(env.repo, env.opsRepo)
	op, err := disable.Execute(withPrincipal(owner), domain.ServiceAccountID(saID))
	require.NoError(t, err)
	require.NotEmpty(t, op.ID, "a mutation answers with an Operation")
	awaitWorkers(t)

	row := requireOneAuditRow(ctx, t, env.pool, "iam.service_account.disabled", saID)
	require.Equal(t, "service_account", row.payload["resource_type"])
	require.Equal(t, saID, row.payload["resource_id"], "the trail names WHOM")
	require.Equal(t, string(accID), row.payload["account_id"])
	require.Equal(t, string(owner), row.payload["actor"], "the trail names WHO")
	require.Equal(t, false, row.payload["enabled"], "and the state the account was left in")
	require.Regexp(t, evtIDFormat, row.id)

	_, mayAuth, err = gate.AccountForServiceAccount(ctx, domain.ServiceAccountID(saID))
	require.NoError(t, err)
	require.False(t, mayAuth,
		"the issuance gate must now refuse this account — this is the observable outcome, and "+
			"the assertion a write that never reached the column would fail")

	// ── Disabling again is a success ───────────────────────────────────────────
	_, err = disable.Execute(withPrincipal(owner), domain.ServiceAccountID(saID))
	require.NoError(t, err, "the state is the subject, not the transition: a repeat must succeed")
	awaitWorkers(t)
	_, mayAuth, err = gate.AccountForServiceAccount(ctx, domain.ServiceAccountID(saID))
	require.NoError(t, err)
	require.False(t, mayAuth, "and it must leave the account where it was")

	// ── Enable ─────────────────────────────────────────────────────────────────
	enable := service_account.NewEnableServiceAccountUseCase(env.repo, env.opsRepo)
	_, err = enable.Execute(withPrincipal(owner), domain.ServiceAccountID(saID))
	require.NoError(t, err)
	awaitWorkers(t)

	back := requireOneAuditRow(ctx, t, env.pool, "iam.service_account.enabled", saID)
	require.Equal(t, string(owner), back.payload["actor"])
	require.Equal(t, saID, back.payload["resource_id"])
	require.Equal(t, true, back.payload["enabled"])

	_, mayAuth, err = gate.AccountForServiceAccount(ctx, domain.ServiceAccountID(saID))
	require.NoError(t, err)
	require.True(t, mayAuth,
		"and the account may authenticate again — a one-way control is one an operator "+
			"cannot use")
}

// The audit trail must not confuse the two directions. A single event type with
// a flag inside would make "who disabled this account" a question you answer by
// reading payloads, and that is exactly the question the log is for.
func TestServiceAccountDisable_TheTwoDirectionsAreDistinctEvents(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	owner, accID := seedUserAccount(t, ctx, env.pool, "sadis2")

	_, err := service_account.NewCreateServiceAccountUseCase(env.repo, env.opsRepo).Execute(
		withPrincipal(owner), domain.ServiceAccount{
			AccountID: accID,
			Name:      domain.SvcAccountName("ci-bot-two-ways"),
		})
	require.NoError(t, err)
	awaitWorkers(t)
	saID := singleID(t, ctx, env,
		`SELECT id FROM kaname.service_accounts WHERE name = $1 AND account_id = $2`,
		"ci-bot-two-ways", string(accID))

	_, err = service_account.NewDisableServiceAccountUseCase(env.repo, env.opsRepo).
		Execute(withPrincipal(owner), domain.ServiceAccountID(saID))
	require.NoError(t, err)
	awaitWorkers(t)
	_, err = service_account.NewEnableServiceAccountUseCase(env.repo, env.opsRepo).
		Execute(withPrincipal(owner), domain.ServiceAccountID(saID))
	require.NoError(t, err)
	awaitWorkers(t)

	require.Len(t, auditRowsByEventResource(ctx, t, env.pool, "iam.service_account.disabled", saID), 1)
	require.Len(t, auditRowsByEventResource(ctx, t, env.pool, "iam.service_account.enabled", saID), 1)
	require.Empty(t, auditRowsByEventResource(ctx, t, env.pool, "iam.service_account.updated", saID),
		"an action is not an attribute edit and must not be filed as one")
}
