// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

type UserChildFinalAuthProbe struct {
	Allowed, OtherTargetAllowed, OtherPrincipalAllowed, StaleClockAllowed bool
	AllowError, OtherTargetError, OtherPrincipalError, StaleClockError    error
	ChildExists                                                           bool
}

// Один физический owner conn проходит настоящий RR stage, закрытый RC
// prepare/finalize и Go checkFinal. Проба не выдаёт разрешения через fake checker.
func ProbeUserChildFinalAuthorization(t *testing.T, ctx context.Context, conn *pgx.Conn, bundle *granteffect.Bundle,
	input kaname.UserChildRegistrationInput, principal operations.Principal,
) UserChildFinalAuthProbe {
	t.Helper()
	stage, _, tx := prepareUserChildBodyProbe(t, ctx, conn, bundle, input, principal)
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	rc, writer := tx.Tx, tx.owner
	decisionAt := writer.fence.decisionAt
	authorization := stage.authorization
	target, subject := authorization.target, authorization.subject
	var out UserChildFinalAuthProbe
	out.Allowed, out.AllowError = authorization.checkFinal(ctx, writer, subject, target.ParentAction, target.ParentObject)
	out.OtherTargetAllowed, out.OtherTargetError = authorization.checkFinal(ctx, writer, subject, target.ParentAction, target.ParentObject+"-other")
	other := operations.Principal{Type: "user", ID: principal.ID + "-other"}
	out.OtherPrincipalAllowed, out.OtherPrincipalError = authorization.checkFinal(operations.WithPrincipal(ctx, other), writer,
		"user:"+other.ID, target.ParentAction, target.ParentObject)
	writer.fence.decisionAt = decisionAt.Add(time.Microsecond)
	out.StaleClockAllowed, out.StaleClockError = authorization.checkFinal(ctx, writer, subject, target.ParentAction, target.ParentObject)
	writer.fence.decisionAt = decisionAt.UTC()
	require.NoError(t, rc.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM kaname.resource_mirror
 WHERE object_type=$1 AND object_id=$2)`, input.ResourceType, input.ResourceID).Scan(&out.ChildExists))
	return out
}

// Подготовка на одном физическом соединении повторяет настоящий RR → RC lifetime.
func prepareUserChildBodyProbe(t *testing.T, ctx context.Context, conn *pgx.Conn, bundle *granteffect.Bundle,
	input kaname.UserChildRegistrationInput, principal operations.Principal,
) (*resourceChildStage, *resourceDecisionProposal, *resourceDecisionTx) {
	t.Helper()
	lifetime, err := newResourceAttemptLifetime(conn, bundle)
	require.NoError(t, err)
	rr, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	require.NoError(t, err)
	defer func() { _ = rr.Rollback(context.WithoutCancel(ctx)) }()
	runner := &ResourceDecisionRunner{bundle: bundle}
	stage, err := runner.stageUserChildRegistration(ctx, rr, lifetime, input, principal, &relverdict.AdministrativeReadBudget{})
	require.NoError(t, err)
	proposal, err := stage.proposal()
	require.NoError(t, err)
	require.NoError(t, stage.source.seal())
	require.NoError(t, rr.Rollback(context.WithoutCancel(ctx)))
	rc, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	require.NoError(t, err)
	identity := bundle.Identity()
	_, err = rc.Exec(ctx, `SELECT kaname.authority_resource_source_enter_v3(
 'global',ARRAY[]::text[],'[]'::jsonb,$1,$2,$3)`, identity.ModelID, identity.CatalogID, identity.ProjectorVersion)
	require.NoError(t, err)
	writer := &authorityWriteTx{writeTx: &writeTx{readTx: readTx{tx: rc}}, fence: authorityFence{mode: kaname.AuthorityFenceGlobal}}
	require.NoError(t, lifetime.prepare(writer))
	var rows, reads int
	require.NoError(t, rc.QueryRow(ctx, `SELECT logical_rows,logical_reads
 FROM kaname._authority_child_registration_prepare_v1($1::jsonb,100000,4096)`, proposal.payload).Scan(&rows, &reads))
	var decisionAt time.Time
	require.NoError(t, rc.QueryRow(ctx, `SELECT decision_at,logical_rows,logical_reads
 FROM kaname._authority_child_registration_finalize_v1($1::jsonb,100000,4096)`, proposal.intent).Scan(&decisionAt, &rows, &reads))
	writer.fence.decisionAt = decisionAt.UTC()
	require.NoError(t, lifetime.bind(writer))
	proposal.prepared = writer
	tx := &resourceDecisionTx{Tx: rc, owner: writer, lifetime: lifetime}
	t.Cleanup(func() { _ = tx.Rollback(context.WithoutCancel(ctx)) })
	return stage, proposal, tx
}

func CommitUserChildBodyProbe(t *testing.T, ctx context.Context, conn *pgx.Conn, bundle *granteffect.Bundle,
	input kaname.UserChildRegistrationInput, principal operations.Principal,
) time.Time {
	t.Helper()
	stage, proposal, tx := prepareUserChildBodyProbe(t, ctx, conn, bundle, input, principal)
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	version, err := stage.applyChildBody(ctx, tx, proposal)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	return version
}

func AbortIncompleteUserChildBodyProbe(t *testing.T, ctx context.Context, conn *pgx.Conn, bundle *granteffect.Bundle,
	input kaname.UserChildRegistrationInput, principal operations.Principal,
) {
	t.Helper()
	_, proposal, tx := prepareUserChildBodyProbe(t, ctx, conn, bundle, input, principal)
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	_, err := tx.Exec(ctx, `SELECT kaname._authority_child_registration_begin_body_v1($1::jsonb)`, proposal.intent)
	require.NoError(t, err)
	require.Error(t, tx.Commit(ctx), "незавершённое тело обязано отвергать commit")
}
