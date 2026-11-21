// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// Настоящие RR capture, participant entry, locks и final clock. Оба исполнения
// сравниваются в одной TX через savepoint: ни clock, ни reserved ID не подменены.
func BindingCommandBatchConformanceForTest(t *testing.T, ctx context.Context, repo *Repository, bundle *granteffect.Bundle, id domain.AccessBindingID, account string, mirror bool) {
	t.Helper()
	owner, err := NewGroupMembershipParticipant(ctx, repo, bundle)
	require.NoError(t, err)
	participant, err := owner.NewBindingStageParticipant(ctx, slog.Default())
	require.NoError(t, err)
	stage, err := participant.stage(ctx, id, false)
	require.NoError(t, err)
	defer stage.close()
	require.False(t, stage.global)
	accounts := []string{account}
	in := kaname.AuthorityWriteIntent{Kind: kaname.AuthorityBinding, Bundle: bundle,
		Plan:   kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceAccounts, Accounts: []domain.AccountID{domain.AccountID(account)}},
		Owners: []kaname.AuthorityOwnerRef{{Kind: "account", ID: account}}}
	writer, err := repo.coordinatedAuthorityWriterWithBegin(ctx, in, "participant", stage.conn.BeginTx)
	require.NoError(t, err)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		rollbackErr := writer.Rollback(cleanup)
		if rollbackErr != pgx.ErrTxClosed {
			require.NoError(t, rollbackErr)
		}
	}()
	epochs, err := json.Marshal(stage.epochs)
	require.NoError(t, err)
	var at time.Time
	require.NoError(t, writer.tx.QueryRow(ctx, `SELECT kaname.authority_binding_epoch_lock($1::text[],$2::jsonb)`, accounts, epochs).Scan(&at))
	store := &reconcileStore{tx: writer.tx, cat: participant.facts, decisionAt: at}
	require.NoError(t, store.AcquireBindingLock(ctx, id))
	require.NoError(t, store.LockBindingsAndRoles(ctx, []domain.AccessBindingID{id}))
	_, err = (&abReader{tx: writer.tx}).Get(ctx, id)
	require.NoError(t, err)
	require.NoError(t, grantMutationPreflight(ctx, writer.tx, "binding"))
	require.NoError(t, lockGrantChildren(ctx, writer.tx))
	require.NoError(t, prelockBindingCommands(ctx, writer.tx))
	var commands []reconcile.BindingCommand
	rows, err := writer.tx.Query(ctx, `SELECT body FROM pg_temp.kaname_binding_stage ORDER BY phase,seq`)
	require.NoError(t, err)
	for rows.Next() {
		var raw []byte
		require.NoError(t, rows.Scan(&raw))
		var command reconcile.BindingCommand
		require.NoError(t, json.Unmarshal(raw, &command))
		commands = append(commands, command)
	}
	err = rows.Err()
	rows.Close()
	require.NoError(t, err)
	memberAt, recordAt, writes := -1, -1, 0
	for i, command := range commands {
		switch command.Kind {
		case "members":
			if memberAt < 0 {
				memberAt = i
			}
			require.NotEmpty(t, command.Members)
		case "record":
			if recordAt < 0 {
				recordAt = i
			}
			require.NotEmpty(t, command.Refs)
		case "write":
			writes++
			require.NotEmpty(t, command.Tuples)
		}
	}
	require.GreaterOrEqual(t, memberAt, 0, "нужен required member INSERT, а не no-op")
	require.Greater(t, recordAt, memberAt, "проверяем реальный исходный порядок members -> record")
	require.Greater(t, writes, 0, "negative обязан исполнить настоящий selected journal")
	require.NoError(t, stage.sequence.prepare(ctx, writer.tx, id, accounts, epochs))
	require.NoError(t, writer.tx.QueryRow(ctx, `SELECT kaname.authority_binding_epoch_lock($1::text[],$2::jsonb)`, accounts, epochs).Scan(&at))
	writer.fence.decisionAt = at.UTC()
	store.decisionAt = at.UTC()
	_, err = writer.tx.Exec(ctx, `SELECT kaname.authority_binding_stage_sequence_finalize_v3($1)`, string(id))
	require.NoError(t, err)
	apply := &preparedBindingStageStore{reconcileStore: store, at: at.UTC()}
	_, batchTracer := writer.tx.Conn().Config().Tracer.(pgx.BatchTracer)
	require.True(t, batchTracer, "контроль обязан исполнить batch, не tracer fallback")
	// Доказываем обе ветви фактического Begin, откатывая только этот probe.
	_, err = writer.tx.Exec(ctx, `SAVEPOINT batch_probe`)
	require.NoError(t, err)
	active, err := apply.BeginBindingCommand(ctx, commands[0])
	require.NoError(t, err)
	require.Equal(t, mirror, active)
	_, err = writer.tx.Exec(ctx, `ROLLBACK TO SAVEPOINT batch_probe`)
	require.NoError(t, err)
	snapshot := func(t *testing.T) string {
		t.Helper()
		var raw []byte
		require.NoError(t, writer.tx.QueryRow(ctx, `SELECT jsonb_build_object(
 'members',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY to_jsonb(m)::text),'[]') FROM kaname.access_binding_target_members m),
 'ledger',(SELECT coalesce(jsonb_agg(to_jsonb(l) ORDER BY to_jsonb(l)::text),'[]') FROM kaname.access_binding_emitted_tuples l),
 'facts',(SELECT coalesce(jsonb_agg(to_jsonb(f) ORDER BY to_jsonb(f)::text),'[]') FROM kaname.relation_fact f),
 'journal',(SELECT coalesce(jsonb_agg(to_jsonb(j) ORDER BY j.id),'[]') FROM kaname.fga_outbox j),
 'epochs',kaname.test_binding_command_batch_epochs_v1())`).Scan(&raw))
		return string(raw)
	}
	before := snapshot(t)
	if !mirror {
		// Сравниваем исходную backend-ошибку BODY, не придумываем новый
		// допустимый SQLSTATE. Begin=false уже доказан на этой же owner stage.
		bad := commands[memberAt]
		bad.Members = append([]domain.TargetMember(nil), bad.Members...)
		bad.Members[0].VerificationStatus = domain.VerificationStatus("INVALID_BATCH_CONTROL")
		var original *pgconn.PgError
		for _, batched := range []bool{false, true} {
			_, err = writer.tx.Exec(ctx, `SAVEPOINT body_failure`)
			require.NoError(t, err)
			if batched {
				err = applyBindingCommand(ctx, apply, bad)
			} else {
				err = bad.Apply(ctx, apply)
			}
			require.ErrorContains(t, err, "target_members: upsert many")
			var pgerr *pgconn.PgError
			require.ErrorAs(t, err, &pgerr)
			require.NotEqual(t, "25P02", pgerr.Code)
			if original == nil {
				original = pgerr
			} else {
				require.Equal(t, original.Code, pgerr.Code)
				require.Equal(t, original.Message, pgerr.Message)
				require.Equal(t, original.ConstraintName, pgerr.ConstraintName)
			}
			_, err = writer.tx.Exec(ctx, `ROLLBACK TO SAVEPOINT body_failure`)
			require.NoError(t, err, "после BODY failure результаты batch полностью закрыты")
			require.JSONEq(t, before, snapshot(t))
		}
	}
	_, err = writer.tx.Exec(ctx, `SAVEPOINT command_parity`)
	require.NoError(t, err)
	for _, command := range commands {
		require.NoError(t, command.Apply(ctx, apply))
	}
	rowwise := snapshot(t)
	require.NotEqual(t, before, rowwise, "oracle должен реально материализовать effects")
	_, err = writer.tx.Exec(ctx, `ROLLBACK TO SAVEPOINT command_parity`)
	require.NoError(t, err)
	require.JSONEq(t, before, snapshot(t))
	for _, command := range commands {
		require.NoError(t, applyBindingCommand(ctx, apply, command))
	}
	require.JSONEq(t, rowwise, snapshot(t), "включая timestamps/IDs/epochs, не только count")
	_, err = writer.tx.Exec(ctx, `ROLLBACK TO SAVEPOINT command_parity`)
	require.NoError(t, err)
	require.JSONEq(t, before, snapshot(t))
	if mirror {
		for _, negative := range []string{"record_before_members", "replay_members", "forged_member"} {
			t.Run(negative, func(t *testing.T) {
				_, e := writer.tx.Exec(ctx, `SAVEPOINT command_negative`)
				require.NoError(t, e)
				switch negative {
				case "record_before_members":
					e = applyBindingCommand(ctx, apply, commands[recordAt])
				case "replay_members":
					for _, command := range commands[:memberAt+1] {
						require.NoError(t, applyBindingCommand(ctx, apply, command))
					}
					e = applyBindingCommand(ctx, apply, commands[memberAt])
				case "forged_member":
					command := commands[memberAt]
					command.Members = append([]domain.TargetMember(nil), command.Members...)
					command.Members[0].ObjectID += "-forged"
					e = applyBindingCommand(ctx, apply, command)
				}
				var pgerr *pgconn.PgError
				require.ErrorAs(t, e, &pgerr)
				require.Equal(t, "42501", pgerr.Code, "не timeout/25P02 вместо первого refusal")
				_, e = writer.tx.Exec(ctx, `ROLLBACK TO SAVEPOINT command_negative`)
				require.NoError(t, e, "BatchResults закрыт и соединение пригодно после отказа")
				require.JSONEq(t, before, snapshot(t), "ни частичных member/ledger/fact/journal effects")
			})
		}
	}
	for _, command := range commands {
		require.NoError(t, applyBindingCommand(ctx, apply, command))
	}
	require.JSONEq(t, rowwise, snapshot(t))
	require.NoError(t, writer.Commit(ctx), "настоящий COMMIT проверяет deferred completion")

}

// Реальный отказ Begin должен остаться первой ошибкой и не запустить body.
func BindingCommandBatchNoEntryForTest(ctx context.Context, tx pgx.Tx) error {
	command := reconcile.BindingCommand{Kind: "members", Members: []domain.TargetMember{{
		BindingID: "absent-batch-binding", RoleID: "absent-batch-role", RuleFP: "batch-refusal",
		ObjectType: "iam.group", ObjectID: "absent-batch-group", VerificationStatus: domain.VerificationActive,
	}}}
	return applyBindingCommand(ctx, &preparedBindingStageStore{reconcileStore: &reconcileStore{tx: tx}}, command)
}
