// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// Только test binary: настоящий RR compiler, затем тот же backend/RC entry.
// Callback расположен после owner capture, до любого coordinator lock.
func BindingMirrorStageForTest(t *testing.T, ctx context.Context, repo *Repository, bundle *granteffect.Bundle, id domain.AccessBindingID, wantGlobal bool, wantAccounts []string, mutate func(), wantChanged bool) {
	t.Helper()
	owner, err := NewGroupMembershipParticipant(ctx, repo, bundle)
	require.NoError(t, err)
	p, err := owner.NewBindingStageParticipant(ctx, slog.Default())
	require.NoError(t, err)
	stage, err := p.stage(ctx, id, false)
	require.NoError(t, err)
	defer stage.close()
	require.Equal(t, wantGlobal, stage.global)
	var accounts []string
	if !stage.global {
		for a := range stage.accounts {
			accounts = append(accounts, a)
		}
		slices.Sort(accounts)
	}
	require.Equal(t, wantAccounts, accounts)
	budget := stage.sequence.parents.source.budget
	retained, owningAccounts := 0, 0
	for key := range stage.sequence.parents.source.entries {
		if key.kind == resourceSourceRegistrationScopes {
			retained++
		}
		if key.kind == resourceSourceAccount {
			owningAccounts++
		}
	}
	// Все дополнительные predicates и их независимый owner reread расходуют
	// тот же whole-attempt budget; этот probe не объявляет SQL-время или O(delta).
	require.Greater(t, retained, 0)
	require.Greater(t, owningAccounts, 0)
	require.GreaterOrEqual(t, budget.RemainingReads(), 0)
	require.GreaterOrEqual(t, budget.RemainingRows(), 0)
	t.Logf("mirror stage actual keys=%d retained=%d accounts=%d remaining_reads=%d remaining_rows=%d", len(stage.sequence.parents.source.entries), retained, owningAccounts, budget.RemainingReads(), budget.RemainingRows())
	if mutate != nil {
		mutate()
	}
	in := kaname.AuthorityWriteIntent{Kind: kaname.AuthorityBinding, Bundle: bundle, Plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}}
	if !stage.global {
		in.Plan.Mode = kaname.AuthorityFenceAccounts
		for _, a := range accounts {
			in.Plan.Accounts = append(in.Plan.Accounts, domain.AccountID(a))
			in.Owners = append(in.Owners, kaname.AuthorityOwnerRef{Kind: "account", ID: a})
		}
	}
	encoded, err := json.Marshal(stage.epochs)
	require.NoError(t, err)
	w, err := repo.coordinatedAuthorityWriterWithBegin(ctx, in, "participant", stage.conn.BeginTx)
	require.NoError(t, err)
	var at time.Time
	err = w.tx.QueryRow(ctx, `SELECT kaname.authority_binding_epoch_lock($1::text[],$2::jsonb)`, accounts, encoded).Scan(&at)
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	rollbackErr := w.Rollback(cleanup)
	cancel()
	require.NoError(t, rollbackErr)
	if wantChanged {
		var pgerr *pgconn.PgError
		require.ErrorAs(t, err, &pgerr)
		require.Equal(t, "40001", pgerr.Code)
	} else {
		require.NoError(t, err)
	}
	require.Same(t, budget, stage.sequence.parents.source.budget)
}

// Дифференциал использует реальные RR строки. В отрицательных ветвях меняется
// только proposal чистому private verifier; это не обход runtime ACL.
func BindingMirrorLocalityDifferentialForTest(t *testing.T, ctx context.Context, tx pgx.Tx, bundle *granteffect.Bundle, binding domain.AccessBindingID, id string, wantLocal bool) {
	t.Helper()
	var halves catalog.Halves
	require.NoError(t, json.Unmarshal(bundle.CanonicalCatalog(), &halves))
	facts, err := catalog.NewFacts(halves)
	require.NoError(t, err)
	b, err := (&abReader{tx: tx}).Get(ctx, binding)
	require.NoError(t, err)
	b.Subjects, err = (&abReader{tx: tx}).ListSubjects(ctx, binding)
	require.NoError(t, err)
	roles, err := loadRolesWithLifecycleMode(ctx, tx, []string{string(b.RoleID)}, rowLock(""))
	require.NoError(t, err)
	bs := bindingScopeFrom(facts, b, roles[b.RoleID])
	life, err := newResourceAttemptLifetime(tx.Conn(), bundle)
	require.NoError(t, err)
	source, err := newResourceSourceCapture(tx, &relverdict.AdministrativeReadBudget{}, life)
	require.NoError(t, err)
	parents, err := newResourceParentCapture(tx, source)
	require.NoError(t, err)
	s := &bindingSequenceCapture{parents: parents, binding: binding}
	store := &bindingSnapshotStore{reconcileStore: &reconcileStore{tx: tx, cat: facts}}
	obj, present, err := store.GetMirrorObject(ctx, "vpc.network", id)
	require.NoError(t, err)
	ancestors, err := store.AncestorObjects(ctx, "vpc.network", id)
	require.NoError(t, err)
	engine := reconcile.New(nil, slog.Default(), catalog.Fixed{F: facts})
	coord := reconcile.MemberCoord{ObjectType: "vpc.network", ObjectID: id}
	input, err := engine.CaptureStagedBindingCoordinate(ctx, store, bs, coord, obj, present, ancestors)
	require.NoError(t, err)
	commands, err := reconcile.CompileCapturedBindingCoordinate(ctx, input, coord, false)
	require.NoError(t, err)
	require.NoError(t, s.captureCoordinate(ctx, coord.ObjectType, id, input, commands, nil))
	before := source.budget.RemainingReads()
	local, err := s.captureMirrorLocality(ctx, facts, coord.ObjectType, id, input, commands)
	require.NoError(t, err)
	require.Equal(t, wantLocal, local)
	require.Less(t, source.budget.RemainingReads(), before, "retained и account действительно прочитаны")
	var sources []resourceProposalSource
	for key, rows := range source.entries {
		item := resourceProposalSource{Kind: key.kind, Type: key.typ, ID: key.id, Projection: key.projection, States: []string{}}
		for _, row := range rows {
			item.States = append(item.States, row.state)
		}
		sources = append(sources, item)
	}
	coordinate, err := json.Marshal(s.coordinates[0])
	require.NoError(t, err)
	query := `WITH i AS (SELECT kaname._authority_resource_capture_index_v2($1::jsonb,100000) idx)
 SELECT kaname._authority_binding_mirror_locality_v3(idx,$2::jsonb,
 kaname._authority_resource_projection_v2(idx,'vpc.network',$3),
 (SELECT to_jsonb(b) FROM kaname.access_bindings b WHERE id=$4),$5::jsonb,
 (SELECT coalesce(jsonb_agg(to_jsonb(e)),'[]'::jsonb) FROM kaname.access_binding_emitted_tuples e WHERE binding_id=$4 AND member_object_type='vpc.network' AND member_object_id=$3)) FROM i`
	for _, mode := range []string{"actual", "missing_retained", "missing_account", "wrong_retained_link"} {
		proposal := make([]resourceProposalSource, 0, len(sources))
		for _, item := range sources {
			if mode == "missing_retained" && item.Kind == resourceSourceRegistrationScopes {
				continue
			}
			if mode == "missing_account" && item.Kind == resourceSourceAccount {
				continue
			}
			if mode == "wrong_retained_link" && item.Kind == resourceSourceRegistrationScopes {
				item.States = slices.Clone(item.States)
				require.NotEmpty(t, item.States)
				var state []json.RawMessage
				require.NoError(t, json.Unmarshal([]byte(item.States[0]), &state))
				var row map[string]any
				require.NoError(t, json.Unmarshal(state[2], &row))
				row["object_id"] = id + "-other"
				state[2], err = json.Marshal(row)
				require.NoError(t, err)
				encoded, e := json.Marshal(state)
				require.NoError(t, e)
				item.States[0] = string(encoded)
			}
			proposal = append(proposal, item)
		}
		encoded, e := json.Marshal(proposal)
		require.NoError(t, e)
		_, e = tx.Exec(ctx, `SAVEPOINT mirror_proposal`)
		require.NoError(t, e)
		var sqlLocal bool
		e = tx.QueryRow(ctx, query, encoded, bundle.CanonicalCatalog(), id, string(binding), coordinate).Scan(&sqlLocal)
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		_, rollbackErr := tx.Exec(cleanup, `ROLLBACK TO SAVEPOINT mirror_proposal`)
		cancel()
		require.NoError(t, rollbackErr)
		if mode == "actual" {
			require.NoError(t, e)
			require.Equal(t, local, sqlLocal)
		} else {
			var pgerr *pgconn.PgError
			require.ErrorAs(t, e, &pgerr)
			require.Equal(t, "42501", pgerr.Code, mode)
		}
	}
	// Адрес с тем же prefix и другим ID не получает local даже без physical DML.
	input.Ledger = append(input.Ledger, reconcile.LedgerRow{Member: coord, Tuple: domain.MembershipTuple{Object: "vpc_network:" + id + "-other"}})
	local, err = s.captureMirrorLocality(ctx, facts, coord.ObjectType, id, input, nil)
	require.NoError(t, err)
	require.False(t, local)
}

// Настоящие RR/RC, prelocks, owner prepare, final epoch clock и command.Apply.
// Отрицательные DML используют runtime LOGIN и rollback каждого savepoint.
func BindingMirrorPreparedApplyForTest(t *testing.T, ctx context.Context, repo *Repository, bundle *granteffect.Bundle, id, other domain.AccessBindingID, account string) {
	t.Helper()
	owner, err := NewGroupMembershipParticipant(ctx, repo, bundle)
	require.NoError(t, err)
	p, err := owner.NewBindingStageParticipant(ctx, slog.Default())
	require.NoError(t, err)
	stage, err := p.stage(ctx, id, false)
	require.NoError(t, err)
	defer stage.close()
	require.False(t, stage.global)
	accounts := []string{account}
	in := kaname.AuthorityWriteIntent{Kind: kaname.AuthorityBinding, Bundle: bundle, Plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceAccounts, Accounts: []domain.AccountID{domain.AccountID(account)}}, Owners: []kaname.AuthorityOwnerRef{{Kind: "account", ID: account}}}
	w, err := repo.coordinatedAuthorityWriterWithBegin(ctx, in, "participant", stage.conn.BeginTx)
	require.NoError(t, err)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		require.NoError(t, w.Rollback(cleanup))
	}()
	expected := map[string]json.RawMessage{"": stage.epochs[""], "$generation": stage.epochs["$generation"], account: stage.epochs[account]}
	epochs, err := json.Marshal(expected)
	require.NoError(t, err)
	var at time.Time
	require.NoError(t, w.tx.QueryRow(ctx, `SELECT kaname.authority_binding_epoch_lock($1::text[],$2::jsonb)`, accounts, epochs).Scan(&at))
	store := &reconcileStore{tx: w.tx, cat: p.facts, decisionAt: at}
	require.NoError(t, store.AcquireBindingLock(ctx, id))
	require.NoError(t, store.LockBindingsAndRoles(ctx, []domain.AccessBindingID{id}))
	_, err = (&abReader{tx: w.tx}).Get(ctx, id)
	require.NoError(t, err)
	require.NoError(t, grantMutationPreflight(ctx, w.tx, "binding"))
	require.NoError(t, lockGrantChildren(ctx, w.tx))
	require.NoError(t, prelockBindingCommands(ctx, w.tx))
	var commands []reconcile.BindingCommand
	rows, err := w.tx.Query(ctx, `SELECT body FROM pg_temp.kaname_binding_stage ORDER BY phase,seq`)
	require.NoError(t, err)
	for rows.Next() {
		var raw []byte
		require.NoError(t, rows.Scan(&raw))
		var c reconcile.BindingCommand
		require.NoError(t, json.Unmarshal(raw, &c))
		commands = append(commands, c)
	}
	err = rows.Err()
	rows.Close()
	require.NoError(t, err)
	var member domain.TargetMember
	for _, c := range commands {
		if c.Kind == "members" && len(c.Members) > 0 {
			member = c.Members[0]
			break
		}
	}
	require.Equal(t, "vpc.network", member.ObjectType)
	budget := stage.sequence.parents.source.budget
	beforeReads, beforeRows := budget.RemainingReads(), budget.RemainingRows()
	require.NoError(t, stage.sequence.prepare(ctx, w.tx, id, accounts, epochs))
	require.Same(t, budget, stage.sequence.parents.source.budget)
	require.LessOrEqual(t, budget.RemainingReads(), beforeReads-8, "6 actual fold reads + existing prepare 2, не новый budget")
	require.Less(t, budget.RemainingRows(), beforeRows)
	insert := `INSERT INTO kaname.access_binding_target_members(binding_id,role_id,rule_fp,object_type,object_id,verification_status) VALUES($1,$2,$3,$4,$5,$6)`
	tryDenied := func(label string, fn func() error) {
		t.Helper()
		_, e := w.tx.Exec(ctx, `SAVEPOINT mirror_apply`)
		require.NoError(t, e)
		e = fn()
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		_, rollbackErr := w.tx.Exec(cleanup, `ROLLBACK TO SAVEPOINT mirror_apply`)
		cancel()
		require.NoError(t, rollbackErr)
		var pgerr *pgconn.PgError
		require.ErrorAs(t, e, &pgerr, label)
		require.Equal(t, "42501", pgerr.Code, label)
	}
	writeMember := func(binding domain.AccessBindingID, typ, object string) error {
		_, e := w.tx.Exec(ctx, insert, string(binding), string(member.RoleID), member.RuleFP, typ, object, member.VerificationStatus)
		return e
	}
	tryDenied("before_final_clock", func() error { return writeMember(id, member.ObjectType, member.ObjectID) })
	require.NoError(t, w.tx.QueryRow(ctx, `SELECT kaname.authority_binding_epoch_lock($1::text[],$2::jsonb)`, accounts, epochs).Scan(&at))
	w.fence.decisionAt = at.UTC()
	store.decisionAt = at.UTC()
	_, err = w.tx.Exec(ctx, `SELECT kaname.authority_binding_stage_sequence_finalize_v3($1)`, string(id))
	require.NoError(t, err)
	// Та же настоящая RC-программа: positive, повреждение, новый BEFORE отказ,
	// rollback повреждения и снова positive без смены backend или TX.
	var paired bool
	require.NoError(t, w.tx.QueryRow(ctx, `SELECT kaname.test_binding_mirror_invocation_v4('pair')`).Scan(&paired))
	require.True(t, paired)
	for _, fault := range []struct{ mode, message string }{
		{"root", "authority cluster barrier missing"},
		{"account", "authority account barrier missing"},
		{"consumer", "authority consumer v2 witness mismatch"},
		{"mirror_nonce", "binding mirror program identity changed"},
		{"clock", "binding mirror write before final held proof"},
		{"population", "authority population latch mode mismatch"},
	} {
		tryDenied("fresh_"+fault.mode, func() error {
			_, e := w.tx.Exec(ctx, `SELECT kaname.test_binding_mirror_invocation_v4($1)`, fault.mode)
			var pgerr *pgconn.PgError
			require.ErrorAs(t, e, &pgerr, fault.mode)
			require.Equal(t, fault.message, pgerr.Message, fault.mode)
			return e
		})
		require.NoError(t, w.tx.QueryRow(ctx, `SELECT kaname.test_binding_mirror_invocation_v4('pair')`).Scan(&paired))
		require.True(t, paired)
	}
	tryDenied("private_probe", func() error {
		_, e := w.tx.Exec(ctx, `SELECT * FROM kaname._authority_binding_mirror_probe_v4()`)
		return e
	})
	tryDenied("wrong_binding", func() error { return writeMember(other, member.ObjectType, member.ObjectID) })
	tryDenied("wrong_coordinate", func() error { return writeMember(id, member.ObjectType, member.ObjectID+"-forged") })
	tryDenied("forged_owner_program", func() error {
		_, e := w.tx.Exec(ctx, `UPDATE pg_temp.kaname_binding_mirror_program SET accounts='[]'::jsonb`)
		return e
	})
	tryDenied("private_scope_approval", func() error {
		_, e := w.tx.Exec(ctx, `SELECT kaname._authority_binding_mirror_before_write_v3('access_binding_target_members','INSERT',NULL,'{}'::jsonb)`)
		return e
	})
	for _, c := range commands {
		require.NoError(t, c.Apply(ctx, &preparedBindingStageStore{reconcileStore: store, at: at.UTC()}))
	}
	t.Logf("actual local apply rollback: commands=%d reads_before=%d reads_after=%d rows_before=%d rows_after=%d", len(commands), beforeReads, budget.RemainingReads(), beforeRows, budget.RemainingRows())
}

// Test-first: точные owner commands получены настоящим RR compiler. Меняется
// только выполнение готовой программы после обычных prelocks и finalization.
// Ошибка возвращается после rollback; успешный COMMIT намеренно виден observer.
func BindingMirrorProgramCommitForTest(t *testing.T, ctx context.Context, repo *Repository, bundle *granteffect.Bundle, id domain.AccessBindingID, account, mutation string) error {
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
	if mutation == "record_before_members" {
		// Та же законная record-команда, но до первого required member.
		if err = commands[recordAt].Apply(ctx, apply); err != nil {
			return err
		}
	}
	for i, command := range commands {
		if mutation == "omit_required_members" && command.Kind == "members" {
			continue
		}
		if mutation == "record_before_members" && i == recordAt {
			continue
		}
		if err = command.Apply(ctx, apply); err != nil {
			return err
		}
		if mutation == "replay_record" && i == recordAt {
			// Второе применение сверх одного certified command. Это отдельный
			// INSERT attempt, не законная UPDATE половина одного UPSERT.
			if err = command.Apply(ctx, apply); err != nil {
				return err
			}
		}
	}
	// Не подменять COMMIT принудительным rollback: именно здесь должен
	// сработать completion отказ при пропуске required physical effect.
	// Тот же actual pgx COMMIT без mapErr: сохраняем SQLSTATE сервера,
	// чтобы transport/timeout отказ не засчитывался за completion oracle.
	return writer.tx.Commit(ctx)
}
