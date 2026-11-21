// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/PRO-Robotech/corelib/operations"
	accountapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/account"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/activewayin"
)

func TestFullSevenCRUDAccountDeletePreservesForeignPending(t *testing.T) {
	w := sevenCRUDPublicFixture(t, "account.delete", "", func(w *sevenCRUDPublicWorld) {
		// Schema-valid старое состояние: активная личность с домом A и PENDING в B.
		// Это Given до owner activation, не mutation обходом full contract.
		tag, err := w.r.admin.Exec(w.r.ctx, `UPDATE kaname.memberships SET state='PENDING' WHERE user_id=$1 AND account_id=$2`, w.member, w.r.b)
		require.NoError(t, err)
		require.EqualValues(t, 1, tag.RowsAffected())
	})
	require.Equal(t, 1, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.users u JOIN kaname.memberships m ON m.user_id=u.id WHERE u.id=$1 AND u.invite_status='ACTIVE' AND u.account_id=$2 AND m.account_id=$3 AND m.state='PENDING'`, w.member, w.r.a, w.r.b))
	call := func(ctx context.Context, f kaname.CRUDWriterFactory) (*operations.Operation, error) {
		return accountapp.NewDeleteAccountUseCase(w.full, w.ops).WithAccountDeleteWriter(f).Execute(ctx, w.account.ID)
	}
	sevenCRUDDeniedAndMissing(t, w, call)
	var foreignBefore, foreignAfter string
	const foreignSQL = `SELECT jsonb_build_array((SELECT to_jsonb(a) FROM kaname.accounts a WHERE id=$1),(SELECT to_jsonb(b) FROM kaname.access_bindings b WHERE id=$2),(SELECT jsonb_agg(to_jsonb(m) ORDER BY m.id) FROM kaname.memberships m WHERE account_id=$1),(SELECT jsonb_agg(to_jsonb(e) ORDER BY to_jsonb(e)::text) FROM kaname.access_binding_emitted_tuples e WHERE binding_id=$2))::text`
	require.NoError(t, w.r.admin.QueryRow(w.ctx, foreignSQL, w.r.b, string(w.foreignBinding)).Scan(&foreignBefore))
	var tupleAt, journalAt int64
	require.NoError(t, w.r.admin.QueryRow(w.ctx, `SELECT COALESCE((SELECT max(id) FROM kaname.fga_outbox),0),COALESCE((SELECT max(sequence_no) FROM kaname.resource_journal),0)`).Scan(&tupleAt, &journalAt))
	var expected, actual []string
	require.NoError(t, w.r.admin.QueryRow(w.ctx, `SELECT array_agg(k ORDER BY k) FROM (
 SELECT fga_user||'|'||relation||'|'||object AS k FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1
 UNION SELECT 'cluster:'||$2||'|cluster|account:'||$3
 UNION SELECT 'account:'||$3||'|account|iam_user:'||user_id FROM kaname.memberships WHERE account_id=$3) e`, string(w.binding), domain.ClusterSingletonID, w.r.a).Scan(&expected))
	require.Len(t, expected, 6, "две записи owner ledger, cluster и три membership pointers")
	var expectedUsers, actualUsers string
	require.NoError(t, w.r.admin.QueryRow(w.ctx, `SELECT jsonb_agg(to_jsonb(u)||jsonb_build_object('account_id',NULL) ORDER BY id)::text FROM kaname.users u WHERE account_id=$1`, w.r.a).Scan(&expectedUsers))
	op, err := call(declarerCtx(w.ctx, w.actor), w.factory)
	sevenCRUDResult(t, w, op, err, codes.OK)
	require.Zero(t, sevenCRUDCount(t, w, `SELECT (SELECT count(*) FROM kaname.accounts WHERE id=$1)+(SELECT count(*) FROM kaname.memberships WHERE account_id=$1)+(SELECT count(*) FROM kaname.access_bindings WHERE resource_type='account' AND resource_id=$1)+(SELECT count(*) FROM kaname.access_binding_subjects WHERE binding_id=$2)+(SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$2)`, w.r.a, string(w.binding)))
	require.Equal(t, 3, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.users WHERE id=ANY($1::text[]) AND account_id IS NULL`, []string{w.owner, w.member, w.unverified}))
	// Полный stored NEW, включая expected_login_kind, обязан совпасть после FK SET NULL.
	require.NoError(t, w.r.admin.QueryRow(w.ctx, `SELECT jsonb_agg(to_jsonb(u) ORDER BY id)::text FROM kaname.users u WHERE id=ANY($1::text[])`, []string{w.owner, w.member, w.unverified}).Scan(&actualUsers))
	require.Equal(t, expectedUsers, actualUsers)
	require.NoError(t, w.r.admin.QueryRow(w.ctx, foreignSQL, w.r.b, string(w.foreignBinding)).Scan(&foreignAfter))
	require.Equal(t, foreignBefore, foreignAfter, "чужой аккаунт, его binding, ledger и членства сохраняются побайтово")
	sevenCRUDFact(t, w, "account:"+w.r.b, "account", "iam_user:"+w.member, true)
	require.NoError(t, w.r.admin.QueryRow(w.ctx, `SELECT COALESCE(array_agg(k ORDER BY k),'{}'::text[]) FROM (
 SELECT (j.payload->>'user')||'|'||r.relation||'|'||(j.payload->>'object') AS k
 FROM kaname.fga_outbox j CROSS JOIN LATERAL jsonb_array_elements_text(CASE WHEN j.payload ? 'relations' THEN j.payload->'relations' ELSE jsonb_build_array(j.payload->>'relation') END) r(relation)
 WHERE j.id>$1 AND j.event_type='fga.tuple.delete') q`, tupleAt).Scan(&actual))
	require.Equal(t, expected, actual, "удаления равны сохранённой ведомости и реальным структурным указателям")
	require.Zero(t, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.relation_fact WHERE subject||'|'||relation||'|'||object_type||':'||object_id=ANY($1::text[])`, expected))
	sevenCRUDCommitted(t, w, "iam.account.deleted", "account", "iam.account", w.r.a)
	require.Equal(t, 1, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.resource_journal WHERE sequence_no>$1 AND resource_kind='account' AND resource_id=$2 AND event_type='DELETED' AND scope=jsonb_build_array(jsonb_build_object('type','cluster','id',$3::text))`, journalAt, w.r.a, domain.ClusterSingletonID))
	require.Equal(t, 1, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.resource_journal WHERE sequence_no>$1 AND resource_kind='iam_access_binding' AND resource_id=$2 AND event_type='DELETED' AND scope=jsonb_build_array(jsonb_build_object('type','account','id',$3::text))`, journalAt, string(w.binding), w.r.a))
	// SET NULL и снятие membership дают по одному UPDATED. Порядок FK callbacks
	// не обещан: промежуточная scope может ещё содержать удаляемый аккаунт,
	// но чужое членство обязано присутствовать в обеих строках своего человека.
	for _, uid := range []string{w.owner, w.member, w.unverified} {
		var count int
		var scopesOK bool
		require.NoError(t, w.r.admin.QueryRow(w.ctx, `SELECT count(*),COALESCE(bool_and(
 scope <@ jsonb_build_array(jsonb_build_object('type','account','id',$3::text),jsonb_build_object('type','account','id',$4::text))
 AND CASE WHEN $2=$5 THEN scope @> jsonb_build_array(jsonb_build_object('type','account','id',$4::text)) ELSE NOT scope @> jsonb_build_array(jsonb_build_object('type','account','id',$4::text)) END),false)
 FROM kaname.resource_journal WHERE sequence_no>$1 AND resource_kind='iam_user' AND resource_id=$2 AND event_type='UPDATED' AND payload->>'id'=$2`, journalAt, uid, w.r.a, w.r.b, w.member).Scan(&count, &scopesOK))
		require.Equal(t, 2, count)
		require.True(t, scopesOK)
	}
	require.Equal(t, 1, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.memberships WHERE user_id=$1 AND account_id=$2 AND state='PENDING'`, w.member, w.r.b))
	require.Equal(t, 8, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.resource_journal WHERE sequence_no>$1`, journalAt), "ровно account/binding DELETE и шесть user UPDATED")
	require.Equal(t, len(expected), sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.fga_outbox WHERE id>$1`, tupleAt), "нет лишних mirror FGA effects")

}

// Отдельная compatibility-проба спрашивает настоящий ActivateInvite и trigger,
// не приписывая raw writer полномочия full2. Посев и операции до Prepare/Activate.
func TestMembershipMirrorActivationTransitionAndRollback(t *testing.T) {
	r, owner := writerProtocolRigBeforePreparation(t)
	third, _ := sevenCRUDSeedAccount(t, r, "mirror-removed")
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	email := domain.Email(string(uid) + "@mirror.example")
	seed, err := owner.Writer(r.ctx)
	require.NoError(t, err)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = seed.Rollback(cleanup)
	}()
	for _, account := range []domain.AccountID{domain.AccountID(r.a), domain.AccountID(r.b), third.ID} {
		person, _, insertErr := seed.UsersW().InsertPending(r.ctx, domain.User{ID: uid, AccountID: account, Email: email, DisplayName: "Mirror pending"}, time.Time{})
		require.NoError(t, insertErr)
		require.Equal(t, uid, person.ID)
	}
	removed, err := seed.UsersW().RemoveMembership(r.ctx, uid, third.ID)
	require.NoError(t, err)
	require.True(t, removed)
	require.NoError(t, seed.Commit(r.ctx))
	markAddressVerified(t, r.ctx, r.admin, uid)
	const stateSQL = `SELECT jsonb_build_array(
      (SELECT to_jsonb(u) FROM kaname.users u WHERE id=$1),
      (SELECT jsonb_agg(to_jsonb(m) ORDER BY m.id) FROM kaname.memberships m WHERE user_id=$1),
      (SELECT count(*) FROM kaname.resource_journal),
      (SELECT count(*) FROM kaname.fga_outbox))::text`
	snapshot := func() string {
		var state string
		require.NoError(t, r.admin.QueryRow(r.ctx, stateSQL, string(uid)).Scan(&state))
		return state
	}
	before := snapshot()
	// Реальный переход PENDING→BLOCKED также сохраняет прежнюю non-PENDING
	// конвенцию, но эта проверка откатывается: права входа здесь не исследуются.
	blocked, err := owner.Writer(r.ctx)
	require.NoError(t, err)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = blocked.Rollback(cleanup)
	}()
	_, err = kanamepg.WriterTx(blocked).Exec(r.ctx, `UPDATE kaname.users SET invite_status='BLOCKED',external_id=$2 WHERE id=$1`, string(uid), "blocked-"+string(uid))
	require.NoError(t, err)
	var active int
	require.NoError(t, membershipMirrorQueryTx(t, blocked).QueryRow(r.ctx, `SELECT count(*) FROM kaname.memberships WHERE user_id=$1 AND state='ACTIVE'`, string(uid)).Scan(&active))
	require.Equal(t, 2, active)
	require.NoError(t, blocked.Rollback(r.ctx))
	require.Equal(t, before, snapshot())
	activate := func(commit bool) {
		tx, txErr := owner.Writer(r.ctx)
		require.NoError(t, txErr)
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = tx.Rollback(cleanup)
		}()
		_, activateErr := tx.UsersW().ActivateInvite(r.ctx, uid, domain.ExternalSubject("activated-"+string(uid)), "Mirror active")
		require.NoError(t, activateErr)
		activewayin.Seed(t, r.ctx, kanamepg.WriterTx(tx))
		var states []string
		require.NoError(t, membershipMirrorQueryTx(t, tx).QueryRow(r.ctx, `SELECT array_agg(state ORDER BY account_id) FROM kaname.memberships WHERE user_id=$1`, string(uid)).Scan(&states))
		require.Equal(t, []string{"ACTIVE", "ACTIVE"}, states)
		var resurrected int
		require.NoError(t, membershipMirrorQueryTx(t, tx).QueryRow(r.ctx, `SELECT count(*) FROM kaname.memberships WHERE user_id=$1 AND account_id=$2`, string(uid), string(third.ID)).Scan(&resurrected))
		require.Zero(t, resurrected)
		if commit {
			require.NoError(t, tx.Commit(r.ctx))
		} else {
			require.NoError(t, tx.Rollback(r.ctx))
		}
	}
	activate(false)
	require.Equal(t, before, snapshot(), "rollback снимает user/member/journal/FGA изменения")
	activate(true)
	require.NotEqual(t, before, snapshot())
	// Законное для схемы чужое PENDING не активируется повторно от правки
	// дома/пригласившего/no-op и ACTIVE↔BLOCKED. Локальная ветка не меняется.
	tag, err := r.admin.Exec(r.ctx, `UPDATE kaname.memberships SET state='PENDING' WHERE user_id=$1 AND account_id=$2`, string(uid), r.b)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())
	var foreignBefore, foreignAfter string
	const foreignSQL = `SELECT to_jsonb(m)::text FROM kaname.memberships m WHERE user_id=$1 AND account_id=$2`
	require.NoError(t, r.admin.QueryRow(r.ctx, foreignSQL, string(uid), r.b).Scan(&foreignBefore))
	for _, change := range []struct{ name, query string }{
		{"home-noop", `UPDATE kaname.users SET account_id=account_id WHERE id=$1`},
		{"inviter-noop", `UPDATE kaname.users SET invited_by=invited_by WHERE id=$1`},
		{"status-noop", `UPDATE kaname.users SET invite_status=invite_status WHERE id=$1`},
		{"active-to-blocked", `UPDATE kaname.users SET invite_status='BLOCKED' WHERE id=$1`},
		{"blocked-to-active", `UPDATE kaname.users SET invite_status='ACTIVE' WHERE id=$1`},
	} {
		t.Run(change.name, func(t *testing.T) {
			changed, updateErr := r.admin.Exec(r.ctx, change.query, string(uid))
			require.NoError(t, updateErr)
			require.EqualValues(t, 1, changed.RowsAffected())
			require.NoError(t, r.admin.QueryRow(r.ctx, foreignSQL, string(uid), r.b).Scan(&foreignAfter))
			require.Equal(t, foreignBefore, foreignAfter)
		})
	}
}

// Владелец меняет disposable schema только внутри откатываемой транзакции;
// runtime LOGIN не получает DDL, нового entry или private proof.
func TestMembershipMirrorReadinessRejectsChangedBodyAndDisabledTrigger(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	var ready bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT kaname._authority_full_contract_storage_v3()`).Scan(&ready))
	require.True(t, ready)
	for _, fault := range []struct{ name, query string }{
		{"body", `CREATE OR REPLACE FUNCTION kaname.membership_mirror_from_user() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$`},
		{"trigger", `ALTER TABLE kaname.users DISABLE TRIGGER membership_mirrors_user_row`},
	} {
		t.Run(fault.name, func(t *testing.T) {
			tx, err := r.admin.Begin(r.ctx)
			require.NoError(t, err)
			defer func() {
				cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = tx.Rollback(cleanup)
			}()
			_, err = tx.Exec(r.ctx, fault.query)
			require.NoError(t, err)
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname._authority_full_contract_storage_v3()`).Scan(&ready))
			require.False(t, ready)
			require.NoError(t, tx.Rollback(r.ctx))
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT kaname._authority_full_contract_storage_v3()`).Scan(&ready))
			require.True(t, ready)
		})
	}
}

// WriterTx уже возвращает underlying writeTx.tx, но объявляет только Exec.
// Узкое test-only приведение читает ту же TX: никакой второй pool connection,
// внешнего admin snapshot или нового production/exported API здесь нет.
func membershipMirrorQueryTx(t *testing.T, w kaname.Writer) pgx.Tx {
	t.Helper()
	tx, ok := kanamepg.WriterTx(w).(pgx.Tx)
	require.True(t, ok, "WriterTx должен содержать исходную pgx.Tx писателя")
	return tx
}
