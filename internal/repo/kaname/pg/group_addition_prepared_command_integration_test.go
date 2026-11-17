// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	abrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
)

func groupAddCommandOpen(t *testing.T, ctx context.Context, factory *kanamepg.GrantPolicyWriters, actor domain.Subject, member domain.GroupMember) kaname.SemanticAuthorityWriter {
	t.Helper()
	w, err := factory.GroupAdditionAuthorityWriter(ctx, member, actor)
	require.NoError(t, err)
	require.NotNil(t, w)
	roleFinalCleanup(t, w)
	require.NoError(t, grantpolicy.RequireGroupAddition(ctx, w, actor, member))
	require.NoError(t, w.GroupsW().RequireMemberOfGroupAccount(ctx, member))
	return w
}

func groupAddCommandFGA(ctx context.Context, w kaname.SemanticAuthorityWriter, member domain.GroupMember) error {
	return w.EmitFGARelationWrite(ctx, []service.RelationTuple{{User: string(member.MemberType) + ":" + string(member.MemberID), Relation: "member", Object: "group:" + string(member.GroupID)}})
}

func groupAddCommandSubject(ctx context.Context, w kaname.SemanticAuthorityWriter, member domain.GroupMember) error {
	return w.AccessBindingsW().EmitSubjectChangeEvent(ctx, abrepo.SubjectChangeEvent{SubjectID: string(member.MemberID), SubjectType: string(member.MemberType), Op: "group_member_change", EventType: "group_member_change"})
}

// Снимок включает реальные строки и policy revisions; sequence gaps после
// rollback допустимы по исходной семантике PostgreSQL и не являются строками.
func groupAddCommandSnapshot(t *testing.T, r protocolRig, member domain.GroupMember) string {
	t.Helper()
	var snapshot string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_build_object(
 'members',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY member_type,member_id),'[]'::jsonb) FROM kaname.group_members m WHERE group_id=$1),
 'facts',(SELECT coalesce(jsonb_agg(to_jsonb(f) ORDER BY subject),'[]'::jsonb) FROM kaname.relation_fact f WHERE object_type='group' AND object_id=$1),
 'journal',(SELECT coalesce(jsonb_agg(to_jsonb(j) ORDER BY sequence_no),'[]'::jsonb) FROM kaname.resource_journal j WHERE resource_kind='iam_group' AND resource_id=$1),
 'fga',(SELECT coalesce(jsonb_agg(to_jsonb(f) ORDER BY id),'[]'::jsonb) FROM kaname.fga_outbox f WHERE payload->>'object'='group:'||$1),
 'subject',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY id),'[]'::jsonb) FROM kaname.subject_change_outbox s WHERE subject_id=$2),
 'epoch',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY key),'[]'::jsonb) FROM kaname.authority_policy_epoch e WHERE key=ANY(ARRAY['*','group:'||$1,$3,'scope:'||$4])))::text`,
		string(member.GroupID), string(member.MemberID), string(member.MemberType)+":"+string(member.MemberID), r.a).Scan(&snapshot))
	return snapshot
}

func groupAddCommandDenied(t *testing.T, err error) {
	t.Helper()
	var pe *pgconn.PgError
	require.ErrorAs(t, err, &pe, "отказ должен исходить из actual ordinary LOGIN SQL")
	require.Equal(t, "42501", pe.Code)
}

// Одна настоящая база и один FULL cutover для всех недорогих mutants.
// Перед каждым mutant открывается новая actual TX; после отказа сравнивается
// полный снимок, включая эффекты body, fold и policy invalidation.
func TestGroupAdditionPreparedCommandDatabaseNegatives(t *testing.T) {
	r := writerProtocolRig(t)
	g, uid, _ := membershipFixture(t, r)
	_, _ = fullContractActivate(t, r)
	full, observed := sequenceObservedFullRepo(t, r)
	factory, err := kanamepg.NewGrantPolicyWriters(r.ctx, full, r.bundle)
	require.NoError(t, err)
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)}
	member := domain.GroupMember{GroupID: g.ID, MemberType: domain.SubjectTypeUser, MemberID: domain.SubjectID(uid)}
	before := groupAddCommandSnapshot(t, r, member)
	cases := []struct {
		name, probe string
		steps       int
	}{
		{"omit-body", "commit", 0},
		{"omit-fga-and-subject", "commit", 1},
		{"omit-subject", "commit", 2},
		{"member-group", "member-group", 0},
		{"member-type", "member-type", 0},
		{"member-id", "member-id", 0},
		{"member-stamp", "member-stamp", 0},
		{"member-replay", "member-replay", 1},
		{"group-empty-delete", "group-empty-delete", 0},
		{"fact-empty-delete", "fact-empty-delete", 0},
		{"subject-empty-delete", "subject-empty-delete", 0},
		{"direct-fact", "direct-fact", 0},
		{"direct-journal", "direct-journal", 0},
		{"wrong-origin", "wrong-origin", 0},
		{"fga-before-member", "fga-replay", 0},
		{"fga-foreign", "fga-foreign", 1},
		{"fga-explicit-id", "fga-explicit-id", 1},
		{"fga-replay", "fga-replay", 2},
		{"subject-before-fold", "subject-replay", 1},
		{"subject-foreign", "subject-foreign", 2},
		{"subject-explicit-id", "subject-explicit-id", 2},
		{"subject-replay", "subject-replay", 3},
		{"prepare-reentry", "prepare-reentry", 0},
		{"finalize-reentry", "finalize-reentry", 0},
		{"finalize-mismatch", "finalize-mismatch", 0},
		{"private-state-write", "private-state-write", 0},
		{"private-program-write", "private-program-write", 0},
		{"private-effects-write", "private-effects-write", 0},
		{"private-completion", "private-completion", 0},
		{"public-fold", "public-fold", 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := fullMeasurementRigContext(t, r)
			observed.take()
			w := groupAddCommandOpen(t, r.ctx, factory, actor, member)
			if tc.steps >= 1 {
				require.NoError(t, w.GroupsW().AddMember(r.ctx, member))
			}
			if tc.steps >= 2 {
				require.NoError(t, groupAddCommandFGA(r.ctx, w, member))
			}
			if tc.steps >= 3 {
				require.NoError(t, groupAddCommandSubject(r.ctx, w, member))
			}
			groupAddCommandDenied(t, kanamepg.GroupAdditionProbeForTest(r.ctx, w, tc.probe))
			groupAddCommandDenied(t, observed.last())
			_ = w.Rollback(context.WithoutCancel(r.ctx))
			require.Equal(t, before, groupAddCommandSnapshot(t, r, member))
		})
	}
	// Законный близнец проходит через те же guards и independent deferred COMMIT.
	t.Run("complete-raw-commit", func(t *testing.T) {
		r := fullMeasurementRigContext(t, r)
		w := groupAddCommandOpen(t, r.ctx, factory, actor, member)
		require.NoError(t, w.GroupsW().AddMember(r.ctx, member))
		require.NoError(t, groupAddCommandFGA(r.ctx, w, member))
		require.NoError(t, groupAddCommandSubject(r.ctx, w, member))
		require.NoError(t, kanamepg.GroupAdditionProbeForTest(r.ctx, w, "commit"))
		membershipCounts(t, r, string(g.ID), "user:"+uid, 1)
		var addedAt time.Time
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT added_at FROM kaname.group_members WHERE group_id=$1 AND member_type='user' AND member_id=$2`, string(g.ID), uid).Scan(&addedAt))
		require.True(t, addedAt.Equal(w.AuthorityFence().DecisionAt()), "actual NEW использует final decision stamp")
	})
	// Дубликат не получает journal slot, но omission остальных двух эффектов
	// по-прежнему отвергается самой БД, даже при обходе writer.Commit.
	r = fullMeasurementRigContext(t, r)
	after := groupAddCommandSnapshot(t, r, member)
	t.Run("duplicate-omit-subject", func(t *testing.T) {
		r := fullMeasurementRigContext(t, r)
		w := groupAddCommandOpen(t, r.ctx, factory, actor, member)
		require.NoError(t, w.GroupsW().AddMember(r.ctx, member))
		require.NoError(t, groupAddCommandFGA(r.ctx, w, member))
		groupAddCommandDenied(t, kanamepg.GroupAdditionProbeForTest(r.ctx, w, "commit"))
		_ = w.Rollback(context.WithoutCancel(r.ctx))
		require.Equal(t, after, groupAddCommandSnapshot(t, r, member))
	})
	t.Run("rollback-and-stale-handle", func(t *testing.T) {
		r := fullMeasurementRigContext(t, r)
		w := groupAddCommandOpen(t, r.ctx, factory, actor, member)
		require.NoError(t, w.GroupsW().AddMember(r.ctx, member))
		require.NoError(t, groupAddCommandFGA(r.ctx, w, member))
		require.NoError(t, groupAddCommandSubject(r.ctx, w, member))
		require.NoError(t, w.Rollback(r.ctx))
		require.ErrorIs(t, kanamepg.GroupAdditionProbeForTest(r.ctx, w, "member-replay"), pgx.ErrTxClosed)
		require.Equal(t, after, groupAddCommandSnapshot(t, r, member))
	})
	t.Run("canceled-factory", func(t *testing.T) {
		r := fullMeasurementRigContext(t, r)
		ctx, cancel := context.WithCancel(r.ctx)
		cancel()
		w, err := factory.GroupAdditionAuthorityWriter(ctx, member, actor)
		require.ErrorIs(t, err, context.Canceled)
		require.Nil(t, w)
		require.Equal(t, after, groupAddCommandSnapshot(t, r, member))
	})
	authorityWaitReleased(t, r.runtime)
}

// Owner fault создаётся только тестом, не является production entry. Он умеет
// испортить nonce либо убрать state; guard обязан заметить разрыв с уже
// подписанной sequence program. После rollback состояние восстанавливается.
func TestGroupAdditionPreparedCommandNonceCustody(t *testing.T) {
	r := writerProtocolRig(t)
	g, uid, _ := membershipFixture(t, r)
	_, err := r.admin.Exec(r.ctx, `CREATE FUNCTION kaname.test_group_add_corrupt_state_v3(p_mode text) RETURNS void
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 BEGIN
 CASE p_mode
 WHEN 'corrupt-command-nonce' THEN UPDATE pg_temp.kaname_group_add_command SET nonce='00000000-0000-0000-0000-000000000000'::uuid;
 WHEN 'corrupt-command-empty' THEN DELETE FROM pg_temp.kaname_group_add_command;
 WHEN 'corrupt-command-missing' THEN DROP TABLE pg_temp.kaname_group_add_command;
 ELSE RAISE EXCEPTION 'неизвестный TEST fault';END CASE;
 END $$;
 REVOKE ALL ON FUNCTION kaname.test_group_add_corrupt_state_v3(text) FROM PUBLIC`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = r.admin.Exec(context.WithoutCancel(r.ctx), `DROP FUNCTION kaname.test_group_add_corrupt_state_v3(text)`)
	})
	_, err = r.admin.Exec(r.ctx, `GRANT EXECUTE ON FUNCTION kaname.test_group_add_corrupt_state_v3(text) TO `+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	full, _ := fullContractActivate(t, r)
	factory, err := kanamepg.NewGrantPolicyWriters(r.ctx, full, r.bundle)
	require.NoError(t, err)
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)}
	member := domain.GroupMember{GroupID: g.ID, MemberType: domain.SubjectTypeUser, MemberID: domain.SubjectID(uid)}
	before := groupAddCommandSnapshot(t, r, member)
	for _, fault := range []string{"corrupt-command-nonce", "corrupt-command-empty", "corrupt-command-missing"} {
		t.Run(fault, func(t *testing.T) {
			r := fullMeasurementRigContext(t, r)
			w := groupAddCommandOpen(t, r.ctx, factory, actor, member)
			require.NoError(t, w.GroupsW().AddMember(r.ctx, member))
			require.NoError(t, groupAddCommandFGA(r.ctx, w, member))
			require.NoError(t, kanamepg.GroupAdditionProbeForTest(r.ctx, w, fault))
			groupAddCommandDenied(t, kanamepg.GroupAdditionProbeForTest(r.ctx, w, "commit"))
			_ = w.Rollback(context.WithoutCancel(r.ctx))
			require.Equal(t, before, groupAddCommandSnapshot(t, r, member))
		})
	}
}

// Один fixture; каждый holder подтверждает actual lock до старта фабрики.
// Проверяем место ожидания в pg_stat_activity, затем final decision_at после
// release. Тест не выводит preclock из скорости ответа и не уменьшает workload.
func TestGroupAdditionPreparedCommandWaitsBeforeFinalClock(t *testing.T) {
	r := writerProtocolRig(t)
	g, uid, sa := membershipFixture(t, r)
	_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.group_members(group_id,member_type,member_id,added_at) VALUES($1,'service_account',$2,now())`, string(g.ID), sa)
	require.NoError(t, err)
	_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject,source_version) VALUES('group',$1,'member','service_account:'||$2,now())`, string(g.ID), sa)
	require.NoError(t, err)
	_, _ = fullContractActivate(t, r)
	cfg := r.runtime.Config()
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(r.ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	base := kanamepg.New(pool, nil)
	contract, err := kanamepg.NewFullWriterContract(r.ctx, base, r.bundle)
	require.NoError(t, err)
	full, err := base.WithFullWriterContract(contract)
	require.NoError(t, err)
	factory, err := kanamepg.NewGrantPolicyWriters(r.ctx, full, r.bundle)
	require.NoError(t, err)
	var pid int
	require.NoError(t, pool.QueryRow(r.ctx, `SELECT pg_backend_pid()`).Scan(&pid))
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)}
	for _, name := range []string{"d3-membership", "d3-user", "d3-sa", "group-member", "relation-fact", "table-fga", "sequence-resource", "sequence-fga", "sequence-subject", "cancel-preparation"} {
		t.Run(name, func(t *testing.T) {
			r := fullMeasurementRigContext(t, r)
			member := domain.GroupMember{GroupID: g.ID, MemberType: domain.SubjectTypeUser, MemberID: domain.SubjectID(uid)}
			if name == "d3-sa" || name == "group-member" || name == "relation-fact" {
				member.MemberType, member.MemberID = domain.SubjectTypeServiceAccount, domain.SubjectID(sa)
			}
			before := groupAddCommandSnapshot(t, r, member)
			holder, err := r.admin.Begin(r.ctx)
			require.NoError(t, err)
			lifecycleRollback(t, holder)
			var holderPID int
			require.NoError(t, holder.QueryRow(r.ctx, `SELECT pg_backend_pid()`).Scan(&holderPID))
			var query string
			var args []any
			switch name {
			case "d3-membership", "cancel-preparation":
				query, args = `SELECT 1 FROM kaname.memberships WHERE user_id=$1 AND account_id=$2 AND state='ACTIVE' FOR UPDATE`, []any{uid, r.a}
			case "d3-user":
				query, args = `SELECT 1 FROM kaname.users WHERE id=$1 FOR UPDATE`, []any{uid}
			case "d3-sa":
				query, args = `SELECT 1 FROM kaname.service_accounts WHERE id=$1 FOR UPDATE`, []any{sa}
			case "group-member":
				query, args = `SELECT 1 FROM kaname.group_members WHERE group_id=$1 AND member_type='service_account' AND member_id=$2 FOR UPDATE`, []any{string(g.ID), sa}
			case "relation-fact":
				query, args = `SELECT 1 FROM kaname.relation_fact WHERE object_type='group' AND object_id=$1 AND relation='member' AND subject='service_account:'||$2 FOR UPDATE`, []any{string(g.ID), sa}
			case "table-fga":
				_, err = holder.Exec(r.ctx, `LOCK TABLE kaname.fga_outbox IN SHARE MODE`)
				require.NoError(t, err)
			default:
				sequence, namespace := "resource_journal_sequence_no_seq", 1262569304
				if name == "sequence-fga" {
					sequence, namespace = "fga_outbox_id_seq", 1262569305
				} else if name == "sequence-subject" {
					sequence, namespace = "subject_change_outbox_id_seq", 1262569301
				}
				var next int64
				require.NoError(t, holder.QueryRow(r.ctx, `SELECT last_value+CASE WHEN is_called THEN 1 ELSE 0 END FROM kaname.`+pgx.Identifier{sequence}.Sanitize()).Scan(&next))
				_, err = holder.Exec(r.ctx, `SELECT pg_advisory_xact_lock($1,hashtext($2::bigint::text))`, namespace, next)
				require.NoError(t, err)
			}
			if query != "" {
				var held int
				require.NoError(t, holder.QueryRow(r.ctx, query, args...).Scan(&held))
				require.Equal(t, 1, held)
			}
			ctx, cancel := context.WithCancel(r.ctx)
			defer cancel()
			var decided time.Time
			done := lifecycleAsync(t, ctx, func(ctx context.Context) error {
				w, err := factory.GroupAdditionAuthorityWriter(ctx, member, actor)
				if err != nil {
					return err
				}
				defer w.Rollback(context.WithoutCancel(ctx))
				decided = w.AuthorityFence().DecisionAt()
				if err = grantpolicy.RequireGroupAddition(ctx, w, actor, member); err != nil {
					return err
				}
				if err = w.GroupsW().RequireMemberOfGroupAccount(ctx, member); err != nil {
					return err
				}
				if err = w.GroupsW().AddMember(ctx, member); err != nil {
					return err
				}
				if err = groupAddCommandFGA(ctx, w, member); err != nil {
					return err
				}
				return groupAddCommandSubject(ctx, w, member)
			})
			require.Eventually(t, func() bool {
				var blocked bool
				err := r.admin.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND $2=ANY(pg_blocking_pids(pid)) AND query LIKE '%authority_group_add_prepare_v3%')`, pid, holderPID).Scan(&blocked)
				return err == nil && blocked
			}, 20*time.Second, 10*time.Millisecond, "actual wait обязан находиться внутри prepare до второй policy clock")
			if name == "cancel-preparation" {
				cancel()
				require.Error(t, lifecycleResult(t, r.ctx, done))
				require.True(t, decided.IsZero())
				require.NoError(t, holder.Rollback(r.ctx))
			} else {
				var releaseFloor time.Time
				require.NoError(t, holder.QueryRow(r.ctx, `SELECT clock_timestamp()`).Scan(&releaseFloor))
				require.NoError(t, holder.Rollback(r.ctx))
				require.NoError(t, lifecycleResult(t, r.ctx, done))
				require.False(t, decided.Before(releaseFloor))
			}
			require.Equal(t, before, groupAddCommandSnapshot(t, r, member))
			authorityWaitReleased(t, pool)
		})
	}
}

var groupAddCommandSignatures = []string{
	"_authority_group_add_program_v3()",
	"authority_group_add_prepare_v3(jsonb,integer,integer)",
	"authority_group_add_finalize_v3(jsonb,integer,integer)",
	"_authority_group_add_row_v3(text,text,jsonb,jsonb)",
	"_authority_group_add_statement_v3(text,text)",
	"authority_group_add_fold_v3(text,jsonb,timestamp with time zone)",
	"authority_group_add_subject_id_v3()",
	"_authority_group_add_subject_v3(text,text,jsonb)",
	"_authority_group_add_complete_v3()",
	"_authority_group_add_storage_v3()",
}

// Все owner faults откатываются отдельно на одном fixture. Проверяется actual
// transitive readiness, а не только сравнение ожидаемого хеша в тестовом Go.
func TestGroupAdditionPreparedCommandReadinessABIAndACL(t *testing.T) {
	r := writerProtocolRig(t)
	var ready bool
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT kaname.authority_crud_storage_v3()`).Scan(&ready))
	require.True(t, ready)
	signatures := append([]string{}, groupAddCommandSignatures...)
	signatures = append(signatures, "relation_fact_fold_row(text,jsonb,timestamp with time zone)", "relation_fact_from_journal()", "authority_subject_change_id_guard_v2()", "authority_subject_change_applied_v2()", "authority_subject_change_statement_guard_v2()")
	for _, signature := range signatures {
		t.Run("body/"+signature, func(t *testing.T) {
			r := fullMeasurementRigContext(t, r)
			tx, err := r.admin.Begin(r.ctx)
			require.NoError(t, err)
			lifecycleRollback(t, tx)
			var definition string
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT pg_get_functiondef(to_regprocedure('kaname.'||$1))`, signature).Scan(&definition))
			require.Contains(t, definition, "AS $function$")
			_, err = tx.Exec(r.ctx, strings.Replace(definition, "AS $function$", "AS $function$\n-- TEST: изменён actual prosrc\n", 1))
			require.NoError(t, err)
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname._authority_full_contract_storage_v3()`).Scan(&ready))
			require.False(t, ready)
			require.NoError(t, tx.Rollback(r.ctx))
			require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT kaname.authority_crud_storage_v3()`).Scan(&ready))
			require.True(t, ready)
		})
		if strings.HasPrefix(signature, "_") {
			t.Run("private-acl/"+signature, func(t *testing.T) {
				r := fullMeasurementRigContext(t, r)
				tx, err := r.admin.Begin(r.ctx)
				require.NoError(t, err)
				lifecycleRollback(t, tx)
				_, err = tx.Exec(r.ctx, `GRANT EXECUTE ON FUNCTION kaname.`+signature+` TO `+pgx.Identifier{r.role}.Sanitize())
				require.NoError(t, err)
				require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname._authority_full_contract_storage_v3()`).Scan(&ready))
				require.False(t, ready)
				require.NoError(t, tx.Rollback(r.ctx))
			})
		}
	}
	for _, edge := range [][2]string{{"fga_outbox", "relation_fact_follows_journal"}, {"subject_change_outbox", "authority_subject_change_id_guard_v2"}, {"subject_change_outbox", "authority_subject_change_applied_v2"}, {"subject_change_outbox", "authority_subject_change_statement_guard_v2"}} {
		t.Run("attachment/"+edge[1], func(t *testing.T) {
			r := fullMeasurementRigContext(t, r)
			tx, err := r.admin.Begin(r.ctx)
			require.NoError(t, err)
			lifecycleRollback(t, tx)
			_, err = tx.Exec(r.ctx, `ALTER TABLE kaname.`+pgx.Identifier{edge[0]}.Sanitize()+` DISABLE TRIGGER `+pgx.Identifier{edge[1]}.Sanitize())
			require.NoError(t, err)
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname._authority_full_contract_storage_v3()`).Scan(&ready))
			require.False(t, ready)
			require.NoError(t, tx.Rollback(r.ctx))
		})
	}
	for _, mutation := range []string{
		`ALTER FUNCTION kaname.authority_group_add_finalize_v3(jsonb,integer,integer) STRICT`,
		`ALTER FUNCTION kaname.authority_group_add_prepare_v3(jsonb,integer,integer) SECURITY INVOKER`,
		`ALTER FUNCTION kaname.authority_group_add_fold_v3(text,jsonb,timestamptz) PARALLEL SAFE`,
		`ALTER FUNCTION kaname.authority_group_add_subject_id_v3() RESET ALL`,
		`ALTER TABLE kaname.subject_change_outbox ALTER COLUMN id SET DEFAULT nextval('kaname.subject_change_outbox_id_seq'::regclass)`,
	} {
		t.Run(mutation, func(t *testing.T) {
			r := fullMeasurementRigContext(t, r)
			tx, err := r.admin.Begin(r.ctx)
			require.NoError(t, err)
			lifecycleRollback(t, tx)
			_, err = tx.Exec(r.ctx, mutation)
			require.NoError(t, err)
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname._authority_full_contract_storage_v3()`).Scan(&ready))
			require.False(t, ready)
			require.NoError(t, tx.Rollback(r.ctx))
		})
	}
}

// Down/Up проверяется настоящим Goose и exact definition/owner/ACL снимком.
// Active FULL refusal уже независимо покрыт неизменённым исходным тестом.
func TestGroupAdditionPreparedCommandGooseRoundTrip(t *testing.T) {
	r := writerProtocolRig(t)
	db, own, previous := sevenCRUDMigrationDB(t, r)
	const stateSQL = `SELECT jsonb_build_object(
 'functions',(SELECT jsonb_agg(jsonb_build_object('name',proname,'definition',pg_get_functiondef(oid),'acl',proacl,'owner',proowner) ORDER BY proname) FROM pg_proc WHERE pronamespace='kaname'::regnamespace AND (proname LIKE '%group_add%v3' OR proname IN ('relation_fact_fold_row','authority_subject_change_id_guard_v2','authority_subject_change_applied_v2','authority_subject_change_statement_guard_v2','_authority_resource_subject_change_wait_v2'))),
 'default',(SELECT pg_get_expr(d.adbin,d.adrelid) FROM pg_attrdef d JOIN pg_attribute a ON a.attrelid=d.adrelid AND a.attnum=d.adnum WHERE a.attrelid='kaname.subject_change_outbox'::regclass AND a.attname='id'))::text`
	var before, after string
	require.NoError(t, r.admin.QueryRow(r.ctx, stateSQL).Scan(&before))
	t.Cleanup(func() { require.NoError(t, goose.UpTo(db, ".", own)) })
	require.NoError(t, goose.Down(db, "."))
	version, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Equal(t, previous, version)
	var count int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM pg_proc WHERE pronamespace='kaname'::regnamespace AND proname LIKE '%group_add%v3'`).Scan(&count))
	require.Zero(t, count)
	var originalDefault bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT pg_get_expr(d.adbin,d.adrelid) IN ('nextval(''kaname.subject_change_outbox_id_seq''::regclass)','nextval(''subject_change_outbox_id_seq''::regclass)') FROM pg_attrdef d JOIN pg_attribute a ON a.attrelid=d.adrelid AND a.attnum=d.adnum WHERE a.attrelid='kaname.subject_change_outbox'::regclass AND a.attname='id'`).Scan(&originalDefault))
	require.True(t, originalDefault)
	var ready bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT kaname._authority_full_contract_storage_v3()`).Scan(&ready))
	require.True(t, ready, "Down вернул прежние transitive pins и исходные 5 bodies")
	require.NoError(t, goose.UpTo(db, ".", own))
	require.NoError(t, r.admin.QueryRow(r.ctx, stateSQL).Scan(&after))
	require.Equal(t, before, after)
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT kaname.authority_crud_storage_v3()`).Scan(&ready))
	require.True(t, ready)
	for _, signature := range groupAddCommandSignatures {
		var allowed bool
		require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(current_user,to_regprocedure('kaname.'||$1),'EXECUTE')`, signature).Scan(&allowed))
		require.Equal(t, !strings.HasPrefix(signature, "_"), allowed, signature)
	}
}
