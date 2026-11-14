// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	bindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/activewayin"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

// Cleanup устанавливается до первого assertion после открытия TX. Fatal на
// seed/gate/tail не оставляет lease и не зависит от отменённого test context.
func roleFinalCleanup(t *testing.T, tx interface{ Rollback(context.Context) error }) {
	t.Helper()
	if tx == nil {
		return
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(ctx)
	})
}

// Сохраняем прежний global drain и его 20s: это диагностическая поправка,
// не исправление пока неизвестной причины задержки /255. Даже own Done=true
// не превращает отказ общего ожидания в PASS.
func roleFinalAwaitOperation(t *testing.T, w delegationUCWorld, id string) *operations.Operation {
	t.Helper()
	wait, cancel := context.WithTimeout(w.r.ctx, 20*time.Second)
	err := operations.Wait(wait)
	cancel()
	if err != nil {
		roleFinalQueueDiagnostic(t, w, id)
		require.NoError(t, err, "исполнитель операций не завершил очередь; op=%s", id)
	}
	op, err := w.ops.Get(w.r.ctx, id)
	if err != nil || op == nil || !op.Done {
		roleFinalQueueDiagnostic(t, w, id)
	}
	require.NoErrorf(t, err, "операция %s не прочитана", id)
	require.NotNil(t, op, "операция %s отсутствует", id)
	require.Truef(t, op.Done, "операция %s не терминальна", id)
	return op
}

// Снимки выполняются ДО Fatal и pool cleanup, каждый с собственными 2s.
// Истёкший контекст теста не отменяет диагностику. Текст SQL, параметры,
// response и сообщения ошибок операции не выводятся: только код и hash SQL.
func roleFinalQueueDiagnostic(t *testing.T, w delegationUCWorld, id string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	op, err := w.ops.Get(ctx, id)
	cancel()
	if err != nil || op == nil {
		t.Logf("role queue diagnostic: op=%s own_get_unavailable=%v missing=%t test_context=%v", id, err, op == nil, w.r.ctx.Err())
	} else {
		t.Logf("role queue diagnostic: op=%s own_done=%t own_error_present=%t own_error_code=%d test_context=%v", id, op.Done, op.Error != nil, op.Error.GetCode(), w.r.ctx.Err())
	}
	stats := w.r.runtime.Stat()
	t.Logf("role queue diagnostic: op=%s runtime_pool acquired=%d idle=%d total=%d constructing=%d", id, stats.AcquiredConns(), stats.IdleConns(), stats.TotalConns(), stats.ConstructingConns())
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	var snapshot string
	err = w.r.admin.QueryRow(ctx, `SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY a.pid),'[]'::jsonb)::text
FROM (SELECT pid,state,wait_event_type,wait_event,pg_blocking_pids(pid) AS blocking_pids,
             query_id,md5(query) AS query_hash,extract(epoch FROM clock_timestamp()-query_start) AS query_age_seconds
      FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()
      ORDER BY pid LIMIT 16) a`).Scan(&snapshot)
	cancel()
	if err != nil {
		t.Logf("role queue diagnostic: op=%s database_snapshot_unavailable=%v", id, err)
		return
	}
	t.Logf("role queue diagnostic: op=%s database_snapshot_limit=16 activity=%s", id, snapshot)
}

func roleFinalCreate(t *testing.T, w delegationUCWorld, writers *kanamepg.GrantPolicyWriters, name string) domain.Role {
	t.Helper()
	uc := roleapp.NewCreateRoleUseCase(w.r.repo, w.ops, w.source)
	if writers != nil {
		uc.WithRoleAuthorityWriter(writers)
	}
	op, err := uc.Execute(declarerCtx(w.r.ctx, w.owner), domain.Role{AccountID: domain.AccountID(w.r.a), Name: domain.RoleName(name), Rules: domain.Rules{{Module: "iam", Resources: []string{"role"}, Verbs: []string{"list"}}}})
	require.NoError(t, err)
	require.Nil(t, roleFinalAwaitOperation(t, w, op.ID).Error)
	var id domain.RoleID
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT id FROM kaname.roles WHERE account_id=$1 AND name=$2`, w.r.a, name).Scan(&id))
	rd, err := w.r.repo.Reader(w.r.ctx)
	if rd != nil {
		roleFinalCleanup(t, rd)
	}
	require.NoError(t, err)
	r, err := rd.Roles().Get(w.r.ctx, id)
	require.NoError(t, err)
	require.NoError(t, rd.Rollback(w.r.ctx))
	return r
}

// Настоящий typed carrier + ledger/fold штатного tuple builder. До activation
// обычный writer законен; после activation helper вызываться не должен.
func roleFinalCarrier(t *testing.T, w delegationUCWorld, r domain.Role, subject domain.Subject) domain.AccessBindingID {
	t.Helper()
	tx, err := lifecycleOwner(w.r).Writer(w.r.ctx)
	if tx != nil {
		roleFinalCleanup(t, tx)
	}
	require.NoError(t, err)
	b, err := bindingset.Insert(w.r.ctx, tx.AccessBindingsW(), domain.AccessBinding{ID: domain.AccessBindingID(ids.NewID("acb")), SubjectType: subject.Type, SubjectID: subject.ID, RoleID: r.ID, ResourceType: "account", ResourceID: w.r.a, Scope: domain.ScopeAccount, Status: domain.AccessBindingStatusActive, Target: domain.AccessTarget{AllInScope: true}})
	require.NoError(t, err)
	tuples := bindingapp.NewRoleTupleReconciler().BuildRoleTuples(b, []domain.Subject{subject}, r)
	require.NotEmpty(t, tuples)
	require.NoError(t, tx.AccessBindingsW().InsertEmittedTuples(w.r.ctx, b.ID, tuples))
	require.NoError(t, tx.AccessBindingsW().EmitRelationWrite(w.r.ctx, tuples))
	require.NoError(t, tx.Commit(w.r.ctx))
	return b.ID
}

func roleFinalAdmin(t *testing.T, w delegationUCWorld) domain.AccessBindingID {
	t.Helper()
	tx, err := lifecycleOwner(w.r).Writer(w.r.ctx)
	if tx != nil {
		roleFinalCleanup(t, tx)
	}
	require.NoError(t, err)
	b, err := bindingset.Insert(w.r.ctx, tx.AccessBindingsW(), domain.AccessBinding{ID: domain.AccessBindingID(ids.NewID("acb")), SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(w.member), RoleID: domain.RoleID(domain.ClusterAdminRoleID), ResourceType: "account", ResourceID: w.r.a, Scope: domain.ScopeAccount, Status: domain.AccessBindingStatusActive, Target: domain.AccessTarget{AllInScope: true}})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(w.r.ctx))
	engine := reconcile.New(kanamepg.NewReconcileAdapter(w.r.admin, w.source), slog.Default(), w.source)
	require.NoError(t, engine.ReconcileBinding(w.r.ctx, b.ID))
	var holders int
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 AND member_object_type='iam.account' AND member_object_id=$2 AND fga_user=$3 AND relation='admin' AND object=$4`, b.ID, w.r.a, "user:"+w.member, "account:"+w.r.a).Scan(&holders))
	require.Equal(t, 1, holders)
	allowed, err := w.door.Check(w.r.ctx, "user:"+w.member, "admin", "account:"+w.r.a)
	require.NoError(t, err)
	require.True(t, allowed, "Дано: actual native admin из этой выдачи")
	return b.ID
}

// Мигрированная permissions-only роль — допустимый OLD источник. Исторический
// viewer строится production builder и writer, а не вставкой relation_fact.
func roleFinalLegacy(t *testing.T, w delegationUCWorld, r domain.Role) domain.Role {
	t.Helper()
	r.Rules = nil
	r.Permissions = domain.Permissions{"iam.account.*.get"}
	tx, err := lifecycleOwner(w.r).Writer(w.r.ctx)
	if tx != nil {
		roleFinalCleanup(t, tx)
	}
	require.NoError(t, err)
	r, err = tx.RolesW().Update(w.r.ctx, r, []string{"rules", "permissions"})
	require.NoError(t, err)
	require.NoError(t, tx.RolesW().ReplaceRuleSelectors(w.r.ctx, r.ID, nil))
	require.NoError(t, tx.RolesW().ReplaceRoleVerbs(w.r.ctx, r.ID, nil))
	require.NoError(t, tx.RolesW().ReplaceRuleRefs(w.r.ctx, r.ID, nil))
	require.NoError(t, tx.Commit(w.r.ctx))
	return r
}

func roleFinalSnapshot(t *testing.T, w delegationUCWorld, roleID domain.RoleID, carrier domain.AccessBindingID) string {
	t.Helper()
	var state string
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT jsonb_build_object('role',to_jsonb(r),'version',r.xmin::text,'verbs',(SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY v.object_type,v.verb),'[]') FROM kaname.role_verb v WHERE v.role_id=r.id),'ledger',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY e.object,e.fga_user,e.relation),'[]') FROM kaname.access_binding_emitted_tuples e WHERE e.binding_id=$2))::text FROM kaname.roles r WHERE r.id=$1`, roleID, carrier).Scan(&state))
	return state
}

func roleFinalTableWait(t *testing.T, w delegationUCWorld, table string, blockerPID int32) {
	t.Helper()
	require.Eventually(t, func() bool {
		var waiting bool
		err := w.r.admin.QueryRow(w.r.ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks l WHERE l.locktype='relation' AND l.relation=$1::regclass AND l.mode='RowExclusiveLock' AND NOT l.granted AND $2=ANY(pg_blocking_pids(l.pid)))`, table, blockerPID).Scan(&waiting)
		return err == nil && waiting
	}, 5*time.Second, 10*time.Millisecond, "actual DML table mode должен ждать данного blocker до final clock")
}

// Старые row-only twins сохранены. SHARE table blocker совместим с прежним
// ROW SHARE prelock, но несовместим с actual DML: ошибка воспроизводится без
// изменения epoch/xmin и без невозможного compatibility+strict конкурента.
func TestRoleActualUpdateFinalDecisionAfterLegacyWait(t *testing.T) {
	for _, surface := range []string{"role_metadata", "role_rules", "catalog_rules", "table_metadata", "table_projection", "table_fold", "sequence_metadata"} {
		for _, expired := range []bool{false, true} {
			t.Run(surface+map[bool]string{false: "_live", true: "_expired"}[expired], func(t *testing.T) {
				w := delegationUCFixture(t)
				// Все business seeds и native materialization — в разрешённой prepared фазе.
				r := roleFinalCreate(t, w, nil, "final_clock_role")
				if surface == "table_fold" {
					r = roleFinalLegacy(t, w, r)
				}
				recipient := domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(w.input.DelegateID)}
				carrier := roleFinalCarrier(t, w, r, recipient)
				authority := roleFinalAdmin(t, w)
				before := roleFinalSnapshot(t, w, r.ID, carrier)
				if surface == "table_fold" {
					var n int
					require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.relation_fact WHERE object_type='account' AND object_id=$1 AND relation='viewer' AND subject=$2`, w.r.a, "service_account:"+w.input.DelegateID).Scan(&n))
					require.Equal(t, 1, n, "Дано: OLD viewer существует до nonempty tuple diff")
				}
				writers, err := kanamepg.NewGrantPolicyWriters(w.r.ctx, w.r.repo, w.r.bundle)
				require.NoError(t, err)
				interval := "1 hour"
				if expired {
					interval = "5 seconds"
				}
				var deadline time.Time
				require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `UPDATE kaname.access_bindings SET expires_at=clock_timestamp()+$2::interval WHERE id=$1 RETURNING expires_at`, authority, interval).Scan(&deadline))
				require.NoError(t, lifecycleOwner(w.r).ActivateAuthorityBundle(w.r.ctx, w.r.bundle))
				// Отдельный actual active Create сохранён; carrier seeds не требуют обхода strict.
				roleFinalCreate(t, w, writers, "active_create_probe")
				blocker, err := w.r.admin.Begin(w.r.ctx)
				if blocker != nil {
					roleFinalCleanup(t, blocker)
				}
				require.NoError(t, err)
				table := ""
				switch surface {
				case "table_metadata":
					table = "kaname.roles"
				case "table_projection":
					table = "kaname.role_verb"
				case "table_fold":
					table = "kaname.relation_fact"
				case "sequence_metadata":
					table = "kaname.resource_journal_sequence_no_seq"
				}
				if surface == "sequence_metadata" {
					// Owner DDL не пишет protected authority rows и законен при strict.
					// Откатываем его после wait: проверяется только nextval dependency.
					_, err = blocker.Exec(w.r.ctx, `ALTER SEQUENCE kaname.resource_journal_sequence_no_seq CACHE 1`)
				} else if table != "" {
					_, err = blocker.Exec(w.r.ctx, `LOCK TABLE `+table+` IN SHARE MODE`)
				} else if surface == "catalog_rules" {
					_, err = blocker.Exec(w.r.ctx, `SELECT 1 FROM kaname.catalog_resource WHERE dotted='iam.role' FOR UPDATE`)
				} else {
					_, err = blocker.Exec(w.r.ctx, `SELECT 1 FROM kaname.roles WHERE id=$1 FOR UPDATE`, r.ID)
				}
				require.NoError(t, err)
				var xid string
				var blockerPID int32
				require.NoError(t, blocker.QueryRow(w.r.ctx, `SELECT pg_current_xact_id()::text,pg_backend_pid()`).Scan(&xid, &blockerPID))
				update := roleapp.NewUpdateRoleUseCase(w.r.repo, w.ops, w.source).WithRoleAuthorityWriter(writers).WithTupleReconciler(bindingapp.NewRoleTupleReconciler())
				input := roleapp.UpdateRoleInput{ID: r.ID, Rules: domain.Rules{{Module: "iam", Resources: []string{"role"}, Verbs: []string{"list", "update"}}}, UpdateMask: []string{"rules"}}
				if strings.HasSuffix(surface, "metadata") {
					description := domain.Description("after legacy wait")
					input = roleapp.UpdateRoleInput{ID: r.ID, Description: &description, UpdateMask: []string{"description"}}
				}
				op, err := update.Execute(declarerCtx(w.r.ctx, w.member), input)
				require.NoError(t, err)
				if table != "" {
					roleFinalTableWait(t, w, table, blockerPID)
				} else {
					semanticWaitIdentity(t, w.r.ctx, w.r.admin, xid)
				}
				var liveAtWait bool
				require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT clock_timestamp()<$1`, deadline).Scan(&liveAtWait))
				require.True(t, liveAtWait, "Дано: источник действовал в начале наблюдаемого ожидания")
				if expired {
					require.Eventually(t, func() bool {
						var passed bool
						e := w.r.admin.QueryRow(w.r.ctx, `SELECT clock_timestamp()>$1`, deadline).Scan(&passed)
						return e == nil && passed
					}, 8*time.Second, 10*time.Millisecond)
				}
				if surface == "sequence_metadata" {
					require.NoError(t, blocker.Rollback(w.r.ctx))
				} else {
					require.NoError(t, blocker.Commit(w.r.ctx))
				}
				done := awaitOperation(t, w.r.ctx, w.ops, op.ID)
				var audit int
				require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.audit_outbox WHERE event_type='iam.role.updated' AND event_payload->>'resource_id'=$1`, r.ID).Scan(&audit))
				if expired {
					require.NotNil(t, done.Error)
					require.Equal(t, int32(codes.PermissionDenied), done.Error.Code)
					require.Zero(t, audit)
					require.Equal(t, before, roleFinalSnapshot(t, w, r.ID, carrier), "отказ сохраняет role/xmin/projection/ledger")
				} else {
					require.Nil(t, done.Error)
					require.Equal(t, 1, audit)
					if strings.HasSuffix(surface, "metadata") {
						var description string
						require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT description FROM kaname.roles WHERE id=$1`, r.ID).Scan(&description))
						require.Equal(t, "after legacy wait", description)
					} else {
						var n int
						require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.role_verb WHERE role_id=$1 AND verb='update'`, r.ID).Scan(&n))
						require.Positive(t, n)
					}
				}
				if surface == "table_fold" {
					var fact, ledger int
					require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.relation_fact WHERE object_type='account' AND object_id=$1 AND relation='viewer' AND subject=$2`, w.r.a, "service_account:"+w.input.DelegateID).Scan(&fact))
					require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 AND source='binding' AND relation='viewer'`, carrier).Scan(&ledger))
					expected := 0
					if expired {
						expected = 1
					}
					require.Equal(t, expected, fact)
					require.Equal(t, expected, ledger, "nonempty OLD viewer удаляется только с успешной ролью")
				}
				authorityWaitReleased(t, w.r.runtime)
			})
		}
	}
}

func TestRoleMutationPreparationCancellationReleasesLease(t *testing.T) {
	for _, lockKind := range []string{"false", "true", "sequence"} {
		t.Run(lockKind, func(t *testing.T) {
			w := delegationUCFixture(t)
			writers, err := kanamepg.NewGrantPolicyWriters(w.r.ctx, w.r.repo, w.r.bundle)
			require.NoError(t, err)
			require.NoError(t, lifecycleOwner(w.r).ActivateAuthorityBundle(w.r.ctx, w.r.bundle))
			var id domain.RoleID
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT id FROM kaname.roles WHERE is_system ORDER BY id LIMIT 1`).Scan(&id))
			blocker, err := w.r.admin.Begin(w.r.ctx)
			if blocker != nil {
				roleFinalCleanup(t, blocker)
			}
			require.NoError(t, err)
			if lockKind == "sequence" {
				_, err = blocker.Exec(w.r.ctx, `ALTER SEQUENCE kaname.resource_journal_sequence_no_seq CACHE 1`)
			} else if lockKind == "true" {
				_, err = blocker.Exec(w.r.ctx, `LOCK TABLE kaname.roles IN SHARE MODE`)
			} else {
				_, err = blocker.Exec(w.r.ctx, `SELECT 1 FROM kaname.roles WHERE id=$1 FOR UPDATE`, id)
			}
			require.NoError(t, err)
			var xid string
			var pid int32
			require.NoError(t, blocker.QueryRow(w.r.ctx, `SELECT pg_current_xact_id()::text,pg_backend_pid()`).Scan(&xid, &pid))
			ctx, cancel := context.WithCancel(declarerCtx(w.r.ctx, w.owner))
			defer cancel()
			done := make(chan error, 1)
			go func() {
				writer, e := writers.RoleMutationWriter(ctx, kaname.RoleMutationRequest{Role: domain.Role{ID: id, IsSystem: true, ClusterID: domain.ClusterID(domain.ClusterSingletonID)}}, domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(w.owner)})
				if writer != nil {
					cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
					_ = writer.Rollback(cleanup)
					stop()
				}
				done <- e
			}()
			if lockKind == "sequence" {
				roleFinalTableWait(t, w, "kaname.resource_journal_sequence_no_seq", pid)
			} else if lockKind == "true" {
				roleFinalTableWait(t, w, "kaname.roles", pid)
			} else {
				semanticWaitIdentity(t, w.r.ctx, w.r.admin, xid)
			}
			cancel()
			select {
			case err = <-done:
				require.Error(t, err)
			case <-time.After(5 * time.Second):
				t.Fatal("cancel не освободил writer")
			}
			require.NoError(t, blocker.Rollback(w.r.ctx))
			authorityWaitReleased(t, w.r.runtime)
		})
	}
}

// Foreign owner не участвует в решении: нужны реальные typed account/user
// rows для FK и owning scope, не injected native authority.
func roleFinalForeignAccount(t *testing.T, w delegationUCWorld, suffix string) domain.AccountID {
	t.Helper()
	user := ids.NewID(domain.PrefixUser)
	account := domain.AccountID(ids.NewID(domain.PrefixAccount))
	tx, err := w.r.admin.Begin(w.r.ctx)
	if tx != nil {
		roleFinalCleanup(t, tx)
	}
	require.NoError(t, err)
	// ACTIVE owner получает реальную строку способа входа в той же TX.
	// Deferred users_active_has_a_way_in_fk остаётся включённым.
	_, err = tx.Exec(w.r.ctx, activewayin.WithWayIn(`INSERT INTO kaname.users(id,account_id,external_id,email,display_name,invite_status) VALUES($1,$2,$3,$4,'Role boundary owner','ACTIVE')`), user, account, suffix, suffix+"@example.test")
	require.NoError(t, err)
	_, err = tx.Exec(w.r.ctx, `INSERT INTO kaname.accounts(id,name,owner_user_id,labels) VALUES($1,$2,$3,'{}'::jsonb)`, account, "role-boundary-"+string(account), user)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(w.r.ctx))
	return account
}

// Полный набор включает own scope и home accounts реальных typed recipients.
// Ни одна account-role не назначается в чужой scope. 256 accounts + role owner
// ref уже не помещаются в 256 ownership refs: это законный GLOBAL, не усечение.
func TestRoleMutationForeignRecipientAccountBoundary(t *testing.T) {
	for _, accounts := range []int{255, 256, 257} {
		t.Run(fmt.Sprint(accounts), func(t *testing.T) {
			w := delegationUCFixture(t)
			r := roleFinalCreate(t, w, nil, "wide_recipient_role")
			carriers := make([]domain.AccessBindingID, 0, accounts-1)
			for i := 0; i < accounts-1; i++ {
				suffix := fmt.Sprintf("role-boundary-%d", i)
				home := roleFinalForeignAccount(t, w, suffix)
				// Чередуем реальные SA/group строки: одинаковый текст не подменяет typed ownership.
				subject := domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(seedSAID(t, w.r.ctx, w.r.admin, string(home), suffix))}
				if i%2 != 0 {
					subject = domain.Subject{Type: domain.SubjectTypeGroup, ID: domain.SubjectID(seedGroupID(t, w.r.ctx, w.r.admin, string(home), suffix))}
				}
				carriers = append(carriers, roleFinalCarrier(t, w, r, subject))
			}
			var count int
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.access_bindings b JOIN kaname.roles r ON r.id=b.role_id WHERE r.id=$1 AND r.account_id=$2 AND b.resource_type='account' AND b.resource_id=r.account_id`, r.ID, w.r.a).Scan(&count))
			require.Equal(t, accounts-1, count, "Дано: lawful own-scope carriers")
			writers, err := kanamepg.NewGrantPolicyWriters(w.r.ctx, w.r.repo, w.r.bundle)
			require.NoError(t, err)
			require.NoError(t, lifecycleOwner(w.r).ActivateAuthorityBundle(w.r.ctx, w.r.bundle))
			proposed := r
			proposed.Rules = domain.Rules{{Module: "iam", Resources: []string{"role"}, Verbs: []string{"list", "update"}}}
			prepared, err := writers.RoleMutationWriter(w.r.ctx, kaname.RoleMutationRequest{Role: proposed, Rules: true, Tuples: bindingapp.NewRoleTupleReconciler()}, domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(w.owner)})
			if prepared != nil {
				roleFinalCleanup(t, prepared)
			}
			require.NoError(t, err)
			fence := prepared.AuthorityFence()
			if accounts == 255 {
				require.Equal(t, kaname.AuthorityFenceAccounts, fence.Mode())
				require.Len(t, fence.Accounts(), accounts)
			} else {
				require.Equal(t, kaname.AuthorityFenceGlobal, fence.Mode())
				require.Empty(t, fence.Accounts())
			}
			require.NoError(t, prepared.Rollback(w.r.ctx))
			update := roleapp.NewUpdateRoleUseCase(w.r.repo, w.ops, w.source).WithRoleAuthorityWriter(writers).WithTupleReconciler(bindingapp.NewRoleTupleReconciler())
			op, err := update.Execute(declarerCtx(w.r.ctx, w.owner), roleapp.UpdateRoleInput{ID: r.ID, Rules: proposed.Rules, UpdateMask: []string{"rules"}})
			require.NoError(t, err)
			require.Nil(t, roleFinalAwaitOperation(t, w, op.ID).Error)
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.access_bindings WHERE role_id=$1 AND grant_capability_version=1`, r.ID).Scan(&count))
			require.Equal(t, len(carriers), count, "полный stage, включая последнюю страницу, не усечён")
			var tail int
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 AND source='binding'`, carriers[len(carriers)-1]).Scan(&tail))
			require.Positive(t, tail)
			authorityWaitReleased(t, w.r.runtime)
		})
	}
}
