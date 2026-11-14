// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	bindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	gdapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/grant_delegation"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func grantPreflightDeadline(t *testing.T, w delegationUCWorld, authority domain.AccessBindingID, expired bool) time.Time {
	t.Helper()
	interval := "1 hour"
	if expired {
		interval = "5 seconds"
	}
	var at time.Time
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `UPDATE kaname.access_bindings SET expires_at=clock_timestamp()+$2::interval WHERE id=$1 RETURNING expires_at`, authority, interval).Scan(&at))
	return at
}
func grantPreflightPassDeadline(t *testing.T, w delegationUCWorld, at time.Time, expired bool) {
	t.Helper()
	var live bool
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT clock_timestamp()<$1`, at).Scan(&live))
	require.True(t, live, "Дано: authority жива в начале actual lock wait")
	if expired {
		require.Eventually(t, func() bool {
			var passed bool
			err := w.r.admin.QueryRow(w.r.ctx, `SELECT clock_timestamp()>$1`, at).Scan(&passed)
			return err == nil && passed
		}, 8*time.Second, 10*time.Millisecond)
	}
}

// Actual Create, native issuer, ordinary participant: table SHARE совместим с
// прежними чтениями, delegate FOR UPDATE не меняет policy source/epoch.
func TestGrantDelegationCreateMutationPreflightWait(t *testing.T) {
	for _, surface := range []string{"table", "delegate_fk"} {
		for _, expired := range []bool{false, true} {
			t.Run(surface+map[bool]string{false: "_live", true: "_expired"}[expired], func(t *testing.T) {
				w := delegationUCFixture(t)
				authority := w.grantAdmin(t)
				deadline := grantPreflightDeadline(t, w, authority, expired)
				require.NoError(t, lifecycleOwner(w.r).ActivateAuthorityBundle(w.r.ctx, w.r.bundle))
				blocker, err := w.r.admin.Begin(w.r.ctx)
				if blocker != nil {
					roleFinalCleanup(t, blocker)
				}
				require.NoError(t, err)
				if surface == "table" {
					_, err = blocker.Exec(w.r.ctx, `LOCK TABLE kaname.grant_delegations IN SHARE MODE`)
				} else {
					var id string
					err = blocker.QueryRow(w.r.ctx, `SELECT id FROM kaname.service_accounts WHERE id=$1 FOR UPDATE`, w.input.DelegateID).Scan(&id)
				}
				require.NoError(t, err)
				var xid string
				var pid int32
				require.NoError(t, blocker.QueryRow(w.r.ctx, `SELECT pg_current_xact_id()::text,pg_backend_pid()`).Scan(&xid, &pid))
				uc := gdapp.NewCreateGrantDelegationUseCase(w.r.repo, w.ops, w.source).WithRelationStore(w.door, nil).WithAuthorityWriter(w.participant)
				op, err := uc.Execute(declarerCtx(w.r.ctx, w.member), w.input)
				require.NoError(t, err)
				if surface == "table" {
					roleFinalTableWait(t, w, "kaname.grant_delegations", pid)
				} else {
					semanticWaitIdentity(t, w.r.ctx, w.r.admin, xid)
				}
				grantPreflightPassDeadline(t, w, deadline, expired)
				require.NoError(t, blocker.Rollback(w.r.ctx))
				done := awaitOperation(t, w.r.ctx, w.ops, op.ID)
				var n int
				require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.grant_delegations WHERE account_id=$1 AND delegate_id=$2`, w.input.AccountID, w.input.DelegateID).Scan(&n))
				if expired {
					require.NotNil(t, done.Error)
					require.Equal(t, int32(codes.PermissionDenied), done.Error.Code)
					require.Zero(t, n)
				} else {
					require.Nil(t, done.Error)
					require.Equal(t, 1, n)
				}
				authorityWaitReleased(t, w.r.runtime)
			})
		}
	}
}

// Actual metadata Update не выдаёт cap v1 и повторно судит обычного admin.
// Sequence DDL законен при strict и не требует запрещённого source UPDATE.
func TestBindingMetadataMutationPreflightWait(t *testing.T) {
	for _, surface := range []string{"table", "sequence", "subject_sequence"} {
		for _, expired := range []bool{false, true} {
			t.Run(surface+map[bool]string{false: "_live", true: "_expired"}[expired], func(t *testing.T) {
				w := delegationUCFixture(t)
				id := stageBinding(t, w.r, w.r.a, false)
				authority := w.grantAdmin(t)
				writers, err := kanamepg.NewGrantPolicyWriters(w.r.ctx, w.r.repo, w.r.bundle)
				require.NoError(t, err)
				deadline := grantPreflightDeadline(t, w, authority, expired)
				require.NoError(t, lifecycleOwner(w.r).ActivateAuthorityBundle(w.r.ctx, w.r.bundle))
				blocker, err := w.r.admin.Begin(w.r.ctx)
				if blocker != nil {
					roleFinalCleanup(t, blocker)
				}
				require.NoError(t, err)
				table := "kaname.access_bindings"
				switch surface {
				case "table":
					_, err = blocker.Exec(w.r.ctx, `LOCK TABLE kaname.access_bindings IN SHARE MODE`)
				case "sequence":
					table = "kaname.resource_journal_sequence_no_seq"
					_, err = blocker.Exec(w.r.ctx, `ALTER SEQUENCE kaname.resource_journal_sequence_no_seq CACHE 1`)
				case "subject_sequence":
					table = "kaname.subject_change_outbox_id_seq"
					_, err = blocker.Exec(w.r.ctx, `ALTER SEQUENCE kaname.subject_change_outbox_id_seq CACHE 1`)
				}
				require.NoError(t, err)
				var pid int32
				require.NoError(t, blocker.QueryRow(w.r.ctx, `SELECT pg_backend_pid()`).Scan(&pid))
				uc := bindingapp.NewUpdateAccessBindingUseCase(w.r.repo, w.ops).WithBindingDecisions(writers)
				result := make(chan grantPreflightResult, 1)
				go func() {
					op, e := uc.Execute(declarerCtx(w.r.ctx, w.member), id, []string{"labels"}, false, domain.Labels{"preflight": "applied"})
					result <- grantPreflightResult{op: op, err: e}
				}()
				roleFinalTableWait(t, w, table, pid)
				grantPreflightPassDeadline(t, w, deadline, expired)
				require.NoError(t, blocker.Rollback(w.r.ctx))
				requireGrantPreflightResult(t, w, result, expired)
				got := bindingRow(t, w.r, id)
				if expired {
					require.Empty(t, got.Labels["preflight"])
				} else {
					require.Equal(t, domain.LabelVal("applied"), got.Labels["preflight"])
				}
				authorityWaitReleased(t, w.r.runtime)
			})
		}
	}
}

// Реальный expiry снимает ledger/member rows. Хвост выбирается по тому же
// ctid-порядку, что RR capture; наблюдается именно prelock SELECT, не DELETE.
func TestBindingExpiryChildPreflightLastPageCancellation(t *testing.T) {
	for _, table := range []string{"access_binding_emitted_tuples", "access_binding_target_members"} {
		t.Run(table, func(t *testing.T) {
			r := writerProtocolRig(t)
			stageSeedGroups(t, r, r.a, 259, "blue")
			id := stageBinding(t, r, r.a, false)
			require.NoError(t, bindingStageEngine(t, r, nil).ReconcileBinding(r.ctx, id))
			require.Equal(t, 259, stageCount(t, r, id))
			expireBindingFixture(t, r, id)
			p := withdrawalParticipant(t, r, nil)
			var before string
			snapshot := func() string {
				var s string
				require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_build_object('b',to_jsonb(b),'ledger',(SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id=b.id),'members',(SELECT count(*) FROM kaname.access_binding_target_members WHERE binding_id=b.id))::text FROM kaname.access_bindings b WHERE b.id=$1`, id).Scan(&s))
				return s
			}
			before = snapshot()
			blocker, err := r.admin.Begin(r.ctx)
			if blocker != nil {
				roleFinalCleanup(t, blocker)
			}
			require.NoError(t, err)
			// Оба закрытых table names — локальные константы теста. Rank совпадает
			// с physical ctid keyset captureGrantChildren, а не порядком group IDs.
			var tail string
			var rank int64
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT row_tid,row_rank FROM (
 SELECT ctid::text AS row_tid,row_number() OVER (ORDER BY ctid) AS row_rank
 FROM kaname.`+table+` WHERE binding_id=$1) captured ORDER BY row_rank DESC LIMIT 1`, id).Scan(&tail, &rank))
			require.Greater(t, rank, int64(256), "Дано: actual identity находится за первой страницей RR capture")
			tag, err := blocker.Exec(r.ctx, `SELECT 1 FROM kaname.`+table+` WHERE binding_id=$1 AND ctid=$2::tid FOR UPDATE`, id, tail)
			require.NoError(t, err)
			require.EqualValues(t, 1, tag.RowsAffected())
			var blockerPID int32
			require.NoError(t, blocker.QueryRow(r.ctx, `SELECT pg_backend_pid()`).Scan(&blockerPID))
			ctx, cancel := context.WithCancel(r.ctx)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- p.ExpireStagedBinding(ctx, id) }()
			prelockSQL := `SELECT 1 FROM kaname.` + table + ` WHERE binding_id=$1 AND ctid=$2::tid AND xmin::text=$3 FOR UPDATE`
			require.Eventually(t, func() bool {
				var waiting bool
				e := r.admin.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity a
 WHERE a.query=$1 AND a.wait_event_type='Lock' AND $2=ANY(pg_catalog.pg_blocking_pids(a.pid)))`, prelockSQL, blockerPID).Scan(&waiting)
				return e == nil && waiting
			}, 5*time.Second, 10*time.Millisecond, "ожидание exact ctid SELECT prelock, не позднего business DELETE")
			require.Equal(t, before, snapshot(), "наблюдаемый parent/child census ещё не изменён")
			cancel()
			select {
			case err = <-done:
				require.Error(t, err)
			case <-time.After(5 * time.Second):
				t.Fatal("cancel оставил stage worker")
			}
			require.NoError(t, blocker.Rollback(r.ctx))
			require.Equal(t, before, snapshot(), "rollback сохраняет parent и весь child census")
			require.NoError(t, p.ExpireStagedBinding(r.ctx, id))
			var n int
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT (SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1)+(SELECT count(*) FROM kaname.access_binding_target_members WHERE binding_id=$1)`, id).Scan(&n))
			require.Zero(t, n)
			authorityWaitReleased(t, r.runtime)
		})
	}
}

// SECURITY DEFINER не принимает неподписанного runtime даже в compatibility.
func TestGrantMutationPreflightRejectsUnsignedRuntime(t *testing.T) {
	r := writerProtocolRig(t)
	for _, profile := range []any{"binding", "withdrawal", "delegation", nil, "role"} {
		tx, err := r.runtime.Begin(r.ctx)
		require.NoError(t, err)
		roleFinalCleanup(t, tx)
		_, err = tx.Exec(r.ctx, `SELECT kaname.authority_grant_mutation_preflight($1::text)`, profile)
		require.Error(t, err)
		require.NoError(t, tx.Rollback(r.ctx))
	}
	authorityWaitReleased(t, r.runtime)
}

// Предлагаемый recipient не может отложить business INSERT до истечения
// issuer: это actual subject_ref_exists KEY SHARE, а не fake checker hook.
func TestBindingCreateRecipientPreflightWait(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "live", true: "expired"}[expired], func(t *testing.T) {
			w := delegationUCFixture(t)
			seed := stageBinding(t, w.r, w.r.a, false)
			template := bindingRow(t, w.r, seed)
			authority := w.grantAdmin(t)
			writers, err := kanamepg.NewGrantPolicyWriters(w.r.ctx, w.r.repo, w.r.bundle)
			require.NoError(t, err)
			deadline := grantPreflightDeadline(t, w, authority, expired)
			require.NoError(t, lifecycleOwner(w.r).ActivateAuthorityBundle(w.r.ctx, w.r.bundle))
			blocker, err := w.r.admin.Begin(w.r.ctx)
			if blocker != nil {
				roleFinalCleanup(t, blocker)
			}
			require.NoError(t, err)
			var id, xid string
			require.NoError(t, blocker.QueryRow(w.r.ctx, `SELECT id FROM kaname.service_accounts WHERE id=$1 FOR UPDATE`, w.input.DelegateID).Scan(&id))
			require.NoError(t, blocker.QueryRow(w.r.ctx, `SELECT pg_current_xact_id()::text`).Scan(&xid))
			uc := bindingapp.NewCreateAccessBindingUseCase(w.r.repo, w.ops, w.source).WithBindingDecisions(writers)
			input := domain.AccessBinding{RoleID: template.RoleID, ResourceType: "account", ResourceID: w.r.a, Scope: domain.ScopeAccount, Subjects: []domain.Subject{{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(w.input.DelegateID)}}, Target: domain.AccessTarget{AllInScope: true}}
			result := make(chan grantPreflightResult, 1)
			go func() {
				op, e := uc.Execute(declarerCtx(w.r.ctx, w.member), input)
				result <- grantPreflightResult{op: op, err: e}
			}()
			semanticWaitIdentity(t, w.r.ctx, w.r.admin, xid)
			grantPreflightPassDeadline(t, w, deadline, expired)
			require.NoError(t, blocker.Rollback(w.r.ctx))
			requireGrantPreflightResult(t, w, result, expired)
			var n int
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.access_bindings WHERE role_id=$1 AND subject_type='service_account' AND subject_id=$2`, template.RoleID, w.input.DelegateID).Scan(&n))
			if expired {
				require.Zero(t, n)
			} else {
				require.Equal(t, 1, n)
			}
			authorityWaitReleased(t, w.r.runtime)
		})
	}
}

// Binding Execute выполняет тот же runner и в синхронном gate, и в worker.
// Оба actual callpaths обязаны отклонять expiry; ожидание Execute асинхронно,
// чтобы test мог наблюдать и отпустить реальный PG lock первого gate.
type grantPreflightResult struct {
	op  *operations.Operation
	err error
}

func requireGrantPreflightResult(t *testing.T, w delegationUCWorld, ch <-chan grantPreflightResult, expired bool) {
	t.Helper()
	var result grantPreflightResult
	select {
	case result = <-ch:
	case <-time.After(10 * time.Second):
		t.Fatal("actual Execute не завершился после release")
		return
	}
	if result.err != nil {
		require.True(t, expired)
		require.Equal(t, codes.PermissionDenied, status.Code(result.err))
		return
	}
	require.NotNil(t, result.op)
	done := awaitOperation(t, w.r.ctx, w.ops, result.op.ID)
	if expired {
		require.NotNil(t, done.Error)
		require.Equal(t, int32(codes.PermissionDenied), done.Error.Code)
	} else {
		require.Nil(t, done.Error)
	}
}

// Порядок canonical subjects задаёт legacy primary и ordinal. Порядок locks
// независим: здесь оба type и service-account IDs намеренно идут обратно.
func TestBindingCreatePreflightPreservesSubjectOrder(t *testing.T) {
	r := writerProtocolRig(t)
	owner := bindingPublicOwner(t, r)
	recipient := seedMemberUser(t, r.ctx, r.admin, r.a, "preflight-order-"+ids.NewID("usr"))
	_, err := r.admin.Exec(r.ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=$1`, recipient)
	require.NoError(t, err)
	seed := stageBinding(t, r, r.a, false)
	template := bindingRow(t, r, seed)
	serviceIDs := []string{ids.NewID("sva"), ids.NewID("sva")}
	slices.Sort(serviceIDs)
	slices.Reverse(serviceIDs)
	require.Greater(t, serviceIDs[0], serviceIDs[1])
	for _, id := range serviceIDs {
		_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.service_accounts(id,account_id,name) VALUES($1,$2,$1)`, id, r.a)
		require.NoError(t, err)
	}
	wanted := []domain.Subject{
		{Type: domain.SubjectTypeUser, ID: domain.SubjectID(recipient)},
		{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(serviceIDs[0])},
		{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(serviceIDs[1])},
	}
	input := domain.AccessBinding{RoleID: template.RoleID, ResourceType: "account", ResourceID: r.a, Scope: domain.ScopeAccount, SubjectType: wanted[0].Type, SubjectID: wanted[0].ID, Subjects: slices.Clone(wanted), Target: domain.AccessTarget{AllInScope: true}}
	writers, err := kanamepg.NewGrantPolicyWriters(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	ops := operations.NewRepo(r.runtime, "kaname")
	create := bindingapp.NewCreateAccessBindingUseCase(r.repo, ops, rolePolicyCatalog(t, r)).WithBindingDecisions(writers)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	op, err := create.Execute(declarerCtx(r.ctx, owner), input)
	require.Equal(t, wanted, input.Subjects, "синхронный preflight не меняет caller slice")
	require.NoError(t, err)
	require.Nil(t, awaitOperation(t, r.ctx, ops, op.ID).Error)
	require.Equal(t, wanted, input.Subjects, "worker preflight тоже не меняет caller slice")
	require.Equal(t, wanted[0].Type, input.SubjectType)
	require.Equal(t, wanted[0].ID, input.SubjectID)
	var bindingID domain.AccessBindingID
	var primaryType, primaryID string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT id,subject_type,subject_id FROM kaname.access_bindings WHERE role_id=$1 AND subject_type='user' AND subject_id=$2`, template.RoleID, recipient).Scan(&bindingID, &primaryType, &primaryID))
	require.Equal(t, string(wanted[0].Type), primaryType)
	require.Equal(t, string(wanted[0].ID), primaryID)
	rows, err := r.admin.Query(r.ctx, `SELECT subject_type,subject_id,ordinal FROM kaname.access_binding_subjects WHERE binding_id=$1 ORDER BY ordinal`, bindingID)
	require.NoError(t, err)
	defer rows.Close()
	var actual []domain.Subject
	var ordinals []int
	for rows.Next() {
		var subject domain.Subject
		var ordinal int
		require.NoError(t, rows.Scan(&subject.Type, &subject.ID, &ordinal))
		actual = append(actual, subject)
		ordinals = append(ordinals, ordinal)
	}
	require.NoError(t, rows.Err())
	rows.Close()
	require.Equal(t, wanted, actual)
	require.Equal(t, []int{0, 1, 2}, ordinals)
	authorityWaitReleased(t, r.runtime)
}
