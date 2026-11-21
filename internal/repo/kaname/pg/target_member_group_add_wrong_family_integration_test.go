// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// Реальные OLD/NEW строки получены исходным reconciler до FULL cutover.
// Каждая попытка использует свежий действительный prepared GroupAdd writer;
// Отказ BEFORE STATEMENT проверяется по точному первому PgError и снимку после rollback.
// До изменённого ROW guard эта попытка не доходит; обхода исходных triggers здесь нет.
func TestTargetMemberGroupAddPreparedWrongFamilyAndFirstFailure(t *testing.T) {
	r, binding, objectID, _ := mirrorLocalityFixture(t)
	engine := bindingStageEngine(t, r, nil)
	require.NoError(t, engine.ReconcileBinding(r.ctx, binding))
	g, uid, _ := membershipFixture(t, r)
	var rows int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.access_binding_target_members WHERE binding_id=$1 AND object_id=$2`, string(binding), objectID).Scan(&rows))
	require.Equal(t, 1, rows, "исходный reconciler должен создать настоящую строку")

	// Тот же конечный owner fault, что в исходном NonceCustody: только nonce.
	// Он не подписывает команду и не предоставляет обычному LOGIN доступ к state.
	_, err := r.admin.Exec(r.ctx, `CREATE FUNCTION kaname.test_group_add_corrupt_state_v3(p_mode text) RETURNS void
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 BEGIN
 CASE p_mode
 WHEN 'corrupt-command-nonce' THEN UPDATE pg_temp.kaname_group_add_command SET nonce='00000000-0000-0000-0000-000000000000'::uuid;
 ELSE RAISE EXCEPTION 'неизвестный TEST fault';END CASE;
 END $$;
 REVOKE ALL ON FUNCTION kaname.test_group_add_corrupt_state_v3(text) FROM PUBLIC`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, cleanupErr := r.admin.Exec(context.WithoutCancel(r.ctx), `DROP FUNCTION kaname.test_group_add_corrupt_state_v3(text)`)
		require.NoError(t, cleanupErr)
	})
	_, err = r.admin.Exec(r.ctx, `GRANT EXECUTE ON FUNCTION kaname.test_group_add_corrupt_state_v3(text) TO `+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	_, _ = fullContractActivate(t, r)
	full, observed := sequenceObservedFullRepo(t, r)
	factory, err := kanamepg.NewGrantPolicyWriters(r.ctx, full, r.bundle)
	require.NoError(t, err)
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)}
	member := domain.GroupMember{GroupID: g.ID, MemberType: domain.SubjectTypeUser, MemberID: domain.SubjectID(uid)}
	snapshot := func() string {
		var members string
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY to_jsonb(m)::text),'[]'::jsonb)::text FROM kaname.access_binding_target_members m WHERE binding_id=$1`, string(binding)).Scan(&members))
		return groupAddCommandSnapshot(t, r, member) + "\n" + members
	}
	before := snapshot()
	mutations := []string{"INSERT", "UPDATE", "DELETE"}
	for _, malformed := range []bool{false, true} {
		state := "valid-command"
		if malformed {
			state = "nonce-mismatch"
		}
		for _, mutation := range mutations {
			t.Run(state+"/"+mutation, func(t *testing.T) {
				r := fullMeasurementRigContext(t, r)
				w := groupAddCommandOpen(t, r.ctx, factory, actor, member)
				observed.take()
				if malformed {
					require.NoError(t, kanamepg.GroupAdditionProbeForTest(r.ctx, w, "corrupt-command-nonce"))
				}
				err := kanamepg.GroupAdditionTargetMemberProbeForTest(r.ctx, w, mutation, string(binding), objectID)
				var pe *pgconn.PgError
				require.ErrorAs(t, err, &pe)
				require.Equal(t, "42501", pe.Code)
				if malformed {
					require.Equal(t, "group addition command lifetime changed", pe.Message)
				} else {
					require.Equal(t, "group addition statement outside exact command", pe.Message)
					require.Contains(t, pe.Where, "_authority_group_add_statement_v3")
				}
				groupAddCommandDenied(t, observed.last())
				require.NoError(t, w.Rollback(context.WithoutCancel(r.ctx)))
				require.Equal(t, before, snapshot())
				membershipCounts(t, r, string(g.ID), "user:"+uid, 0)
			})
		}
	}
	// Законный близнец доказывает работоспособность того же prepared fixture.
	t.Run("complete-original-command", func(t *testing.T) {
		r := fullMeasurementRigContext(t, r)
		w := groupAddCommandOpen(t, r.ctx, factory, actor, member)
		require.NoError(t, w.GroupsW().AddMember(r.ctx, member))
		require.NoError(t, groupAddCommandFGA(r.ctx, w, member))
		require.NoError(t, groupAddCommandSubject(r.ctx, w, member))
		require.NoError(t, kanamepg.GroupAdditionProbeForTest(r.ctx, w, "commit"))
		membershipCounts(t, r, string(g.ID), "user:"+uid, 1)
	})
	authorityWaitReleased(t, r.runtime)
}
