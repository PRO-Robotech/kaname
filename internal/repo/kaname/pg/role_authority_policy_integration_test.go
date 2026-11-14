// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/stretchr/testify/require"

	groupapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/group"
	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

func rolePolicyCatalog(t *testing.T, r protocolRig) catalog.Source {
	t.Helper()
	var halves catalog.Halves
	require.NoError(t, json.Unmarshal(r.bundle.CanonicalCatalog(), &halves))
	facts, err := catalog.NewFacts(halves)
	require.NoError(t, err)
	return catalog.Fixed{F: facts}
}
func TestRolePolicyActualCreateUpdateRawOwnerAndClosedIdentity(t *testing.T) {
	r := writerProtocolRig(t)
	var uid string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, r.a).Scan(&uid))
	writers, err := kanamepg.NewGrantPolicyWriters(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	ops := operations.NewRepo(r.runtime, "kaname")
	create := roleapp.NewCreateRoleUseCase(r.repo, ops, rolePolicyCatalog(t, r)).WithRoleAuthorityWriter(writers)
	update := roleapp.NewUpdateRoleUseCase(r.repo, ops, rolePolicyCatalog(t, r)).WithRoleAuthorityWriter(writers)
	var target string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT id FROM kaname.roles WHERE is_system ORDER BY id LIMIT 1`).Scan(&target))
	rules := domain.Rules{{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{target}}}
	ctx := declarerCtx(r.ctx, uid)
	input := domain.Role{AccountID: domain.AccountID(r.a), Name: "policy_owner_role", Rules: rules}
	// Prepared handoff не включает публичное semantic решение.
	op, err := create.Execute(ctx, input)
	require.NoError(t, err)
	require.NotNil(t, awaitOperation(t, r.ctx, ops, op.ID).Error)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	op, err = create.Execute(ctx, input)
	require.NoError(t, err)
	require.Nil(t, awaitOperation(t, r.ctx, ops, op.ID).Error)
	var rid string
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT id FROM kaname.roles WHERE account_id=$1 AND name=$2`, r.a, input.Name).Scan(&rid))
	op, err = update.Execute(ctx, roleapp.UpdateRoleInput{ID: domain.RoleID(rid), Rules: rules, UpdateMask: []string{"rules"}})
	require.NoError(t, err)
	require.Nil(t, awaitOperation(t, r.ctx, ops, op.ID).Error)
	w, err := writers.RoleAuthorityWriter(ctx, domain.Role{ID: domain.RoleID(rid), AccountID: domain.AccountID(r.a)}, false, domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)})
	require.NoError(t, err)
	proof, err := grantpolicy.CollectWitnessedLowerBound(ctx, w, domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)})
	require.NoError(t, err)
	require.False(t, proof.Census().Component.Complete(), "нижняя граница не стирает incomplete census")
	require.NoError(t, w.Rollback(ctx))
	require.NoError(t, lifecycleOwner(r).CloseAuthorityBundle(r.ctx))
	input.Name = "policy_closed_role"
	op, err = create.Execute(ctx, input)
	require.NoError(t, err)
	require.NotNil(t, awaitOperation(t, r.ctx, ops, op.ID).Error)
	authorityWaitReleased(t, r.runtime)
}
func TestRolePolicyOwnerRevocationWaitsSameFenceAndFailsAfterCommit(t *testing.T) {
	r := writerProtocolRig(t)
	var oldOwner, newOwner string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, r.a).Scan(&oldOwner))
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, r.b).Scan(&newOwner))
	writers, err := kanamepg.NewGrantPolicyWriters(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	tx, err := r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	in := kaname.AuthorityWriteIntent{Kind: kaname.AuthorityIdentity, Bundle: r.bundle, Plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}}
	r.enter(t, tx, in, "participant")
	_, err = tx.Exec(r.ctx, `UPDATE kaname.accounts SET owner_user_id=$2 WHERE id=$1`, r.a, newOwner)
	require.NoError(t, err)
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(oldOwner)}
	proposed := domain.Role{ID: domain.RoleID(ids.NewID("rol")), AccountID: domain.AccountID(r.a), Name: "owner_revoked", Rules: domain.Rules{{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}}}}
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		w, e := writers.RoleAuthorityWriter(ctx, proposed, true, actor)
		if e != nil {
			done <- e
			return
		}
		defer w.Rollback(context.Background())
		done <- grantpolicy.RequireRole(ctx, w, actor, proposed, true)
	}()
	select {
	case e := <-done:
		t.Fatalf("decision passed held owner fence: %v", e)
	case <-time.After(100 * time.Millisecond):
	}
	require.NoError(t, tx.Commit(r.ctx))
	require.Error(t, <-done, "отозванный owner не оправдывает новую роль старым снимком")
	authorityWaitReleased(t, r.runtime)
}
func TestGroupAdditionActualWorkerChecksPendingForeignGrantBeforeMembership(t *testing.T) {
	r := writerProtocolRig(t)
	g, uid, _ := membershipFixture(t, r)
	membershipBinding(t, r, string(g.ID), r.b, "PENDING", true)
	writers, err := kanamepg.NewGrantPolicyWriters(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	ops := operations.NewRepo(r.runtime, "kaname")
	add := groupapp.NewAddMemberUseCase(r.repo, ops).WithGroupAdditionAuthorityWriter(writers)
	op, err := add.Execute(declarerCtx(r.ctx, uid), groupapp.AddMemberInput{GroupID: g.ID, MemberType: domain.SubjectTypeUser, MemberID: domain.SubjectID(uid)})
	require.NoError(t, err)
	require.NotNil(t, awaitOperation(t, r.ctx, ops, op.ID).Error)
	membershipCounts(t, r, string(g.ID), "user:"+uid, 0)
	authorityWaitReleased(t, r.runtime)
}
