// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
	"github.com/stretchr/testify/require"
)

func TestPreparedRoleAccessLabelSourceSnapshotsUseSignedWriter(t *testing.T) {
	r, owner := writerProtocolRigBeforePreparation(t)
	definition := seedAccessDefinition(t, r, "account", r.a, "source_snapshot")
	var uid string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, r.a).Scan(&uid))
	_, err := r.admin.Exec(r.ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=$1`, uid)
	require.NoError(t, err)
	second := seedMemberUser(t, r.ctx, r.admin, r.a, "source-snapshot-second")
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)}
	applyRules := domain.Rules{accessRoleApply(definition.id)}
	ordinaryRules := domain.Rules{{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}}}
	seed, err := owner.Writer(r.ctx)
	require.NoError(t, err)
	defer func() { _ = seed.Rollback(context.WithoutCancel(r.ctx)) }()
	roles := make([]domain.Role, 2)
	bindings := make([]domain.AccessBindingID, 2)
	for i, rules := range []domain.Rules{applyRules, ordinaryRules} {
		name := "snapshot_apply"
		if i == 1 {
			name = "snapshot_ordinary"
		}
		role := domain.Role{ID: domain.RoleID(ids.NewID(domain.PrefixRole)), AccountID: domain.AccountID(r.a), Name: domain.RoleName(name), Rules: rules}
		ordinary, _, err := domain.SplitGrantCapabilityRules(rules)
		require.NoError(t, err)
		role.Permissions, err = domain.CompileRules(ordinary)
		require.NoError(t, err)
		projection, err := r.bundle.Projection(role)
		require.NoError(t, err)
		roles[i], err = seed.RolesW().Insert(r.ctx, role)
		require.NoError(t, err)
		require.NoError(t, seed.RolesW().ReplaceRuleSelectors(r.ctx, role.ID, projection.Selectors))
		require.NoError(t, seed.RolesW().ReplaceRoleVerbs(r.ctx, role.ID, projection.Verbs))
		subjects := []domain.Subject{actor}
		if i == 0 {
			subjects = append(subjects, domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(second)})
		}
		binding, err := bindingset.Insert(r.ctx, seed.AccessBindingsW(), domain.AccessBinding{
			ID: domain.AccessBindingID(ids.NewID("acb")), SubjectType: actor.Type, SubjectID: actor.ID, Subjects: subjects,
			RoleID: role.ID, ResourceType: "account", ResourceID: r.a, Scope: domain.DeriveFromResourceType("account"),
			Status: domain.AccessBindingStatusActive, Target: domain.AccessTarget{AllInScope: true},
		})
		require.NoError(t, err)
		bindings[i] = binding.ID
	}
	require.NoError(t, seed.Commit(r.ctx))
	// Owner-only fixture до handoff. Private projection guard возвращён в той
	// же транзакции; runtime не получает private DML или source-check EXECUTE.
	privateSeed, err := r.admin.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, privateSeed)
	_, err = privateSeed.Exec(r.ctx, `UPDATE kaname.access_bindings SET grant_capability_version=1 WHERE id=ANY($1::text[])`, []string{string(bindings[0]), string(bindings[1])})
	require.NoError(t, err)
	_, err = privateSeed.Exec(r.ctx, `ALTER TABLE kaname.authority_role_access_label_rule DISABLE TRIGGER authority_role_access_label_rule_closed`)
	require.NoError(t, err)
	_, caps, err := domain.SplitGrantCapabilityRules(applyRules)
	require.NoError(t, err)
	for _, cap := range caps {
		_, err = privateSeed.Exec(r.ctx, accessRoleProjectionInsert, roles[0].ID, cap.RuleFP, cap.DefinitionID)
		require.NoError(t, err)
	}
	_, err = privateSeed.Exec(r.ctx, `ALTER TABLE kaname.authority_role_access_label_rule ENABLE TRIGGER authority_role_access_label_rule_closed`)
	require.NoError(t, err)
	require.NoError(t, privateSeed.Commit(r.ctx))
	require.NoError(t, owner.PrepareAuthorityBundle(r.ctx, r.bundle))
	full, _ := fullContractActivate(t, r)
	factory, err := kanamepg.NewGrantPolicyWriters(r.ctx, full, r.bundle)
	require.NoError(t, err)

	for _, scenario := range []struct {
		name                                     string
		create, rules, apply, capture, negatives bool
	}{
		{name: "create-apply", create: true, rules: true, apply: true, capture: true, negatives: true},
		{name: "update-apply", rules: true, apply: true, capture: true},
		{name: "ordinary-create-actor-still-has-apply", create: true, rules: true},
		{name: "metadata-apply-role-does-not-enable-source-read"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			request := kaname.RoleMutationRequest{Create: scenario.create, Rules: scenario.rules}
			if scenario.create {
				request.Role = domain.Role{ID: domain.RoleID(ids.NewID(domain.PrefixRole)), AccountID: domain.AccountID(r.a), Name: domain.RoleName("snapshot_proposed"), Rules: ordinaryRules}
			} else {
				id := roles[1].ID
				if !scenario.rules {
					id = roles[0].ID
				}
				reader, err := full.Reader(r.ctx)
				require.NoError(t, err)
				request.Role, request.ExpectedVersion, err = reader.Roles().GetWithVersion(r.ctx, id)
				require.NoError(t, err)
				require.NoError(t, reader.Rollback(r.ctx))
				request.Update = true
				request.UpdateMask = []string{"rules"}
				if !scenario.rules {
					request.UpdateMask = []string{"description"}
					request.Role.Description = "snapshot metadata only"
				}
			}
			if scenario.apply {
				request.Role.Rules = applyRules
			}
			ordinary, _, err := domain.SplitGrantCapabilityRules(request.Role.Rules)
			require.NoError(t, err)
			request.Role.Permissions, err = domain.CompileRules(ordinary)
			require.NoError(t, err)
			writer, err := factory.RoleMutationWriter(r.ctx, request, actor)
			require.NoError(t, err)
			defer func() { _ = writer.Rollback(context.WithoutCancel(r.ctx)) }()
			kanamepg.PreparedRoleSourceSnapshotConformanceForTest(t, r.ctx, writer, actor, roles[0].ID, roles[1].ID, bindings[0], scenario.capture, scenario.negatives)
			require.NoError(t, writer.Rollback(r.ctx))
		})
	}
}
