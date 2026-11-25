// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"testing"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	bindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

// Вызовы используют одну и ту же редакцию роли. Отказ постороннему должен
// оставить её пригодной для последующей авторизованной операции.
func TestRoleSelectorMoveUpdateCommitsPendingNoCopy(t *testing.T) {
	r, owner := writerProtocolRigBeforePreparation(t)
	actor := bindingPublicOwner(t, r)
	var recipient string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, r.b).Scan(&recipient))
	project := seedMetadataActualProject(t, r, "selector-move-project")
	old := domain.Rule{Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"team": "blue"}}
	setProjectLabels(t, r.ctx, r.admin, project.ID, old.MatchLabels)
	role := domain.Role{ID: domain.RoleID(ids.NewID(domain.PrefixRole)), AccountID: domain.AccountID(r.a),
		Name: "selector_move_commit", Rules: domain.Rules{old}}
	var err error
	role.Permissions, err = domain.CompileRules(role.Rules)
	require.NoError(t, err)
	projection, err := r.bundle.Projection(role)
	require.NoError(t, err)
	seed, err := owner.Writer(r.ctx)
	require.NoError(t, err)
	roleFinalCleanup(t, seed)
	_, err = seed.RolesW().Insert(r.ctx, role)
	require.NoError(t, err)
	require.NoError(t, seed.RolesW().ReplaceRuleSelectors(r.ctx, role.ID, projection.Selectors))
	require.NoError(t, seed.RolesW().ReplaceRoleVerbs(r.ctx, role.ID, projection.Verbs))
	require.NoError(t, seed.RolesW().ReplaceRuleRefs(r.ctx, role.ID, domain.RuleRefsOf(role.Rules)))
	require.NoError(t, seed.EmitFGARelationWrite(r.ctx, []service.RelationTuple{
		{User: "account:" + r.a, Relation: "account", Object: "iam_role:" + string(role.ID)},
	}))
	subject := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(recipient)}
	binding, err := bindingset.Insert(r.ctx, seed.AccessBindingsW(), domain.AccessBinding{
		ID: domain.AccessBindingID(ids.NewID("acb")), RoleID: role.ID, SubjectType: subject.Type, SubjectID: subject.ID,
		ResourceType: "account", ResourceID: r.a, Scope: domain.ScopeAccount, Status: domain.AccessBindingStatusPending,
		Target: domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "iam.project", ID: string(project.ID)}}},
	})
	require.NoError(t, err)
	reconciler := bindingapp.NewRoleTupleReconciler()
	tuples := reconciler.BuildRoleTuples(binding, []domain.Subject{subject}, role)
	require.Len(t, tuples, 1)
	require.Equal(t, "account:"+r.a, tuples[0].User)
	require.Equal(t, "account", tuples[0].Relation)
	require.Equal(t, "iam_access_binding:"+string(binding.ID), tuples[0].Object)
	require.NoError(t, seed.AccessBindingsW().InsertEmittedTuples(r.ctx, binding.ID, tuples))
	require.NoError(t, seed.AccessBindingsW().EmitRelationWrite(r.ctx, tuples))
	require.NoError(t, seed.Commit(r.ctx))

	editor := groupLifecycleBinding(t, r, r.a, actor, "move_role_update", domain.Rule{
		Module: "iam", Resources: []string{"role"}, ResourceNames: []string{string(role.ID)}, Verbs: []string{"update"},
	})
	pool, _, diagnostic := roleActorFiniteLogin(t, r)
	shared, contract := pendingSourceApplyProjectLabel(t, r, owner, actor, project.ID, editor)
	roleRepo := kanamepg.New(pool, nil)
	dedicated, err := kanamepg.NewFullWriterContract(r.ctx, roleRepo, r.bundle)
	require.NoError(t, err)
	roleRepo, err = roleRepo.WithFullWriterContract(dedicated)
	require.NoError(t, err)
	factory, err := kanamepg.NewRolePolicyWriters(r.ctx, shared, roleRepo, r.bundle)
	require.NoError(t, err)
	ops := operations.NewRepo(r.runtime, "kaname")
	update := roleapp.NewUpdateRoleUseCase(shared, ops, rolePolicyCatalog(t, r)).
		WithRoleAuthorityWriter(&finiteRoleWriterDiagnostic{RolePolicyWriters: factory, diagnostic: diagnostic}).
		WithTupleReconciler(reconciler)

	check := func(t *testing.T, user, rel, obj string, want bool) {
		t.Helper()
		allowed, err := (delegationNativeDoor{r}).Check(r.ctx, "user:"+user, rel, obj)
		require.NoError(t, err)
		require.Equal(t, want, allowed, "%s %s %s", user, rel, obj)
	}
	check(t, actor, "v_update", "iam_role:"+string(role.ID), true)
	check(t, recipient, "v_update", "iam_role:"+string(role.ID), false)
	check(t, recipient, "v_get", "project:"+string(project.ID), false)

	var version string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT xmin::text FROM ONLY kaname.roles WHERE id=$1`, role.ID).Scan(&version))
	first := uint32(0)
	request := &iamv1.UpdateRoleRequest{
		RoleId: string(role.ID), ResourceVersion: version,
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"access_label_selector_move"}},
		AccessLabelSelectorMove: &iamv1.RoleAccessLabelSelectorMove{
			Positions: []*iamv1.RoleAccessLabelSelectorMove_Position{{RuleIndex: &first}},
		},
	}
	handler := roleapp.NewHandler(nil, update, nil, nil, nil)
	run := func(t *testing.T, user string) *operations.Operation {
		t.Helper()
		ctx := contract.Context(declarerCtx(r.ctx, user))
		op, err := handler.Update(ctx, request)
		require.NoError(t, err)
		return awaitOperation(t, r.ctx, ops, op.GetId())
	}
	// Читаем физическую строку проекта и всю область выдачи с независимого
	// соединения после завершения операции. Любая копия или расширение видны.
	grantState := func(t *testing.T) string {
		t.Helper()
		var state string
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_build_array(
			to_jsonb(b),p.xmin::text,p.labels,p.access_labels,
			(SELECT jsonb_agg(to_jsonb(s) ORDER BY s.ordinal) FROM ONLY kaname.access_binding_subjects s WHERE s.binding_id=b.id),
			(SELECT jsonb_agg(to_jsonb(m) ORDER BY m.rule_fp,m.object_type,m.object_id) FROM ONLY kaname.access_binding_target_members m WHERE m.binding_id=b.id),
			(SELECT jsonb_agg(to_jsonb(e) ORDER BY e.object,e.fga_user,e.relation) FROM ONLY kaname.access_binding_emitted_tuples e WHERE e.binding_id=b.id)
		)::text FROM ONLY kaname.access_bindings b, ONLY kaname.projects p WHERE b.id=$1 AND p.id=$2`, binding.ID, project.ID).Scan(&state))
		return state
	}
	assertStored := func(t *testing.T, rule domain.Rule, arm string, auditCount int, sameVersion bool) {
		t.Helper()
		expected, err := domain.EncodeRules(domain.Rules{rule})
		require.NoError(t, err)
		var stored, labels, access []byte
		var current, storedArm string
		var count, audit, journal int
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT r.xmin::text,r.rules,
			(SELECT count(*) FROM ONLY kaname.role_rule_selectors WHERE role_id=r.id),
			s.arm,s.match_labels,s.match_access_labels,
			(SELECT count(*) FROM kaname.audit_outbox WHERE event_type='iam.role.updated' AND event_payload->>'resource_id'=r.id),
			(SELECT count(*) FROM kaname.resource_journal WHERE resource_kind='iam_role' AND resource_id=r.id AND event_type='UPDATED')
			FROM ONLY kaname.roles r JOIN ONLY kaname.role_rule_selectors s ON s.role_id=r.id WHERE r.id=$1`, role.ID).
			Scan(&current, &stored, &count, &storedArm, &labels, &access, &audit, &journal))
		require.Equal(t, sameVersion, current == version)
		require.JSONEq(t, string(expected), string(stored))
		require.Equal(t, 1, count)
		require.Equal(t, arm, storedArm)
		if arm == "labels" {
			require.JSONEq(t, `{"team":"blue"}`, string(labels))
			require.JSONEq(t, `{}`, string(access))
		} else {
			require.JSONEq(t, `{}`, string(labels))
			require.JSONEq(t, `{"team":"blue"}`, string(access))
		}
		require.Equal(t, auditCount, audit)
		require.Equal(t, auditCount, journal)
	}
	var ready bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT p.labels='{"team":"blue"}' AND p.access_labels=p.labels AND b.status='PENDING'
		AND b.target=jsonb_build_object('resources',jsonb_build_array(jsonb_build_object('type','iam.project','id',p.id)))
		AND NOT EXISTS(SELECT FROM kaname.access_binding_target_members WHERE binding_id=b.id)
		FROM kaname.projects p, kaname.access_bindings b WHERE p.id=$1 AND b.id=$2`, project.ID, binding.ID).Scan(&ready))
	require.True(t, ready)
	before := grantState(t)
	assertStored(t, old, "labels", 0, true)
	t.Run("unauthorized rolls back", func(t *testing.T) {
		denied := run(t, recipient)
		require.NotNil(t, denied.Error)
		require.Equal(t, int32(codes.PermissionDenied), denied.Error.GetCode(), "%v", denied.Error)
		assertStored(t, old, "labels", 0, true)
		require.Equal(t, before, grantState(t))
	})

	t.Run("authorized commits", func(t *testing.T) {
		done := run(t, actor)
		require.Nil(t, done.Error, "%v", done.Error)
		next := old
		next.MatchAccessLabels, next.MatchLabels = old.MatchLabels, nil
		assertStored(t, next, "access_labels", 1, false)
		require.Equal(t, before, grantState(t))
		check(t, recipient, "v_get", "project:"+string(project.ID), false)
		var audited bool
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT event_payload->>'actor'=$2 AND event_payload->'changed_fields'='["rules"]'::jsonb
		FROM kaname.audit_outbox WHERE event_type='iam.role.updated' AND event_payload->>'resource_id'=$1`, role.ID, actor).Scan(&audited))
		require.True(t, audited)
	})
}
