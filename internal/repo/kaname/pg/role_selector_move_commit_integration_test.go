// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"log/slog"
	"testing"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	bindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

// Вызовы используют одну и ту же редакцию роли. Отказ постороннему должен
// оставить её пригодной для последующей авторизованной операции.
func TestRoleSelectorMoveUpdateCommitsPendingNoCopy(t *testing.T) {
	testRoleSelectorMoveUpdateNoCopy(t, domain.AccessBindingStatusPending, false, false)
}

func TestRoleSelectorMoveUpdatePreservesActiveNoCopy(t *testing.T) {
	testRoleSelectorMoveUpdateNoCopy(t, domain.AccessBindingStatusActive, false, false)
}

func TestRoleSelectorMoveUpdatePreservesActiveSelectedPairs(t *testing.T) {
	testRoleSelectorMoveUpdateNoCopy(t, domain.AccessBindingStatusActive, true, false)
}

func TestRoleSelectorMoveUpdatePreservesActiveNestedProjectNoCopy(t *testing.T) {
	testRoleSelectorMoveUpdateNoCopy(t, domain.AccessBindingStatusActive, false, true)
}

func testRoleSelectorMoveUpdateNoCopy(t *testing.T, status domain.AccessBindingStatus, unrelatedLabel, nested bool) {
	t.Helper()
	active := status == domain.AccessBindingStatusActive
	r, owner := writerProtocolRigBeforePreparation(t)
	actor := bindingPublicOwner(t, r)
	var recipient string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, r.b).Scan(&recipient))
	outsider := recipient
	if active {
		recipient = seedMemberUser(t, r.ctx, r.admin, r.a, "active-selector-move")
		_, err := r.admin.Exec(r.ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=$1`, recipient)
		require.NoError(t, err)
	}
	project := seedMetadataActualProject(t, r, "selector-move-project")
	old := domain.Rule{Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"team": "blue"}}
	projectLabels := map[string]string{"team": "blue"}
	if unrelatedLabel {
		projectLabels["description"] = "legacy-only"
	}
	setProjectLabels(t, r.ctx, r.admin, project.ID, projectLabels)
	target := domain.ResourceRef{Type: "iam.project", ID: string(project.ID)}
	next := old
	next.MatchAccessLabels, next.MatchLabels = old.MatchLabels, nil
	if nested {
		seedNestedProjectEdge(t, r, project.ID)
		target = domain.ResourceRef{Type: "iam.account", ID: r.a}
		old = domain.Rule{Module: "iam", Resources: []string{"account"}, ResourceNames: []string{r.a}, Verbs: []string{"get"},
			Children: []domain.Rule{{Resources: []string{"project"}, Verbs: []string{"get"}, MatchLabels: old.MatchLabels}}}
		next = old
		next.Children = []domain.Rule{{Resources: []string{"project"}, Verbs: []string{"get"}, MatchAccessLabels: old.Children[0].MatchLabels}}
	}
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
		ResourceType: "account", ResourceID: r.a, Scope: domain.ScopeAccount, Status: status,
		Target: domain.AccessTarget{Resources: []domain.ResourceRef{target}},
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
	materialize := []domain.AccessBindingID{editor}
	if active {
		materialize = append(materialize, binding.ID)
	}
	shared, contract := pendingSourceApplyProjectLabel(t, r, owner, actor, project.ID, materialize...)
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
	check(t, recipient, "v_get", "project:"+string(project.ID), active)
	if active {
		check(t, outsider, "v_get", "project:"+string(project.ID), false)
	}

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
	if nested {
		request.AccessLabelSelectorMove.Positions[0].ChildIndex = &first
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
	oldSelectors := domain.Rules{old}.MaterializingSelectors()
	nextSelectors := domain.Rules{next}.MaterializingSelectors()
	oldFP, newFP := oldSelectors[len(oldSelectors)-1].RuleFP, nextSelectors[len(nextSelectors)-1].RuleFP
	grantState := func(t *testing.T, compareRights bool) string {
		t.Helper()
		var state string
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_build_array(
			to_jsonb(b),p.xmin::text,p.labels,p.access_labels,
			(SELECT jsonb_agg(to_jsonb(s) ORDER BY s.ordinal) FROM ONLY kaname.access_binding_subjects s WHERE s.binding_id=b.id),
			(SELECT jsonb_agg(item ORDER BY item) FROM (
				SELECT CASE WHEN $3 AND m.object_type='iam.project' AND m.object_id=p.id AND m.rule_fp IN ($4,$5)
					OR $3 AND $6 AND m.object_type='iam.account' AND m.object_id=b.resource_id AND m.rule_fp IN ($7,$8)
					THEN to_jsonb(m)-ARRAY['rule_fp','created_at','updated_at']
					ELSE to_jsonb(m) END AS item
				FROM ONLY kaname.access_binding_target_members m WHERE m.binding_id=b.id
			) AS members),
			(SELECT jsonb_agg(to_jsonb(e) ORDER BY e.object,e.fga_user,e.relation,e.member_object_type,e.member_object_id) FROM ONLY kaname.access_binding_emitted_tuples e WHERE e.binding_id=b.id)
		)::text FROM ONLY kaname.access_bindings b, ONLY kaname.projects p WHERE b.id=$1 AND p.id=$2`, binding.ID, project.ID, compareRights, oldFP, newFP, nested, old.Fingerprint(), next.Fingerprint()).Scan(&state))
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
			FROM ONLY kaname.roles r JOIN ONLY kaname.role_rule_selectors s ON s.role_id=r.id WHERE r.id=$1 AND (s.container_type IS NOT NULL)=$2`, role.ID, nested).
			Scan(&current, &stored, &count, &storedArm, &labels, &access, &audit, &journal))
		require.Equal(t, sameVersion, current == version)
		require.JSONEq(t, string(expected), string(stored))
		require.Equal(t, len(oldSelectors), count)
		if nested {
			var parent, child string
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT p.rule_fp, c.rule_fp FROM ONLY kaname.role_rule_selectors p
				JOIN ONLY kaname.role_rule_selectors c ON c.role_id=p.role_id WHERE p.role_id=$1 AND p.arm='names'
				AND p.container_type IS NULL AND c.container_type='iam.account' AND c.container_arm='names'
				AND c.container_resource_names=ARRAY[$2::text]`, role.ID, r.a).Scan(&parent, &child))
			selected := domain.Rules{rule}.MaterializingSelectors()
			require.Equal(t, selected[0].RuleFP, parent)
			require.Equal(t, selected[1].RuleFP, child)
		}
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
	assertActiveRows := func(t *testing.T, fingerprint string) {
		t.Helper()
		var fingerprints []string
		var hasRead bool
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
			ARRAY(SELECT rule_fp FROM ONLY kaname.access_binding_target_members
				WHERE binding_id=$1 AND role_id=$2 AND object_type='iam.project' AND object_id=$3
				AND verification_status='ACTIVE' AND rule_fp IN ($5,$6) ORDER BY rule_fp),
			EXISTS(SELECT FROM ONLY kaname.access_binding_emitted_tuples
				WHERE binding_id=$1 AND source='member' AND member_object_type='iam.project' AND member_object_id=$3
				AND fga_user=$4 AND relation='v_get' AND object='project:'||$3)`,
			binding.ID, role.ID, project.ID, "user:"+recipient, oldFP, newFP).Scan(&fingerprints, &hasRead))
		require.Equal(t, []string{fingerprint}, fingerprints)
		require.True(t, hasRead)
		if nested {
			var parentFP string
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT rule_fp FROM ONLY kaname.access_binding_target_members
			     WHERE binding_id=$1 AND role_id=$2 AND object_type='iam.account' AND object_id=$3 AND live AND verification_status='ACTIVE'`,
				binding.ID, role.ID, r.a).Scan(&parentFP))
			want := old.Fingerprint()
			if fingerprint == newFP {
				want = next.Fingerprint()
			}
			require.Equal(t, want, parentFP)
			check(t, recipient, "v_get", "account:"+r.a, true)
			check(t, outsider, "v_get", "project:"+string(project.ID), false)
		}
	}
	var ready bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT p.labels=$4::jsonb AND p.access_labels='{"team":"blue"}'::jsonb AND b.status=$3
		AND b.target=jsonb_build_object('resources',jsonb_build_array(jsonb_build_object('type',$5::text,'id',$6::text)))
		AND ($3='ACTIVE' OR NOT EXISTS(SELECT FROM kaname.access_binding_target_members WHERE binding_id=b.id))
		FROM kaname.projects p, kaname.access_bindings b WHERE p.id=$1 AND b.id=$2`, project.ID, binding.ID, status, jsonObject(projectLabels), target.Type, target.ID).Scan(&ready))
	require.True(t, ready)
	if active {
		require.NotEqual(t, old.Fingerprint(), next.Fingerprint())
		assertActiveRows(t, oldFP)
	}
	before := grantState(t, false)
	beforeRights := before
	if active {
		beforeRights = grantState(t, true)
	}
	countProjectWrite := func(t *testing.T) int {
		t.Helper()
		var count int
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM ONLY kaname.fga_outbox
			WHERE event_type='fga.tuple.write' AND payload=jsonb_build_object('object','project:'||$1::text,'user','user:'||$2::text,
				'relation','v_get','relations',jsonb_build_array('v_get','viewer'))`, project.ID, recipient).Scan(&count))
		return count
	}
	beforeWrites := countProjectWrite(t)
	assertStored(t, old, "labels", 0, true)
	t.Run("unauthorized rolls back", func(t *testing.T) {
		denied := run(t, recipient)
		require.NotNil(t, denied.Error)
		require.Equal(t, int32(codes.PermissionDenied), denied.Error.GetCode(), "%v", denied.Error)
		assertStored(t, old, "labels", 0, true)
		require.Equal(t, before, grantState(t, false))
		require.Equal(t, beforeWrites, countProjectWrite(t))
		if active {
			assertActiveRows(t, oldFP)
			check(t, recipient, "v_get", "project:"+string(project.ID), true)
			check(t, outsider, "v_get", "project:"+string(project.ID), false)
		}
	})

	if nested {
		t.Run("stale role version rolls back both members", func(t *testing.T) {
			stale := proto.Clone(request).(*iamv1.UpdateRoleRequest)
			stale.ResourceVersion = "1"
			require.NotEqual(t, version, stale.ResourceVersion)
			ctx := contract.Context(declarerCtx(r.ctx, actor))
			reply, err := handler.Update(ctx, stale)
			if err != nil {
				require.Equal(t, codes.FailedPrecondition, grpcstatus.Code(err))
			} else {
				failed := awaitOperation(t, r.ctx, ops, reply.GetId())
				require.NotNil(t, failed.Error)
				require.Equal(t, int32(codes.FailedPrecondition), failed.Error.GetCode())
			}
			assertStored(t, old, "labels", 0, true)
			require.Equal(t, before, grantState(t, false))
			require.Equal(t, beforeWrites, countProjectWrite(t))
			assertActiveRows(t, oldFP)
			check(t, recipient, "v_get", "project:"+string(project.ID), true)
		})
	}

	t.Run("authorized commits", func(t *testing.T) {
		done := run(t, actor)
		if active && done.Error != nil {
			assertStored(t, old, "labels", 0, true)
			require.Equal(t, before, grantState(t, false))
			assertActiveRows(t, oldFP)
			check(t, recipient, "v_get", "project:"+string(project.ID), true)
			check(t, outsider, "v_get", "project:"+string(project.ID), false)
		}
		require.Nil(t, done.Error, "%v", done.Error)
		assertStored(t, next, "access_labels", 1, false)
		require.Equal(t, beforeRights, grantState(t, active))
		wantWrites := beforeWrites
		if active {
			wantWrites++
		}
		require.Equal(t, wantWrites, countProjectWrite(t))
		if active {
			assertActiveRows(t, newFP)
			check(t, outsider, "v_get", "project:"+string(project.ID), false)
		}
		check(t, recipient, "v_get", "project:"+string(project.ID), active)
		var audited bool
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT event_payload->>'actor'=$2 AND event_payload->'changed_fields'='["rules"]'::jsonb
		FROM kaname.audit_outbox WHERE event_type='iam.role.updated' AND event_payload->>'resource_id'=$1`, role.ID, actor).Scan(&audited))
		require.True(t, audited)
		if nested {
			ctx := contract.Context(r.ctx)
			membership, err := kanamepg.NewGroupMembershipParticipant(ctx, shared, r.bundle)
			require.NoError(t, err)
			staged, err := membership.NewBindingStageParticipant(ctx, slog.Default())
			require.NoError(t, err)
			source := rolePolicyCatalog(t, r)
			engine := reconcile.New(kanamepg.NewReconcileAdapter(r.runtime, source), slog.Default(), source)
			require.NoError(t, engine.WithStagedBindingReconciler(staged))
			require.NoError(t, engine.ReconcileBinding(ctx, binding.ID))
			assertActiveRows(t, newFP)
			check(t, recipient, "v_get", "project:"+string(project.ID), true)
			require.Equal(t, beforeRights, grantState(t, true))
			checkBindingProjectCustody(t, r, binding.ID)
		}
	})
}
