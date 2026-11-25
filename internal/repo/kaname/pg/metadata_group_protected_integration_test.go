// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	groupapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/group"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

func TestGroupProtectedMetadataCommitsExactOutputsThroughAPI(t *testing.T) {
	r, owner := writerProtocolRigBeforePreparation(t)
	actor := bindingPublicOwner(t, r)
	create, err := lifecycleOwner(r).Writer(r.ctx)
	require.NoError(t, err)
	defer func() { _ = create.Rollback(context.WithoutCancel(r.ctx)) }()
	group, err := create.GroupsW().Insert(r.ctx, domain.Group{
		ID: domain.GroupID(ids.NewID(domain.PrefixGroup)), AccountID: domain.AccountID(r.a),
		Name: "group-api-protected", Labels: domain.Labels{},
	})
	require.NoError(t, err)
	sibling, err := create.GroupsW().Insert(r.ctx, domain.Group{
		ID: domain.GroupID(ids.NewID(domain.PrefixGroup)), AccountID: group.AccountID,
		Name: "group-api-sibling", Labels: domain.Labels{},
	})
	require.NoError(t, err)
	require.NoError(t, create.EmitFGARelationWrite(r.ctx, []service.RelationTuple{
		{User: "account:" + r.a, Relation: "account", Object: "iam_group:" + string(group.ID)},
		{User: "account:" + r.a, Relation: "account", Object: "iam_group:" + string(sibling.ID)},
	}))
	require.NoError(t, create.Commit(r.ctx))
	seedDefinition := func(key, value string) string {
		t.Helper()
		var definition string
		require.NoError(t, r.admin.QueryRow(r.ctx, `INSERT INTO kaname.authority_access_label_definition
			(scope_kind,scope_id,module,resource,label_key) VALUES('account',$1,'iam','group',$2)
			RETURNING id::text`, r.a, key).Scan(&definition))
		_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_value(definition_id,label_value)
			VALUES($1::uuid,$2)`, definition, value)
		require.NoError(t, err)
		return definition
	}
	team := seedDefinition("team", "blue")
	seedDefinition("no_apply", "blocked")
	seedMetadataActualApplySource(t, r, actor, team)
	require.NoError(t, owner.PrepareAuthorityBundle(r.ctx, r.bundle))
	w := metadataFixtureModeWithRig(t, false, "full", r, func(r protocolRig) {
		editor := groupLifecycleBinding(t, r, r.a, actor, "group_api_editor", domain.Rule{
			Module: "iam", Resources: []string{"group"}, Verbs: []string{"update"},
		})
		source := rolePolicyCatalog(t, r)
		engine := reconcile.New(kanamepg.NewReconcileAdapter(r.admin, source), slog.Default(), source)
		require.NoError(t, engine.ReconcileBinding(r.ctx, editor))
	})

	ports, err := w.factory.WithInstalledGroupAccessLabels(r.ctx)
	require.NoError(t, err)
	require.NotNil(t, ports)
	update := groupapp.NewUpdateGroupUseCase(w.full, w.ops)
	handler := groupapp.NewHandler(nil, update, nil, nil, nil, nil, nil, nil).
		WithGroupAccessLabelsWriter(ports)

	var original json.RawMessage
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT to_jsonb(g) FROM ONLY kaname.groups g WHERE id=$1`,
		group.ID).Scan(&original))
	counts := func() [3]int {
		t.Helper()
		var out [3]int
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
			(SELECT count(*) FROM kaname.audit_outbox WHERE event_type='iam.group.updated' AND event_payload->>'resource_id'=$1),
			(SELECT count(*) FROM kaname.resource_reconcile_outbox WHERE event_type='mirror.upsert' AND object_type='iam.group' AND object_id=$1),
			(SELECT count(*) FROM kaname.resource_journal WHERE event_type='UPDATED' AND resource_kind='iam_group' AND resource_id=$1)`,
			group.ID).Scan(&out[0], &out[1], &out[2]))
		return out
	}
	before := counts()
	run := func(access, labels map[string]string, description string, want codes.Code) {
		t.Helper()
		mask := []string{"access_labels", "description"}
		if labels != nil {
			mask = append(mask, "labels")
		}
		operation, err := handler.Update(declarerCtx(r.ctx, actor), &iamv1.UpdateGroupRequest{
			GroupId: string(group.ID), AccessLabels: access, Description: description, Labels: labels,
			UpdateMask: &fieldmaskpb.FieldMask{Paths: mask},
		})
		require.NoError(t, err)
		result := awaitOperation(t, r.ctx, w.ops, operation.GetId())
		if want == codes.OK {
			require.Nil(t, result.Error)
			return
		}
		require.NotNil(t, result.Error)
		require.Equal(t, int32(want), result.Error.Code, result.Error.Message)
	}
	check := func(description string, labels map[string]string, added [3]int) {
		t.Helper()
		expected, err := json.Marshal(map[string]any{
			"access_labels": domain.Labels{"team": "blue"}, "description": description, "labels": labels,
		})
		require.NoError(t, err)
		var exact bool
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT to_jsonb(g)=($2::jsonb||$3::jsonb)
			FROM ONLY kaname.groups g WHERE id=$1`, group.ID, original, expected).Scan(&exact))
		require.True(t, exact)
		require.Equal(t, [3]int{before[0] + added[0], before[1] + added[1], before[2] + added[2]}, counts())
	}
	access, noLabels := map[string]string{"team": "blue"}, map[string]string{}
	run(access, nil, "принято", codes.OK)
	check("принято", noLabels, [3]int{1, 1, 1})
	run(map[string]string{"team": "blue", "no_apply": "blocked"}, nil, "отклонено", codes.PermissionDenied)
	check("принято", noLabels, [3]int{1, 1, 1})

	run(access, nil, "описание", codes.OK)
	check("описание", noLabels, [3]int{2, 1, 2})
	labels := map[string]string{"display": "listed"}
	run(access, labels, "описание", codes.OK)
	check("описание", labels, [3]int{3, 2, 3})

	readVersions := func() json.RawMessage {
		t.Helper()
		var receipt json.RawMessage
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_build_array(g.xmin::text,g.ctid::text,
			(SELECT to_jsonb(p) FROM kaname.authority_policy_epoch p WHERE p.key='group:'||g.id),
			(SELECT to_jsonb(b) FROM kaname.authority_binding_epoch b WHERE b.scope=g.account_id))
			FROM ONLY kaname.groups g WHERE g.id=$1`, group.ID).Scan(&receipt))
		return receipt
	}
	versions := readVersions()
	run(access, labels, "описание", codes.OK)
	check("описание", labels, [3]int{3, 2, 3})
	require.JSONEq(t, string(versions), string(readVersions()))

	for _, tc := range []struct {
		caller, name string
		want         codes.Code
	}{
		{actor, string(sibling.Name), codes.AlreadyExists},
		{w.outsider, string(sibling.Name), codes.PermissionDenied},
		{w.outsider, "group-api-available", codes.PermissionDenied},
	} {
		operation, err := handler.Update(declarerCtx(r.ctx, tc.caller), &iamv1.UpdateGroupRequest{
			GroupId: string(group.ID), AccessLabels: access, Name: tc.name,
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"access_labels", "name"}},
		})
		require.NoError(t, err)
		failure := awaitOperation(t, r.ctx, w.ops, operation.GetId()).Error
		require.NotNil(t, failure)
		require.Equal(t, int32(tc.want), failure.Code, failure.Message)
		if tc.want == codes.AlreadyExists {
			require.Equal(t, "Group with name "+tc.name+" already exists", failure.Message)
		}
		check("описание", labels, [3]int{3, 2, 3})
		require.JSONEq(t, string(versions), string(readVersions()))
	}
}
