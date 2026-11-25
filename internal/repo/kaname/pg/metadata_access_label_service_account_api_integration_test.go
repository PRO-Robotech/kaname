// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"encoding/json"
	"log/slog"
	"testing"

	saapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/service_account"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

// Реальный SA Update: apply, mixed, clear, no-op и два OLD holder через обычный LOGIN.
func TestMetadataAccessLabelsActualServiceAccountUpdate(t *testing.T) {
	for _, mode := range []string{"prepared", "active", "full"} {
		t.Run(mode, func(t *testing.T) { testMetadataAccessLabelsActualServiceAccountUpdate(t, mode) })
	}
}

func testMetadataAccessLabelsActualServiceAccountUpdate(t *testing.T, mode string) {
	t.Helper()
	r, owner := writerProtocolRigBeforePreparation(t)
	actor := bindingPublicOwner(t, r)
	var definitions []string
	for key, values := range map[string][]string{"team": {"before", "after"}, "keep": {"yes", "no"}, "no_apply": {"blocked"}} {
		var definition string
		require.NoError(t, r.admin.QueryRow(r.ctx, `INSERT INTO kaname.authority_access_label_definition
   (scope_kind,scope_id,module,resource,label_key) VALUES('account',$1,'iam','serviceAccount',$2) RETURNING id::text`, r.a, key).Scan(&definition))
		for _, value := range values {
			_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_value(definition_id,label_value) VALUES($1::uuid,$2)`, definition, value)
			require.NoError(t, err)
		}
		if key != "no_apply" {
			definitions = append(definitions, definition)
		}
	}
	seedMetadataActualApplySource(t, r, actor, definitions...)
	require.NoError(t, owner.PrepareAuthorityBundle(r.ctx, r.bundle))
	var recipient string
	var losing, surviving, editor domain.AccessBindingID
	w := metadataFixtureModeWithRig(t, false, mode, r, func(r protocolRig) {
		recipient = seedMemberUser(t, r.ctx, r.admin, r.a, "sa-protected-recipient")
		losing = groupLifecycleBinding(t, r, r.a, recipient, "sa_team_holder", domain.Rule{
			Module: "iam", Resources: []string{"serviceAccount"}, Verbs: []string{"get"}, MatchAccessLabels: map[string]string{"team": "before"},
		})
		surviving = groupLifecycleBinding(t, r, r.a, recipient, "sa_keep_holder", domain.Rule{
			Module: "iam", Resources: []string{"serviceAccount"}, Verbs: []string{"get"}, MatchAccessLabels: map[string]string{"keep": "yes"},
		})
		editor = groupLifecycleBinding(t, r, r.a, actor, "sa_protected_editor", domain.Rule{Module: "iam", Resources: []string{"serviceAccount"}, Verbs: []string{"update"}})
	})
	ports, err := w.factory.WithInstalledAccessLabels(r.ctx)
	require.NoError(t, err)
	_, ok := ports.(kaname.ServiceAccountAccessLabelsWriterFactory)
	require.True(t, ok, "SA writer requires the installed SA contract")
	rig := r
	rig.repo = w.full
	engine := bindingStageEngine(t, rig, nil)
	require.NoError(t, engine.ReconcileBinding(r.ctx, editor))
	update := saapp.NewUpdateServiceAccountUseCase(w.full, w.ops).WithServiceAccountMetadataWriter(ports)
	handler := saapp.NewHandler(nil, update, nil, nil, nil, nil, nil)
	// Object-only runner использует штатный source/clock/commit путь; регистрацию модулей не вызываем.
	runner, err := kanamepg.NewResourceDecisionRunner(r.ctx, w.full, r.bundle, authzguard.NewRelationWriteGate(delegationNativeDoor{rig}))
	require.NoError(t, err)
	objects, err := runner.NewObjectReconciler(slog.Default())
	require.NoError(t, err)
	toProtoLabels := func(labels domain.Labels) map[string]string {
		if labels == nil {
			return nil
		}
		result := make(map[string]string, len(labels))
		for key, value := range labels {
			result[string(key)] = string(value)
		}
		return result
	}

	reader := metadataActualReadbackLogin(t, r)
	var original json.RawMessage
	require.NoError(t, reader.QueryRow(r.ctx, `SELECT to_jsonb(s) FROM kaname.service_accounts s WHERE id=$1`, w.sa.ID).Scan(&original))
	run := func(subject string, access, ordinary domain.Labels, mask []string, want codes.Code) {
		t.Helper()
		op, err := handler.Update(declarerCtx(r.ctx, subject), &iamv1.UpdateServiceAccountRequest{ServiceAccountId: string(w.sa.ID), AccessLabels: toProtoLabels(access), Labels: toProtoLabels(ordinary), UpdateMask: &fieldmaskpb.FieldMask{Paths: mask}})
		require.NoError(t, err)
		result := awaitOperation(t, r.ctx, w.ops, op.GetId())
		if want == codes.OK {
			require.Nil(t, result.Error)
		} else {
			require.NotNil(t, result.Error)
			require.Equal(t, int32(want), result.Error.Code, result.Error.Message)
		}
	}
	snapshot := func() string {
		t.Helper()
		var result string
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_build_object(
   'row',(SELECT jsonb_build_array(xmin::text,ctid::text,to_jsonb(s)) FROM kaname.service_accounts s WHERE id=$1),
   'generation',(SELECT to_jsonb(d) FROM kaname.authority_access_label_dirty_root d WHERE root_type='iam.serviceAccount' AND root_id=$1),
   'facts',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY object_type,object_id,relation,subject),'[]') FROM kaname.authority_access_label_dirty_fact d WHERE root_type='iam.serviceAccount' AND root_id=$1),
   'audit',(SELECT count(*) FROM kaname.audit_outbox WHERE event_type='iam.service_account.updated' AND event_payload->>'resource_id'=$1),
   'journal',(SELECT count(*) FROM kaname.resource_journal WHERE resource_kind='iam_service_account' AND resource_id=$1 AND event_type='UPDATED'))::text`, w.sa.ID).Scan(&result))
		return result
	}
	before := snapshot()
	run(w.actor, domain.Labels{"team": "before", "keep": "yes"}, nil, []string{"access_labels"}, codes.PermissionDenied)
	require.JSONEq(t, before, snapshot(), "ordinary update cannot replace apply/Grant")
	run(actor, domain.Labels{"team": "before", "keep": "yes"}, domain.Labels{"ordinary": "preserved"}, []string{"labels", "access_labels"}, codes.OK)
	var exact bool
	require.NoError(t, reader.QueryRow(r.ctx, `SELECT to_jsonb(s)=($2::jsonb||'{"labels":{"ordinary":"preserved"},"access_labels":{"team":"before","keep":"yes"}}'::jsonb) FROM kaname.service_accounts s WHERE id=$1`, w.sa.ID, original).Scan(&exact))
	require.True(t, exact, "another LOGIN sees exactly the accepted mixed image")
	for _, id := range []domain.AccessBindingID{losing, surviving} {
		require.NoError(t, engine.ReconcileBinding(r.ctx, id))
	}
	var holders int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(DISTINCT binding_id) FROM kaname.access_binding_emitted_tuples
  WHERE binding_id=ANY($1::text[]) AND member_object_type='iam.serviceAccount' AND member_object_id=$2
  AND object='iam_service_account:'||$2 AND relation='viewer' AND fga_user=$3`, []string{string(losing), string(surviving)}, w.sa.ID, "user:"+recipient).Scan(&holders))
	require.Equal(t, 2, holders)
	var oldFact json.RawMessage
	require.NoError(t, reader.QueryRow(r.ctx, `SELECT to_jsonb(f) FROM kaname.relation_fact f
 WHERE object_type='iam_service_account' AND object_id=$1 AND relation='viewer' AND subject=$2`, w.sa.ID, "user:"+recipient).Scan(&oldFact))
	run(actor, domain.Labels{"team": "after", "keep": "yes"}, nil, []string{"accessLabels"}, codes.OK)
	var fresh bool
	require.NoError(t, reader.QueryRow(r.ctx, `SELECT kaname.authority_access_label_fact_fresh_v1('iam_service_account',$1,'viewer',$2)`, w.sa.ID, "user:"+recipient).Scan(&fresh))
	require.True(t, fresh, "second holder retains the OLD physical fact")
	var sameFact bool
	require.NoError(t, reader.QueryRow(r.ctx, `SELECT to_jsonb(f)=$3::jsonb FROM kaname.relation_fact f
 WHERE object_type='iam_service_account' AND object_id=$1 AND relation='viewer' AND subject=$2`, w.sa.ID, "user:"+recipient, oldFact).Scan(&sameFact))
	require.True(t, sameFact, "protected write preserves the retained physical fact")
	require.NoError(t, objects.ReconcileObject(r.ctx, "iam.serviceAccount", string(w.sa.ID)))
	var remainingHolders []string
	require.NoError(t, reader.QueryRow(r.ctx, `SELECT coalesce(array_agg(DISTINCT binding_id ORDER BY binding_id),'{}'::text[])
 FROM kaname.access_binding_emitted_tuples WHERE binding_id=ANY($1::text[]) AND member_object_type='iam.serviceAccount' AND member_object_id=$2
 AND object='iam_service_account:'||$2 AND relation='viewer' AND fga_user=$3`, []string{string(losing), string(surviving)}, w.sa.ID, "user:"+recipient).Scan(&remainingHolders))
	require.Equal(t, []string{string(surviving)}, remainingHolders, "object reconciliation removes only the losing holder")
	var factPresent bool
	require.NoError(t, reader.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.relation_fact
 WHERE object_type='iam_service_account' AND object_id=$1 AND relation='viewer' AND subject=$2)`, w.sa.ID, "user:"+recipient).Scan(&factPresent))
	require.True(t, factPresent, "the independent surviving holder keeps the materialized fact")
	require.NoError(t, reader.QueryRow(r.ctx, `SELECT kaname.authority_access_label_fact_fresh_v1('iam_service_account',$1,'viewer',$2)`, w.sa.ID, "user:"+recipient).Scan(&fresh))
	require.True(t, fresh)

	before = snapshot()
	run(actor, domain.Labels{"team": "after", "keep": "yes"}, nil, []string{"access_labels"}, codes.OK)
	require.JSONEq(t, before, snapshot(), "idempotent protected no-op preserves all durable effects")
	run(actor, domain.Labels{"no_apply": "blocked"}, nil, []string{"access_labels"}, codes.PermissionDenied)
	require.JSONEq(t, before, snapshot(), "known key without apply leaves no partial writes")
	run(actor, domain.Labels{}, nil, []string{"access_labels"}, codes.OK)
	var ordinary, access json.RawMessage
	require.NoError(t, reader.QueryRow(r.ctx, `SELECT labels,access_labels FROM kaname.service_accounts WHERE id=$1`, w.sa.ID).Scan(&ordinary, &access))
	require.JSONEq(t, `{"ordinary":"preserved"}`, string(ordinary))
	require.JSONEq(t, `{}`, string(access))
	require.NoError(t, reader.QueryRow(r.ctx, `SELECT kaname.authority_access_label_fact_fresh_v1('iam_service_account',$1,'viewer',$2)`, w.sa.ID, "user:"+recipient).Scan(&fresh))
	require.False(t, fresh, "clear fences the last surviving holder fact")
	var audits int
	require.NoError(t, reader.QueryRow(r.ctx, `SELECT count(*) FROM kaname.audit_outbox WHERE event_type='iam.service_account.updated' AND event_payload->>'resource_id'=$1 AND event_payload->>'actor'=$2`, w.sa.ID, actor).Scan(&audits))
	require.Equal(t, 3, audits)
	var pendingRoots, pendingFacts int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
 (SELECT count(*) FROM kaname.authority_access_label_dirty_root WHERE root_type='iam.serviceAccount' AND root_id=$1),
 (SELECT count(*) FROM kaname.authority_access_label_dirty_fact WHERE root_type='iam.serviceAccount' AND root_id=$1)`, w.sa.ID).Scan(&pendingRoots, &pendingFacts))
	require.Equal(t, 1, pendingRoots)
	require.Positive(t, pendingFacts, "clear opened revocation work")
	var pendingViewer bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.authority_access_label_dirty_fact
 WHERE root_type='iam.serviceAccount' AND root_id=$1 AND object_type='iam_service_account' AND object_id=$1
 AND relation='viewer' AND subject=$2)`, w.sa.ID, "user:"+recipient).Scan(&pendingViewer))
	require.True(t, pendingViewer, "clear includes the exact surviving viewer revocation")
	require.NoError(t, objects.ReconcileObject(r.ctx, "iam.serviceAccount", string(w.sa.ID)))
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
 (SELECT count(*) FROM kaname.authority_access_label_dirty_root WHERE root_type='iam.serviceAccount' AND root_id=$1),
 (SELECT count(*) FROM kaname.authority_access_label_dirty_fact WHERE root_type='iam.serviceAccount' AND root_id=$1)`, w.sa.ID).Scan(&pendingRoots, &pendingFacts))
	require.Zero(t, pendingRoots, "ordinary object reconciliation finishes the generation")
	require.Zero(t, pendingFacts)
	require.NoError(t, reader.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.relation_fact
 WHERE object_type='iam_service_account' AND object_id=$1 AND relation='viewer' AND subject=$2)`, w.sa.ID, "user:"+recipient).Scan(&factPresent))
	require.False(t, factPresent, "another LOGIN observes the revoked fact physically absent")
	require.NoError(t, reader.QueryRow(r.ctx, `SELECT count(*) FROM kaname.access_binding_emitted_tuples
 WHERE member_object_type='iam.serviceAccount' AND member_object_id=$1
 AND object='iam_service_account:'||$1 AND relation='viewer' AND fga_user=$2`, w.sa.ID, "user:"+recipient).Scan(&holders))
	require.Zero(t, holders, "no holder ledger can restore the revoked fact")
}
