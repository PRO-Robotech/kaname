// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestExternalMetadataOrdinaryAndNoopCommit(t *testing.T) {
	const dotted, model, id = "vpc.network", "vpc_network", "external-ordinary/commit"
	r, owner := writerProtocolRigBeforePreparation(t)
	actorID := bindingPublicOwner(t, r)
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(actorID)}
	require.NoError(t, owner.PrepareAuthorityBundle(r.ctx, r.bundle))
	w := metadataFixtureModeWithRig(t, false, "prepared", r)
	_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.resource_mirror
 (object_type,object_id,parent_account_id,parent_project_id)
 VALUES($1,$2,$3,$4),('compute.instance',$2,$3,$4)`, dotted, id, r.a, string(w.project.ID))
	require.NoError(t, err)
	seedExternalMetadataUpdateBinding(t, r, actorID, model, id, string(w.project.ID))

	const writer = "kaname.authority_metadata_mirror_apply_v1(text,text)"
	calls := []string{
		"kaname.authority_metadata_mirror_ordinary_identity_v1(text,text)",
		"kaname.authority_metadata_mirror_ordinary_discover_v1(text,text,integer,integer)",
		"kaname.authority_metadata_mirror_ordinary_preflight_v1(text,text,jsonb,jsonb,text,text,text,integer,integer,integer)",
		"kaname.authority_metadata_mirror_ordinary_accept_v1(text,text)",
		writer,
	}
	for _, function := range calls {
		var allowed bool
		require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(current_user,$1,'EXECUTE')`,
			function).Scan(&allowed))
		require.True(t, allowed, function)
	}
	for _, private := range []string{
		"kaname._authority_metadata_mirror_ordinary_root_v1(text,text,jsonb,jsonb,integer,integer,integer)",
		"kaname._authority_metadata_mirror_ordinary_command_v1()",
		"kaname._authority_metadata_mirror_ordinary_write_v1(text,text)",
		"kaname._authority_metadata_mirror_ordinary_complete_v1()",
	} {
		var allowed bool
		require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(current_user,$1,'EXECUTE')`,
			private).Scan(&allowed))
		require.False(t, allowed)
	}
	root := domain.ResourceRef{Type: dotted, ID: id}
	update := func(next domain.Labels, subject domain.Subject) (domain.ResourceMetadata, error) {
		t.Helper()
		return w.factory.UpdateExternalMetadataForTest(r.ctx, root, next, domain.Labels{}, []string{"labels", "access_labels"}, subject)
	}
	state := func() json.RawMessage {
		t.Helper()
		var out json.RawMessage
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_build_object(
 'root',(SELECT jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m)) FROM ONLY kaname.resource_mirror m
   WHERE m.object_type=$1 AND m.object_id=$2),
 'other',(SELECT jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m)) FROM ONLY kaname.resource_mirror m
   WHERE m.object_type='compute.instance' AND m.object_id=$2),
 'policy',kaname.authority_policy_epoch_read(ARRAY['*','scope:'||$3::text]),
 'binding',kaname.authority_binding_epoch_read(ARRAY[$3::text]),
 'permanent',(SELECT coalesce(jsonb_agg(to_jsonb(b) ORDER BY b.object_type),'[]') FROM ONLY kaname.object_project_binding b
   WHERE b.object_id=$2),
 'audit',(SELECT count(*) FROM ONLY kaname.audit_outbox WHERE event_payload->>'resource_type'=$1 AND event_payload->>'resource_id'=$2),
 'reconcile',(SELECT count(*) FROM ONLY kaname.resource_reconcile_outbox WHERE object_type=$1 AND object_id=$2),
 'dirty',(SELECT coalesce(jsonb_agg(to_jsonb(d)),'[]') FROM ONLY kaname.authority_access_label_dirty_root d
   WHERE d.root_type=$1 AND d.root_id=$2))`, dotted, id, r.a).Scan(&out))
		return out
	}
	initial := state()
	out, err := update(nil, domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(w.outsider)})
	require.Error(t, err)
	require.Equal(t, domain.ResourceMetadata{}, out)
	require.JSONEq(t, string(initial), string(state()))
	out, err = update(nil, actor)
	require.NoError(t, err)
	require.Equal(t, domain.ResourceMetadata{ResourceType: dotted, ResourceID: id, Labels: map[string]string{}, AccessLabels: map[string]string{}}, out)
	require.JSONEq(t, string(initial), string(state()))

	labels := domain.Labels{"owner": "team-green"}
	expectedLabels := map[string]string{"owner": "team-green"}
	// Ошибка последнего INSERT откатывает зеркало, обе эпохи и аудит.
	_, err = r.admin.Exec(r.ctx, `CREATE FUNCTION kaname.test_external_ordinary_queue_failure() RETURNS trigger
 LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'ordinary outbox unavailable in fixture'; END $$;
 CREATE TRIGGER test_external_ordinary_queue_failure BEFORE INSERT ON kaname.resource_reconcile_outbox
 FOR EACH ROW EXECUTE FUNCTION kaname.test_external_ordinary_queue_failure()`)
	require.NoError(t, err)
	out, err = update(labels, actor)
	var failed *pgconn.PgError
	require.ErrorAs(t, err, &failed)
	require.Equal(t, "P0001", failed.Code)
	require.Equal(t, domain.ResourceMetadata{}, out)
	require.JSONEq(t, string(initial), string(state()))
	_, err = r.admin.Exec(r.ctx, `DROP TRIGGER test_external_ordinary_queue_failure ON kaname.resource_reconcile_outbox;
 DROP FUNCTION kaname.test_external_ordinary_queue_failure()`)
	require.NoError(t, err)
	out, err = update(labels, actor)
	require.NoError(t, err)
	require.Equal(t, domain.ResourceMetadata{ResourceType: dotted, ResourceID: id, Labels: expectedLabels, AccessLabels: map[string]string{}}, out)
	final := state()
	var before, after struct {
		Other, Root, Permanent, Dirty json.RawMessage
		Audit, Reconcile              int
	}
	require.NoError(t, json.Unmarshal(initial, &before))
	require.NoError(t, json.Unmarshal(final, &after))
	require.NotEqual(t, before.Root, after.Root)
	require.Equal(t, before.Audit+1, after.Audit)
	require.Equal(t, before.Reconcile+1, after.Reconcile)
	require.JSONEq(t, string(before.Other), string(after.Other))
	require.JSONEq(t, string(before.Permanent), string(after.Permanent))
	require.JSONEq(t, string(before.Dirty), string(after.Dirty))
	var auditEvent, reconcileEvent string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT a.event_type,q.event_type
 FROM ONLY kaname.audit_outbox a JOIN ONLY kaname.resource_reconcile_outbox q
 ON q.object_type=$1::text AND q.object_id=$2::text AND q.created_at=a.created_at
 WHERE a.tenant_account_id=$4::text AND a.event_payload=jsonb_build_object(
 'actor',jsonb_build_object('type','user','id',$3::text),'resource_type',$1::text,'resource_id',$2::text,
 'account_id',$4::text,'changed_fields',jsonb_build_array('labels'))
 AND a.status='pending' AND a.attempts=0 AND a.next_attempt_at=a.created_at AND a.sent_at IS NULL AND a.last_error IS NULL
 AND q.id>0 AND q.sent_at IS NULL AND q.last_error IS NULL AND q.attempt_count=0`, dotted, id, actorID, r.a).Scan(&auditEvent, &reconcileEvent))
	require.Equal(t, "iam.resource_metadata.labels_updated", auditEvent)
	require.Equal(t, "mirror.upsert", reconcileEvent)
	out, err = update(labels, actor)
	require.NoError(t, err)
	require.Equal(t, expectedLabels, out.Labels)
	require.JSONEq(t, string(final), string(state()))
}

// Право обновления выводится из действующей выдачи и проверяемого журнала
// материализации. Отдельная строка relation_fact не доказывает источник.
func seedExternalMetadataUpdateBinding(t *testing.T, r protocolRig, actorID, model, id, project string) {
	t.Helper()
	// Внешний объект входит в область через зарегистрированную связь.
	_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.resource_parent_edge(object_type,object_id,parent_type,parent_id,depth)
 VALUES($1,$2,'project',$3,1)`, model, id, project)
	require.NoError(t, err)
	rule := domain.Rule{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"update"}}
	binding := groupLifecycleBinding(t, r, r.a, actorID, "external_metadata_editor", rule)
	catalog := rolePolicyCatalog(t, r)
	engine := reconcile.New(kanamepg.NewReconcileAdapter(r.admin, catalog), slog.Default(), catalog)
	require.NoError(t, engine.ReconcileBinding(r.ctx, binding))
	require.True(t, ledgerHasTuple(t, r.ctx, r.runtime, binding, "user:"+actorID, "v_update", model+":"+id),
		"выдача должна материализовать точный объект и глагол")
}
