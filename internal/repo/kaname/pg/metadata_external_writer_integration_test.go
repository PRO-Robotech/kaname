// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"encoding/json"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestExternalMetadataOwnerWriteCompletesAtomically(t *testing.T) {
	const dotted, model, id = "vpc.network", "vpc_network", "external-owner/atomic"
	r, owner := writerProtocolRigBeforePreparation(t)
	actorID := bindingPublicOwner(t, r)
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(actorID)}
	var definition string
	require.NoError(t, r.admin.QueryRow(r.ctx, `INSERT INTO kaname.authority_access_label_definition
 (scope_kind,scope_id,module,resource,label_key) VALUES('account',$1,'vpc','network','team') RETURNING id::text`, r.a).Scan(&definition))
	_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_value(definition_id,label_value)
 VALUES($1::uuid,'after')`, definition)
	require.NoError(t, err)
	seedMetadataActualApplySource(t, r, actorID, definition)
	_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject)
 VALUES($1,$2,'v_update',$3)`, model, id, "user:"+actorID)
	require.NoError(t, err)
	require.NoError(t, owner.PrepareAuthorityBundle(r.ctx, r.bundle))
	w := metadataFixtureModeWithRig(t, false, "prepared", r)
	_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.resource_mirror
 (object_type,object_id,parent_account_id,parent_project_id)
 VALUES ($1,$2,$3,$4),('compute.instance',$2,$3,$4)`, dotted, id, r.a, string(w.project.ID))
	require.NoError(t, err)
	installExternalRegistrationReceiptProbe(t, r)
	readState := func() json.RawMessage {
		t.Helper()
		var s json.RawMessage
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_build_object(
 'mirror',(SELECT jsonb_agg(jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m)) ORDER BY m.object_type)
 FROM ONLY kaname.resource_mirror m WHERE m.object_id=$1),
 'binding',(SELECT coalesce(jsonb_agg(to_jsonb(b) ORDER BY b.object_type),'[]'::jsonb)
 FROM ONLY kaname.object_project_binding b WHERE b.object_id=$1),
 'audit',(SELECT count(*) FROM ONLY kaname.audit_outbox WHERE event_type='iam.resource_metadata.access_labels_updated'
 AND event_payload->>'resource_type'=$2 AND event_payload->>'resource_id'=$1),
 'reconcile',(SELECT count(*) FROM ONLY kaname.resource_reconcile_outbox WHERE object_type=$2 AND object_id=$1),
 'freshness',(SELECT coalesce(jsonb_agg(to_jsonb(d)),'[]'::jsonb)
 FROM ONLY kaname.authority_access_label_dirty_root d WHERE root_type=$2 AND root_id=$1))`, id, dotted).Scan(&s))
		return s
	}
	run := func(mode string) (kanamepg.ExternalRegistrationReceiptTrace, error) {
		return kanamepg.ProbeExternalRegistrationReceipt(r.ctx, w.factory, dotted, id, "compute_instance", actor, true, mode)
	}
	before := readState()
	_, err = run("omit")
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "42501", pgErr.Code)
	require.JSONEq(t, string(before), string(readState()))
	_, err = run("rollback")
	require.NoError(t, err)
	require.JSONEq(t, string(before), string(readState()))
	root := domain.ResourceRef{Type: dotted, ID: id}
	ordinary := domain.Labels{"owner": "team-red"}
	access := domain.Labels{"team": "after"}
	update := func() (domain.ResourceMetadata, error) {
		return w.factory.UpdateExternalMetadataForTest(r.ctx, root, ordinary, access, []string{"labels", "access_labels"}, actor)
	}
	// Сначала у роли нет доступа к закрытой обёртке. Даём его только в
	// тестовой БД, чтобы выполнить настоящий Go-путь без публичного API.
	role := pgx.Identifier{r.role}.Sanitize()
	_, err = r.admin.Exec(r.ctx, "GRANT UPDATE (labels) ON kaname.resource_mirror TO "+role)
	require.NoError(t, err)
	_, err = update()
	require.ErrorIs(t, err, iamerr.ErrPermissionDenied)
	require.JSONEq(t, string(before), string(readState()))
	_, err = r.admin.Exec(r.ctx, "GRANT EXECUTE ON FUNCTION kaname.authority_metadata_mirror_write_v1(text,text) TO "+role)
	require.NoError(t, err)
	// Ошибка последней записи должна откатить уже выполненные UPDATE и audit INSERT.
	_, err = r.admin.Exec(r.ctx, `CREATE FUNCTION kaname.test_external_metadata_queue_failure() RETURNS trigger
 LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test reconcile write failure' USING ERRCODE='P0001'; END; $$;
 CREATE TRIGGER test_external_metadata_queue_failure AFTER INSERT ON kaname.resource_reconcile_outbox
 FOR EACH ROW WHEN (NEW.object_id='external-owner/atomic') EXECUTE FUNCTION kaname.test_external_metadata_queue_failure()`)
	require.NoError(t, err)
	_, err = update()
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "P0001", pgErr.Code)
	require.JSONEq(t, string(before), string(readState()))
	_, err = r.admin.Exec(r.ctx, `DROP TRIGGER test_external_metadata_queue_failure ON kaname.resource_reconcile_outbox;
 DROP FUNCTION kaname.test_external_metadata_queue_failure()`)
	require.NoError(t, err)
	actual, err := update()
	require.NoError(t, err)
	require.Equal(t, domain.ResourceMetadata{ResourceType: dotted, ResourceID: id, Labels: ordinary, AccessLabels: access}, actual)
	var initial, final struct {
		Mirror           [][]json.RawMessage
		Binding          json.RawMessage
		Audit, Reconcile int
	}
	require.NoError(t, json.Unmarshal(before, &initial))
	require.NoError(t, json.Unmarshal(readState(), &final))
	require.Equal(t, initial.Audit+1, final.Audit)
	require.Equal(t, initial.Reconcile+1, final.Reconcile)
	require.JSONEq(t, string(initial.Binding), string(final.Binding))
	require.Len(t, final.Mirror, 2)
	require.Equal(t, initial.Mirror[0], final.Mirror[0], "физическая строка compute.instance с тем же id")
	var stored struct {
		Labels       map[string]string `json:"labels"`
		AccessLabels map[string]string `json:"access_labels"`
	}
	require.NoError(t, json.Unmarshal(final.Mirror[1][2], &stored))
	require.Equal(t, actual.Labels, stored.Labels)
	require.Equal(t, actual.AccessLabels, stored.AccessLabels)
}
