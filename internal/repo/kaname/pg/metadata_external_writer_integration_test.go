// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/operations/operationspb"
	resourceapi "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/resource_metadata"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
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
	declare := func(key, value string) string {
		t.Helper()
		var definition string
		require.NoError(t, r.admin.QueryRow(r.ctx, `INSERT INTO kaname.authority_access_label_definition
 (scope_kind,scope_id,module,resource,label_key) VALUES('account',$1,'vpc','network',$2) RETURNING id::text`, r.a, key).Scan(&definition))
		_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_value(definition_id,label_value)
 VALUES($1::uuid,$2)`, definition, value)
		require.NoError(t, err)
		return definition
	}
	definition := declare("team", "after")
	// Второй ключ объявлен с допустимым значением, но без apply у актора.
	declare("restricted", "on")
	seedMetadataActualApplySource(t, r, actorID, definition)
	require.NoError(t, owner.PrepareAuthorityBundle(r.ctx, r.bundle))
	w := metadataFixtureModeWithRig(t, false, "prepared", r)
	_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.resource_mirror
 (object_type,object_id,parent_account_id,parent_project_id,source_version)
 VALUES ($1,$2,$3,$4,'2026-11-14T10:00:00Z'),('compute.instance',$2,$3,$4,DEFAULT)`, dotted, id, r.a, string(w.project.ID))
	require.NoError(t, err)
	seedExternalMetadataUpdateBinding(t, r, actorID, model, id, string(w.project.ID))
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
	// Потеря EXECUTE прерывает запись. Штатная повторная установка восстанавливает фасад.
	role := pgx.Identifier{r.role}.Sanitize()
	_, err = r.admin.Exec(r.ctx, "REVOKE EXECUTE ON FUNCTION kaname.authority_metadata_mirror_apply_v1(text,text) FROM "+role)
	require.NoError(t, err)
	_, err = update()
	require.ErrorIs(t, err, iamerr.ErrPermissionDenied)
	require.JSONEq(t, string(before), string(readState()))
	_, err = r.admin.Exec(r.ctx, `SELECT kaname.authority_protocol_grant_runtime($1::regrole)`, r.role)
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
	// Проверки используют текущую LOGIN-роль и настоящую таблицу операций.
	principal := operations.Principal{Type: "user", ID: actorID}
	ctx := grpcsrv.WithTrustedACR(grpcsrv.WithTrustedPrincipal(operations.WithPrincipal(r.ctx, principal), principal, true), "1", true)
	ops := operations.NewRepo(r.runtime, "kaname")
	adapter := w.factory.ExternalMetadataOperationForTest()
	inspect := &metadataOperationProbe{writer: adapter, ops: ops, mode: "cancel"}
	uc, err := resourceapi.NewUpdateUseCase(inspect, ops)
	require.NoError(t, err)
	input := resourceapi.UpdateInput{ResourceType: dotted, ResourceID: id, Labels: ordinary, AccessLabels: access, UpdateMask: []string{"labels", "access_labels"}}
	for _, rejected := range []context.Context{
		operations.WithPrincipal(r.ctx, principal),
		grpcsrv.WithTrustedACR(ctx, "", true),
		operations.WithPrincipal(ctx, operations.Principal{Type: "user", ID: actorID + "-other"}),
	} {
		_, err = uc.Execute(rejected, input)
		require.Equal(t, codes.PermissionDenied, status.Code(err))
	}
	require.Zero(t, inspect.calls)
	_, err = uc.Execute(ctx, input)
	require.Equal(t, codes.Canceled, status.Code(err))
	require.JSONEq(t, string(before), string(readState()))
	inspect.mode = "terminal-failure"
	_, err = r.admin.Exec(ctx, `CREATE FUNCTION kaname.test_mirror_operation_fail() RETURNS trigger LANGUAGE plpgsql
 AS $$ BEGIN RAISE EXCEPTION 'terminal operation failed'; END; $$;
 CREATE TRIGGER test_mirror_operation_fail AFTER UPDATE ON kaname.operations FOR EACH ROW
 WHEN (NEW.done AND NEW.response_type IS NOT NULL) EXECUTE FUNCTION kaname.test_mirror_operation_fail()`)
	require.NoError(t, err)
	_, err = uc.Execute(ctx, input)
	require.Error(t, err)
	failed, err := ops.GetOwned(ctx, inspect.id, operations.OwnerFromPrincipal(principal))
	require.NoError(t, err)
	require.True(t, failed.Done)
	require.NotNil(t, failed.Error)
	require.Nil(t, failed.Response)
	require.JSONEq(t, string(before), string(readState()))
	_, err = r.admin.Exec(ctx, `DROP TRIGGER test_mirror_operation_fail ON kaname.operations; DROP FUNCTION kaname.test_mirror_operation_fail()`)
	require.NoError(t, err)
	// Драйвер потерял подтверждение после настоящего commit: use case обязан
	// восстановить сохранённый typed response. Второго вызова записи здесь нет.
	// Sequence не откатывается вместе с транзакцией. Первая попытка
	// срывается уже после записи зеркала; вторая фиксирует тот же op.ID.
	_, err = r.admin.Exec(ctx, `CREATE SEQUENCE kaname.test_mirror_operation_attempt;
 CREATE FUNCTION kaname.test_mirror_operation_retry() RETURNS trigger
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
 BEGIN
  IF nextval('kaname.test_mirror_operation_attempt'::regclass)=1 THEN
   RAISE EXCEPTION 'test retry' USING ERRCODE='40001';
  END IF;
  RETURN NEW;
 END; $$;
 CREATE TRIGGER test_mirror_operation_retry AFTER UPDATE ON kaname.operations FOR EACH ROW
 WHEN (NEW.done AND NEW.response_type IS NOT NULL) EXECUTE FUNCTION kaname.test_mirror_operation_retry()`)
	require.NoError(t, err)
	inspect.mode = "lost-ack"
	done, err := uc.Execute(ctx, input)
	require.NoError(t, err)
	require.True(t, done.Done)
	require.Equal(t, inspect.id, done.ID)
	require.NotNil(t, inspect.direct)
	require.True(t, proto.Equal(operationspb.ToProto(inspect.direct), operationspb.ToProto(done)))
	require.Equal(t, 3, inspect.calls)
	key, ok := kaname.MirrorMetadataOperationKey(root)
	require.True(t, ok)
	var attempts, opCount, successCount int
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT last_value,
 (SELECT count(*) FROM ONLY kaname.operations WHERE resource_id=$1 AND principal_id=$2),
 (SELECT count(*) FROM ONLY kaname.operations WHERE resource_id=$1 AND principal_id=$2 AND done AND response_type IS NOT NULL)
 FROM kaname.test_mirror_operation_attempt`, key, principal.ID).Scan(&attempts, &opCount, &successCount))
	require.Equal(t, 2, attempts)
	require.Equal(t, 3, opCount)
	require.Equal(t, 1, successCount)
	var actual iamv1.ResourceMetadata
	require.NoError(t, done.Response.UnmarshalTo(&actual))
	require.Equal(t, dotted, actual.GetResourceType())
	require.Equal(t, id, actual.GetResourceId())
	require.Equal(t, map[string]string{"owner": "team-red"}, actual.GetLabels())
	require.Equal(t, map[string]string{"team": "after"}, actual.GetAccessLabels())
	var storedAccount string
	require.NoError(t, r.runtime.QueryRow(ctx, `SELECT account_id FROM ONLY kaname.operations WHERE id=$1`, done.ID).Scan(&storedAccount))
	require.Equal(t, r.a, storedAccount)
	type mirrorState struct {
		Mirror           [][]json.RawMessage
		Binding          json.RawMessage
		Audit, Reconcile int
	}
	var initial, final mirrorState
	require.NoError(t, json.Unmarshal(before, &initial))
	require.NoError(t, json.Unmarshal(readState(), &final))
	require.Equal(t, initial.Audit+1, final.Audit)
	require.Equal(t, initial.Reconcile+1, final.Reconcile)
	require.JSONEq(t, string(initial.Binding), string(final.Binding))
	require.Len(t, final.Mirror, 2)
	require.Equal(t, initial.Mirror[0], final.Mirror[0], "физическая строка compute.instance с тем же id")
	type mirrorLabels struct {
		Labels       map[string]string `json:"labels"`
		AccessLabels map[string]string `json:"access_labels"`
	}
	var stored mirrorLabels
	require.NoError(t, json.Unmarshal(final.Mirror[1][2], &stored))
	require.Equal(t, actual.Labels, stored.Labels)
	require.Equal(t, actual.AccessLabels, stored.AccessLabels)
	t.Run("ordinary-and-noop-after-protected", func(t *testing.T) {
		exerciseOrdinaryMirrorOperation(t, r, w.factory, root, ctx, principal)
	})
	t.Run("update-and-apply-to-another-key-do-not-authorize-write", func(t *testing.T) {
		before := readState()
		deniedWriter := &metadataOperationProbe{writer: adapter, ops: ops}
		update, err := resourceapi.NewUpdateUseCase(deniedWriter, ops)
		require.NoError(t, err)
		denied := resourceapi.UpdateInput{
			ResourceType: dotted, ResourceID: id,
			AccessLabels: domain.Labels{"team": "after", "restricted": "on"}, UpdateMask: []string{"access_labels"},
		}
		op, err := update.Execute(ctx, denied)
		require.Equal(t, codes.PermissionDenied, status.Code(err))
		require.Nil(t, op)
		require.Equal(t, 1, deniedWriter.calls)
		failed, err := ops.GetOwned(ctx, deniedWriter.id, operations.OwnerFromPrincipal(principal))
		require.NoError(t, err)
		require.True(t, failed.Done)
		require.Nil(t, failed.Response)
		require.NotNil(t, failed.Error)
		require.Equal(t, int32(codes.PermissionDenied), failed.Error.Code)
		require.JSONEq(t, string(before), string(readState()))
	})
	t.Run("clear-with-update-and-exact-apply", func(t *testing.T) {
		var before, after mirrorState
		require.NoError(t, json.Unmarshal(readState(), &before))
		update, err := resourceapi.NewUpdateUseCase(adapter, ops)
		require.NoError(t, err)
		op, err := update.Execute(ctx, resourceapi.UpdateInput{
			ResourceType: dotted, ResourceID: id, UpdateMask: []string{"access_labels"},
		})
		require.NoError(t, err)
		require.NotNil(t, op)
		require.True(t, op.Done)
		require.Nil(t, op.Error)
		saved, err := ops.GetOwned(ctx, op.ID, operations.OwnerFromPrincipal(principal))
		require.NoError(t, err)
		require.True(t, proto.Equal(operationspb.ToProto(op), operationspb.ToProto(saved)))
		var response iamv1.ResourceMetadata
		require.NoError(t, saved.Response.UnmarshalTo(&response))
		require.Equal(t, dotted, response.GetResourceType())
		require.Equal(t, id, response.GetResourceId())
		require.Empty(t, response.GetAccessLabels())

		require.NoError(t, json.Unmarshal(readState(), &after))
		require.Len(t, before.Mirror, 2)
		require.Len(t, after.Mirror, 2)
		require.Equal(t, before.Mirror[0], after.Mirror[0])
		require.JSONEq(t, string(before.Binding), string(after.Binding))
		require.Equal(t, before.Audit+1, after.Audit)
		require.Equal(t, before.Reconcile+1, after.Reconcile)
		var oldMetadata, newMetadata mirrorLabels
		require.NoError(t, json.Unmarshal(before.Mirror[1][2], &oldMetadata))
		require.NoError(t, json.Unmarshal(after.Mirror[1][2], &newMetadata))
		require.Equal(t, map[string]string{"team": "after"}, oldMetadata.AccessLabels)
		require.Equal(t, map[string]string{}, newMetadata.AccessLabels)
		require.Equal(t, oldMetadata.Labels, newMetadata.Labels)
		require.Equal(t, oldMetadata.Labels, response.GetLabels())
	})
}

type metadataOperationProbe struct {
	direct   *operations.Operation
	writer   kaname.ResourceMetadataUpdateWriter
	ops      operations.FullRepo
	mode, id string
	calls    int
}

func (p *metadataOperationProbe) UpdateResourceMetadata(ctx context.Context, root domain.ResourceRef, labels, access domain.Labels, mask []string, pending operations.Operation) (*operations.Operation, error) {
	p.calls++
	p.id = pending.ID
	if p.mode == "cancel" {
		if _, err := p.ops.CancelOwned(ctx, p.id, operations.OwnerFromPrincipal(pending.Principal)); err != nil {
			return nil, err
		}
	}
	done, err := p.writer.UpdateResourceMetadata(ctx, root, labels, access, mask, pending)
	if err == nil && p.mode == "lost-ack" {
		p.direct = done
		return nil, errors.New("transport lost after commit")
	}
	return done, err
}
