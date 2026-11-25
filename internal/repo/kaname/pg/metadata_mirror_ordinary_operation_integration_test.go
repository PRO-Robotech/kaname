// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/operations/operationspb"
	resourceapi "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/resource_metadata"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func exerciseOrdinaryMirrorOperation(t *testing.T, r protocolRig, factory *kanamepg.MetadataMutationWriters, root domain.ResourceRef, ctx context.Context, principal operations.Principal) {
	t.Helper()
	ops := operations.NewRepo(r.runtime, "kaname")
	uc, err := resourceapi.NewUpdateUseCase(factory.ExternalMetadataOperationForTest(), ops)
	require.NoError(t, err)
	type state struct {
		Root, Peer, Policy, Binding json.RawMessage
		Audit, Reconcile            int
	}
	read := func() state {
		t.Helper()
		var s state
		require.NoError(t, r.admin.QueryRow(ctx, `SELECT
   (SELECT jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m)) FROM ONLY kaname.resource_mirror m WHERE m.object_type=$1 AND m.object_id=$2),
   (SELECT jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m)) FROM ONLY kaname.resource_mirror m WHERE m.object_type='compute.instance' AND m.object_id=$2),
   kaname.authority_policy_epoch_read(ARRAY['*','scope:'||$3::text]),
   kaname.authority_binding_epoch_read(ARRAY[$3::text]),
   (SELECT count(*) FROM ONLY kaname.audit_outbox a WHERE a.event_type='iam.resource_metadata.labels_updated' AND a.event_payload->>'resource_type'=$1 AND a.event_payload->>'resource_id'=$2),
   (SELECT count(*) FROM ONLY kaname.resource_reconcile_outbox q WHERE q.object_type=$1 AND q.object_id=$2)`, root.Type, root.ID, r.a).Scan(&s.Root, &s.Peer, &s.Policy, &s.Binding, &s.Audit, &s.Reconcile))
		return s
	}
	input := resourceapi.UpdateInput{ResourceType: root.Type, ResourceID: root.ID, Labels: domain.Labels{"owner": "team-blue"}, AccessLabels: domain.Labels{"team": "after"}, UpdateMask: []string{"labels", "access_labels"}}
	role := pgx.Identifier{r.role}.Sanitize()
	// Имитируем неполную установку последней фазы для текущей LOGIN-роли.
	_, err = r.admin.Exec(ctx, "REVOKE EXECUTE ON FUNCTION kaname.authority_metadata_mirror_ordinary_accept_v1(text,text) FROM "+role)
	require.NoError(t, err)
	before := read()
	t.Run("reject-without-accept", func(t *testing.T) {
		var allowed bool
		require.NoError(t, r.runtime.QueryRow(ctx, `SELECT has_function_privilege(current_user,'kaname.authority_metadata_mirror_ordinary_accept_v1(text,text)','EXECUTE')`).Scan(&allowed))
		require.False(t, allowed)
		_, err := uc.Execute(ctx, input)
		require.Equal(t, codes.PermissionDenied, status.Code(err))
		require.Equal(t, before, read())
	})
	_, err = r.admin.Exec(ctx, `SELECT kaname.authority_protocol_grant_runtime($1::regrole)`, r.role)
	require.NoError(t, err)
	verify := func(t *testing.T, op *operations.Operation) {
		t.Helper()
		require.NotNil(t, op)
		require.True(t, op.Done)
		stored, err := ops.GetOwned(ctx, op.ID, operations.OwnerFromPrincipal(principal))
		require.NoError(t, err)
		require.True(t, proto.Equal(operationspb.ToProto(op), operationspb.ToProto(stored)))
		var response iamv1.ResourceMetadata
		require.NoError(t, op.Response.UnmarshalTo(&response))
		require.Equal(t, root.Type, response.GetResourceType())
		require.Equal(t, root.ID, response.GetResourceId())
		require.Equal(t, map[string]string{"owner": "team-blue"}, response.GetLabels())
		require.Equal(t, map[string]string{"team": "after"}, response.GetAccessLabels())
	}
	t.Run("ordinary-with-unchanged-access-labels", func(t *testing.T) {
		op, err := uc.Execute(ctx, input)
		require.NoError(t, err)
		verify(t, op)
		after := read()
		require.NotEqual(t, before.Root, after.Root)
		require.Equal(t, before.Peer, after.Peer)
		require.NotEqual(t, before.Policy, after.Policy)
		require.NotEqual(t, before.Binding, after.Binding)
		require.Equal(t, before.Audit+1, after.Audit)
		require.Equal(t, before.Reconcile+1, after.Reconcile)
	})
	t.Run("noop-on-identical-maps-and-empty-mask", func(t *testing.T) {
		before := read()
		same, err := uc.Execute(ctx, input)
		require.NoError(t, err)
		verify(t, same)
		empty, err := uc.Execute(ctx, resourceapi.UpdateInput{ResourceType: root.Type, ResourceID: root.ID})
		require.NoError(t, err)
		verify(t, empty)
		require.NotEqual(t, same.ID, empty.ID)
		require.Equal(t, before, read())
	})
	t.Run("noop-still-requires-update", func(t *testing.T) {
		var other operations.Principal
		other.Type = "user"
		require.NoError(t, r.admin.QueryRow(ctx, `SELECT owner_user_id FROM ONLY kaname.accounts WHERE id=$1`, r.b).Scan(&other.ID))
		denied := grpcsrv.WithTrustedACR(grpcsrv.WithTrustedPrincipal(operations.WithPrincipal(r.ctx, other), other, true), "1", true)
		before := read()
		_, err := uc.Execute(denied, resourceapi.UpdateInput{ResourceType: root.Type, ResourceID: root.ID})
		require.Equal(t, codes.PermissionDenied, status.Code(err))
		require.Equal(t, before, read())
	})
}
