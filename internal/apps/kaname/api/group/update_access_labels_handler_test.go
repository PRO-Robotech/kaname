// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package group

import (
	"context"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	repogroup "github.com/PRO-Robotech/kaname/internal/repo/kaname/group"
	"github.com/PRO-Robotech/kaname/internal/service"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

func TestGroupHandlerUpdateAccessLabelsMask(t *testing.T) {
	for _, tc := range []struct {
		name        string
		mask        []string
		body        map[string]string
		protected   bool
		wantAccess  domain.Labels
		wantMask    []string
		wantChanged []string
	}{
		{name: "absent implicit preserves"},
		{name: "empty implicit preserves", body: map[string]string{}},
		{name: "ordinary mask ignores protected body", mask: []string{"description"}, body: map[string]string{"team": "red"}},
		{name: "implicit replacement", body: map[string]string{"team": "red"}, protected: true, wantAccess: domain.Labels{"team": "red"}, wantMask: []string{"access_labels"}, wantChanged: []string{"access_labels"}},
		{name: "explicit clear by absence", mask: []string{"access_labels"}, protected: true, wantAccess: domain.Labels{}, wantMask: []string{"access_labels"}, wantChanged: []string{"access_labels"}},
		{name: "explicit camel case clear", mask: []string{"accessLabels"}, body: map[string]string{}, protected: true, wantAccess: domain.Labels{}, wantMask: []string{"access_labels"}, wantChanged: []string{"access_labels"}},
		{name: "mixed with description", mask: []string{"description", "accessLabels"}, body: map[string]string{"team": "red"}, protected: true, wantAccess: domain.Labels{"team": "red"}, wantMask: []string{"description", "access_labels"}, wantChanged: []string{"description", "access_labels"}},
		{name: "protected equal no op", mask: []string{"access_labels"}, body: map[string]string{"team": "blue"}, protected: true, wantAccess: domain.Labels{"team": "blue"}, wantMask: []string{"access_labels"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := newLcgRepo(domain.Labels{"ordinary": "old"})
			repo.grp.AccessLabels = domain.Labels{"team": "blue"}
			ops := newFakeGrpOps()
			writer := &groupAccessLabelsProbe{changed: tc.wantChanged}
			ordinary := &lifecycleFactoryProbe{writer: &lifecycleWriterProbe{}}
			uc := NewUpdateGroupUseCase(repo, ops).WithLifecycleWriter(ordinary)
			h := (&Handler{update: uc}).WithGroupAccessLabelsWriter(writer)

			req := &iamv1.UpdateGroupRequest{GroupId: lcgGrpID, AccessLabels: tc.body}
			if tc.mask != nil {
				req.UpdateMask = &fieldmaskpb.FieldMask{Paths: slices.Clone(tc.mask)}
			}
			if slices.Contains(tc.mask, "description") {
				req.Description = "revised"
			}
			ctx := machineCtx()
			op, err := h.Update(ctx, req)
			require.NoError(t, err)
			var done *operations.Operation
			require.Eventually(t, func() bool {
				done, _ = ops.Get(ctx, op.GetId())
				return done != nil && done.Done
			}, 2*time.Second, time.Millisecond)
			require.Nil(t, done.Error)
			require.Equal(t, tc.mask, req.GetUpdateMask().GetPaths(), "the input mask is unchanged")
			if !tc.protected {
				require.Equal(t, []kaname.GroupMutation{kaname.GroupUpdate}, ordinary.kinds)
				require.Equal(t, domain.Labels{"team": "blue"}, ordinary.groups[0].AccessLabels)
				require.Zero(t, writer.opens)
				return
			}
			require.Empty(t, ordinary.kinds)
			require.Equal(t, 1, writer.opens)
			require.Equal(t, domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: "sva0000000000000bot1"}, writer.actor)
			require.Equal(t, tc.wantMask, writer.mask)
			require.Equal(t, tc.wantMask, writer.rowMask)
			require.Equal(t, tc.wantAccess, writer.target.AccessLabels)
			var result iamv1.Group
			require.NoError(t, done.Response.UnmarshalTo(&result))
			require.True(t, maps.Equal(tc.body, result.GetAccessLabels()), "the operation returns the accepted map")
			if slices.Contains(tc.mask, "description") {
				require.Equal(t, "revised", result.GetDescription())
			}
			if len(tc.wantChanged) == 0 {
				require.Empty(t, writer.audits)
				require.Empty(t, writer.reconcile)
				return
			}
			require.Len(t, writer.audits, 1)
			require.Equal(t, auditEventGroupUpdated, writer.audits[0].EventType)
			require.Equal(t, "sva0000000000000bot1", writer.audits[0].Payload["actor"])
			require.Equal(t, tc.wantChanged, writer.audits[0].Payload["changed_fields"])
			require.Equal(t, [][3]string{{"mirror.upsert", "iam.group", lcgGrpID}}, writer.reconcile)
		})
	}
}

func TestGroupHandlerUpdateRejectsProtectedLabelsWhenUnavailable(t *testing.T) {
	// Deliberately has no repository or operations port: denial precedes both.
	h := &Handler{update: NewUpdateGroupUseCase(nil, nil)}
	for _, req := range []*iamv1.UpdateGroupRequest{
		{GroupId: lcgGrpID, AccessLabels: map[string]string{"team": "red"}},
		{GroupId: lcgGrpID, UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"accessLabels"}}},
	} {
		op, err := h.Update(machineCtx(), req)
		require.Nil(t, op)
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
	}
}

type groupAccessLabelsProbe struct {
	kaname.SemanticAuthorityWriter
	repogroup.WriterIface
	target    domain.Group
	mask      []string
	rowMask   []string
	actor     domain.Subject
	opens     int
	changed   []string
	audits    []service.AuditEvent
	reconcile [][3]string
}

var _ kaname.GroupAccessLabelsWriterFactory = (*groupAccessLabelsProbe)(nil)
var _ kaname.PreparedWriteExecutor = (*groupAccessLabelsProbe)(nil)
var _ kaname.MetadataUpdateEffects = (*groupAccessLabelsProbe)(nil)

func (w *groupAccessLabelsProbe) GroupAccessLabelsWriter(_ context.Context, g domain.Group, mask []string, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	w.opens++
	w.target, w.mask, w.actor = g, slices.Clone(mask), actor
	return w, nil
}

func (w *groupAccessLabelsProbe) ExecutePreparedWrite(ctx context.Context, open func(context.Context) (kaname.Writer, error), action func(context.Context, kaname.Writer) error) error {
	writer, err := open(ctx)
	if err != nil {
		return err
	}
	return action(ctx, writer)
}

func (w *groupAccessLabelsProbe) GroupsW() repogroup.WriterIface { return w }

func (w *groupAccessLabelsProbe) Update(_ context.Context, g domain.Group, mask []string) (domain.Group, error) {
	w.rowMask = slices.Clone(mask)
	return g, nil
}

func (w *groupAccessLabelsProbe) MetadataChangedFields() []string { return slices.Clone(w.changed) }

func (w *groupAccessLabelsProbe) EmitAuditEvent(_ context.Context, event service.AuditEvent) error {
	w.audits = append(w.audits, event)
	return nil
}

func (w *groupAccessLabelsProbe) EmitReconcileEvent(_ context.Context, eventType, resourceType, resourceID string) error {
	w.reconcile = append(w.reconcile, [3]string{eventType, resourceType, resourceID})
	return nil
}
