// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

import (
	"context"
	"maps"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/callerorigin"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

type userAccessWriteStep func(context.Context, domain.UserID, domain.Labels, domain.Labels, domain.Subject) (domain.User, bool, error)

type userAccessWrite struct {
	ops   *updOpsRepo
	apply userAccessWriteStep
}

func (w userAccessWrite) CreateUserAccessLabelsOperation(ctx context.Context, pending operations.Operation) error {
	return w.ops.Create(ctx, pending)
}

func (w userAccessWrite) UpdateUserAccessLabels(ctx context.Context, id domain.UserID, labels, access domain.Labels, actor domain.Subject, pending operations.Operation) (operations.Operation, bool, error) {
	updated, changed, err := w.apply(ctx, id, labels, access, actor)
	if err != nil {
		return operations.Operation{}, false, err
	}
	response, err := marshalUser(updated)
	if err != nil {
		return operations.Operation{}, false, err
	}
	if err := w.ops.MarkDone(ctx, pending.ID, response); err != nil {
		return operations.Operation{}, false, err
	}
	pending.Done, pending.Response = true, response
	return pending, changed, nil
}

func TestUpdateUserProtectedMetadata(t *testing.T) {
	principal := operations.Principal{Type: "service_account", ID: "sva0000000000000bot1"}
	ctx := operations.WithPrincipal(t.Context(), principal)
	ctx = callerorigin.WithAssurance(callerorigin.With(ctx, callerorigin.PresentedCredential), "1")
	for _, tc := range []struct {
		name                     string
		oldAccess                domain.Labels
		mask                     []string
		ordinary, access         map[string]string
		wantOrdinary, wantAccess domain.Labels
		deny                     bool
	}{
		{name: "установка", access: map[string]string{"team": "a"}, wantAccess: domain.Labels{"team": "a"}},
		{name: "замена", oldAccess: domain.Labels{"team": "a"}, access: map[string]string{"team": "b"}, wantAccess: domain.Labels{"team": "b"}},
		{name: "пустая карта по маске", oldAccess: domain.Labels{"team": "a"}, mask: []string{"accessLabels"}, wantAccess: domain.Labels{}},
		{name: "обе карты", ordinary: map[string]string{"dept": "a"}, access: map[string]string{"team": "b"}, wantOrdinary: domain.Labels{"dept": "a"}, wantAccess: domain.Labels{"team": "b"}},
		{name: "очистка обеих карт", mask: []string{"labels", "access_labels"}, oldAccess: domain.Labels{"team": "a"}, wantOrdinary: domain.Labels{}, wantAccess: domain.Labels{}},
		{name: "выбраны только защищённые", mask: []string{"access_labels"}, ordinary: map[string]string{"dept": "ignore"}, access: map[string]string{"team": "b"}, wantAccess: domain.Labels{"team": "b"}},
		{name: "повтор подтверждает текущее состояние", oldAccess: domain.Labels{"team": "b"}, access: map[string]string{"team": "b"}, wantAccess: domain.Labels{"team": "b"}},
		{name: "отказ в смешанной правке", ordinary: map[string]string{"dept": "a"}, access: map[string]string{"team": "b"}, wantOrdinary: domain.Labels{"dept": "a"}, wantAccess: domain.Labels{"team": "b"}, deny: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo, ops := newUpdUserRepo(), newUpdOpsRepo()
			repo.user.Labels = domain.Labels{"dept": "old"}
			repo.user.AccessLabels = tc.oldAccess
			var actor domain.Subject
			var workerPrincipal operations.Principal
			var id domain.UserID
			var ordinary, access domain.Labels
			var calls int
			write := userAccessWrite{ops: ops, apply: func(ctx context.Context, target domain.UserID, labels, protected domain.Labels, who domain.Subject) (domain.User, bool, error) {
				id, ordinary, access, actor = target, labels, protected, who
				workerPrincipal = operations.PrincipalFromContext(ctx)
				calls++
				if tc.deny {
					return domain.User{}, false, iamerr.ErrPermissionDenied
				}
				result := repo.user
				if labels != nil {
					result.Labels = labels
				}
				result.AccessLabels = protected
				return result, !maps.Equal(result.Labels, repo.user.Labels) || !maps.Equal(protected, repo.user.AccessLabels), nil
			}}
			h := (&Handler{update: NewUpdateUserUseCase(repo, ops)}).WithUserAccessLabelsWriter(write)
			request := &iamv1.UpdateUserRequest{UserId: updUserID, Labels: tc.ordinary, AccessLabels: tc.access, UpdateMask: &fieldmaskpb.FieldMask{Paths: tc.mask}}
			op, err := h.Update(ctx, request)
			require.NoError(t, err)
			wait, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			require.NoError(t, operations.Wait(wait))
			done, err := ops.Get(ctx, op.GetId())
			require.NoError(t, err)
			require.True(t, done.Done)
			require.Equal(t, principal, done.Principal)
			require.Equal(t, updUserID, done.ResourceID)
			var metadata iamv1.UpdateUserMetadata
			require.NoError(t, done.Metadata.UnmarshalTo(&metadata))
			require.True(t, metadata.GetProtectedLabels())
			require.Equal(t, principal, workerPrincipal)
			require.Equal(t, domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(principal.ID)}, actor)
			require.Equal(t, domain.UserID(updUserID), id)
			require.Equal(t, 1, calls)
			require.Equal(t, tc.wantOrdinary, ordinary)
			require.Equal(t, tc.wantAccess, access)
			require.Zero(t, repo.updCalls)
			if tc.deny {
				require.Equal(t, int32(codes.PermissionDenied), done.Error.GetCode())
				require.Nil(t, done.Response)
				return
			}
			require.Nil(t, done.Error)
			var result iamv1.User
			require.NoError(t, done.Response.UnmarshalTo(&result))
			wantLabels := repo.user.Labels
			if tc.wantOrdinary != nil {
				wantLabels = tc.wantOrdinary
			}
			require.True(t, maps.Equal(labelsFromProto(result.GetLabels()), wantLabels))
			require.True(t, maps.Equal(labelsFromProto(result.GetAccessLabels()), tc.wantAccess))
		})
	}
}

type pendingUserAccessWrite struct{ userAccessWrite }

func (w pendingUserAccessWrite) UpdateUserAccessLabels(_ context.Context, _ domain.UserID, _, _ domain.Labels, _ domain.Subject, pending operations.Operation) (operations.Operation, bool, error) {
	return pending, true, nil
}

func TestUpdateUserProtectedRequiresCommittedOperation(t *testing.T) {
	ctx := callerorigin.WithAssurance(callerorigin.With(ownerCtx(), callerorigin.PresentedCredential), "1")
	repo, ops := newUpdUserRepo(), newUpdOpsRepo()
	h := (&Handler{update: NewUpdateUserUseCase(repo, ops)}).WithUserAccessLabelsWriter(pendingUserAccessWrite{userAccessWrite{ops: ops}})
	op, err := h.Update(ctx, &iamv1.UpdateUserRequest{UserId: updUserID, AccessLabels: map[string]string{"team": "a"}})
	require.NoError(t, err)
	wait, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(wait))
	done, err := ops.Get(ctx, op.GetId())
	require.NoError(t, err)
	require.True(t, done.Done)
	require.Equal(t, int32(codes.Internal), done.Error.GetCode())
	require.Nil(t, done.Response)
}

func TestUpdateUserProtectedAdmission(t *testing.T) {
	h := &Handler{update: NewUpdateUserUseCase(nil, nil)}
	for _, request := range []*iamv1.UpdateUserRequest{
		{UserId: updUserID, Labels: map[string]string{"dept": "a"}, AccessLabels: map[string]string{"team": "b"}},
		{UserId: updUserID, UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"access_labels"}}},
	} {
		op, err := h.Update(ownerCtx(), request)
		require.Nil(t, op)
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
	}
	h.WithUserAccessLabelsWriter(userAccessWrite{apply: func(context.Context, domain.UserID, domain.Labels, domain.Labels, domain.Subject) (domain.User, bool, error) {
		panic("проверка вызывающего должна завершиться до исполнения")
	}})
	for _, ctx := range []context.Context{ownerCtx(), callerorigin.With(ownerCtx(), callerorigin.PresentedCredential)} {
		op, err := h.Update(ctx, &iamv1.UpdateUserRequest{UserId: updUserID, AccessLabels: map[string]string{"team": "b"}})
		require.Nil(t, op)
		require.Equal(t, codes.PermissionDenied, status.Code(err))
	}
}

func TestUpdateUserOrdinaryMaskUsesIdentityWriter(t *testing.T) {
	repo, ops := newUpdUserRepo(), newUpdOpsRepo()
	repo.user.AccessLabels = domain.Labels{"team": "keep"}
	h := (&Handler{update: NewUpdateUserUseCase(repo, ops)}).WithUserAccessLabelsWriter(userAccessWrite{ops: ops, apply: func(context.Context, domain.UserID, domain.Labels, domain.Labels, domain.Subject) (domain.User, bool, error) {
		panic("маска выбирает только обычные метки")
	}})
	op, err := h.Update(ownerCtx(), &iamv1.UpdateUserRequest{
		UserId: updUserID, Labels: map[string]string{"dept": "new"}, AccessLabels: map[string]string{"team": "ignored"},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"labels"}},
	})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(ctx))
	done, err := ops.Get(ctx, op.GetId())
	require.NoError(t, err)
	require.True(t, done.Done)
	require.Nil(t, done.Error)
	var metadata iamv1.UpdateUserMetadata
	require.NoError(t, done.Metadata.UnmarshalTo(&metadata))
	require.False(t, metadata.GetProtectedLabels())
	require.Equal(t, 1, repo.updCalls)
	require.Equal(t, domain.Labels{"team": "keep"}, repo.user.AccessLabels)
	require.Equal(t, domain.Labels{"dept": "new"}, repo.user.Labels)
}

func TestUpdateUserCopiesProtectedCommandBeforeWorker(t *testing.T) {
	ctx := callerorigin.WithAssurance(callerorigin.With(ownerCtx(), callerorigin.PresentedCredential), "1")
	repo, ops := newUpdUserRepo(), newUpdOpsRepo()
	uc := NewUpdateUserUseCase(repo, ops)
	release := make(chan struct{})
	var ordinary, access domain.Labels
	uc.accessLabelsWriter = userAccessWrite{ops: ops, apply: func(_ context.Context, _ domain.UserID, l, a domain.Labels, _ domain.Subject) (domain.User, bool, error) {
		<-release
		ordinary, access = l, a
		return repo.user, false, nil
	}}
	in := UpdateUserInput{ID: updUserID, Labels: domain.Labels{"dept": "old"}, AccessLabels: domain.Labels{"team": "a"}}
	_, err := uc.Execute(ctx, in)
	in.Labels["dept"], in.AccessLabels["team"] = "new", "b"
	close(release)
	require.NoError(t, err)
	wait, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(wait))
	require.Equal(t, domain.Labels{"dept": "old"}, ordinary)
	require.Equal(t, domain.Labels{"team": "a"}, access)
}
