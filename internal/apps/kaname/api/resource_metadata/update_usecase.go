// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package resource_metadata

import (
	"context"
	"errors"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type updateOperationRepo interface {
	operations.Repo
	operations.OwnedOperationRepo
}

type updateUseCase struct {
	writer kaname.ResourceMetadataUpdateWriter
	ops    updateOperationRepo
}

func NewUpdateUseCase(writer kaname.ResourceMetadataUpdateWriter, ops updateOperationRepo) (UpdateUseCase, error) {
	if writer == nil || ops == nil {
		return nil, kaname.ErrSemanticIdentityUnavailable
	}
	return &updateUseCase{writer, ops}, nil
}

func (u *updateUseCase) Execute(ctx context.Context, in UpdateInput) (*operations.Operation, error) {
	p, err := authzguard.RequirePublicPrincipalACR(ctx, metadataUpdateRequiredACR)
	if err != nil {
		return nil, err
	}
	// Штампуем также отображаемое имя из доверенного principal.
	ctx = operations.WithPrincipal(ctx, p)
	root := domain.ResourceRef{Type: in.ResourceType, ID: in.ResourceID}
	key, ok := kaname.MirrorMetadataOperationKey(root)
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "invalid resource coordinate")
	}
	if err := shared.ValidateUpdateMask(in.UpdateMask, map[string]struct{}{"labels": {}, "access_labels": {}}, nil); err != nil {
		return nil, shared.MapRepoErrAt(ctx, err)
	}
	if err := in.Labels.Validate(); err != nil {
		return nil, shared.MapRepoErrAt(ctx, err)
	}
	if err := in.AccessLabels.Validate(); err != nil {
		return nil, shared.MapRepoErrAt(ctx, err)
	}
	pending, err := operations.NewFromContext(ctx, domain.PrefixOperationIAM, "Update resource metadata",
		&iamv1.UpdateResourceMetadataMetadata{ResourceType: root.Type, ResourceId: root.ID})
	if err != nil {
		return nil, shared.MapRepoErrAt(ctx, err)
	}
	pending.ResourceID = key
	if err = u.ops.Create(ctx, pending); err != nil {
		return nil, shared.MapRepoErrAt(ctx, err)
	}
	// ID операции один для всех повторов RR → RC внутри writer.
	op, err := u.writer.UpdateResourceMetadata(ctx, root, in.Labels, in.AccessLabels, in.UpdateMask, pending)
	if err == nil {
		return metadataOperationResult(op, pending, root)
	}
	cause := shared.MapRepoErrAt(ctx, err)
	if status.Code(cause) == codes.Internal && (errors.Is(err, kaname.ErrSourceUnconfirmed) || errors.Is(err, kaname.ErrSourceReadLimit) || errors.Is(err, kaname.ErrSemanticIdentityUnavailable) || errors.Is(err, kaname.ErrAuthorityClassificationChanged)) {
		cause = status.Error(codes.Unavailable, shared.UnavailableMessage)
	}
	// MarkError применяет CAS WHERE NOT done. В частности, завершившийся
	// COMMIT и победивший Cancel сохраняют записанный ими результат.
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	markErr := u.ops.MarkError(cleanup, pending.ID, status.Convert(cause).Proto())
	cancel()
	if markErr == nil {
		return nil, cause
	}
	read, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	stored, readErr := u.ops.GetOwned(read, pending.ID, operations.OwnerFromPrincipal(p))
	if readErr != nil {
		return nil, unconfirmedOperation(pending.ID)
	}
	return metadataOperationResult(stored, pending, root)
}

func metadataOperationResult(op *operations.Operation, pending operations.Operation, root domain.ResourceRef) (*operations.Operation, error) {
	if op == nil || op.ID != pending.ID || !op.Done || op.Principal.Type != pending.Principal.Type ||
		op.Principal.ID != pending.Principal.ID || !proto.Equal(op.Metadata, pending.Metadata) {
		return nil, unconfirmedOperation(pending.ID)
	}
	if op.Error != nil {
		if op.Error.Code == int32(codes.OK) || op.Response != nil {
			return nil, unconfirmedOperation(pending.ID)
		}
		return nil, status.ErrorProto(op.Error)
	}
	var state iamv1.ResourceMetadata
	if op.Response == nil || op.Response.UnmarshalTo(&state) != nil || state.GetResourceType() != root.Type || state.GetResourceId() != root.ID {
		return nil, unconfirmedOperation(pending.ID)
	}
	return op, nil
}

func unconfirmedOperation(id string) error {
	return status.Errorf(codes.Unavailable, "cannot confirm terminal state of operation %s", id)
}
