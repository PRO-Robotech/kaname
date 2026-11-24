// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package module

import (
	"context"
	"errors"
	"log/slog"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/authzsnapshot"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
)

// PublicationUseCase обслуживает регистрацию модуля оператором Kaname.
type PublicationUseCase struct {
	snapshots *authzsnapshot.Store
	runner    modulecatalog.CatalogPublicationTxRunner
	checker   adminChecker
	ops       operationRepo
	maxBytes  int
	logger    *slog.Logger
}

func NewPublicationUseCase(snapshots *authzsnapshot.Store, runner modulecatalog.CatalogPublicationTxRunner,
	checker adminChecker, ops operationRepo, maxBytes int, logger *slog.Logger,
) (*PublicationUseCase, error) {
	if snapshots == nil || runner == nil || checker == nil || ops == nil || maxBytes <= 0 || logger == nil {
		return nil, errors.New("публикация каталога требует источник редакции, писатель, авторизацию, операции и предел документа")
	}
	return &PublicationUseCase{snapshots: snapshots, runner: runner, checker: checker, ops: ops, maxBytes: maxBytes, logger: logger}, nil
}

// PublicationHandler обслуживает публичный вход оператора Kaname.
type PublicationHandler struct {
	iamv1.UnimplementedCatalogPublicationServiceServer
	publication *PublicationUseCase
}

func NewPublicationHandler(uc *PublicationUseCase) *PublicationHandler {
	return &PublicationHandler{publication: uc}
}

func (h *PublicationHandler) PlanPublication(ctx context.Context, req *iamv1.PlanCatalogPublicationRequest) (*iamv1.PlanCatalogPublicationResponse, error) {
	if h.publication == nil {
		return nil, status.Error(codes.Unavailable, "публикация каталога сейчас недоступна")
	}
	return h.publication.plan(ctx, req.GetModule(), req.GetDocument())
}

func (h *PublicationHandler) ApplyPublication(ctx context.Context, req *iamv1.ApplyCatalogPublicationRequest) (*operationpb.Operation, error) {
	if h.publication == nil {
		return nil, status.Error(codes.Unavailable, "публикация каталога сейчас недоступна")
	}
	return h.publication.apply(ctx, req.GetModule(), req.GetDocument(), req.GetStateToken())
}

// authorize закрепляет текущую модель до первого решения о праве. Писатель
// повторяет решение внутри транзакции после всех блокировок.
func (uc *PublicationUseCase) authorize(ctx context.Context, fullMethod string) (context.Context, error) {
	if err := authzguard.RequireCatalogPublicationACR(ctx, fullMethod); err != nil {
		return nil, err
	}
	pinned := ctx
	var err error
	if _, ok := authzsnapshot.FromContext(ctx); ok {
		err = uc.snapshots.ConfirmPin(ctx)
	} else {
		pinned, err = uc.snapshots.Pin(ctx)
	}
	if err != nil {
		return nil, uc.rpcError(ctx, err)
	}
	if err := requireClusterSystemAdmin(pinned, uc.checker); err != nil {
		return nil, err
	}
	return pinned, nil
}

func (uc *PublicationUseCase) plan(ctx context.Context, module string, document []byte) (*iamv1.PlanCatalogPublicationResponse, error) {
	ctx, err := uc.authorize(ctx, iamv1.CatalogPublicationService_PlanPublication_FullMethodName)
	if err != nil {
		return nil, err
	}
	plan, err := modulecatalog.PlanCatalogPublication(ctx, uc.runner, module, document, uc.maxBytes)
	if err != nil {
		return nil, uc.rpcError(ctx, err)
	}
	if err := uc.snapshots.ConfirmPin(ctx); err != nil {
		return nil, uc.rpcError(ctx, err)
	}
	return &iamv1.PlanCatalogPublicationResponse{
		StateToken:    plan.StateToken,
		ModelRevision: plan.Model.Revision,
		ModelDigest:   plan.Model.Digest,
	}, nil
}

func (uc *PublicationUseCase) apply(ctx context.Context, module string, document []byte, stateToken string) (*operationpb.Operation, error) {
	ctx, err := uc.authorize(ctx, iamv1.CatalogPublicationService_ApplyPublication_FullMethodName)
	if err != nil {
		return nil, err
	}
	if stateToken == "" {
		return nil, uc.rpcError(ctx, modulecatalog.ErrExpectedStateRequired)
	}
	op, err := operations.NewFromContext(ctx, domain.PrefixOperationIAM, "Регистрация каталога модуля",
		&iamv1.ApplyCatalogPublicationMetadata{Module: module})
	if err != nil {
		return nil, uc.rpcError(ctx, err)
	}
	if err := uc.ops.CreateWithPrincipal(ctx, op, op.Principal); err != nil {
		return nil, uc.rpcError(ctx, err)
	}
	model, err := modulecatalog.ApplyCatalogPublication(ctx, uc.runner, module, document, uc.maxBytes, stateToken)
	if err != nil {
		gerr := uc.rpcError(ctx, err)
		if writeErr := uc.ops.MarkError(ctx, op.ID, status.Convert(gerr).Proto()); writeErr != nil {
			uc.logger.ErrorContext(ctx, "не удалось сохранить отказ публикации", "operation_id", op.ID, "error", writeErr)
		}
		return nil, gerr
	}
	uc.snapshots.ObserveCommittedRevision(model.Revision, model.Digest)

	response, err := anypb.New(&iamv1.ApplyCatalogPublicationResponse{ModelRevision: model.Revision, ModelDigest: model.Digest})
	if err != nil {
		return nil, uc.rpcError(ctx, err)
	}
	if err := uc.ops.MarkDoneWithMetadata(ctx, op.ID, op.Metadata, response); err != nil {
		uc.logger.ErrorContext(ctx, "не удалось сохранить завершение публикации", "operation_id", op.ID, "error", err)
	}
	op.Done, op.Response = true, response
	return shared.OperationToProto(&op), nil
}

func (uc *PublicationUseCase) rpcError(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return status.FromContextError(err).Err()
	case errors.Is(err, modulecatalog.ErrPublicationOperatorDenied):
		return authzguard.PermissionDenied()
	case errors.Is(err, authzsnapshot.ErrUnconfirmed):
		return authzguard.AuthzBackendUnavailable()
	case errors.Is(err, modulecatalog.ErrPublicationDocument),
		errors.Is(err, modulecatalog.ErrExpectedStateRequired),
		errors.Is(err, modulecatalog.ErrDerive):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, modulecatalog.ErrStateMoved):
		return status.Error(codes.Aborted, "каталог изменился, запросите новый план публикации")
	case errors.Is(err, modulecatalog.ErrBeyondAnchor),
		errors.Is(err, modulecatalog.ErrStaleRevision),
		errors.Is(err, modulecatalog.ErrRevisionConflict):
		return status.Error(codes.FailedPrecondition, err.Error())
	default:
		uc.logger.ErrorContext(ctx, "ошибка публикации каталога", "error", err)
		return status.Error(codes.Internal, "ошибка публикации каталога")
	}
}
