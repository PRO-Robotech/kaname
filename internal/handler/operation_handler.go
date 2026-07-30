// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package handler — thin gRPC transport layer для kacho-iam: parses request,
// delegates to service use-case, formats response.
//
// Resource-specific handlers (Account / Project / User / ServiceAccount /
// Group / Role / AccessBinding) живут под internal/apps/kacho/api/<resource>/;
// этот пакет держит только общий OperationHandler — единый envelope для всех
// IAM long-running operations.
package handler

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"
	"github.com/PRO-Robotech/kacho/pkg/operations"
)

// OperationHandler реализует operationpb.OperationServiceServer — единый
// envelope для всех IAM long-running operations (parity с остальными шестью
// сервисами).
//
// Get/Cancel энфорсят владельца операции ownership-scoped портом
// (GetOwned/CancelOwned): предикат владения живёт ВНУТРИ того же оператора, что
// читает/мутирует строку. Форма «прочитал → сравнил → выполнил» здесь
// недопустима по двум причинам: (а) внутрисервисный инвариант выражается
// конструкцией базы, не программной проверкой; (б) такая проверка открыта при
// отказе чтения — неудачное чтение это «не знаю», а не «разрешено», и
// продолжать по «не знаю» на мутирующем пути нельзя. Чужой/несуществующий id
// отдаёт одинаковый NotFound (no-leak).
type OperationHandler struct {
	operationpb.UnimplementedOperationServiceServer
	repo operations.Repo
}

// NewOperationHandler создает OperationHandler. В проде repo — pgRepo, который
// реализует operations.OwnedOperationRepo; если не реализует (ошибка wiring'а) —
// ownership-вызовы возвращают INTERNAL (fail-closed, не silent-bypass).
func NewOperationHandler(repo operations.Repo) *OperationHandler {
	return &OperationHandler{repo: repo}
}

func (h *OperationHandler) Get(ctx context.Context, req *operationpb.GetOperationRequest) (*operationpb.Operation, error) {
	if req.OperationId == "" {
		return nil, status.Error(codes.InvalidArgument, "operation_id required")
	}
	owned, ok := operations.AsOwned(h.repo)
	if !ok {
		return nil, status.Error(codes.Internal, "operation get failed")
	}
	// Owner-ключ резолвится ИСКЛЮЧИТЕЛЬНО из доверенного ctx-principal'а
	// (anti-spoof). Безымянный вызывающий владельцем не является:
	// PrincipalFromContext на ctx без принципала отдаёт системный fallback
	// {system, bootstrap}, который совпадает с ownership-предикатом на КАЖДОЙ
	// операции, записанной системным путём; OwnerFromContext вместо этого
	// сообщает об отсутствии ключа, и мы отдаём тот же no-leak NotFound, что и
	// на чужой операции.
	owner, hasOwner := operations.OwnerFromContext(ctx)
	if !hasOwner {
		return nil, status.Errorf(codes.NotFound, "operation %s not found", req.OperationId)
	}
	op, err := owned.GetOwned(ctx, req.OperationId, owner)
	if err != nil {
		if errors.Is(err, operations.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "operation %s not found", req.OperationId)
		}
		// Generic Internal без leak'а pgx-detail (host / dsn в тексте
		// raw err — категорически нельзя пропускать наружу).
		return nil, status.Error(codes.Internal, "operation get failed")
	}
	return operationToProto(op), nil
}

func (h *OperationHandler) Cancel(ctx context.Context, req *operationpb.CancelOperationRequest) (*operationpb.Operation, error) {
	if req.OperationId == "" {
		return nil, status.Error(codes.InvalidArgument, "operation_id required")
	}
	owned, ok := operations.AsOwned(h.repo)
	if !ok {
		return nil, status.Error(codes.Internal, "operation cancel failed")
	}
	owner, hasOwner := operations.OwnerFromContext(ctx)
	if !hasOwner {
		return nil, status.Errorf(codes.NotFound, "operation %s not found", req.OperationId)
	}
	// Атомарный CancelOwned несёт предикат владения и CAS-on-done в одном
	// UPDATE … RETURNING — отдельный reload-Get после отмены не нужен.
	op, err := owned.CancelOwned(ctx, req.OperationId, owner)
	if err != nil {
		if errors.Is(err, operations.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "operation %s not found", req.OperationId)
		}
		if errors.Is(err, operations.ErrAlreadyDone) {
			return nil, status.Errorf(codes.FailedPrecondition, "operation %s already completed", req.OperationId)
		}
		return nil, status.Error(codes.Internal, "operation cancel failed")
	}
	return operationToProto(op), nil
}
