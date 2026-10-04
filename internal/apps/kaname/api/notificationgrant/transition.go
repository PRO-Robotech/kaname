// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package notificationgrant

// transition.go — Revoke / Restore записи выдачи (приёмка NTF-1 Р5; замысел
// З18, CX1-09). Образец — `InternalClusterService/RevokeAdmin`: внутренний
// слушатель, право — администратор кластера, ответ — Operation.
//
// Порядок:
//  1. форма входа — синхронно, первым шагом;
//  2. право — `system_admin` на кластере (authzguard.RequireClusterAdmin);
//  3. одна транзакция: CAS-переход записи; у перехода пространства —
//     намерение кортежа `sender` в журнале kaname; завершённая операция.
//     Отказ перехода (записи нет, не то состояние) откатывает транзакцию
//     целиком — Operation при отказе не создаётся.

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/PRO-Robotech/corelib/operations"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleseed"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// transitionKind — вид перехода.
type transitionKind int

const (
	kindRevoke transitionKind = iota + 1
	kindRestore
)

// TransitionUseCase — Revoke либо Restore, по виду.
type TransitionUseCase struct {
	kind       transitionKind
	writer     grantWriter
	relations  relationOutboxEmitter
	ops        operationTxCreator
	txb        service.TxBeginner
	adminCheck adminChecker
}

// NewRevokeUseCase — Revoke.
func NewRevokeUseCase(w grantWriter, rel relationOutboxEmitter, ops operationTxCreator,
	txb service.TxBeginner, admin adminChecker) *TransitionUseCase {
	return &TransitionUseCase{kind: kindRevoke, writer: w, relations: rel, ops: ops, txb: txb, adminCheck: admin}
}

// NewRestoreUseCase — Restore.
func NewRestoreUseCase(w grantWriter, rel relationOutboxEmitter, ops operationTxCreator,
	txb service.TxBeginner, admin adminChecker) *TransitionUseCase {
	return &TransitionUseCase{kind: kindRestore, writer: w, relations: rel, ops: ops, txb: txb, adminCheck: admin}
}

// Execute — переход над записью пространства (template == nil) либо записью
// шаблона.
func (uc *TransitionUseCase) Execute(ctx context.Context, namespace string, template *string) (*operationpb.Operation, error) {
	if err := validateNamespace(namespace); err != nil {
		return nil, err
	}
	if template != nil {
		if err := validateTemplate(*template); err != nil {
			return nil, err
		}
	}
	if err := authzguard.RequireClusterAdmin(ctx, uc.adminCheck); err != nil {
		return nil, err
	}

	meta := &iamv1.NotificationGrantMetadata{Namespace: namespace, Template: template}
	op, err := operations.NewFromContext(ctx, domain.PrefixOperationIAM, uc.describe(namespace, template), meta)
	if err != nil {
		return nil, err
	}
	resp, err := anypb.New(&emptypb.Empty{})
	if err != nil {
		return nil, fmt.Errorf("marshal response: %w", err)
	}
	if err := uc.apply(ctx, namespace, template, op, resp); err != nil {
		return nil, uc.refusalOf(err, namespace, template)
	}
	op.Done = true
	op.Response = resp
	return shared.OperationToProto(&op), nil
}

func (uc *TransitionUseCase) describe(namespace string, template *string) string {
	verb := "Revoke"
	if uc.kind == kindRestore {
		verb = "Restore"
	}
	if template != nil {
		return fmt.Sprintf("%s notification grant %s template %s", verb, namespace, *template)
	}
	return fmt.Sprintf("%s notification grant %s", verb, namespace)
}

// apply — одна транзакция: переход, намерение кортежа, операция.
func (uc *TransitionUseCase) apply(ctx context.Context, namespace string, template *string,
	op operations.Operation, resp *anypb.Any) error {
	tx, err := uc.txb.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op после Commit

	switch {
	case template == nil && uc.kind == kindRevoke:
		err = uc.writer.RevokeNamespace(ctx, tx, namespace)
	case template == nil:
		err = uc.writer.RestoreNamespace(ctx, tx, namespace)
	case uc.kind == kindRevoke:
		err = uc.writer.RevokeTemplate(ctx, tx, namespace, *template)
	default:
		err = uc.writer.RestoreTemplate(ctx, tx, namespace, *template)
	}
	if err != nil {
		return err
	}

	// Кортеж `sender` — проекция записи ПРОСТРАНСТВА; переходы шаблона его не
	// трогают (оси независимы).
	if template == nil {
		sender, serr := moduleseed.SenderTuple(namespace)
		if serr != nil {
			return serr
		}
		tuples := []service.RelationTuple{{User: sender.User(), Relation: sender.Relation(), Object: sender.Object()}}
		if uc.kind == kindRevoke {
			err = uc.relations.EmitDeleteTx(ctx, tx, tuples)
		} else {
			err = uc.relations.EmitWriteTx(ctx, tx, tuples)
		}
		if err != nil {
			return fmt.Errorf("sender tuple intent: %w", err)
		}
	}

	if err := uc.ops.CreateDoneTx(ctx, tx, op, operations.PrincipalFromContext(ctx), resp); err != nil {
		return fmt.Errorf("persist operation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// refusalOf — отказ перехода в таблицу Р5; прочее — фиксированный INTERNAL.
func (uc *TransitionUseCase) refusalOf(err error, namespace string, template *string) error {
	switch {
	case errors.Is(err, domain.ErrNotificationGrantNotFound):
		return grantNotFound(namespace)
	case errors.Is(err, domain.ErrNotificationGrantState) && uc.kind == kindRevoke:
		return grantState(namespace, template, "is already revoked")
	case errors.Is(err, domain.ErrNotificationGrantState):
		return grantState(namespace, template, "is not revoked")
	default:
		return shared.MapRepoErr(err)
	}
}
