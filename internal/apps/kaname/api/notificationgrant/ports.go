// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package notificationgrant — InternalNotificationGrantService: решение о письме
// источника (`ResolveSend`) и рычаг администратора кластера над выдачей
// (`Revoke`/`Restore`) (приёмка NTF-1 Р5; замысел З18).
//
// Internal-only (запрет #6): служба регистрируется только на внутреннем
// слушателе. Привязки у контракта — только у `Revoke`/`Restore`, под
// `/internal/`: их зовёт администратор кластера через внутренний край.
package notificationgrant

// ports.go — узкие порты use-case'ов. Адаптеры — internal/repo/kaname/pg,
// провязка — cmd/kaname. Ни pgx, ни grpc здесь нет.

import (
	"context"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// grantStateReader — чтение записи выдачи и записи шаблона ОДНИМ оператором.
// Реализуется *kanamepg.NotificationGrantRepo.
type grantStateReader interface {
	ReadSendState(ctx context.Context, namespace, template string) (domain.NotificationGrantState, bool, error)
}

// feedReaderDoor — дверь решения kaname: та же функция вердикта, что отвечает
// `InternalIAMService/Check` (место Д-3). Реализуется *service.AuthorizeService.
type feedReaderDoor interface {
	CheckRelation(ctx context.Context, req service.CheckRelationRequest) (*service.CheckResult, error)
}

// grantWriter — CAS-переходы записи выдачи в транзакции вызывающего. Отказ
// перехода — domain.ErrNotificationGrantNotFound либо
// domain.ErrNotificationGrantState. Реализуется *kanamepg.NotificationGrantRepo.
type grantWriter interface {
	RevokeNamespace(ctx context.Context, tx service.Tx, namespace string) error
	RestoreNamespace(ctx context.Context, tx service.Tx, namespace string) error
	RevokeTemplate(ctx context.Context, tx service.Tx, namespace, template string) error
	RestoreTemplate(ctx context.Context, tx service.Tx, namespace, template string) error
}

// relationOutboxEmitter — намерение кортежа в журнале kaname той же
// транзакцией. Реализуется *kanamepg.FGAOutboxEmitter.
type relationOutboxEmitter interface {
	EmitWriteTx(ctx context.Context, tx service.Tx, tuples []service.RelationTuple) error
	EmitDeleteTx(ctx context.Context, tx service.Tx, tuples []service.RelationTuple) error
}

// operationTxCreator — завершённая операция в транзакции перехода.
// Реализуется *kanamepg.OperationTxCreator.
type operationTxCreator interface {
	CreateDoneTx(ctx context.Context, tx service.Tx, op operations.Operation, p operations.Principal, response *anypb.Any) error
}

// adminChecker — вопрос «администратор ли кластера» (образец RevokeAdmin).
type adminChecker = authzguard.RelationChecker
