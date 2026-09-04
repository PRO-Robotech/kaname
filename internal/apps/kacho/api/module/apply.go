// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package module

// apply.go — `InternalModuleService.Apply`.
//
// # Конверт ТЕРМИНАЛЕН, и это форма всей службы, а не удобство
//
// Строка операции сохраняется `done=false` ДО мутации — чтобы её id был
// запрашиваем всегда, — мутация исполняется синхронно в одной транзакции
// применителя, затем строка переводится в терминальное состояние вместе с
// метаданными и ответом, и вызывающий получает конверт уже с `done = true`.
// Полла не требуется.
//
// Асинхронного исполнителя у iam нет вовсе; завести здесь первого в дереве
// значило бы принести новую инфраструктуру ради одного глагола — и обосновывать
// её отдельно, а не строкой.
//
// # Отказ — СИНХРОННАЯ gRPC-ошибка, а не операция с ошибкой внутри
//
// Всякий отказ применения (расхождение подтверждения, выход за опору, превышение
// потолка, бюджет оператора) откатывает транзакцию целиком: ничего не записано и
// записи аудита нет. Показывать такой исход конвертом означало бы заводить
// строку операции о событии, которого не было.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"
	"github.com/PRO-Robotech/kacho/pkg/safeconv"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/modulecatalog"
	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

// ApplyUseCase — приводит строки каталога модуля к объявленному доставленным
// манифестом состоянию, ровно если состояние модуля не сдвинулось с плана.
type ApplyUseCase struct {
	delivery DeliverySource
	applier  CatalogApplier
	opsRepo  operationRepo
	logger   *slog.Logger
	// adminCheck — гейт права. nil ⇒ fail-closed (см. authz.go).
	adminCheck adminChecker
}

// NewApplyUseCase — конструктор.
func NewApplyUseCase(d DeliverySource, a CatalogApplier, ops operationRepo, logger *slog.Logger) *ApplyUseCase {
	return &ApplyUseCase{delivery: d, applier: a, opsRepo: ops, logger: logger}
}

// WithAdminChecker — провязка гейта права. Только композиционный корень.
func (uc *ApplyUseCase) WithAdminChecker(c adminChecker) *ApplyUseCase {
	uc.adminCheck = c
	return uc
}

// Execute — синхронная проверка входа, синхронная мутация, терминальный конверт.
func (uc *ApplyUseCase) Execute(
	ctx context.Context,
	module, expectedState string,
	maxResettledRuleRefs, maxResettledRoleVerbs *int32,
) (*operationpb.Operation, error) {
	// ГЕЙТ ПРАВА — ПЕРВЫМ СТЕЙТМЕНТОМ. Порядок наблюдаем: вызывающий без права
	// получает отказ в правах даже на заведомо негодном входе.
	if err := requireClusterSystemAdmin(ctx, uc.adminCheck); err != nil {
		return nil, err
	}
	if module == "" {
		return nil, shared.InvalidArg("module", "required")
	}
	if uc.applier == nil {
		return nil, shared.MapRepoErr(iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"применитель каталога не провязан"))
	}

	m, err := manifestFromDelivery(ctx, uc.delivery, module)
	if err != nil {
		return nil, err
	}

	// Потолки и подтверждение проверяет САМ применитель — вторая копия проверки
	// здесь разошлась бы с ней молча. Переносится только форма числа: контракт
	// объявляет потолки 32-битными с явным присутствием, а применитель говорит
	// об `int` — присутствие при этом СОХРАНЯЕТСЯ, потому что ноль есть законное
	// и самое частое значение («подтверждаю: ни одного права не отбирать»), и
	// перепутать его с «не задано» нельзя.
	req := modulecatalog.Request{
		Manifest:              m,
		ExpectedState:         expectedState,
		MaxResettledRuleRefs:  intFromOptional(maxResettledRuleRefs),
		MaxResettledRoleVerbs: intFromOptional(maxResettledRoleVerbs),
	}

	op, oerr := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Apply permission-module catalog of %s", module),
		&iamv1.ApplyModuleMetadata{Module: module},
	)
	if oerr != nil {
		return nil, oerr
	}
	if err := uc.opsRepo.Create(ctx, op); err != nil {
		return nil, fmt.Errorf("persist operation: %w", err)
	}

	rep, aerr := uc.applier.Apply(ctx, req)
	if aerr != nil {
		gerr := applyRefusal(module, aerr)
		// Терминальный отказ записывается на уже сохранённую строку операции,
		// чтобы полл видел настоящую ошибку, а не отсутствие строки; вызывающему
		// при этом отдаётся СИНХРОННАЯ ошибка — см. шапку файла.
		_ = uc.opsRepo.MarkError(ctx, op.ID, status.Convert(gerr).Proto())
		return nil, gerr
	}

	meta, resp, merr := applyOperationPayload(module, rep)
	if merr != nil {
		return nil, merr
	}
	if err := uc.opsRepo.MarkDoneWithMetadata(ctx, op.ID, meta, resp); err != nil {
		// Для вызывающего не фатально: транзакция применителя закоммичена, строка
		// операции существует, поэтому полл отвечает, а не отдаёт «нет такой».
		// Само-исцеления здесь НЕТ — резолвер сирот метаданные этого типа не
		// разбирает намеренно, — поэтому отказ логируется громко, а не глотается.
		if uc.logger != nil {
			uc.logger.ErrorContext(ctx, "применение каталога модуля: завершить операцию не удалось",
				slog.String("operation_id", op.ID),
				slog.String("module", module),
				slog.String("err", err.Error()))
		}
	}
	op.Done = true
	op.Metadata = meta
	op.Response = resp

	return shared.OperationToProto(&op), nil
}

// applyRefusal — отказ применителя, приведённый к конвенции ответа.
//
// Тексты применителя приезжают ДОСЛОВНО: они называют популяцию, её потолок и
// фактическое число, то есть ровно то, чем оператор чинит вход. Приведение
// добавляет к ним код и имя модуля, но их не переписывает.
func applyRefusal(module string, err error) error {
	switch {
	case errors.Is(err, modulecatalog.ErrExpectedStateRequired),
		errors.Is(err, modulecatalog.ErrLimitRequired):
		// Отсутствующее подтверждение и незаданный потолок — отказ ФОРМЫ:
		// вызывающий чинит запрос, а не состояние.
		return shared.MapRepoErr(iamerr.Wrapf(iamerr.ErrInvalidArg, "%v", err))
	case errors.Is(err, modulecatalog.ErrDerive):
		return shared.MapRepoErr(iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"манифест модуля %s не даёт строк каталога: %v", module, err))
	}
	// Всё прочее — состояние: разошедшееся подтверждение, выход за опору,
	// превышение потолка, отказ оператора базы. Ответ несёт причину применителя
	// и не выдумывает своей.
	return shared.MapRepoErr(iamerr.Wrapf(iamerr.ErrFailedPrecondition, "%v", err))
}

// applyOperationPayload — терминальная пара (метаданные, ответ), объявленная
// контрактом `Apply`.
//
// # Чего здесь НЕТ и почему это сказано, а не умолчано
//
// `planned_resettled_*` — то, что план обещал по каждой популяции, вычисленное
// ТЕМ ЖЕ выражением внутри транзакции применителя, ДО переселения. Перепись
// применителя (`modulecatalog.Report`) этих величин сегодня не несёт, поэтому
// заполнить их нечем — и подставить сюда фактические числа значило бы объявить
// «план обещал ровно столько», чего никто не измерял.
//
// Поверхность при этом не лжёт: `Apply` требует подтверждения, а подтверждение
// производит только `Plan`, и он отказывает, пока производитель планового
// состояния не провязан. То есть недостающая величина сегодня не наблюдается
// ни одним вызывающим, а её производитель назван — общий отбор переселяемого
// внутри транзакции применителя.
func applyOperationPayload(module string, rep modulecatalog.Report) (meta, resp *anypb.Any, err error) {
	meta, err = anypb.New(&iamv1.ApplyModuleMetadata{Module: module})
	if err != nil {
		return nil, nil, fmt.Errorf("operation metadata: %w", err)
	}
	// Ширина чисел — 32 бита, и её хватает с запасом в два порядка: бюджет одного
	// применения исчерпывается сотнями тысяч строк переселения, а строк каталога
	// у платформы низкие сотни.
	resp, err = anypb.New(&iamv1.ApplyModuleResponse{
		Module:                    module,
		Changed:                   rep.Changed(),
		ModuleWritten:             rep.ModuleWritten,
		WrittenResources:          safeconv.IntToInt32(rep.WrittenResources),
		WrittenVerbs:              safeconv.IntToInt32(rep.WrittenVerbs),
		RetiredResources:          safeconv.IntToInt32(rep.RetiredResources),
		RetiredVerbs:              safeconv.IntToInt32(rep.RetiredVerbs),
		ResettledRuleRefs:         safeconv.IntToInt32(rep.Resettled.RuleRefs),
		ResettledRoleVerbs:        safeconv.IntToInt32(rep.Resettled.RoleVerbs),
		PrunedSelectorRows:        safeconv.IntToInt32(rep.PrunedSelectorRows),
		PrunedSelectorRowsDropped: safeconv.IntToInt32(rep.PrunedSelectorRowsDropped),
		PrunedSelectorTypes:       safeconv.IntToInt32(rep.PrunedSelectorTypes),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("operation response: %w", err)
	}
	return meta, resp, nil
}

// intFromOptional — присутствие 32-битного поля контракта, перенесённое в
// присутствие указателя применителя. `nil` остаётся `nil`: отсутствие потолка
// обязано быть отличимо от нуля.
func intFromOptional(v *int32) *int {
	if v == nil {
		return nil
	}
	n := int(*v)
	return &n
}
