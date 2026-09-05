// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package module

// handler.go — тонкий транспорт `InternalModuleService`.
//
// Запрет #6: хендлер регистрируется ТОЛЬКО на внутреннем слушателе (:9091), и
// никогда на внешнем. Префикс `Internal` в имени службы — действующий
// дискриминатор, а не привычка именования: метод такой службы во внешний
// маршрутизатор не попадает by construction.
//
// Бизнес-логики здесь нет: каждый метод немедленно передаёт вызов своему
// use-case'у. Гейт права стоит в use-case первым стейтментом — там же, где
// принимается решение, а не в обёртке, которую можно обойти вторым вызывающим.

import (
	"context"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"
)

// Handler реализует iamv1.InternalModuleServiceServer.
type Handler struct {
	iamv1.UnimplementedInternalModuleServiceServer

	plan  *PlanUseCase
	apply *ApplyUseCase
	get   *GetUseCase
	list  *ListUseCase
}

// NewHandler собирает хендлер из четырёх use-case'ов.
// Композиционный корень: cmd/kacho-iam/wiring.go.
func NewHandler(plan *PlanUseCase, apply *ApplyUseCase, get *GetUseCase, list *ListUseCase) *Handler {
	return &Handler{plan: plan, apply: apply, get: get, list: list}
}

// Plan — что применение доставленного манифеста СДЕЛАЛО БЫ. Синхронное чтение.
func (h *Handler) Plan(ctx context.Context, req *iamv1.PlanModuleRequest) (*iamv1.PlanModuleResponse, error) {
	return h.plan.Execute(ctx, req.GetModule())
}

// Apply — приведение строк каталога модуля к объявленному состоянию.
// Терминальный конверт `Operation`; всякий отказ — синхронная gRPC-ошибка.
func (h *Handler) Apply(ctx context.Context, req *iamv1.ApplyModuleRequest) (*operationpb.Operation, error) {
	// Потолки передаются УКАЗАТЕЛЯМИ, а не значениями геттеров: `GetMax…`
	// отдаёт ноль и на незаданном поле, и на заданном нулём, тогда как ноль
	// здесь — законное и самое частое подтверждение («ни одного права не
	// отбирать»). Потеряв присутствие на транспорте, отказ «поле не задано»
	// стал бы невыразимым.
	return h.apply.Execute(ctx, req.GetModule(), req.GetExpectedState(),
		req.MaxResettledRuleRefs, req.MaxResettledRoleVerbs)
}

// Get — живые строки одного модуля.
func (h *Handler) Get(ctx context.Context, req *iamv1.GetModuleRequest) (*iamv1.ModuleCatalog, error) {
	return h.get.Execute(ctx, req.GetModule())
}

// List — живые модули каталога с числами.
func (h *Handler) List(ctx context.Context, _ *iamv1.ListModulesRequest) (*iamv1.ListModulesResponse, error) {
	return h.list.Execute(ctx)
}
