// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// register_module_internal_only_test.go — `IAM-MA-1-26`: служба
// `InternalModuleService` НЕ достижима на публичном слушателе (запрет #6).
//
// Утверждение — ПАРА, и обе половины обязательны:
//
//   - на ПУБЛИЧНОМ сервере каждый из четырёх глаголов отвечает `Unimplemented`:
//     маршрута на внешнем муксе не существует;
//   - на ВНУТРЕННЕМ — отвечает ЧЕМ УГОДНО, кроме `Unimplemented`: вызов дошёл до
//     гейта права хендлера, и это доказывает, что маршрут существует.
//
// Без второй половины проба зеленела бы на службе, не смонтированной НИГДЕ:
// «нет на внешнем» и «нет вовсе» отвечают одинаково.
//
// Проба чисто транспортная (bufconn, ни базы, ни хранилища отношений): её
// предмет — провязка `registerPublicServices` / `registerInternalServices`, а не
// поведение глаголов.
package main

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	moduleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/module"
)

func TestInternalModuleService_MA126_InternalOnly_NotOnExternalListener(t *testing.T) {
	// Хендлер собран с непровязанными портами НАМЕРЕННО: гейт права стоит первым
	// стейтментом каждого глагола и до портов дело не доходит. Регрессия,
	// обошедшая гейт, разыменовала бы nil и упала бы паникой — проба показала бы
	// это отказом, а не зелёным.
	handler := moduleapp.NewHandler(
		moduleapp.NewPlanUseCase(nil, nil, nil),
		moduleapp.NewApplyUseCase(nil, nil, nil, nil),
		moduleapp.NewGetUseCase(nil),
		moduleapp.NewListUseCase(nil),
	)
	svcs := &services{moduleHandler: handler}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pubConn := serveBufconn(t, func(s *grpc.Server) {
		registerPublicServices(s, svcs, nil)
	})
	intConn := serveBufconn(t, func(s *grpc.Server) {
		registerInternalServices(s, svcs, nil, "", nil)
	})

	// Четыре глагола ОДНИМ перечнем: требование к ним одно, и перечислив их
	// порознь, можно было бы забыть один молча.
	calls := map[string]func(cc grpc.ClientConnInterface) error{
		"Plan": func(cc grpc.ClientConnInterface) error {
			_, err := iamv1.NewInternalModuleServiceClient(cc).
				Plan(ctx, &iamv1.PlanModuleRequest{Module: "vpc"})
			return err
		},
		"Apply": func(cc grpc.ClientConnInterface) error {
			_, err := iamv1.NewInternalModuleServiceClient(cc).
				Apply(ctx, &iamv1.ApplyModuleRequest{Module: "vpc", ExpectedState: "state"})
			return err
		},
		"Get": func(cc grpc.ClientConnInterface) error {
			_, err := iamv1.NewInternalModuleServiceClient(cc).
				Get(ctx, &iamv1.GetModuleRequest{Module: "vpc"})
			return err
		},
		"List": func(cc grpc.ClientConnInterface) error {
			_, err := iamv1.NewInternalModuleServiceClient(cc).
				List(ctx, &iamv1.ListModulesRequest{})
			return err
		},
	}

	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, codes.Unimplemented, status.Code(call(pubConn)),
				"%s: Internal.* не публикуется на внешнем слушателе (запрет #6)", name)
			require.NotEqual(t, codes.Unimplemented, status.Code(call(intConn)),
				"%s: маршрут обязан существовать на внутреннем слушателе — иначе "+
					"«нет на внешнем» неотличимо от «не смонтировано нигде»", name)
			// Гейт права стоит первым: с непровязанным проверяющим ответ
			// внутреннего слушателя — отказ в правах, а не отказ формы и не
			// паника.
			require.Equal(t, codes.PermissionDenied, status.Code(call(intConn)),
				"%s: непровязанный гейт обязан отказывать fail-closed", name)
		})
	}
}
