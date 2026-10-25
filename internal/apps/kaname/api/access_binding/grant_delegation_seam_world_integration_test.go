// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// grant_delegation_seam_world_integration_test.go — ЕДИНСТВЕННОЕ место, где
// испытуемый приёмки делегированных выдач (PRO-Robotech/kaname#986) входит в мир Д.
//
// # Почему отдельный файл
//
// Пробы мира Д написаны до реализации и собирались на стволе без неё: тогда
// конструкторов службы `GrantDelegationService` и четвёртого пути права
// выдавать в дереве не было, и обе функции стояли пустыми. Реализация
// провязывает испытуемого здесь и только здесь.
//
// Обе функции ниже зовёт сборка мира (`buildHandlers`, `newGrantVerbs`).
// Реализация провязывает испытуемого ИМИ и только ими — теми же частями, что
// композиционный корень (`cmd/kaname/wiring.go`, `grpc_register.go`):
//
//   - `gdWireSubject` — регистрация службы (`iamv1.RegisterGrantDelegationServiceServer`)
//     в регистратор мира над хранилищем, дверью решения и операциями мира;
//   - `gdWireGrantPath` — провязка четвёртого пути права выдавать в ТЕ экземпляры
//     `Create`/`Revoke`/`Delete` выдачи, которыми ходят пробы.
//
// Проба возможностей (`requireSubject`) отличает «служба не объявлена в
// контракте» от «объявлена, но в мир не провязана» и называет каждое звено
// отдельной строкой, поэтому забытая провязка краснеет своим текстом, а не
// выдаёт себя за отсутствующую возможность.

import (
	"google.golang.org/grpc"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	gdapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/grant_delegation"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// gdWireSubject — регистрация испытуемого в мир Д (Р1 приёмки) теми же
// конструкторами, что в корне службы (`cmd/kaname/wiring.go`).
func gdWireSubject(w *gdWorld, reg grpc.ServiceRegistrar) {
	src := catalog.Fixed{F: w.facts}
	h := gdapp.NewHandler(
		gdapp.NewCreateGrantDelegationUseCase(w.repo, w.ops, src).WithRelationStore(w.door, nil),
		gdapp.NewGetGrantDelegationUseCase(w.repo).WithRelationStore(w.door),
		gdapp.NewListGrantDelegationsUseCase(w.repo).WithRelationStore(w.door),
		gdapp.NewRevokeGrantDelegationUseCase(w.repo, w.ops).WithRelationStore(w.door, nil),
	)
	iamv1.RegisterGrantDelegationServiceServer(reg, h)
}

// gdWireGrantPath — четвёртый путь права выдавать в глаголы выдачи мира Д (Р2):
// тот же путь, что корень службы даёт `Create`, `Revoke` и `Delete` выдачи.
func gdWireGrantPath(w *gdWorld, c *accessbindingapp.CreateAccessBindingUseCase,
	r *accessbindingapp.RevokeAccessBindingUseCase, d *accessbindingapp.DeleteAccessBindingUseCase) {
	p := accessbindingapp.NewDelegatedGrantPath(w.repo, w.door)
	c.WithDelegatedGrantPath(p)
	r.WithDelegatedGrantPath(p)
	d.WithDelegatedGrantPath(p)
}
