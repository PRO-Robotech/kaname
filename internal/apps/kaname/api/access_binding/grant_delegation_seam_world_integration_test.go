// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// grant_delegation_seam_world_integration_test.go — ЕДИНСТВЕННОЕ место, где
// испытуемый приёмки делегированных выдач (PRO-Robotech/kaname#986) входит в мир Д.
//
// # Почему отдельный файл и почему он сейчас пуст
//
// Пробы мира Д написаны до реализации и обязаны собираться на сегодняшнем
// стволе. Конструкторов службы `GrantDelegationService` и порта четвёртого пути
// права выдавать в дереве нет, поэтому назвать их здесь нельзя: проба, которая
// не собирается, не исполняется, а «не собралось» — не красный.
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
// Пустые тела — не заглушка испытуемого: они ничего не отвечают и ничего не
// разрешают. Проба возможностей (`requireSubject`) отличает «служба не объявлена
// в контракте» от «объявлена, но в мир не провязана» и называет каждое звено
// отдельной строкой, поэтому забытая провязка краснеет своим текстом, а не
// выдаёт себя за отсутствующую возможность.

import (
	"google.golang.org/grpc"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
)

// gdWireSubject — регистрация испытуемого в мир Д (Р1 приёмки).
func gdWireSubject(_ *gdWorld, _ grpc.ServiceRegistrar) {}

// gdWireGrantPath — четвёртый путь права выдавать в глаголы выдачи мира Д (Р2).
func gdWireGrantPath(_ *gdWorld, _ *accessbindingapp.CreateAccessBindingUseCase,
	_ *accessbindingapp.RevokeAccessBindingUseCase, _ *accessbindingapp.DeleteAccessBindingUseCase) {
}
