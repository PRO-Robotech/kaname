// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package webauthnverify

// disabled.go — решение «ключи доступа на установке выключены» (задача
// PRO-Robotech/kaname#827; приёмка
// `docs/engineering/acceptance/step-up-with-any-enrolled-method.md`, Р7;
// замысел §2.6).
//
// # Одно написание у шести читателей
//
// Выключено ⟺ перечень происхождений объявлен ПУСТЫМ («никого», Ф7 Р2). Решение
// читают выдача регистрации Ф7, выдача входа ключом Ф13, выдача повышения
// ключом, признак `accessKeys.available` чтения состояния, перечень
// `stepUpMethods` и заведённое для вида `assurance` — и все зовут [Binding.Disabled],
// а не повторяют сравнение длины перечня: второе написание разошлось бы с первым
// молча. `nil` по-прежнему значит «не объявлено» и отвергается при сборке
// глаголов — до этого места он не доходит.
//
// Текст и признак отказа объявлены здесь же и один раз: оба пакета полос их
// импортируют, а транспорт каждой полосы печатает сентинел своей формой.

import "errors"

// Disabled — ключи доступа на установке выключены: перечень происхождений
// объявлен пустым. Ни одно происхождение не принимается, и ни одна выдача
// испытания не имеет смысла.
func (b Binding) Disabled() bool { return b.Origins != nil && len(b.Origins) == 0 }

const (
	// TextKeysDisabled — отказ выдачи на установке без ключей (Р7). Контракт.
	TextKeysDisabled = "access keys are turned off on this installation"
	// ReasonKeysDisabled — признак того же отказа (`ErrorInfo.reason`).
	ReasonKeysDisabled = "ACCESS_KEYS_DISABLED"
)

// ErrKeysDisabled — сентинел отказа: состояние установки, не ввод вызывающего
// (`FAILED_PRECONDITION` у gRPC, 400 `code` 9 у полосы формы).
var ErrKeysDisabled = errors.New(TextKeysDisabled)
