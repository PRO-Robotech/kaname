// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest

// classgrants.go — ключ оболочки `classGrantsOnlyOnContainers`: модуль решает
// публичность своих объектов сам (стадия S7, задача PRO-Robotech/kaname#950).
//
// Приёмка docs/engineering/acceptance/anonymous-and-authenticated-are-subject-classes.md,
// редакция 17, Р11 п. 1 и SC-80.
//
// # Почему ключ оболочки, а не ресурса
//
// Это признак МОДУЛЯ: после kaname#951 манифест вправе не нести раздела
// `resources`, и ключ записи ресурса до такого модуля не дошёл бы. Ворота
// выдачи судят по нему все живые типы модуля.
//
// # Одна форма значения
//
// Ключ отсутствует (не объявлено) либо равен true. `false` — второй способ
// сказать «нет», его загрузка отвергает находкой — так же, как
// `publicReadToChildren: false` (SC-71 (в)). Модель прав ключ не трогает:
// рендер блоков от него не зависит (SC-80 (а)).

import (
	"errors"

	"gopkg.in/yaml.v3"
)

// ErrClassGrantsFalse — `classGrantsOnlyOnContainers: false`: второй способ
// сказать «нет».
var ErrClassGrantsFalse = errors.New("manifest: classGrantsOnlyOnContainers is either absent or true")

// DeclaresClassGrantsOnlyOnContainers — модуль объявил ключ S7
// (`classGrantsOnlyOnContainers: true`).
func (m *Manifest) DeclaresClassGrantsOnlyOnContainers() bool {
	return m.ClassGrantsOnlyOnContainers != nil && *m.ClassGrantsOnlyOnContainers
}

// validateClassGrants — форма значения ключа (SC-80 (б)).
func validateClassGrants(m *Manifest, doc *yaml.Node) []error {
	if m.ClassGrantsOnlyOnContainers == nil || *m.ClassGrantsOnlyOnContainers {
		return nil
	}
	return []error{linkFault{
		kind:   ErrClassGrantsFalse,
		coord:  locate(doc, "classGrantsOnlyOnContainers"),
		detail: "classGrantsOnlyOnContainers: значение false не принимается — ключ либо отсутствует, либо равен true",
	}}
}
