// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import "strings"

// PersonalAccountNamePrefix — знак ПРОСТРАНСТВА ИМЁН личных аккаунтов (приёмка Ф4
// Р9). Личный аккаунт заводит система как следствие регистрации (Р8): его имя
// `personal-cloud-<хвост>` выбирается без участия арендатора, и «personal-cloud-…»
// человек прочтёт, а идентификатор — нет.
//
// Написание объявлено ЗДЕСЬ единожды и читается ДВУМЯ сторонами: генератором имени
// зеркала (`user.RegisterMirrorTx`) и резервом префикса в
// `AccountService.Create/Update`. Две копии разошлись бы молча — резерв перестал бы
// накрывать реально заводимые имена, а имя зеркала перестало бы попадать в
// зарезервированное пространство (code-authoring §5.1: одно написание значения).
const PersonalAccountNamePrefix = "personal-cloud-"

// IsPersonalAccountName — имя принадлежит зарезервированному пространству личных
// аккаунтов. Дефис на границе несущий: `personal-cloud-abc` зарезервировано, а
// `personal-cloudabc` (без дефиса) — обычное имя ВНЕ резерва.
func IsPersonalAccountName(name AccountName) bool {
	return strings.HasPrefix(string(name), PersonalAccountNamePrefix)
}
