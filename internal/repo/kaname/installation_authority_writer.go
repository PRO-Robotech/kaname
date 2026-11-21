// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package kaname

import "context"

// InstallationAuthorityWriterFactory открывает писателя установки под GLOBAL.
// Фазу и identity определяет доверенный серверный протокол; bundle не выдумывается
// до загрузки каталога. Порт не принимает решений о выдаче новых полномочий.
type InstallationAuthorityWriterFactory interface {
	InstallationAuthorityWriter(context.Context, AuthorityOperation) (Writer, error)
}
