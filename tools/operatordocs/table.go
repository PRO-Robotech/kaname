// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// table.go — единственная точка, где берётся действующая таблица стража.
//
// Отдельной функцией, а не обращением к переменной по месту: инъекция подаёт
// разбору битую таблицу, и подмена одного вызова читается, тогда как подмена
// нескольких обращений разошлась бы с собой.
package operatordocs

import "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"

// requiredSettings — таблица величин, без которых служба не пускается.
// Объявлена и доказана прогоном в пакете настройки; второго перечня здесь не
// заводится.
func requiredSettings() []config.RequiredSetting { return config.RequiredSettings }
