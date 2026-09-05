// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package iamhooks

import (
	"context"
	"net/http"

	"github.com/PRO-Robotech/kacho/pkg/observability/health"
)

// named / muxWithReadiness — ЕДИНСТВЕННОЕ место, знающее, каким носителем
// собрана диагностическая поверхность владельца прав.
//
// Утверждения соседнего файла говорят о ПОВЕДЕНИИ и носителя не называют: смена
// носителя обязана двигать эту проводку и оставлять утверждения дословно теми же
// — иначе пара «до фикса красно / после зелено» сравнивала бы разные проверки.
// На сведении с общим носителем (задача продукта #1729) сменился ровно этот файл.
func named(name string, check func(context.Context) error) health.Checker {
	return health.Checker{Name: name, Check: check}
}

func muxWithReadiness(checkers ...health.Checker) *http.ServeMux {
	return NewMux(Handlers{Health: health.New(checkers)})
}
