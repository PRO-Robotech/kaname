// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
)

// testModuleRoster — перечень личностей модулей для проб, собирающих цепочку
// стражей вне `runServe` (kaname#984): край и модуль-владелец в пространстве
// `kacho` домена `kacho.cloud` — те, кого эти пробы предъявляют законными.
func testModuleRoster() moduleidentity.Roster {
	r, err := moduleidentity.Parse(probeServiceNameForm, []string{
		"kacho/kacho-api-gateway=edge",
		"kacho/kacho-vpc=module-writer",
	})
	if err != nil {
		panic("перечень личностей проб не разобрался: " + err.Error())
	}
	return r
}
