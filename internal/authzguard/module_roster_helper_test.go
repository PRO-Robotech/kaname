// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard

import (
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
)

// testModuleRoster — перечень личностей модулей, которым пробы пакета
// собирают стражей (kaname#984): признание модуля — объявленная пара, и проба,
// собравшая стража без перечня, судила бы мир, где модулем не признаётся никто.
//
// Пары — те, что пробы предъявляют как ЗАКОННЫХ модулей; формы, которые пробы
// предъявляют как чужие (необъявленное пространство, чужой домен, снятый
// оператор), сюда не входят намеренно.
func testModuleRoster() moduleidentity.Roster {
	r, err := moduleidentity.Parse([]string{
		"kacho/kacho-api-gateway=edge",
		"kacho/kacho-vpc=module-writer",
		"kacho/kacho-compute=module-writer",
		"kacho/kacho-nlb=module-writer",
		"kacho/kacho-registry=module-writer",
		"kacho/kacho-storage=module-writer",
		"kacho-storage/kacho-storage=module-writer",
		"registry/kacho-registry-dp=data-plane",
	})
	if err != nil {
		panic("перечень личностей проб не разобрался: " + err.Error())
	}
	return r
}
