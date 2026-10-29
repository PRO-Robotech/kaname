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
// оператор), сюда не входят намеренно. Учётки названы формой имени службы проб
// пакета (testServiceNameForm, kaname#308).
func testModuleRoster() moduleidentity.Roster {
	f := testServiceNameForm
	r, err := moduleidentity.Parse(f, []string{
		"kacho/" + f.Account("api-gateway") + "=edge",
		"kacho/" + f.Account("vpc") + "=module-writer",
		"kacho/" + f.Account("compute") + "=module-writer",
		"kacho/" + f.Account("nlb") + "=module-writer",
		"kacho/" + f.Account("registry") + "=module-writer",
		"kacho/" + f.Account("storage") + "=module-writer",
		"platform-storage/" + f.Account("storage") + "=module-writer",
		"registry/" + f.Account("registry-dp") + "=data-plane",
	})
	if err != nil {
		panic("перечень личностей проб не разобрался: " + err.Error())
	}
	return r
}
