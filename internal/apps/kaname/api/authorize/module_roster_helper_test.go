// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authorize

import (
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
)

// testModuleRoster — перечень личностей, которым пробы пакета собирают
// обработчик (kaname#984): пиром-модулем признаётся только объявленная пара,
// и проба без перечня судила бы мир, где модуля нет ни одного.
func testModuleRoster() moduleidentity.Roster {
	r, err := moduleidentity.Parse([]string{"kacho/kacho-vpc=module-writer"})
	if err != nil {
		panic("перечень личностей проб не разобрался: " + err.Error())
	}
	return r
}
