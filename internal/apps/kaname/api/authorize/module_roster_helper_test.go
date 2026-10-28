// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authorize

import (
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	"github.com/PRO-Robotech/kaname/internal/servicesan"
)

// testModuleRoster — перечень личностей, которым пробы пакета собирают
// обработчик (kaname#984): пиром-модулем признаётся только объявленная пара,
// и проба без перечня судила бы мир, где модуля нет ни одного. Учётки названы
// формой имени службы проб пакета (probeModuleForm, kaname#308).
func testModuleRoster() moduleidentity.Roster {
	return testModuleRosterOfForm(probeModuleForm)
}

// testModuleRosterOfForm — тот же перечень под объявленной формой form: модуль
// vpc в пространстве `kacho` назван учёткой этой формы. Форма, которой учётка
// сертификата проб (`moduleCertCtx`) не имеет, признаёт перечнем другую
// учётку — и пир проб модулем не узнаётся.
func testModuleRosterOfForm(form servicesan.Form) moduleidentity.Roster {
	r, err := moduleidentity.Parse(form, []string{"kacho/" + form.Account("vpc") + "=module-writer"})
	if err != nil {
		panic("перечень личностей проб не разобрался: " + err.Error())
	}
	return r
}
