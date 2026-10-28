// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// adjudicate-declared-breaks — читает вывод `buf breaking --error-format=json`
// со стандартного входа и сопоставляет его с перечнем объявленных разрывов.
//
// ИСХОДОВ ТРИ: 0 — чисто · 1 — находка · 2 — гейт НЕ СДЕЛАЛ СВОЕЙ РАБОТЫ.
// Третий не вычитается из вердикта и не зачитывается в успех. Форма вызова и
// исходы — у declaredbreak.Run: там их судят пробы.
package main

import (
	"os"

	"github.com/PRO-Robotech/kaname/tools/declaredbreak"
)

func main() {
	os.Exit(declaredbreak.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
