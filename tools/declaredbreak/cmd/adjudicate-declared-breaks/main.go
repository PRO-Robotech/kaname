// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// adjudicate-declared-breaks — читает вывод `buf breaking --error-format=json`
// со стандартного входа и сопоставляет его с перечнем объявленных разрывов.
//
// ИСХОДОВ ТРИ: 0 — чисто · 1 — находка · 2 — гейт НЕ СДЕЛАЛ СВОЕЙ РАБОТЫ.
// Третий не вычитается из вердикта и не зачитывается в успех.
package main

import (
	"fmt"
	"os"

	"github.com/PRO-Robotech/kaname/tools/declaredbreak"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "ПРОВЕРКА НЕ ИСПОЛНЯЛАСЬ: нужен ровно один довод — "+
			"путь к перечню объявленных разрывов")
		os.Exit(2)
	}
	decls, err := declaredbreak.LoadDeclarations(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "ПРОВЕРКА НЕ ИСПОЛНЯЛАСЬ: %v\n", err)
		os.Exit(2)
	}
	findings, err := declaredbreak.ParseFindings(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ПРОВЕРКА НЕ ИСПОЛНЯЛАСЬ: %v\n", err)
		os.Exit(2)
	}
	res := declaredbreak.Adjudicate(findings, decls)
	fmt.Print(res.Report())
	if !res.Clean() {
		os.Exit(1)
	}
}
