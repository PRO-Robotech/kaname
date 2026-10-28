// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package declaredbreak

import (
	"fmt"
	"io"
)

// Run — исполнение адъюдикатора: доводы, вход buf, отчёт и код возврата.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "ПРОВЕРКА НЕ ИСПОЛНЯЛАСЬ: нужен ровно один довод — "+
			"путь к перечню объявленных разрывов")
		return 2
	}
	decls, err := LoadDeclarations(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "ПРОВЕРКА НЕ ИСПОЛНЯЛАСЬ: %v\n", err)
		return 2
	}
	findings, err := ParseFindings(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "ПРОВЕРКА НЕ ИСПОЛНЯЛАСЬ: %v\n", err)
		return 2
	}
	res := Adjudicate(findings, decls)
	fmt.Fprint(stdout, res.Report())
	if !res.Clean() {
		return 1
	}
	return 0
}
