// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// operator-docs — порождает и сверяет документы, которые читает чужой оператор:
// перечень третьих сторон и перечень обязательных величин в документе установки.
//
// Вызов — через цель сборки, а не руками:
//
//	make -C services/iam operator-docs         порождает
//	make -C services/iam operator-docs-check   сверяет
package main

import (
	"flag"
	"os"

	"github.com/PRO-Robotech/kaname/tools/operatordocs"
)

func main() {
	root := flag.String("root", ".", "корень дерева iam")
	write := flag.Bool("write", false, "записать порождённое (без флага — только сверить)")
	flag.Parse()

	os.Exit(operatordocs.Run(operatordocs.Options{Root: *root, Write: *write, Out: os.Stdout}))
}
