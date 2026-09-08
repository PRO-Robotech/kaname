// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Команда module-manifest-check — сборочная цель, судящая манифесты модулей
// дерева разработки. Её зовёт конвейер через `make -C services/iam
// module-manifest-check`.
//
// ТОНКАЯ: композиция стадий, тексты и коды возврата живут в
// services/iam/internal/manifestcheckrun, потому что тот же исполнитель зовётся
// действием `iamctl validate`. Вторая композиция тех же стадий разошлась бы с
// этой молча — и разошлась бы там, где расхождение не видно: обе дают «годно»
// на честном дереве.
//
// Коды возврата и их смысл объявлены на пакете; здесь только вызов.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/PRO-Robotech/kaname/internal/manifestcheckrun"
)

func main() {
	root, err := manifestcheckrun.ParseRoot(os.Args[0], os.Args[1:])
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintf(os.Stderr, "проверка НЕ ИСПОЛНЯЛАСЬ: %v\n", err)
		}
		os.Exit(manifestcheckrun.ExitNotRun)
	}
	os.Exit(manifestcheckrun.Run(root, os.Stdout, os.Stderr))
}
