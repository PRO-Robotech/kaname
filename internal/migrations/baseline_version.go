// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations

import (
	"fmt"
	"io/fs"
	"path"
	"strconv"
	"strings"
)

// BaselineVersion — версия СВОДА цепочки: наименьшая версия среди её миграций.
//
// ВЫВОДИТСЯ ИЗ ЦЕПОЧКИ, А НЕ ВЫПИСЫВАЕТСЯ ЧИСЛОМ. Выписанное число не имеет
// производителя: сведение цепочки заново (а оно уже было — 171 миграция сведена
// в один файл) сдвинуло бы свод, и константа рядом осталась бы прежней молча.
//
// Пустой обход — ОТКАЗ, а не ноль: «версий не нашлось» иначе неотличимо от
// «версий нет», и страж, который на этом строится, промолчал бы там, где ему
// полагается отказать.
func BaselineVersion(fsys fs.FS) (int64, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return 0, fmt.Errorf("прочитать цепочку миграций: %w", err)
	}

	var (
		lowest int64
		seen   int
	)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if path.Ext(name) != ".sql" {
			continue
		}
		underscore := strings.IndexByte(name, '_')
		if underscore <= 0 {
			continue
		}
		v, perr := strconv.ParseInt(name[:underscore], 10, 64)
		if perr != nil {
			continue
		}
		seen++
		if seen == 1 || v < lowest {
			lowest = v
		}
	}
	if seen == 0 {
		return 0, fmt.Errorf("в цепочке миграций не найдено НИ ОДНОЙ версии: " +
			"обход пуст, и о своде не известно ничего")
	}
	return lowest, nil
}
