// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/PRO-Robotech/corelib/treecorpus"
)

// ProdGoFiles — непроверочные исходники каталогов `internal` и `cmd` модуля с
// корнем root: путь относительно корня в косой записи → текст. Состав берётся
// из индекса git, а не с диска.
//
// Это тот состав, который `FamilyVerdict` судит на дереве. Гейт, опирающийся на
// ту же перепись (например, на число вызовов писателя записи выпуска), берёт
// состав отсюда: два состава одного факта разошлись бы молча.
func ProdGoFiles(root string) (map[string]string, error) {
	files := map[string]string{}
	for _, d := range []string{"internal", "cmd"} {
		paths, err := treecorpus.UnderWithSuffix(filepath.Join(root, d), ".go")
		if err != nil {
			return nil, fmt.Errorf("обход %s: %w", d, err)
		}
		for _, p := range paths {
			if strings.HasSuffix(p, "_test.go") {
				continue
			}
			b, err := os.ReadFile(p) // #nosec G304 -- путь из состава дерева этого модуля
			if err != nil {
				return nil, fmt.Errorf("чтение %s: %w", p, err)
			}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return nil, fmt.Errorf("относительный путь %s: %w", p, err)
			}
			files[filepath.ToSlash(rel)] = string(b)
		}
	}
	return files, nil
}
