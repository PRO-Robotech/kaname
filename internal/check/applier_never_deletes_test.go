// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// applier_never_deletes_test.go — по каталогу применителя ролей модуля
// (порт с монорепо, см. годок `applier_never_deletes.go`).
package check_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// applierPackageDir — каталог применителя ролей модуля, ОТ КОРНЯ своего
// модуля (было `services/iam/internal/apps/kaname/moduleroles`).
const applierPackageDir = "internal/apps/kaname/moduleroles"

// applierPackageFileFloor — порог: пакет применителя обязан состоять хотя бы
// из этого числа файлов, иначе он уехал/переименован и гейт судит пустоту.
const applierPackageFileFloor = 2

// TestMODRD15ApplierNeverDeletesARoleRow — сам гейт. Имя сохранено дословно.
func TestMODRD15ApplierNeverDeletesARoleRow(t *testing.T) {
	t.Parallel()
	root, prefix := platformtree.RequireCorpus(t)
	if prefix != "" {
		root = filepath.Join(root, filepath.FromSlash(prefix))
	}
	dir := filepath.Join(root, filepath.FromSlash(applierPackageDir))

	files, err := treecorpus.UnderWithSuffix(dir, ".go")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: каталог применителя %s не обойдён: %v",
			applierPackageDir, err)
	}

	var (
		parsed, ifaceMethods, literals int
		sites                          []check.ApplierDeleteSite
	)
	for _, abs := range files {
		if len(abs) > 8 && abs[len(abs)-8:] == "_test.go" {
			continue
		}
		src, rerr := os.ReadFile(abs) // #nosec G304 -- путь взят индексом дерева
		if rerr != nil {
			t.Fatalf("чтение %s: %v", abs, rerr)
		}
		s, census, serr := check.ScanApplierDeletes(abs, src)
		if serr != nil {
			t.Fatalf("разбор %s: %v", abs, serr)
		}
		parsed++
		ifaceMethods += census.InterfaceMethods
		literals += census.StringLiterals
		sites = append(sites, s...)
	}

	t.Logf("перепись: файлов пакета разобрано %d, методов интерфейсов осмотрено %d, "+
		"строковых литералов осмотрено %d, находок %d",
		parsed, ifaceMethods, literals, len(sites))

	if parsed < applierPackageFileFloor {
		t.Fatalf("пакет применителя %s разобран %d файлами при пороге %d — каталог "+
			"уехал либо переименован, и молчание гейта ничего не значит",
			applierPackageDir, parsed, applierPackageFileFloor)
	}
	if ifaceMethods == 0 {
		t.Fatalf("в пакете применителя не осмотрено ни одного метода интерфейса — "+
			"порт `RoleWriter` не найден разбором, и первая ось судит пустоту (файлов %d)", parsed)
	}

	for _, s := range sites {
		rel, _ := filepath.Rel(root, s.File)
		t.Errorf("%s:%d — %s (%s). Применитель ролей модуля не удаляет строку роли: форма "+
			"отзыва выбрана решением (пометка, `UPDATE`, не `DELETE`). %s",
			rel, s.Line, s.What, s.Kind, applierDeleteFindingWhy(s.Kind))
	}
}

func applierDeleteFindingWhy(kind string) string {
	if kind == "port-verb" {
		return "Порт объявляет метод, чьё имя означает удаление СТРОКИ РОЛИ — а роль с " +
			"выдачами удалить нельзя (ON DELETE RESTRICT), и это молча уронит применителя " +
			"на первой же используемой роли."
	}
	return "Оператор DELETE над таблицей ролей строковым литералом означает то же самое " +
		"в обход интерфейса порта."
}
