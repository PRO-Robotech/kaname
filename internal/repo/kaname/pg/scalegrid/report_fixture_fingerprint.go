// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package scalegrid

import (
	"fmt"
	"path"
)

// Два читающих отчёта используют общий файл orchestration и общие измерители:
// даже fullgrid вызывает sumLoops из strength. Список явно замыкает эти пути,
// включая собственное определение, печать, TestMain и внешние версии из модуля.
// Старый продуктовый отпечаток не включает фикстуры других семейств.
var readReportFixtureClosure = []struct{ file, role string }{
	{gridDir + "/report_fixture_fingerprint.go", "сетка"},
	{gridDir + "/fingerprint.go", "сетка"},
	{gridDir + "/ddlsubject.go", "сетка"},
	{gridDir + "/report.go", "сетка"},
	{gridDir + "/freshness_test.go", "сетка"},
	{verdictDir + "/scalegrid_probe_integration_test.go", "вердикт"},
	{verdictDir + "/strength_probe_integration_test.go", "вердикт"},
	{verdictDir + "/report_bounded_seed_integration_test.go", "вердикт"},
	{verdictDir + "/r7_cost_bounded_seed_integration_test.go", "вердикт"},
	{verdictDir + "/recruit_constructibility_bounded_seed_integration_test.go", "вердикт"},
	{verdictDir + "/query_integration_test.go", "вердикт"},
	{verdictDir + "/export_test.go", "вердикт"},
	{verdictDir + "/grantarm_assembly_test.go", "вердикт"},
	{verdictDir + "/planrows_live_integration_test.go", "вердикт"},
	{verdictDir + "/list_page_cost_integration_test.go", "вердикт"},
	{verdictDir + "/testmain_pgtest_test.go", "вердикт"},
	{"services/iam/internal/repo/kaname/pg/planrows/planrows.go", "извлекатель-плана"},
	{"services/iam/internal/repo/kaname/pg/resource_mirror/emitter.go", "производитель-зеркала"},
	{"services/iam/internal/testsupport/activewayin/activewayin.go", "способ-входа-фикстуры"},
	{"services/iam/internal/treeposture/treeposture.go", "посадка-модуля"},
	{migrateDir + "/migrations.go", "миграции"},
	{"services/iam/go.mod", "зависимости-модуля"},
	{"services/iam/go.sum", "зависимости-модуля"},
}

// Дополнительные роли разрешены только для точных обязательных файлов.
// Неизвестный путь по-прежнему отвергается fileIdentity.
func reportFixtureIdentity(rel string) (string, bool) {
	for _, ref := range readReportFixtureClosure {
		if rel == ref.file {
			return ref.role + "/" + path.Base(rel), true
		}
	}
	return "", false
}

func computeReadReportFingerprint(root, family string) (Fingerprint, error) {
	fp, err := ComputeFingerprint(root)
	if err != nil {
		return fp, err
	}
	files := append([]string(nil), fp.Files...)
	seen := make(map[string]bool, len(files))
	for _, file := range files {
		seen[file] = true
	}
	for _, ref := range readReportFixtureClosure {
		if !seen[ref.file] {
			files = append(files, ref.file)
			seen[ref.file] = true
		}
	}
	// stampFiles читает каждый обязательный файл: отсутствие — ошибка.
	if err := stampFiles(root, files, &fp); err != nil {
		return fp, err
	}
	fp.Predicate = FingerprintPredicate + "; семейство " + family +
		": дополнительно полный явный readReportFixtureClosure (посев, TX, измерители, renderer, TestMain, версии зависимостей и само определение); отсутствие обязательного файла — отказ"
	return fp, nil
}

// ComputeFullGridFingerprint общий для генератора полной сетки и её гейта.
func ComputeFullGridFingerprint(root string) (Fingerprint, error) {
	return computeReadReportFingerprint(root, "полная сетка")
}

// ComputeStrengthGridFingerprint общий для генератора прочности и её гейта.
func ComputeStrengthGridFingerprint(root string) (Fingerprint, error) {
	return computeReadReportFingerprint(root, "прочность")
}

// Ошибка определения происхождения не превращается в отчёт без отпечатка.
func TakeFullGridProvenance(runCommand string, grid [][]Point) (Provenance, error) {
	p := TakeProvenance(runCommand, grid)
	if p.treeRoot == "" {
		return p, fmt.Errorf("scalegrid: корень происхождения полной сетки не установлен")
	}
	fp, err := ComputeFullGridFingerprint(p.treeRoot)
	p.Fingerprint = fp
	return p, err
}

func TakeStrengthGridProvenance(runCommand string) (Provenance, error) {
	p := TakeProvenance(runCommand, nil)
	if p.treeRoot == "" {
		return p, fmt.Errorf("scalegrid: корень происхождения прочности не установлен")
	}
	fp, err := ComputeStrengthGridFingerprint(p.treeRoot)
	p.Fingerprint = fp
	return p, err
}
