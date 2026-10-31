// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"strings"
)

// HistoricalRegistrationMigration — архив исходной ветви с совпавшим номером.
const HistoricalRegistrationMigration = "internal/migrations/historical/20261026090000_module_writes_only_what_its_manifest_declares.sql"

// AuditHistoricalRegistrationMigration проверяет содержимое и отсутствие в
// исполняемой FS, включая переименованную копию. Только после этого архив
// исключается из сравнения номеров; произвольный вложенный SQL не исключается.
func AuditHistoricalRegistrationMigration(body []byte, executable fs.FS) error {
	const identity = "bd9449a671136b68ae82ce38edabbe2801a056fd4f7919fde769406be7bced29"
	if fmt.Sprintf("%x", sha256.Sum256(body)) != identity {
		return fmt.Errorf("historical registration migration differs from the original immutable SQL")
	}
	return fs.WalkDir(executable, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(name, ".sql") {
			return nil
		}
		data, err := fs.ReadFile(executable, name)
		if err != nil {
			return err
		}
		if fmt.Sprintf("%x", sha256.Sum256(data)) == identity || strings.HasPrefix(name, "historical/") {
			return fmt.Errorf("historical migration is executable through migrations.FS: %s", name)
		}
		return nil
	})
}
