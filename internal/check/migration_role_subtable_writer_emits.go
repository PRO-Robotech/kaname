// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// migration_role_subtable_writer_emits.go — ЗАГОТОВКА красного прогона kaname#76:
// форма входа и выхода гейта §3.2а без разбора. Заменяется разбором тем же
// изменением.
package check

import "fmt"

// RoleSubtableFinding — раздел миграции, пишущий подтаблицы роли без события.
type RoleSubtableFinding struct {
	File    string
	Section string
	Table   string
	Why     string
}

// String — находка одной строкой.
func (f RoleSubtableFinding) String() string {
	return fmt.Sprintf("%s [%s] %s: %s", f.File, f.Section, f.Table, f.Why)
}

// RoleSubtableCensus — объём осмотренного.
type RoleSubtableCensus struct {
	Files, Sections, Population, Writers, Calling int
	Floor                                         string
	Outside                                       []string
}

// AuditRoleSubtableWriters — гейт §3.2а.
func AuditRoleSubtableWriters(corpus TreeCorpus) ([]RoleSubtableFinding, RoleSubtableCensus, error) {
	return nil, RoleSubtableCensus{Files: len(corpus), Sections: len(corpus)}, nil
}
