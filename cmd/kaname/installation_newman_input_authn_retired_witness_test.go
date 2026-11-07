// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import "encoding/json"

// Только данные уже полученных снимков. Список не расширяет SQL и не включает
// аутентификацию, операции или произвольные payload outbox.
var rid11RetiredPrivateTables = []string{
	"registration_legacy_cluster_writer_identity", "registration_account_writer_switch",
	"clusters", "accounts", "groups", "access_bindings", "access_binding_subjects",
	"access_binding_emitted_tuples", "access_binding_target_members", "relation_fact",
}

func rid11RetiredPrivateTable(table string) bool {
	for _, name := range rid11RetiredPrivateTables {
		if table == name {
			return true
		}
	}
	return false
}

// SQL строки остаются строками: json.RawMessage здесь потерял бы исходные
// пробелы. Отдельный rawRowsJSON сохраняет прежний Go hash domain и порядок строк.
// Отсутствующий снимок или превышение границы наблюдается и запрещает приёмку.
func rid11RetiredPrivateWitness(a, b rid03NewmanSnapshot) map[string]any {
	bounded := true
	bytes := 0
	side := func(s rid03NewmanSnapshot) map[string]any {
		tables := map[string]any{}
		for _, table := range rid11RetiredPrivateTables {
			rows, rawPresent := s.Raw[table]
			sql, sqlPresent := s.Whole.retiredSQLRows[table]
			raw, err := json.Marshal(rows)
			size := len(raw)
			for _, text := range sql {
				size += len(text)
			}
			if err != nil || len(rows) > 4096 || len(sql) > 4096 || bytes+size > 8*1024*1024 {
				bounded = false
				continue
			}
			bytes += size
			// Копия массива не позволяет последующей замене элемента изменить witness.
			texts := append([]string{}, sql...)
			tables[table] = map[string]any{"rawPresent": rawPresent, "sqlPresent": sqlPresent, "rawRowsJSON": string(raw), "sqlRows": texts}
		}
		return map[string]any{"primaryStartedAt": s.Whole.PrimaryStartedAt, "primaryFinishedAt": s.Whole.PrimaryFinishedAt, "wholeSHA256": rid03EvidenceHash(s.Whole), "rawSHA256": rid03EvidenceHash(s.Raw), "tables": tables}
	}
	before, after := side(a), side(b)
	return map[string]any{"format": "RID11_RETIRED_HISTORY_PRIVATE_SQL_V1", "private": true, "bounded": bounded, "before": before, "after": after}
}
