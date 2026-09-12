// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// client_expiry_immutable_test.go — срок клиента, способного к утверждению,
// НЕИЗМЕНЯЕМ после создания. Порт с монорепо, см. годок
// `client_expiry_immutable.go`.
package check_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

const (
	// clientExpiryColumn — столбец срока.
	clientExpiryColumn = "expires_at"
	// clientExpiryMigrations — каталог миграций владельца таблиц, ОТ КОРНЯ
	// своего модуля (было `services/iam/internal/migrations/`).
	clientExpiryMigrations = "internal/migrations/"
	// clientExpiryCensusFloor — порог переписи.
	clientExpiryCensusFloor = 200
)

// clientExpiryTables — таблицы клиентов, способных к утверждению. Третья
// таблица клиентов сюда не входит намеренно: ключевого материала у неё нет.
var clientExpiryTables = []string{"user_oauth_clients", "service_account_oauth_clients"}

// TestClientExpiryIsNeverUpdated — сам гейт. Имя сохранено дословно.
func TestClientExpiryIsNeverUpdated(t *testing.T) {
	t.Parallel()
	root, prefix := platformtree.RequireCorpus(t)
	if prefix != "" {
		root = filepath.Join(root, filepath.FromSlash(prefix))
	}
	tree := gateTree(t, root)

	declared := map[string]string{}
	migrationsRead := 0
	for rel := range tree.files {
		if !strings.HasPrefix(rel, clientExpiryMigrations) || !strings.HasSuffix(rel, ".sql") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			continue
		}
		migrationsRead++
		up := migrations.MigrationUpSection(string(body))
		for _, table := range clientExpiryTables {
			if _, ok := declared[table]; ok {
				continue
			}
			if b := check.SQLCreateTableBody(up, table); b != "" {
				declared[table] = rel
				if !strings.Contains(b, clientExpiryColumn) {
					t.Errorf("таблица %s объявлена в %s и столбца %q НЕ несёт. Предпосылка "+
						"решения §2.10 отпала: неизменяемость стерегут у столбца, которого "+
						"нет, и гейт молчал бы по построению.", table, rel, clientExpiryColumn)
				}
			}
		}
	}
	for _, table := range clientExpiryTables {
		if declared[table] == "" {
			t.Fatalf("объявления таблицы %s в %s (прочитано файлов %d) не найдено — гейт "+
				"стережёт координату, которой больше не существует",
				table, clientExpiryMigrations, migrationsRead)
		}
	}

	var rels []string
	for rel := range tree.files {
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			continue
		}
		rels = append(rels, rel)
	}
	sort.Strings(rels)

	var (
		parsed  int
		census  check.SQLUpdateCensus
		updates []check.SQLUpdate
	)
	for _, rel := range rels {
		src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			continue
		}
		us, c, serr := check.ScanSQLUpdates(rel, src, clientExpiryTables)
		if serr != nil {
			t.Fatalf("разбор %s: %v", rel, serr)
		}
		parsed++
		census.StringLiterals += c.StringLiterals
		census.SQLLiterals += c.SQLLiterals
		census.Updates += c.Updates
		census.UpdatesWithoutColumns += c.UpdatesWithoutColumns
		updates = append(updates, us...)
	}

	var touched []string
	for _, u := range updates {
		touched = append(touched, fmt.Sprintf("%s:%d %s → %s SET %s",
			u.File, u.Line, u.Func, u.Table, strings.Join(u.Columns, ", ")))
	}
	sort.Strings(touched)

	t.Logf("перепись: файлов миграций прочитано %d, объявления таблиц найдены (%s); "+
		"не-тестовых файлов Go разобрано %d, строковых литералов осмотрено %d, из них "+
		"операторов SQL %d, из них правок стережённых таблиц %d (без разобранных столбцов %d)",
		migrationsRead, strings.Join(clientExpiryTables, ", "), parsed,
		census.StringLiterals, census.SQLLiterals, census.Updates, census.UpdatesWithoutColumns)

	if parsed < clientExpiryCensusFloor {
		t.Fatalf("перепись обвалилась: разобрано %d файлов при пороге %d", parsed, clientExpiryCensusFloor)
	}
	if census.SQLLiterals == 0 {
		t.Fatalf("на %d файлах не найдено НИ ОДНОГО литерала SQL — разбор перестал видеть "+
			"предмет, и его молчание сказано ни о чём", parsed)
	}
	if census.Updates == 0 {
		t.Fatalf("правок таблиц %v в дереве НОЛЬ при %d литералах SQL. Разбор не производит "+
			"признака, который стережёт: он молчал бы и на правке срока.",
			clientExpiryTables, census.SQLLiterals)
	}

	var findings []string
	for _, u := range updates {
		for _, col := range u.Columns {
			if col != clientExpiryColumn {
				continue
			}
			findings = append(findings, fmt.Sprintf("%s:%d  %s — %s SET %s",
				u.File, u.Line, u.Func, u.Table, strings.Join(u.Columns, ", ")))
		}
	}
	sort.Strings(findings)
	if len(findings) > 0 {
		t.Fatalf("срок клиента правится после создания — %d место(а):\n  %s\n\n"+
			"На неизменяемости срока стоит структурная гарантия: срок выданного токена не "+
			"превышает остатка срока клиента. Исходов два: не двигать срок (создать нового "+
			"клиента) либо вернуть проверку остатка на путь запроса ТЕМ ЖЕ изменением.",
			len(findings), strings.Join(findings, "\n  "))
	}

	t.Logf("законные правки этих таблиц (столбец срока среди них не назван), %d", len(touched))
}
