// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// write_tx_opener_test.go — гейт по дереву службы (см. `write_tx_opener.go`).
package check_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// writeOpenerScope — пакеты службы, чьи не-тестовые файлы судятся.
var writeOpenerScope = []string{"./cmd/...", "./internal/..."}

// writeOpenerTableFloor — журналируемых таблиц не меньше: семь таблиц ресурсов
// и три подтаблицы состава. Меньше — вывод из миграций ослеп, и гейт судил бы
// неполный перечень.
const writeOpenerTableFloor = 10

// TestWriteTransactionsOpenThroughTheJournalOpener — сам гейт.
func TestWriteTransactionsOpenThroughTheJournalOpener(t *testing.T) {
	root := moduleRoot(t)
	tables, migFiles, err := check.JournaledTables(filepath.Join(root, "internal", "migrations"))
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(tables), writeOpenerTableFloor,
		"ПРЕДПОСЫЛКА: из %d файлов миграций выведено %d журналируемых таблиц %v — разбор триггеров ослеп",
		migFiles, len(tables), tables)

	sites, census, err := check.ScanWriteOpeners(root, writeOpenerScope, tables, nil)
	require.NoError(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ: дерево не разобрано")
	t.Logf("перепись: миграций %d · %s", migFiles, census)

	// ПРЕДПОСЫЛКИ: обход видел получателей, и открывающий на месте. Пустой
	// обход — не зелёный.
	require.Positive(t, census.Files, "ПРЕДПОСЫЛКА: не прочитано ни одного файла")
	require.Positive(t, census.StarterCalls, "ПРЕДПОСЫЛКА: ни одного вызова на пуле — типы получателя не распознаются")
	require.Positive(t, census.OpenerBegins,
		"ПРЕДПОСЫЛКА: в %s нет ни одного открытия транзакции — открывающий уехал, и гейт судит пустоту",
		check.WriteOpenerFile)
	require.Positive(t, census.JudgedStmts, "ПРЕДПОСЫЛКА: ни одного оператора с константным текстом")

	lines := make([]string, 0, len(sites))
	for _, s := range sites {
		lines = append(lines, s.String())
	}
	require.Empty(t, sites, "пишущая транзакция мимо открывающего либо запись журналируемой таблицы пулом:\n  %s",
		strings.Join(lines, "\n  "))
}
