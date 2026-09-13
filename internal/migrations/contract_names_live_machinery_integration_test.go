// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// contract_names_live_machinery_integration_test.go — ТАБЛИЦА И КАНАЛ, НАЗВАННЫЕ
// КОММЕНТАРИЕМ КОНТРАКТА, СПРАШИВАЮТСЯ У ЖИВОЙ СХЕМЫ.
//
// # Предмет (kacho#2486)
//
// `rpc ForceLogout` обещал строку в `caep_outbox` «so federated downstream RPs get
// notified» и рассылку по каналу, обновляющую кэш отзыва на крае ≤ 1s. Конвейер
// снят миграцией `0007_drop_caep_pipeline.sql`, канал — `755001_…`; производителя
// ни у того, ни у другого не осталось ни одного. Оба утверждения пережили свой
// предмет и продолжали читаться интегратором как действующие.
//
// # Почему по ЖИВОЙ схеме, а не по тексту миграций
//
// Ровно по той же причине, что и у соседнего гейта каналов: текстовый предикат
// считает существующим объявление, чей предмет снят более поздней миграцией, —
// и наоборот, не видит созданного позже. Здесь проигрывается вся цепь и
// спрашивается ИТОГОВОЕ состояние каталога.
//
// Второго источника истины не заводится намеренно: разбор SQL рядом с живой
// схемой был бы вторым местом об одном предмете, и разошлось бы то, которое не
// исполняется.
//
// # Что считается ЗАЯВЛЕНИЕМ
//
// Не всякое имя в обратных кавычках, а имя ВМЕСТЕ С МАРКЕРОМ, который ставит сам
// комментарий (суффикс `_outbox`, слово `table`/`channel` сразу за именем,
// оборот `NOTIFY … on` перед ним). Правило и замер его точности — в шапке
// `internal/check/contract_names_live_machinery.go`: голый предикат по обратным
// кавычкам даёт 66 % ложных находок и потому негоден.
//
// Способность предиката упасть и смолчать доказана инъекцией —
// `internal/check/contract_names_live_machinery_injection_test.go`.
package migrations_test

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// contractCorpusDir — корень набора контрактов ОТНОСИТЕЛЬНО корня модуля.
const contractCorpusDir = "proto"

// TestIntegration_ContractNamesOnlyLiveSchemaMachinery — таблица и канал,
// названные контрактом, существуют в применённой схеме.
func TestIntegration_ContractNamesOnlyLiveSchemaMachinery(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)

	tables := schemaTablesOf(t, db)
	channels := setOf(notifyChannelsProducedBy(t, db))

	require.NotEmptyf(t, tables, "перепись таблиц пуста: схема не накатилась либо "+
		"запрос к каталогу читает не то — на пустой переписи КАЖДОЕ заявление ниже "+
		"стало бы находкой, и гейт назвал бы дефектом собственную поломку")
	require.NotEmptyf(t, channels, "перепись каналов пуста: то же основание — "+
		"беспредметный обход не вердикт")

	sources := readContractSources(t)
	require.NotEmptyf(t, sources, "набор контрактов пуст: «ноль находок» здесь "+
		"означало бы «ноль прочитанного»")

	found, census := check.AuditMachineryClaims(check.MachineryFacts{
		Sources:  sources,
		Tables:   tables,
		Channels: channels,
	})

	t.Logf("перепись: контрактов прочитано %d · блоков комментария %d · "+
		"заявлений о таблице %d · о канале %d · таблиц в схеме %d · каналов в схеме %d",
		census.Files, census.CommentBlocks,
		census.ByKind[check.MachineryTable], census.ByKind[check.MachineryChannel],
		len(tables), len(channels))

	require.NotZerof(t, census.ByKind[check.MachineryTable]+census.ByKind[check.MachineryChannel],
		"ни одного заявления о машинерии не распознано: предмета у гейта нет, и его "+
			"молчание неотличимо от молчания мёртвой проверки")

	for _, c := range found {
		if c.Kind == check.MachineryContract {
			continue // ось соседнего контракта судит собрат в internal/check
		}
		t.Errorf("%s:%d: комментарий контракта называет %s %q — в применённой схеме "+
			"такого объекта нет. Исходов три: реализовать · снять утверждение вместе с "+
			"предметом · записать решение о неисполнимости и сослаться на него. Оставить "+
			"как есть — не исход: интегратор перемерить не может",
			c.File, c.Line, c.Kind, c.Name)
	}
}

// schemaTablesOf — таблицы схемы службы в ИТОГОВОМ состоянии.
func schemaTablesOf(t *testing.T, db *sql.DB) map[string]struct{} {
	t.Helper()
	rows, err := db.Query(`
		SELECT c.relname
		  FROM pg_class c
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname = 'kaname'
		   AND c.relkind IN ('r', 'p', 'v', 'm')`)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()

	out := map[string]struct{}{}
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		out[name] = struct{}{}
	}
	require.NoError(t, rows.Err())
	return out
}

// setOf — перечень как множество.
func setOf(in []string) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for _, v := range in {
		out[v] = struct{}{}
	}
	return out
}

// readContractSources — исходники набора контрактов модуля.
func readContractSources(t *testing.T) map[string]string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoErrorf(t, err, "рабочий каталог не установлен: судить не о чем")
	moduleRoot, err := platformtree.ModuleRootFrom(wd)
	require.NoErrorf(t, err, "корень модуля не установлен: обход шёл бы по чужому дереву")

	root := filepath.Join(moduleRoot, contractCorpusDir)
	sources := map[string]string{}
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".proto") {
			return nil
		}
		body, rerr := os.ReadFile(path) // #nosec G304 -- обход собственного набора контрактов
		if rerr != nil {
			return rerr
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		sources[filepath.ToSlash(rel)] = string(body)
		return nil
	})
	require.NoErrorf(t, err, "обход набора контрактов %s", root)
	return sources
}
