// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// limit_export_procedure.go — разбор инструкций установки на предмет процедуры,
// которой оператор сохраняет строки таблицы ПЕРЕД её сносом (задача продукта #2134,
// приёмка KAN-QUOTA-1 §9 `ПР-3`, сценарий `KAN-Q4-07`).
//
// # Предмет
//
// Накат отказывает, увидев живые строки в таблице, которую снесёт ещё не
// применённая миграция, и называет оператору два шага: сохранить и разрешить
// снос. Первый — команда, и производит её РОВНО ОДНО место, `dropguard.PreserveCommand`.
//
// Оператор читает эту команду дважды и в двух РАЗНЫХ местах: в отказе, когда
// накат уже встал, и в инструкции обновления, когда он к обновлению готовится.
// Два написания одной команды расходятся молча — и расходится то, которое НЕ
// исполняется, то есть документ. Поэтому документ обязан нести её ДОСЛОВНО, а не
// пересказом.
//
// # Оси находки — две, и они с разных сторон
//
//  1. **инструкция службы доступа обязана нести команду для таблицы величин.**
//     Версия, снимающая домен величин, сносит `kaname.limits`; счёт её строк
//     ненулевой у ЛЮБОЙ установки (цепочка сеет умолчания, администратор пишет
//     сверх), значит отказ наступит у каждого, и процедура обязана быть записана
//     ЗАРАНЕЕ. Ось привязана к координате намеренно: без неё «команды нет вовсе»
//     давало бы ноль предметов, то есть зелёное на достигнутой потере;
//  2. **всякая процедура выгрузки в любой инструкции обязана совпадать с
//     производителем побайтово.** Ось ловит ВТОРОЕ написание — то, что заведут
//     соседи, скопировав абзац и поправив под себя.
//
// # Порт с монорепо — пара файлов названа, а не умолчана
//
// Перенесено с `PRO-Robotech/kacho:internal/repohygiene/limitexportprocedure.go`
// (семейство снято вынесением службы, `kacho#2597`; предмет жив здесь — задача
// #17: INSTALL.md службы несёт команду для `kaname.limits`). Изменилось: дом
// производителя (`PRO-Robotech/corelib:dropguard`, приезжает пином — своей копии
// порт НЕ заводит), пакет, координата инструкции (приставки `services/iam/` в
// самостоятельном клоне нет) и имена трёх внутренних помощников, разведённые с
// соседями по пакету. Осталось дословно: имя гейта, обе оси находки и разбор.
//
// # Чего разбор НЕ видит — названо, а не спрятано
//
// Команду, разорванную переносом строки: строка документа читается целиком, и
// перенос внутри неё разорвал бы и саму команду для того, кто её копирует.
// Отдельно: разбор судит ТЕКСТ инструкции, а не то, что psql её исполнит, —
// исполнимость против живой схемы утверждает интеграционная проба службы
// доступа, где база поднимается.
package check

import (
	"fmt"
	"sort"
	"strings"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/corelib/dropguard"
)

// ExportProcedureCensus — объём осмотренного. Печатается всегда: «находок ноль»
// обязано быть отличимо от «прочитано ноль».
type ExportProcedureCensus struct {
	// Guides — инструкций прочитано.
	Guides int
	// Lines — строк в них прочитано.
	Lines int
	// Procedures — строк, несущих процедуру выгрузки о КОНКРЕТНОЙ таблице.
	Procedures int
	// Templates — строк-образцов, где имя таблицы оставлено оператору. Считаются
	// отдельно: образец не утверждает о таблице ничего и сверять его с
	// производителем не с чем.
	Templates int
	// Tables — таблицы, чью выгрузку эти строки называют.
	Tables []string
}

func (c ExportProcedureCensus) String() string {
	return fmt.Sprintf("перепись: инструкций прочитано %d, строк %d, процедур выгрузки %d, образцов %d, таблиц названо %d (%s)",
		c.Guides, c.Lines, c.Procedures, c.Templates, len(c.Tables), strings.Join(c.Tables, ", "))
}

// exportCopyMarker — по чему строка документа опознаётся как процедура выгрузки. Это
// мета-команда оболочки psql, и в прозе она не встречается: у разбора нет риска
// принять за процедуру объяснение процедуры.
// InstallGuideSuffix — по чему инструкции обновления опознаются в составе дерева.
const InstallGuideSuffix = "INSTALL.md"

// ExportProcedureGuides — корпус инструкций обновления из ДЕРЕВА.
//
// Дерево приходит параметром, а отбор объявлен здесь и больше нигде: гейт и
// инъекция зовут ОДНУ функцию, поэтому синтетика проверяет тот же отбор, что
// исполняется на боевом прогоне, а не его копию. Пустой обход — отказ
// (`ErrEmptyTraversal`), а не «находок ноль».
func ExportProcedureGuides(tree *treecorpus.Tree) (TreeCorpus, error) {
	return CorpusFrom(tree, func(rel string) bool {
		return strings.HasSuffix(rel, InstallGuideSuffix)
	})
}

const exportCopyMarker = `\copy (`

// JudgeExportProcedure судит корпус инструкций: ключ — путь, значение — текст.
//
// required — таблицы, чья процедура выгрузки обязана быть записана, и в какой
// именно инструкции. Возвращает перепись и находки; находок ноль — годно.
func JudgeExportProcedure(guides map[string]string, required map[string]string) (ExportProcedureCensus, []string) {
	var (
		census ExportProcedureCensus
		found  []string
		seen   = map[string]bool{}
		tables = map[string]bool{}
	)

	paths := make([]string, 0, len(guides))
	for p := range guides {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, path := range paths {
		census.Guides++
		for n, line := range strings.Split(guides[path], "\n") {
			census.Lines++
			if !strings.Contains(line, exportCopyMarker) {
				continue
			}
			table := tableInsideExportCopy(line)
			if isExportTemplateTable(table) {
				census.Templates++
				continue
			}
			census.Procedures++
			if table == "" {
				found = append(found, fmt.Sprintf(
					"%s:%d процедура выгрузки не называет таблицы — оператору нечего подставить: %s",
					path, n+1, strings.TrimSpace(line)))
				continue
			}
			tables[table] = true

			// Обобщённая форма («<таблица>») — это шаблон, который оператор
			// заполняет по отказу, а не команда о конкретной таблице. Она
			// сверяется с производителем на том же шаблоне.
			want := dropguard.PreserveCommand(table)
			if !strings.Contains(line, want) {
				found = append(found, fmt.Sprintf(
					"%s:%d процедура выгрузки таблицы %s разошлась с производителем "+
						"(corelib/dropguard.PreserveCommand).\n  в документе: %s\n  производит:  %s",
					path, n+1, table, strings.TrimSpace(line), want))
				continue
			}
			seen[path+"\x00"+table] = true
		}
	}

	reqTables := make([]string, 0, len(required))
	for table := range required {
		reqTables = append(reqTables, table)
	}
	sort.Strings(reqTables)
	for _, table := range reqTables {
		guide := required[table]
		if _, ok := guides[guide]; !ok {
			found = append(found, fmt.Sprintf(
				"%s не прочитана: инструкции обновления, в которой обязана лежать процедура "+
					"выгрузки таблицы %s, в дереве нет", guide, table))
			continue
		}
		if !seen[guide+"\x00"+table] {
			found = append(found, fmt.Sprintf(
				"%s не несёт процедуры выгрузки таблицы %s.\n  ожидается дословно: %s\n"+
					"  Снос этой таблицы уничтожит назначенное администратором установки. "+
					"Оператор, встретивший отказ наката, ищет процедуру здесь; не найдя её, "+
					"он оставляет исполнимым единственный названный шаг — разрешить уничтожение.",
				guide, table, dropguard.PreserveCommand(table)))
		}
	}

	census.Tables = make([]string, 0, len(tables))
	for t := range tables {
		census.Tables = append(census.Tables, t)
	}
	sort.Strings(census.Tables)
	sort.Strings(found)
	return census, found
}

// isExportTemplateTable — образец, в котором имя таблицы оставлено оператору
// (`<таблица>`), а не названо. Разбор судит имя по форме, а не по конкретному
// написанию заполнителя: заполнитель пишут прозой и на любом языке, а
// квалифицированное имя таблицы Postgres — нет.
func isExportTemplateTable(table string) bool {
	if table == "" {
		return false
	}
	for _, r := range table {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '.', r == '"':
		default:
			return true
		}
	}
	return false
}

// tableInsideExportCopy достаёт имя таблицы из процедуры выгрузки — то, что стоит между
// `SELECT * FROM ` и закрывающей скобкой `\copy`.
func tableInsideExportCopy(line string) string {
	i := strings.Index(line, exportCopyMarker)
	if i < 0 {
		return ""
	}
	rest := line[i+len(exportCopyMarker):]
	j := strings.LastIndex(rest, `) TO `)
	if j < 0 {
		return ""
	}
	const from = "SELECT * FROM "
	inner := strings.TrimSpace(rest[:j])
	if !strings.HasPrefix(inner, from) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(inner, from))
}
