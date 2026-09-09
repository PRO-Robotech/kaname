// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// limit_drop_refusal_integration_test.go — накат ОТКАЗЫВАЕТ на снятии таблицы
// величин и называет оператору процедуру выгрузки (задача #2134, условие 2
// предиката; приёмка KAN-QUOTA-1 §9 `ПР-3`, сценарий `KAN-Q4-07`).
//
// # Что здесь утверждается и почему это не повтор соседних проб
//
// Условие 2 предиката задачи требует, чтобы процедура выгрузки была названа «в
// тексте отказа старта, который сообщает о СНЯТИИ». Соседние пробы покрывают
// половины этого утверждения и ни одна — его целиком:
//
//   - `pkg/dropguard` доказывает форму отказа на СИНТЕТИЧЕСКОЙ цепи («widgets»):
//     сохранение названо, названо прежде уничтожения. О таблице величин и о цепи
//     службы доступа она не утверждает ничего;
//   - гейт `internal/repohygiene` сверяет текст инструкции с производителем
//     ПОБАЙТОВО, но судит текст, а не поведение наката;
//   - `limit_export_before_retirement_integration_test.go` доказывает, что
//     документированный запрос ОТРАБАТЫВАЕТ против живой схемы. Он не спрашивает,
//     наступит ли отказ, который направит к этому запросу.
//
// Незакрытым оставалось то, что дороже всех трёх: **сработает ли страж на самой
// `kaname.limits`**. До этой пробы ответ был «by construction» — то есть вывод, а
// не замер. Вывод опирается на то, что распознаватель снятий узнает форму, в
// которой стадия S4 напишет снос; форма, которой он не знает, даёт не красное и
// не зелёное, а МОЛЧАНИЕ (`testing.md` §«Гейт на класс», п. 7). Молчание здесь
// означает, что накат снесёт таблицу без отказа, а оператор узнает о потере по
// последствиям — ровно то, ради чего задача #2134 существует.
//
// # Почему снос СИНТЕТИЧЕСКИЙ, а не взят из дерева
//
// Стадия S4 не начата, и настоящей миграции сноса в цепи нет. Проба подаёт стражу
// цепь службы плюс ОДНУ ещё не применённую миграцию, снимающую `kaname.limits` в
// той канонической форме, какой снос записан у соседей (`DROP TABLE IF EXISTS
// <схема>.<таблица>;` — предикат: `git grep -n 'DROP TABLE' -- 'services/*/internal/migrations/*.sql'`).
// Применённая миграция при этом не тронута ни байтом: наложение живёт в памяти
// пробы, дерево не правится.
//
// Проба говорит поэтому не «S4 сделана», а «когда S4 напишет снос ЭТОЙ формой,
// оператор получит отказ с командой выгрузки, а не молчаливую потерю». Напишет
// другой — покраснеет здесь, и это её работа.
package migrations_test

import (
	"context"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/dropguard"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// retirementVersion — версия синтетического сноса. Старше всякой применённой:
// снос, оказавшийся младше, был бы уже применён и предметом стража не стал бы.
const retirementVersion int64 = 29990101000000

// retirementMigration — снос таблицы величин в канонической форме дерева.
func retirementMigration(table string) string {
	return "-- +goose Up\nDROP TABLE IF EXISTS " + table + ";\n\n" +
		"-- +goose Down\nSELECT 1;\n"
}

// chainWithPendingRetirement — цепь службы плюс один ещё не применённый снос.
// Дерево не правится: наложение существует только на время прогона.
func chainWithPendingRetirement(t *testing.T, table string) fs.FS {
	t.Helper()

	overlay := fstest.MapFS{}
	entries, err := fs.ReadDir(migrations.FS, ".")
	require.NoError(t, err)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		raw, rerr := fs.ReadFile(migrations.FS, e.Name())
		require.NoError(t, rerr)
		overlay[e.Name()] = &fstest.MapFile{Data: raw}
	}
	require.NotEmpty(t, overlay, "цепь службы прочитана пустой: наложение говорило бы не о ней")

	name := fmt.Sprintf("%d_limit_authority_leaves_iam.sql", retirementVersion)
	overlay[name] = &fstest.MapFile{Data: []byte(retirementMigration(table))}
	return overlay
}

// TestLimitDropRefusal_NamesTheExportProcedureBeforeDestruction — несущая половина.
func TestLimitDropRefusal_NamesTheExportProcedureBeforeDestruction(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}

	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer db.Close()

	// Таблица непуста БЕЗ помощи пробы: цепь сеет умолчания сама. Это и есть
	// довод задачи — отказ наступит у каждой установки, а не у подготовленной.
	seeded := countLimits(t, db)
	require.Positive(t, seeded, "цепь не посеяла ни одной величины: стражу нечего было бы "+
		"считать, и отказ ниже зеленел бы на пустоте")

	inv, err := dropguard.Inventory("iam", chainWithPendingRetirement(t, limitsTable))
	require.NoError(t, err)

	// Распознаватель обязан УВИДЕТЬ снос. Проверяется отдельным утверждением:
	// не увидев его, страж промолчит, и «нарушений ноль» ниже было бы неотличимо
	// от «прочитано ноль».
	var seenDrop bool
	for _, d := range inv.Drops {
		if strings.EqualFold(d.Table, limitsTable) && d.Version == retirementVersion {
			seenDrop = true
		}
	}
	require.True(t, seenDrop, "распознаватель снятий не увидел сноса %s в форме "+
		"`DROP TABLE IF EXISTS`: страж промолчит, накат уничтожит %d строк без отказа, "+
		"и оператор узнает о потере по последствиям.\nпрочитано файлов: %d, снятий: %+v",
		limitsTable, seeded, inv.FilesScanned, inv.Drops)

	rep := dropguard.Preflight(context.Background(),
		func(ctx context.Context, table string) (int64, error) {
			return dropguard.Observe(ctx, db, table)
		},
		inv,
		func(version int64) (bool, error) { return version != retirementVersion, nil },
		nil,
		dropguard.WholeChain())

	require.Len(t, rep.Violations, 1,
		"страж не отказал на сносе непустой %s: %+v", limitsTable, rep.Violations)
	msg := rep.Violations[0].Error()

	// 1. Отказ называет ТАБЛИЦУ — оператору нечего подставлять, если не названа.
	require.Contains(t, msg, limitsTable,
		"отказ не называет таблицы величин:\n%s", msg)

	// 2. Отказ называет КОМАНДУ выгрузки, а не совет её сделать. Команда берётся
	//    у производителя: два написания разошлись бы молча, и разошлось бы то,
	//    которое не исполняется.
	save := dropguard.PreserveCommand(limitsTable)
	require.Contains(t, msg, save,
		"отказ не называет команды выгрузки %q — из двух шагов оператору исполним "+
			"только уничтожение, и он выберет его:\n%s", save, msg)

	// 3. Сохранение названо ПРЕЖДЕ уничтожения: первый исполнимый шаг, попавшийся
	//    в отказе, и есть тот, который оператор сделает.
	i, j := strings.Index(msg, save), strings.Index(msg, dropguard.ApprovalEnv)
	require.GreaterOrEqual(t, j, 0, "отказ перестал называть осознанное уничтожение:\n%s", msg)
	require.Less(t, i, j, "уничтожение названо прежде сохранения:\n%s", msg)

	// 4. Отказ называет ЧИСЛО строк — оператор сверяет с ним `COPY <число>`.
	require.Contains(t, msg, fmt.Sprintf("%d", seeded),
		"отказ не называет числа строк (%d), и оператору не с чем сверить выгрузку:\n%s",
		seeded, msg)

	t.Logf("перепись: прочитано файлов цепи %d, снятий в наложенной цепи %d, "+
		"величин в таблице %d, нарушений %d; отказ называет команду выгрузки и число строк",
		inv.FilesScanned, len(inv.Drops), seeded, len(rep.Violations))
}

// TestLimitDropRefusal_EmptyTableIsNotRefused — положительный близнец. Без него
// утверждение выше зеленело бы на страже, отказывающем ВСЕГДА: тогда «отказ есть»
// не значило бы «отказ наступил из-за живых строк».
//
// Мир отличается от несущего РОВНО ОДНИМ фактом: таблица опустошена.
func TestLimitDropRefusal_EmptyTableIsNotRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}

	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer db.Close()

	_, err := db.Exec("DELETE FROM " + limitsTable)
	require.NoError(t, err, "опустошение таблицы величин — единственный различающий факт")
	require.Zero(t, countLimits(t, db), "таблица обязана быть пуста: иначе миры не различаются")

	inv, err := dropguard.Inventory("iam", chainWithPendingRetirement(t, limitsTable))
	require.NoError(t, err)

	rep := dropguard.Preflight(context.Background(),
		func(ctx context.Context, table string) (int64, error) {
			return dropguard.Observe(ctx, db, table)
		},
		inv,
		func(version int64) (bool, error) { return version != retirementVersion, nil },
		nil,
		dropguard.WholeChain())

	require.Empty(t, rep.Violations,
		"страж отказал на ПУСТОЙ таблице величин: тогда его отказ не свидетельствует "+
			"о живых строках, и несущая половина зеленела бы на страже, отвергающем всё:\n%+v",
		rep.Violations)

	t.Logf("перепись: величин в таблице 0, снятий в наложенной цепи %d, нарушений 0 — "+
		"сохранять нечего, отказа нет", len(inv.Drops))
}
