// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// limit_drop_refusal_integration_test.go — накат ОТКАЗЫВАЕТ на снятии таблицы
// величин и называет оператору процедуру выгрузки (задача #2134, условие 2
// предиката; приёмка KAN-QUOTA-1 §9 `ПР-3`, сценарий `KAN-Q4-07`).
//
// # ПРЕДМЕТ ПРОБЫ ОСТАЛСЯ, А ЕЁ МИР ПЕРЕСТАЛ БЫТЬ СИНТЕТИЧЕСКИМ (kaname#58)
//
// Прежняя редакция накладывала на цепь службы ОДНУ выдуманную миграцию сноса:
// стадия S4 не была начата, настоящего сноса в дереве не существовало, и проба
// честно говорила «когда S4 напишет снос ЭТОЙ формой, оператор получит отказ».
//
// Стадия наступила. Снос лежит в цепи (`20260914000000`), и вместе с ним исчезла
// предпосылка прежнего мира — таблица не доживает до головы. Проба поэтому НЕ
// ослаблена и не снята: она переведена на НАСТОЯЩИЙ снос и настоящую цепь, а
// база доводится до версии НЕПОСРЕДСТВЕННО ПЕРЕД ним. Это ровно то состояние, в
// котором оператор встречает отказ, — и утверждение стало сильнее прежнего:
// оно больше не зависит от того, угадала ли проба форму, которой снос напишут.
//
// # ЧТО ЗДЕСЬ УТВЕРЖДАЕТСЯ И ПОЧЕМУ ЭТО НЕ ПОВТОР СОСЕДЕЙ
//
//   - `pkg/dropguard` доказывает форму отказа на СИНТЕТИЧЕСКОЙ цепи («widgets»):
//     сохранение названо, названо прежде уничтожения. О таблице величин и о цепи
//     службы доступа она не утверждает ничего;
//   - гейт `internal/check` сверяет текст инструкции с производителем ПОБАЙТОВО,
//     но судит текст, а не поведение наката;
//   - `limit_export_before_retirement_integration_test.go` доказывает, что
//     документированный запрос ОТРАБАТЫВАЕТ против живой схемы. Он не спрашивает,
//     наступит ли отказ, который направит к этому запросу;
//   - `dropguard_integration_test.go` доказывает, что снос ОБЪЯВЛЕН и число строк
//     сошлось с базой. Он не спрашивает, что происходит, когда объявления НЕТ, —
//     а именно это состояние и встречает оператор, накатывающий чужой выпуск.
//
// Незакрытым без этой пробы остаётся то, что дороже всех четырёх: сработает ли
// страж на самой `kaname.limits`. Ответ «by construction» был бы выводом, а не
// замером: распознаватель, не знающий формы сноса, даёт не красное и не зелёное,
// а МОЛЧАНИЕ (`testing.md` §«Гейт на класс», п. 7). Молчание здесь означает, что
// накат снесёт таблицу без отказа, а оператор узнает о потере по последствиям.
package migrations_test

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/dropguard"
	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// limitRetirementVersion — версия НАСТОЯЩЕГО сноса хранилища величин.
//
// Число, а не поиск по дереву: проба обязана сломаться, если снос переедет в
// другую версию, — тогда мир «непосредственно перед ним» строится не там, и
// вердикт относился бы к другому состоянию схемы.
const limitRetirementVersion int64 = 20260914000000

// upToJustBeforeLimitRetirement — цепь службы, доведённая до версии
// НЕПОСРЕДСТВЕННО ПЕРЕД снятием хранилища величин.
//
// Это состояние оператора, а не лаборатория: он стоит на предыдущем выпуске, у
// него есть таблица со строками, и накат следующего выпуска обязан ему отказать.
func upToJustBeforeLimitRetirement(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.UpTo(db, ".", limitRetirementVersion-1),
		"цепь обязана доходить до версии перед снятием: иначе мир пробы — не тот, "+
			"в котором оператор встречает отказ")

	// Предпосылка называется ЯВНО: без таблицы всё ниже говорило бы о пустоте.
	var exists bool
	require.NoError(t, db.QueryRow(
		`SELECT to_regclass('kaname.limits') IS NOT NULL`).Scan(&exists))
	require.True(t, exists, "на версии перед снятием таблицы величин нет — значит "+
		"остановка пришлась не туда, и отказ ниже свидетельствовал бы не о ней")
	return db
}

// pendingRetirement — снос ещё НЕ применён, всё прочее применено.
func pendingRetirement(version int64) (bool, error) { return version != limitRetirementVersion, nil }

// TestLimitDropRefusal_NamesTheExportProcedureBeforeDestruction — несущая половина.
func TestLimitDropRefusal_NamesTheExportProcedureBeforeDestruction(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}

	db := upToJustBeforeLimitRetirement(t, pgtest.NewEmptyDB(t))
	defer db.Close()

	// Таблица непуста БЕЗ помощи пробы: цепь сеет умолчания сама. Это и есть
	// довод задачи — отказ наступит у каждой установки, а не у подготовленной.
	seeded := countLimits(t, db)
	require.Positive(t, seeded, "цепь не посеяла ни одной величины: стражу нечего было бы "+
		"считать, и отказ ниже зеленел бы на пустоте")

	inv, err := dropguard.Inventory("iam", migrations.FS)
	require.NoError(t, err)

	// Распознаватель обязан УВИДЕТЬ снос в цепи. Проверяется отдельным
	// утверждением: не увидев его, страж промолчит, и «нарушений ноль» ниже было
	// бы неотличимо от «прочитано ноль».
	var seenDrop bool
	for _, d := range inv.Drops {
		if strings.EqualFold(d.Table, limitsTable) && d.Version == limitRetirementVersion {
			seenDrop = true
		}
	}
	require.True(t, seenDrop, "распознаватель снятий не увидел сноса %s версии %d: "+
		"страж промолчит, накат уничтожит %d строк без отказа, и оператор узнает о "+
		"потере по последствиям.\nпрочитано файлов: %d, снятий: %+v",
		limitsTable, limitRetirementVersion, seeded, inv.FilesScanned, inv.Drops)

	// Одобрений НЕТ — это состояние оператора, накатывающего чужой выпуск: у него
	// объявление автора не спрашивают, у него спрашивают его собственное согласие.
	rep := dropguard.Preflight(context.Background(),
		func(ctx context.Context, table string) (int64, error) {
			return dropguard.Observe(ctx, db, table)
		},
		inv, pendingRetirement, nil, dropguard.WholeChain())

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

	t.Logf("перепись: прочитано файлов цепи %d, снятий в цепи %d, величин в таблице %d, "+
		"нарушений %d; отказ называет команду выгрузки и число строк",
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

	db := upToJustBeforeLimitRetirement(t, pgtest.NewEmptyDB(t))
	defer db.Close()

	_, err := db.Exec("DELETE FROM " + limitsTable)
	require.NoError(t, err, "опустошение таблицы величин — единственный различающий факт")
	require.Zero(t, countLimits(t, db), "таблица обязана быть пуста: иначе миры не различаются")

	inv, err := dropguard.Inventory("iam", migrations.FS)
	require.NoError(t, err)

	rep := dropguard.Preflight(context.Background(),
		func(ctx context.Context, table string) (int64, error) {
			return dropguard.Observe(ctx, db, table)
		},
		inv, pendingRetirement, nil, dropguard.WholeChain())

	require.Empty(t, rep.Violations,
		"страж отказал на ПУСТОЙ таблице величин: тогда его отказ не свидетельствует "+
			"о живых строках, и несущая половина зеленела бы на страже, отвергающем всё:\n%+v",
		rep.Violations)

	t.Logf("перепись: величин в таблице 0, снятий в цепи %d, нарушений 0 — "+
		"сохранять нечего, отказа нет", len(inv.Drops))
}
