// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// catalog_referent_integration_test.go — у типа объекта регистрации есть
// РЕФЕРЕНТ: живая строка каталога ресурсов, а не приставка имени.
//
// ЧТО ЭТО ЛОВИТ. Правило приёма (`pkg/authz/proxytuple.ValidateTuple`) сверяет
// отношение с закрытым набором и связывает тип объекта с доменом вызывающего
// ПРИСТАВКОЙ. Приставка не отвечает на вопрос «а есть ли такой ресурс у
// платформы»: тип `vpc_totally_invented` приставку несёт и до этой правки
// доезжал до строки зеркала дословно. Модуль не мог присвоить себе чужое — но
// мог объявить НЕСУЩЕСТВУЮЩЕЕ СВОЁ, и дальше это росло строками в таблицах
// владельца прав.
//
// ПОЧЕМУ ЗДЕСЬ, А НЕ В ПРАВИЛЕ ПРИЁМА. Каталог — данные базы владельца прав;
// пяти потребителям, которые то же правило импортируют, он недоступен by
// construction. Значит сверка с ним живёт там, где лежат обе стороны — словарь
// и факт, — и выражена ОПЕРАТОРОМ в той же транзакции (запрет #10), а не
// чтением-и-действием.
//
// Пропускается под `go test -short`.
package resource_mirror_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/resource_mirror"
	"github.com/PRO-Robotech/kacho-iam/internal/testsupport/iampgtest"
)

// TestResourceMirror_UpsertTx_TypeOutsideCatalogIsRefused — ОБЕ стороны на одной
// оси, и положительный контроль обязателен: без него отрицание зеленело бы на
// реализации, отвергающей вообще всё.
//
//	живой тип каталога      (`vpc.network`)            → строка ложится
//	выдуманный тип          (`vpc_totally_invented`)   → отказ, тип НАЗВАН, строки нет
//	снятый тип каталога     (`compute.disk`)           → отказ: строка есть, но не живая
func TestResourceMirror_UpsertTx_TypeOutsideCatalogIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	// Закрытие С ПРЕДЕЛОМ, а не «когда-нибудь»: пробы этого файла падают через
	// `require` ВНУТРИ открытой транзакции, и такое соединение в пул не
	// возвращается уже никогда. Отложенное закрытие встало бы ждать писателя,
	// которого нет, пакет упёрся бы в предел прогона и напечатал `FAIL` — то
	// есть «не выполнилось» пришло бы к читателю под видом красного, и вердикта
	// не осталось бы НИ У ОДНОЙ пробы пакета, включая прошедшие.
	pgtest.ClosePoolAtEnd(t, pool)

	cases := []struct {
		name       string
		objectType string
		objectID   string
		accepted   bool
	}{
		{"живой тип каталога принимается", "vpc.network", "net-live", true},
		{"выдуманный тип со ЗАКОННОЙ приставкой отвергается", "vpc_totally_invented", "x1", false},
		{"снятый тип каталога отвергается", "compute.disk", "dsk-1", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tx, berr := pool.Begin(ctx)
			require.NoError(t, berr)
			t.Cleanup(func() { _ = tx.Rollback(ctx) })

			_, uerr := resource_mirror.UpsertTx(ctx, tx, resource_mirror.Row{
				ObjectType:      tc.objectType,
				ObjectID:        tc.objectID,
				ParentProjectID: "prj-P",
				ParentAccountID: "acc-A",
				SourceVersion:   time.Now().UTC(),
			})

			if tc.accepted {
				require.NoError(t, uerr, "живой тип каталога обязан приниматься")
				var n int
				require.NoError(t, tx.QueryRow(ctx,
					`SELECT count(*) FROM kacho_iam.resource_mirror
					  WHERE object_type = $1 AND object_id = $2`,
					tc.objectType, tc.objectID).Scan(&n))
				require.Equal(t, 1, n, "строка зеркала обязана лечь")
				return
			}

			require.Error(t, uerr, "тип без живой строки каталога обязан быть отвергнут")
			require.ErrorIs(t, uerr, iamerr.ErrUnknownResourceType,
				"отказ обязан нести СВОЙ признак: по общему признаку неверного аргумента "+
					"вызывающий не отличит эту полосу от грамматической")
			// Признак остаётся ЧАСТНЫМ случаем общего: пять мест дерева ветвятся на
			// общий, и завести полосу рядом значило бы молча увести отказ в «прочее».
			require.ErrorIs(t, uerr, iamerr.ErrInvalidArg,
				"частный признак обязан оставаться общим неверным аргументом")
			require.Contains(t, uerr.Error(), tc.objectType,
				"отказ обязан НАЗЫВАТЬ тип: без имени вызывающий не знает, что чинить")

			// Отказ не оставляет следа: транзакция ещё жива, и строки в ней нет.
			var n int
			require.NoError(t, tx.QueryRow(ctx,
				`SELECT count(*) FROM kacho_iam.resource_mirror
				  WHERE object_type = $1 AND object_id = $2`,
				tc.objectType, tc.objectID).Scan(&n))
			require.Equal(t, 0, n, "отвергнутая регистрация не вправе оставить строку зеркала")
		})
	}
}

// TestResourceMirror_RetiredTypeKeepsItsAlreadyRegisteredRows — снятие типа с
// платформы НЕ отбирает у арендатора уже зарегистрированный ресурс.
//
// Это обратная сторона решения «условие ПРИЁМА, а не ключ таблицы», и ради неё
// внешний ключ на `(dotted, live)` здесь отвергнут: он выражал бы ту же сверку,
// но сделал бы снятие типа невозможным, пока у арендатора есть хоть один
// ресурс этого типа, — то есть поставил бы административную операцию платформы
// в зависимость от чужих данных, а альтернативой был бы каскад, уносящий эти
// данные. Строка, легшая до снятия, обязана и лежать, и читаться.
func TestResourceMirror_RetiredTypeKeepsItsAlreadyRegisteredRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	// Закрытие С ПРЕДЕЛОМ, а не «когда-нибудь»: пробы этого файла падают через
	// `require` ВНУТРИ открытой транзакции, и такое соединение в пул не
	// возвращается уже никогда. Отложенное закрытие встало бы ждать писателя,
	// которого нет, пакет упёрся бы в предел прогона и напечатал `FAIL` — то
	// есть «не выполнилось» пришло бы к читателю под видом красного, и вердикта
	// не осталось бы НИ У ОДНОЙ пробы пакета, включая прошедшие.
	pgtest.ClosePoolAtEnd(t, pool)

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	// Откат — ОТЛОЖЕННЫМ вызовом, а не через t.Cleanup, и порядок здесь несущий:
	// отложенные исполняются ДО уборки теста, а закрытие пула стоит именно в
	// уборке. Значит соединение освобождается раньше, чем его начинают ждать.
	// Проба, которая не коммитит, обязана вернуть соединение сама — иначе предел
	// закрытия честно сработает и назовёт её виновной.
	defer func() { _ = tx.Rollback(ctx) }()

	// Контроль предпосылки: тип в каталоге ЕСТЬ и он НЕ живой. Без этой строки
	// проба ниже зеленела бы и на пустом каталоге.
	var live bool
	require.NoError(t, tx.QueryRow(ctx,
		`SELECT live FROM kacho_iam.catalog_resource WHERE dotted = 'compute.disk'`).Scan(&live))
	require.False(t, live, "предпосылка пробы: `compute.disk` снят строкой каталога")

	// Строка, легшая, пока тип был жив (регистрация прежних времён).
	_, err = tx.Exec(ctx,
		`INSERT INTO kacho_iam.resource_mirror (object_type, object_id, parent_project_id)
		 VALUES ('compute.disk', 'dsk-legacy', 'prj-P')`)
	require.NoError(t, err, "снятый тип не вправе становиться непредставимым в зеркале")

	var n int
	require.NoError(t, tx.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.resource_mirror
		  WHERE object_type = 'compute.disk' AND object_id = 'dsk-legacy'`).Scan(&n))
	require.Equal(t, 1, n, "уже зарегистрированный ресурс снятого типа обязан оставаться читаемым")
}

// TestResourceMirror_UpsertTx_VersionBumpAlsoNeedsALiveType — полоса «поднять
// только версию» не обходит условие приёма.
//
// Она стоит ПЕРВОЙ и на существующей строке срабатывает без вставки, поэтому
// без собственного условия дала бы обход: тип снят, а регистрация им проходит,
// потому что строка уже есть. Ноль затронутых строк здесь не молчит — вторая
// полоса того же вызова доводит дело до отказа.
func TestResourceMirror_UpsertTx_VersionBumpAlsoNeedsALiveType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	// Закрытие С ПРЕДЕЛОМ, а не «когда-нибудь»: пробы этого файла падают через
	// `require` ВНУТРИ открытой транзакции, и такое соединение в пул не
	// возвращается уже никогда. Отложенное закрытие встало бы ждать писателя,
	// которого нет, пакет упёрся бы в предел прогона и напечатал `FAIL` — то
	// есть «не выполнилось» пришло бы к читателю под видом красного, и вердикта
	// не осталось бы НИ У ОДНОЙ пробы пакета, включая прошедшие.
	pgtest.ClosePoolAtEnd(t, pool)

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	// Откат — ОТЛОЖЕННЫМ вызовом, а не через t.Cleanup, и порядок здесь несущий:
	// отложенные исполняются ДО уборки теста, а закрытие пула стоит именно в
	// уборке. Значит соединение освобождается раньше, чем его начинают ждать.
	// Проба, которая не коммитит, обязана вернуть соединение сама — иначе предел
	// закрытия честно сработает и назовёт её виновной.
	defer func() { _ = tx.Rollback(ctx) }()

	first := time.Now().UTC().Add(-time.Minute)
	_, err = tx.Exec(ctx,
		`INSERT INTO kacho_iam.resource_mirror
		   (object_type, object_id, parent_project_id, source_version)
		 VALUES ('compute.disk', 'dsk-bump', 'prj-P', $1)`, first)
	require.NoError(t, err)

	// Та же проекция, версия строго новее — ровно вход полосы «поднять версию».
	_, uerr := resource_mirror.UpsertTx(ctx, tx, resource_mirror.Row{
		ObjectType:      "compute.disk",
		ObjectID:        "dsk-bump",
		ParentProjectID: "prj-P",
		SourceVersion:   time.Now().UTC(),
	})
	require.ErrorIs(t, uerr, iamerr.ErrUnknownResourceType,
		"полоса поднятия версии обязана спрашивать каталог наравне со вставкой")

	// Контроль: отметка версии НЕ сдвинулась — отказ не применил половину работы.
	var stored time.Time
	require.NoError(t, tx.QueryRow(ctx,
		`SELECT source_version FROM kacho_iam.resource_mirror
		  WHERE object_type = 'compute.disk' AND object_id = 'dsk-bump'`).Scan(&stored))
	require.WithinDuration(t, first, stored, time.Second,
		"отвергнутая регистрация не вправе сдвинуть отметку версии")
}

// TestResourceMirror_DeleteTx_DoesNotAskTheCatalog — снятие ресурса, чей тип уже
// снят с платформы, проходит.
//
// Пара к условию приёма, и без неё решение было бы половинчатым: спроси снятие
// каталог — ресурс, зарегистрированный до снятия типа, стал бы НЕудаляемым, а
// его строка продолжала бы участвовать в подборе по признакам. Невыполнимое
// снятие означает право, которое не отзывается, — а это дороже, чем отказ на
// приёме.
func TestResourceMirror_DeleteTx_DoesNotAskTheCatalog(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	// Закрытие С ПРЕДЕЛОМ, а не «когда-нибудь»: пробы этого файла падают через
	// `require` ВНУТРИ открытой транзакции, и такое соединение в пул не
	// возвращается уже никогда. Отложенное закрытие встало бы ждать писателя,
	// которого нет, пакет упёрся бы в предел прогона и напечатал `FAIL` — то
	// есть «не выполнилось» пришло бы к читателю под видом красного, и вердикта
	// не осталось бы НИ У ОДНОЙ пробы пакета, включая прошедшие.
	pgtest.ClosePoolAtEnd(t, pool)

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	stamp := time.Now().UTC().Add(-time.Minute)
	_, err = tx.Exec(ctx,
		`INSERT INTO kacho_iam.resource_mirror
		   (object_type, object_id, parent_project_id, source_version)
		 VALUES ('compute.disk', 'dsk-withdraw', 'prj-P', $1)`, stamp)
	require.NoError(t, err)

	require.NoError(t, resource_mirror.DeleteTx(ctx, tx, "compute.disk", "dsk-withdraw", time.Now().UTC()),
		"снятие обязано работать и на типе, снятом с платформы")

	var n int
	require.NoError(t, tx.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.resource_mirror
		  WHERE object_type = 'compute.disk' AND object_id = 'dsk-withdraw'`).Scan(&n))
	require.Equal(t, 0, n, "строка обязана быть снята")
}
