// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// build_type_dictionary_agrees_with_catalog_integration_test.go — СЛОВАРЬ
// СБОРКИ и ПОСЕЯННЫЙ КАТАЛОГ говорят об одном типе одно и то же (задача
// продукта #1995).
//
// # Предмет
//
// Переводов «имя каталога → имя модели прав» в дереве ДВА, и это решение, а не
// дрейф. Производитель зеркала (`resource_mirror`) спрашивает ЖИВУЮ строку
// каталога в той же транзакции, что и пишет (#1982). Посевщик прибора порядков
// (`scalegrid/dictionary.go`) знать имя обязан ДО отправки пачки, на каждом из
// миллиона объектов, и потому переводит ТАБЛИЦЕЙ СБОРКИ
// (`authzmap.ModelTypeName`).
//
// Пока эти двое согласны на популяции, которую посевщик способен посеять, числа
// прибора описывают ту популяцию, которую он называет. Разойдутся — числа станут
// недействительными МОЛЧА: посев пройдёт, отчёт напечатается, и неверным будет
// только то, о ЧЁМ он.
//
// # Почему прогон против ЖИВОЙ базы, а не разбор миграции
//
// Утверждается ИСХОД накатанной цепи: строку каталога переопределяет любая
// поздняя миграция, и текст одного файла об этом не знает. Разбор SQL здесь не
// участвует ни одной строкой — он распознаватель, и молча пропустил бы форму
// записи, которой не знает (`testing.md` §«Гейт на класс», п. 7).
//
// # Что этот гейт НЕ сторожит — сказано вслух
//
// Тип, заведённый ПРИМЕНЕНИЕМ МАНИФЕСТА в работающем процессе, в посеянном
// каталоге не лежит, и здесь его нет. Его случай держит НЕ этот гейт, а СХЕМА:
// таблице сборки он неизвестен, `ModelTypeName` возвращает его как есть — с
// точкой, — а обе колонки ребра несут `CHECK (… !~~ '%.%')`. Вторая половина
// пробы это и утверждает: посев такого типа ОТКАЗЫВАЕТ, а не меряет другую
// популяцию тихо.
package migrations_test

import (
	"database/sql"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
)

// edgeObjectTypeDictionaryConstraint — ограничение, которым держится граница.
const edgeObjectTypeDictionaryConstraint = "resource_parent_edge_object_type_model_dictionary"

// TestIntegration_BuildTypeDictionaryAgreesWithTheSeededCatalog — согласие двух
// переводов на ЖИВЫХ строках посеянного каталога.
//
// Перепись печатается ВСЕГДА и до всякого вердикта: без неё «ноль расхождений»
// неотличимо от «ноль прочитанного».
func TestIntegration_BuildTypeDictionaryAgreesWithTheSeededCatalog(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)

	rows, err := db.Query(`
		SELECT dotted, object_type, live
		  FROM kaname.catalog_resource
		 ORDER BY dotted`)
	require.NoError(t, err, "чтение посеянного каталога ресурсов")
	defer func() { _ = rows.Close() }()

	type entry struct {
		dotted     string
		objectType string
		live       bool
	}
	var catalog []entry
	for rows.Next() {
		var e entry
		require.NoError(t, rows.Scan(&e.dotted, &e.objectType, &e.live))
		catalog = append(catalog, e)
	}
	require.NoError(t, rows.Err())

	var total, live, agree int
	var retiredDivergent []string
	for _, e := range catalog {
		total++
		got := authzmap.ModelTypeName(e.dotted)
		if !e.live {
			if got != e.objectType {
				retiredDivergent = append(retiredDivergent, e.dotted)
			}
			continue
		}
		live++
		if got == e.objectType {
			agree++
			continue
		}
		t.Errorf("РАСХОЖДЕНИЕ на ЖИВОЙ строке каталога: %q — каталог говорит %q, "+
			"таблица сборки %q.\n"+
			"  Посевщик прибора порядков (scalegrid/dictionary.go) переводит таблицей "+
			"сборки и на этом типе напишет в ребро НЕ ТО имя, каким его называет "+
			"производитель зеркала. Числа прибора станут описывать другую популяцию, "+
			"и по отчёту это неразличимо.\n"+
			"  Чинить: привести таблицу сборки к строке каталога — либо, если тип "+
			"снят, пометить строку `live = false`, и посевщик до него не дойдёт.",
			e.dotted, e.objectType, got)
	}

	// ПРЕДПОСЫЛКА — своим утверждением: на пустой популяции согласие тривиально.
	require.NotZerof(t, total,
		"в посеянном каталоге НОЛЬ строк: сверять нечего, и молчание этой пробы "+
			"означало бы согласие, которого никто не проверял")
	require.NotZerof(t, live,
		"живых строк каталога НОЛЬ при %d прочитанных: посевщик не смог бы посеять "+
			"ни одного объекта, и согласие двух словарей здесь вакуумно", total)

	t.Logf("перепись: строк каталога %d · живых %d · совпало на живых %d · "+
		"разошлось на СНЯТЫХ %d %v",
		total, live, agree, len(retiredDivergent), retiredDivergent)
	t.Logf("расхождение на снятой строке находкой НЕ является: вставка зеркала " +
		"обусловлена живой строкой каталога (scalegrid/seed.go, CTE live_type), " +
		"поэтому до снятых типов посевщик не доходит by construction")
}

// TestIntegration_UnknownDottedTypeIsRefusedByTheSchemaNotMeasuredQuietly —
// вторая половина границы: чего гейт выше не сторожит, то держит СХЕМА.
//
// Утверждение проверяется в ОБЕ стороны, и мир отрицательного случая отличается
// от положительного близнеца РОВНО ОДНИМ фактом — точкой в имени типа.
func TestIntegration_UnknownDottedTypeIsRefusedByTheSchemaNotMeasuredQuietly(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}

	// Имя, которого в таблице сборки нет: так выглядит тип, заведённый
	// применением манифеста в работающем процессе.
	const runtimeDotted = "probe1995.thing"

	t.Run("словарь сборки возвращает незнакомое имя КАК ЕСТЬ — с точкой", func(t *testing.T) {
		require.Equal(t, runtimeDotted, authzmap.ModelTypeName(runtimeDotted),
			"незнакомое имя обязано вернуться неизменным: именно точка в нём и "+
				"делает отказ схемы неизбежным")
	})

	insertEdge := func(t *testing.T, db *sql.DB, objectType string) error {
		t.Helper()
		_, err := db.Exec(`
			INSERT INTO kaname.resource_parent_edge
			       (object_type, object_id, parent_type, parent_id, depth)
			VALUES ($1, 'obj-1995', 'project', 'prj-1995', 1)`, objectType)
		return err
	}

	t.Run("тип С ТОЧКОЙ отвергается ограничением по имени", func(t *testing.T) {
		db := freshIamSchema(t)

		err := insertEdge(t, db, runtimeDotted)
		require.Error(t, err,
			"посев типа, неизвестного таблице сборки, обязан ОТКАЗАТЬ: иначе прибор "+
				"тихо померил бы популяцию, которой не называл")
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr, "ожидалась ошибка Postgres, а не %T", err)
		require.Equal(t, "23514", pgErr.Code, "отказ обязан прийти от CHECK")
		require.Equal(t, edgeObjectTypeDictionaryConstraint, pgErr.ConstraintName,
			"отказ обязан прийти от ИМЕНОВАННОГО ограничения словаря, а не от соседа: "+
				"иначе красное доказывает не то, ради чего проба заведена")
	})

	t.Run("ЗАКОННЫЙ БЛИЗНЕЦ: то же ребро без точки — проходит", func(t *testing.T) {
		db := freshIamSchema(t)

		require.NoError(t, insertEdge(t, db, "probe1995_thing"),
			"имя словаря модели обязано проходить: без этой половины отрицание выше "+
				"зеленело бы на схеме, отвергающей вообще всё")
	})
}
