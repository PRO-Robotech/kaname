// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// divergence_integration_test.go — РАЗНОСТЬ ЗЕРКАЛА И КАТАЛОГА ЧИТАЕТСЯ, И У
// НЕРАЗРЕШИМОЙ ЕЁ ЧАСТИ ЕСТЬ ДЕРЖАТЕЛЬ.
//
// # Предмет (kacho#1828)
//
// Сужение записи действует ВПЕРЁД: у того, что записано до него, производителя
// отзыва нет. Величина этой разности не была измерена ни разу — не «оказалась
// нулём», а не спрашивалась ни одной функцией дерева.
//
// # ЧТО РОНЯЕТ ПРОГОН, А ЧТО ПЕЧАТАЕТСЯ — И ГРАНИЦА НАЗВАНА ЧЕСТНО
//
// Роняет НЕРАЗРЕШИМАЯ часть: тип, которого каталог не знает вовсе, и тип,
// снятый без преемника. С ними нельзя сделать НИЧЕГО — переселять некуда,
// назвать нечем, а отозвать значит отнять доступ.
//
// НЕ роняет снятое С ПРЕЕМНИКОМ, и это не послабление. Переживание снятия —
// объявленное свойство дерева, закреплённое пробой
// `TestResourceMirror_RetiredTypeKeepsItsAlreadyRegisteredRows` в этом же
// пакете. Гейт, роняющий прогон на нём, краснел бы на исправном состоянии сразу
// после всякого законного снятия типа — и его выключили бы первым. Эта половина
// ПЕЧАТАЕТСЯ переписью: решение о ней (переселить либо отозвать) ОТНИМАЕТ
// доступ и принадлежит владельцу, а не проверке.
//
// # Почему на СВЕЖЕЙ схеме это не вакуумный зелёный
//
// На свежей схеме зеркало пусто, и любое отрицание о нём зеленело бы ни о чём.
// Поэтому утверждения строятся на ПОСТРОЕННОМ состоянии: проба сама заводит
// строку каждого из четырёх видов и требует, чтобы читатель различил их все, а
// вторая — что состояние, снятое ПОСЕВОМ ПРОДУКТА, читается тем же читателем и
// называет преемника, которого несёт настоящий каталог.
//
// # ЧЕГО ЭТОТ ПРОГОН НЕ ПОКРЫВАЕТ — сказано прямо
//
// Зеркало свежей схемы пусто BY CONSTRUCTION, поэтому зелёный третьей пробы
// («неразрешимой разности нет») — утверждение о ХАРНЕССЕ, а не о поднятом
// стенде. Величину, ради которой заведён kacho#1828, даёт только база с данными
// арендатора: там разность может быть непустой, и решение по каждой её строке
// принимает владелец, потому что отзыв ОТНИМАЕТ доступ.
//
// Что здесь закрыто целиком — ЧИТАТЕЛЬ: до этого файла разность не спрашивала
// ни одна функция дерева, и «ноль» было неотличимо от «не мерили».
package resource_mirror_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/resource_mirror"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

// TestIntegration_DivergenceTellsTheFourStatesApart — читатель разности
// различает все четыре ответа каталога.
//
// Это доказательство СПОСОБНОСТИ гейта ниже упасть: мир строится подачей входа,
// и каждый вид отличается от соседа РОВНО ОДНИМ фактом — ответом каталога на
// его тип.
func TestIntegration_DivergenceTellsTheFourStatesApart(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	ctx := context.Background()
	pool := freshMirrorPool(t)

	// Каталог: живой тип, снятый с преемником, снятый БЕЗ преемника.
	// Четвёртый вид строки каталога не имеет вовсе — в этом он и состоит.
	mustExec(t, pool, `
		INSERT INTO kaname.catalog_module (module, live) VALUES ('probe', true)
		ON CONFLICT DO NOTHING`)
	mustExec(t, pool, `
		INSERT INTO kaname.catalog_resource
		       (module, resource, dotted, retired_at, retired_reason, superseded_by, live, object_type)
		VALUES ('probe', 'live',      'probe.live',      NULL,  NULL,      NULL,           true,  'probe_live'),
		       ('probe', 'succeeded', 'probe.succeeded', now(), 'снят',    'probe.live',   false, 'probe_succeeded'),
		       ('probe', 'orphan',    'probe.orphan',    now(), 'снят',    NULL,           false, 'probe_orphan')`)

	// Зеркало: по строке на каждый из четырёх видов. Пишем НАПРЯМУЮ — предмет
	// пробы ровно в том, что такие строки существуют помимо пути приёма (он их
	// сегодня отвергает, и в этом весь класс: сузили ВПЕРЁД).
	mustExec(t, pool, `
		INSERT INTO kaname.resource_mirror (object_type, object_id)
		VALUES ('probe.live', 'o-1'),
		       ('probe.succeeded', 'o-2'),
		       ('probe.orphan', 'o-3'),
		       ('probe.unknown', 'o-4')`)

	rows, scanned, err := resource_mirror.Divergence(ctx, pool)
	require.NoError(t, err)
	require.Equalf(t, 4, scanned, "перепись обязана назвать ОСМОТРЕННОЕ: на пустом "+
		"зеркале любое утверждение о разности зеленеет ни о чём")

	byType := map[string]resource_mirror.DivergenceRow{}
	for _, r := range rows {
		byType[r.ObjectType] = r
	}

	require.NotContainsf(t, byType, "probe.live",
		"живой тип в разность не входит: включив его, читатель утопил бы предмет в норме")
	require.Len(t, rows, 3, "разность — ровно три оставшихся вида")

	require.Equal(t, resource_mirror.CatalogRetiredSucceeded, byType["probe.succeeded"].State)
	require.Equalf(t, "probe.live", byType["probe.succeeded"].SupersededBy,
		"преемник обязан быть НАЗВАН: без него строку некуда переселять, и состояние "+
			"сливается с сиротским")
	require.Equal(t, resource_mirror.CatalogRetiredOrphan, byType["probe.orphan"].State)
	require.Equal(t, resource_mirror.CatalogAbsent, byType["probe.unknown"].State)
	require.Equal(t, int64(1), byType["probe.unknown"].Rows)

	unresolvable := resource_mirror.UnresolvableDivergence(rows)
	require.Lenf(t, unresolvable, 2, "неразрешимых видов два — снятый без преемника и "+
		"неизвестный каталогу; снятое С ПРЕЕМНИКОМ сюда не входит, у него исход назван")
}

// TestIntegration_NoUnresolvableDivergenceInTheAppliedSchema — вердикт о
// состоянии, которое строит САМ ПРОДУКТ.
//
// Отдельно от пробы выше, и это несущее: та доказывает, что читатель РАЗЛИЧАЕТ
// виды, эта — что на схеме, накатанной штатно, неразрешимой разности НЕТ. Первая
// без второй ничего не утверждает о продукте, вторая без первой зеленела бы на
// сломанном читателе.
func TestIntegration_NoUnresolvableDivergenceInTheAppliedSchema(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	ctx := context.Background()
	pool := freshMirrorPool(t)

	catalogLive := scalarInt(t, pool,
		`SELECT count(*) FROM kaname.catalog_resource WHERE live`)
	catalogRetired := scalarInt(t, pool,
		`SELECT count(*) FROM kaname.catalog_resource WHERE NOT live`)
	require.NotZerof(t, catalogLive, "живых строк каталога ноль — схема не накатилась "+
		"либо посев не отработал; на пустом каталоге КАЖДЫЙ тип зеркала стал бы находкой, "+
		"и гейт назвал бы дефектом собственную поломку")

	rows, scanned, err := resource_mirror.Divergence(ctx, pool)
	require.NoError(t, err)

	unresolvable := resource_mirror.UnresolvableDivergence(rows)
	succeeded := len(rows) - len(unresolvable)

	t.Logf("перепись: типов в зеркале %d · строк каталога живых %d · снятых %d · "+
		"разность %d (снятых с преемником %d · неразрешимых %d)",
		scanned, catalogLive, catalogRetired, len(rows), succeeded, len(unresolvable))

	for _, r := range rows {
		if r.State == resource_mirror.CatalogRetiredSucceeded {
			// ПЕЧАТАЕТСЯ, а не роняет: исход назван каталогом, но выбор между
			// переселением и отзывом ОТНИМАЕТ доступ и принадлежит владельцу.
			t.Logf("РЕШЕНИЕ ВЛАДЕЛЬЦА: тип %q снят, строк зеркала %d, живой преемник %q — "+
				"переселить либо отозвать (kacho#1828)", r.ObjectType, r.Rows, r.SupersededBy)
		}
	}

	for _, r := range unresolvable {
		t.Errorf("строки зеркала на типе %q (%d шт.) разрешить НЕЧЕМ: каталог отвечает "+
			"«%s», живого преемника не назвал никто. Право на таких объектах живёт в "+
			"реляционной форме и переживает и снятие типа, и сужение записи — ключ судит "+
			"строку зеркала, а не кортеж",
			r.ObjectType, r.Rows, r.State)
	}
}

// TestIntegration_DivergenceNamesTheSuccessorTheSeededCatalogCarries — читатель
// работает на состоянии, которое строит ПОСЕВ ПРОДУКТА, а не только на
// синтетике соседней пробы.
//
// Без этой пробы обе стороны мира были бы моими: я объявил бы снятый тип, я же
// назвал бы ему преемника, и совпадение доказывало бы согласие фикстуры с самой
// собой. Здесь снятый тип и его преемник приходят из посева, и читатель обязан
// назвать ИМЕННО ИХ.
func TestIntegration_DivergenceNamesTheSuccessorTheSeededCatalogCarries(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	ctx := context.Background()
	pool := freshMirrorPool(t)

	// Предпосылка: посев несёт снятый тип С ПРЕЕМНИКОМ. Без этой строки проба
	// зеленела бы на каталоге, где снятых типов нет вовсе.
	var seededSuccessor string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT coalesce(superseded_by, '') FROM kaname.catalog_resource
		  WHERE dotted = 'compute.disk' AND NOT live`).Scan(&seededSuccessor))
	require.NotEmptyf(t, seededSuccessor, "предпосылка: посев называет преемника снятого "+
		"типа; без неё ветвь «снят с преемником» проверять не на чем")

	// Строка, легшая, пока тип был жив, — регистрация прежних времён. Путь
	// приёма её сегодня отвергает, и в этом весь класс: сузили ВПЕРЁД.
	mustExec(t, pool, `
		INSERT INTO kaname.resource_mirror (object_type, object_id, parent_project_id)
		VALUES ('compute.disk', 'dsk-legacy', 'prj-P')`)

	rows, scanned, err := resource_mirror.Divergence(ctx, pool)
	require.NoError(t, err)
	require.Equal(t, 1, scanned)
	require.Len(t, rows, 1)
	require.Equal(t, resource_mirror.CatalogRetiredSucceeded, rows[0].State)
	require.Equalf(t, seededSuccessor, rows[0].SupersededBy,
		"преемник обязан приехать ИЗ КАТАЛОГА, а не из фикстуры")
	require.Emptyf(t, resource_mirror.UnresolvableDivergence(rows),
		"снятое С ПРЕЕМНИКОМ неразрешимым не является: исход назван строкой каталога, "+
			"и роняя прогон здесь, гейт краснел бы после всякого законного снятия типа")
}

// freshMirrorPool — своя база на общем контейнере пакета.
//
// Закрытие С ПРЕДЕЛОМ по той же причине, что у соседних проб файла-собрата:
// падение через `require` внутри открытой транзакции не возвращает соединение в
// пул никогда, и отложенное закрытие встало бы ждать писателя, которого нет.
func freshMirrorPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := coredb.NewPool(context.Background(), iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	return pool
}

// mustExec — построение мира пробы. Отказ здесь «не выполнилось», а не находка:
// на непостроенном мире утверждения ниже зеленели бы ни о чём.
func mustExec(t *testing.T, pool *pgxpool.Pool, stmt string) {
	t.Helper()
	_, err := pool.Exec(context.Background(), stmt)
	require.NoErrorf(t, err, "мир пробы не построен — вердикта о продукте нет")
}

// scalarInt — одно число из базы.
func scalarInt(t *testing.T, pool *pgxpool.Pool, stmt string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(), stmt).Scan(&n))
	return n
}
