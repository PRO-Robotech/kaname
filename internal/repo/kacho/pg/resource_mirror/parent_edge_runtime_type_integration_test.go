// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// parent_edge_runtime_type_integration_test.go — ЦЕПЬ ПРЕДКОВ ТИПА, ЗАВЕДЁННОГО
// ПРИМЕНЕНИЕМ МАНИФЕСТА В РАБОТАЮЩЕМ ПРОЦЕССЕ.
//
// # Предмет
//
// Строку зеркала такой тип получает: условие приёма спрашивает ЖИВУЮ строку
// каталога (`catalog_resource`), а её применение манифеста и заводит. Цепь
// предков той же регистрации переводилась словарём, ПОРОЖДЁННЫМ СБОРКОЙ
// (`authzmap.ModelTypeName`), и тот словарь тотален: незнакомое имя он
// возвращает КАК ЕСТЬ. Для типа, заведённого применением, «как есть» — это
// точечное имя каталога (`billing.invoice`), а колонка требует имени МОДЕЛИ
// (`billing_invoice`, проверка `object_type NOT LIKE '%.%'`).
//
// Исход — ОТКАЗ ВСЕЙ ТРАНЗАКЦИИ регистрации: ни строки зеркала, ни цепи. Отказ
// громкий, и это лучше тихого промаха материализатора (#1967), но означает он то
// же самое — объекта в зеркале нет, а без строки зеркала правило не отберёт его
// ни при каком материализаторе (kacho#1982).
//
// # Почему проб три, а не одна
//
// Первая — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ на живом соседе, которого сборка знает
// (`vpc.network`): без него «строки нет» неотличимо от «проход не пишет цепь
// вовсе», и отрицание зеленело бы на реализации, не делающей ничего.
// Вторая — сам предмет: тип, заведённый применением, доезжает до цепи именем
// модели, и под точечным именем не остаётся ничего.
// Третья — СНЯТИЕ: обе половины регистрации пишет одна транзакция, и снимать их
// обязана тоже одна. Перевод на снятии берётся тот же; назови его иначе —
// снятие не совпадёт ни с одним ребром и промолчит, то есть будет выглядеть
// исполненным.
//
// Пропускается под `go test -short`.
package resource_mirror_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/resource_mirror"
	"github.com/PRO-Robotech/kacho-iam/internal/testsupport/iampgtest"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

// TestParentEdges_RuntimeAppliedTypeIsWrittenInTheModelDictionary — тип,
// которого НЕТ в словаре сборки, но ЕСТЬ живой строкой каталога.
func TestParentEdges_RuntimeAppliedTypeIsWrittenInTheModelDictionary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	// ── ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ. Живой сосед, которого словарь сборки знает.
	// Без него утверждения ниже зеленели бы на проходе, не пишущем цепь вовсе.
	upsertCommitted(t, ctx, pool, resource_mirror.Row{
		ObjectType:      "vpc.network",
		ObjectID:        "net-control",
		ParentProjectID: "prj-P",
		ParentAccountID: "acc-A",
		SourceVersion:   time.Now().Truncate(time.Microsecond),
		ParentChain:     []string{"project:prj-P", "account:acc-A"},
	})
	require.Equal(t, 2, countEdges(t, ctx, pool, "vpc_network", "net-control"),
		"положительный контроль не сработал: цепь не пишется и на типе, который "+
			"словарь сборки знает, — значит утверждения о предмете ниже были бы "+
			"вакуумны")

	// ── ПРЕДМЕТ. Тип заводится ПРИМЕНЕНИЕМ — строкой каталога, а не пересборкой.
	applyRuntimeType(t, ctx, pool, "billing", "invoice", "billing_invoice")

	upsertCommitted(t, ctx, pool, resource_mirror.Row{
		ObjectType:      "billing.invoice", // словарь КАТАЛОГА — как зовёт регистрация
		ObjectID:        "inv-runtime",
		ParentProjectID: "prj-P",
		ParentAccountID: "acc-A",
		SourceVersion:   time.Now().Truncate(time.Microsecond),
		ParentChain:     []string{"project:prj-P", "account:acc-A"},
	})

	require.Equal(t, 2, countEdges(t, ctx, pool, "billing_invoice", "inv-runtime"),
		"цепь типа, заведённого применением манифеста, не записана именем модели: "+
			"вопрос о доступе приходит этим словарём, и соединение по другому "+
			"написанию не совпадёт ни на одном шаге")

	// Отрицание рядом: под точечным именем не осталось НИЧЕГО. Без него
	// «перевёл» было бы неотличимо от «записал обоими именами».
	var underCatalog int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.resource_parent_edge
		  WHERE object_type = 'billing.invoice'`).Scan(&underCatalog))
	require.Zero(t, underCatalog, "ребро осталось под точечным именем словаря каталога")

	// Строка зеркала свой словарь сохраняет: перевод стоит на стыке.
	var mirrored int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.resource_mirror
		  WHERE object_type = 'billing.invoice' AND object_id = 'inv-runtime'`).Scan(&mirrored))
	require.Equal(t, 1, mirrored, "строки зеркала нет — регистрация не доехала вовсе")
}

// TestParentEdges_RuntimeAppliedTypeUnregisterClearsTheChain — снятие называет
// цепь ТЕМ ЖЕ словарём, каким её писала регистрация.
//
// Без этой пробы промах снятия выглядел бы исполненным: `DELETE`, не совпавший
// ни с одним ребром, отдаёт ноль строк и ошибкой не является. Право пережило бы
// свой предмет — тот же класс, ради которого снятие цепи вообще заведено.
func TestParentEdges_RuntimeAppliedTypeUnregisterClearsTheChain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	applyRuntimeType(t, ctx, pool, "billing", "invoice", "billing_invoice")

	version := time.Now().Truncate(time.Microsecond)
	upsertCommitted(t, ctx, pool, resource_mirror.Row{
		ObjectType:      "billing.invoice",
		ObjectID:        "inv-gone",
		ParentProjectID: "prj-P",
		ParentAccountID: "acc-A",
		SourceVersion:   version,
		ParentChain:     []string{"project:prj-P", "account:acc-A"},
	})
	require.Equal(t, 2, countEdges(t, ctx, pool, "billing_invoice", "inv-gone"),
		"предпосылка пробы не создана: цепи, которую надо снять, нет")

	deleteCommitted(t, ctx, pool, "billing.invoice", "inv-gone", version.Add(time.Second))

	require.Zero(t, countEdges(t, ctx, pool, "billing_invoice", "inv-gone"),
		"цепь пережила снятие: снятие назвало её не тем словарём, каким писала "+
			"регистрация, и потому не совпало ни с одним ребром — ноль затронутых "+
			"строк ошибкой не является, и промах выглядит исполненным")
}

// ── helpers ──────────────────────────────────────────────────────────────────

// applyRuntimeType заводит тип ТАК, КАК ЕГО ЗАВОДИТ ПРИМЕНЕНИЕ МАНИФЕСТА, —
// живыми строками каталога, без пересборки. Словарь сборки о нём не знает и
// знать не может: он порождён из манифестов дерева на момент компиляции.
func applyRuntimeType(t *testing.T, ctx context.Context, pool *pgxpool.Pool, module, resource, objectType string) {
	t.Helper()
	_, err := pool.Exec(ctx,
		`INSERT INTO kacho_iam.catalog_module (module) VALUES ($1)
		 ON CONFLICT (module) DO NOTHING`, module)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		`INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, object_type)
		 VALUES ($1, $2, $1 || '.' || $2, $3)`, module, resource, objectType)
	require.NoError(t, err)
}

func countEdges(t *testing.T, ctx context.Context, pool *pgxpool.Pool, objectType, objectID string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.resource_parent_edge
		  WHERE object_type = $1 AND object_id = $2`, objectType, objectID).Scan(&n))
	return n
}
