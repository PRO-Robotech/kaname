// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// catalog_snapshot_cost_integration_test.go — ЗАМЕР, условие посадки §8 п. 1
// приёмки `catalog-readers-move-to-the-table.md` (задача продукта #1838).
//
// # Что здесь меряется и почему именно это
//
// §2.4 приёмки принял снимок в памяти ДОВОДОМ, а не числом, и сам назвал признак
// своего отвержения: «замер покажет, что обновление снимка стоит дороже, чем
// запрос». Довод без числа — это решение, которое нечем опровергнуть; здесь оно
// получает величину.
//
// Строк ДВЕ, и они сняты на ОДНОЙ посадке и на ПРОГРЕТОМ состоянии
// (`testing.md` §«Замер под нагрузкой», пп. 1–2): холодный старт мерил бы
// заполнение кешей и установление соединения, а не предмет.
//
//	строка 1 — СНИМОК:          обновление (то же чтение, каким читает страж)
//	                            плюс обращение к уже прочитанному факту
//	строка 2 — ПО ТРЕБОВАНИЮ:   то же чтение, но НА КАЖДОМ обращении горячего пути
//
// # Что утверждается, а что только печатается
//
// Утверждение здесь ОДНО и с огромным запасом: обращение к снимку дешевле
// обращения к базе не менее чем в сто раз. Это разница сред (память против
// сетевого обхода), а не тонкая настройка, поэтому порог не флейкует; выбери мы
// порог «на глаз возле измеренного» — проба краснела бы на занятой машине и её
// отключили бы первой.
//
// Абсолютные величины ПЕЧАТАЮТСЯ, но не утверждаются: они свойство машины, а не
// продукта, и вписывать их в предикат значило бы мерить ранер.
//
// # Чего замер НЕ говорит
//
// Он не говорит, сколько обращений к каталогу приходится на запрос арендатора, —
// это свойство нагрузки, а не кода. Он даёт цену ОДНОГО обращения каждым путём и
// цену одного круга обновления; частное из них — арифметика, а не догадка.

import (
	"context"
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho-iam/internal/catalog"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
)

// catalogSnapshotDeclaredPeriod — объявленное окно отставания снимка.
//
// Величина ДУБЛИРУЕТСЯ здесь намеренно и об этом сказано вслух: умолчание ручки
// живёт в композиционном корне (`cmd/kacho-iam`), а корень пробе репозитория не
// виден — пакет чужой и импортировать его отсюда нельзя. Расхождение поймает не
// компилятор, а читатель отчёта: величина названа в отчёте рядом с именем ручки
// `KACHO_IAM_CATALOG_SNAPSHOT_REFRESH_INTERVAL_MS`, и сверить их — одна команда.
const catalogSnapshotDeclaredPeriod = 15 * time.Second

// TestIAMCT2_SnapshotCostAgainstOnDemand — замер §8 п. 1.
func TestIAMCT2_SnapshotCostAgainstOnDemand(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	pool, _, ctx := countedCatalogPool(t)
	repo := kachopg.NewCatalogRepo(pool)

	// Посадка ОДНА на обе строки: один контейнер, один пул, один прогон.
	census, err := seed.AssertCatalogParity(ctx, repo, seed.ImageAnchor())
	if err != nil {
		t.Fatalf("страж паритета: %v", err)
	}
	snap, err := catalog.NewSnapshot(census.Live, repo, nil, nil)
	if err != nil {
		t.Fatalf("снимок: %v", err)
	}

	// Предпосылка замера: предмет НЕПУСТ. На пустом каталоге обе строки были бы
	// величинами о ничём, а вывод — беспредметным.
	vocab := snap.Facts().AllVerbVocabulary()
	if len(vocab) == 0 || len(census.Live.Resources) == 0 {
		t.Fatalf("каталог пуст: ресурсов %d, глаголов словаря %d — мерить нечего",
			len(census.Live.Resources), len(vocab))
	}
	probeType, _ := snap.Facts().FGAObjectType(census.Live.Resources[0].Module + "." +
		census.Live.Resources[0].Resource)
	if probeType == "" {
		t.Fatalf("тип для обращения к снимку не резолвится — обращение мерило бы промах")
	}

	const (
		warmups    = 20
		iterations = 60
	)

	// ПРОГРЕВ: план запроса, соединение пула, кеши страниц. Без него первая
	// величина отличалась бы на порядок и вывод был бы про холодный старт.
	for i := 0; i < warmups; i++ {
		if _, err := repo.ReadLiveCatalog(ctx); err != nil {
			t.Fatalf("прогрев: %v", err)
		}
		_ = snap.Facts().VerbsOfType(probeType)
	}

	dbRead := measureSnapshotCost(t, iterations, func() {
		if _, err := repo.ReadLiveCatalog(ctx); err != nil {
			t.Fatalf("чтение каталога: %v", err)
		}
	})
	snapRead := measureSnapshotCost(t, iterations, func() {
		_ = snap.Facts().VerbsOfType(probeType)
	})
	refresh := measureSnapshotCost(t, iterations, func() {
		if err := snap.Refresh(ctx); err != nil {
			t.Fatalf("обновление снимка: %v", err)
		}
	})

	perPeriod := dbRead.median // цена одного круга обновления за период

	t.Logf("ЗАМЕР §8 п. 1 (одна посадка, прогрето: %d прогревов, %d измерений на строку)",
		warmups, iterations)
	t.Logf("перепись предмета: модулей %d · ресурсов %d · глаголов %d · словарь типа %d",
		census.RowModules, census.RowResources, census.RowVerbs, len(vocab))
	t.Logf("строка 1 · СНИМОК: обновление медиана %v (p99 %v) раз в %v; "+
		"обращение к факту медиана %v (p99 %v)",
		refresh.median, refresh.p99, catalogSnapshotDeclaredPeriod, snapRead.median, snapRead.p99)
	t.Logf("строка 2 · ПО ТРЕБОВАНИЮ: чтение каталога медиана %v (p99 %v) НА КАЖДОМ обращении",
		dbRead.median, dbRead.p99)
	t.Logf("отставание: %v — объявлено ручкой KACHO_IAM_CATALOG_SNAPSHOT_REFRESH_INTERVAL_MS, не вшито",
		catalogSnapshotDeclaredPeriod)
	t.Logf("отношение: обращение к снимку дешевле обращения к базе в %.0f раз; "+
		"снимок платит %v за %v на реплику, чтение по требованию — столько же за КАЖДОЕ обращение",
		float64(dbRead.median)/float64(snapRead.median), perPeriod, catalogSnapshotDeclaredPeriod)

	// Единственное утверждение — и оно с запасом в порядки: разница сред, а не
	// настройки. Порог возле измеренного краснел бы на занятой машине.
	if ratio := float64(dbRead.median) / float64(snapRead.median); ratio < 100 {
		t.Errorf("обращение к снимку дешевле обращения к базе лишь в %.1f раза — "+
			"довод §2.4 отвергается замером, и предметом становится чтение по требованию", ratio)
	}

	// ВТОРАЯ половина условия посадки: нужен ли индекс под чтение живого
	// множества (§3.2 п. 4). Отвечает не догадка о размере таблицы, а ПЛАН и
	// СЕРВЕРНОЕ время: индекс сокращает только серверную долю, и только если
	// планировщик вообще станет его читать.
	serverTotal, nodes := explainLiveCatalog(t, ctx, pool)
	share := 100 * float64(serverTotal) / float64(dbRead.median)
	t.Logf("индекс §3.2 п. 4: серверное исполнение трёх операторов %v из обхода %v — %.1f%% цены; "+
		"узлы плана %v — остальное обход и разбор ответа, их индекс не сокращает",
		serverTotal, dbRead.median, share, nodes)

	// Обновление НЕ дороже одного чтения по требованию: оно и ЕСТЬ то же чтение
	// (§2.4 — «тем же чтением, каким страж уже читает строки»). Утверждается с
	// запасом вдвое: сборка фактов поверх чтения стоит своего, но не кратно.
	if refresh.median > 2*dbRead.median {
		t.Errorf("круг обновления %v дороже чтения по требованию %v более чем вдвое — "+
			"снимок перестал наполняться тем же чтением", refresh.median, dbRead.median)
	}
}

// snapshotCostRow — величины одной строки замера.
type snapshotCostRow struct {
	median time.Duration
	p99    time.Duration
}

// measureSnapshotCost — медиана и p99 по n прогонам.
//
// Медиана, а не среднее: среднее смешивает дешёвое большинство с дорогим
// меньшинством и обманывает тем сильнее, чем лучше работает кеш
// (`architecture.md` §«Пул размеряется по длинному меньшинству»).
func measureSnapshotCost(t *testing.T, n int, fn func()) snapshotCostRow {
	t.Helper()
	if n <= 0 {
		t.Fatalf("измерений запрошено %d — величина была бы о пустоте", n)
	}
	samples := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		start := time.Now()
		fn()
		samples = append(samples, time.Since(start))
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	p99 := samples[(len(samples)*99)/100]
	if idx := len(samples) - 1; (len(samples)*99)/100 > idx {
		p99 = samples[idx]
	}
	return snapshotCostRow{median: samples[len(samples)/2], p99: p99}
}

// explainLiveCatalog — СЕРВЕРНОЕ время исполнения трёх операторов живого
// множества, суммой.
//
// Меряется `EXPLAIN (ANALYZE)`, а не секундомером вызывающего: секундомер
// включает обход и разбор ответа, то есть ровно то, чего индекс не сокращает, и
// на такой величине вывод «индекс не нужен» был бы сделан не о том.
func explainLiveCatalog(t *testing.T, ctx context.Context, pool interface {
	QueryRow(context.Context, string, ...any) pgx.Row
},
) (time.Duration, []string) {
	t.Helper()
	stmts := []string{
		`SELECT module FROM kacho_iam.catalog_module WHERE live`,
		`SELECT module, resource, object_type FROM kacho_iam.catalog_resource WHERE live`,
		`SELECT module, resource, verb, per_object FROM kacho_iam.catalog_verb WHERE live`,
	}
	var total time.Duration
	var nodes []string
	for _, q := range stmts {
		var raw []byte
		if err := pool.QueryRow(ctx, "EXPLAIN (ANALYZE, FORMAT JSON) "+q).Scan(&raw); err != nil {
			t.Fatalf("EXPLAIN %q: %v", q, err)
		}
		var plans []struct {
			ExecutionTime float64 `json:"Execution Time"`
			Plan          struct {
				NodeType string `json:"Node Type"`
			} `json:"Plan"`
		}
		if err := json.Unmarshal(raw, &plans); err != nil || len(plans) == 0 {
			t.Fatalf("разбор плана %q: %v", q, err)
		}
		total += time.Duration(plans[0].ExecutionTime * float64(time.Millisecond))
		if plans[0].Plan.NodeType == "" {
			t.Fatalf("узел плана %q не прочитан — вывод об индексе был бы о пустоте", q)
		}
		nodes = append(nodes, plans[0].Plan.NodeType)
	}
	if total <= 0 {
		t.Fatalf("серверное время нулевое — план не прочитан, вердикт был бы беспредметен")
	}
	return total, nodes
}
