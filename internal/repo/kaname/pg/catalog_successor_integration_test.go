// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// catalog_successor_integration_test.go — преемник снятого ресурса доезжает от
// СТРОКИ до факта, которым отвечает витрина (kacho#1814, приёмка
// `docs/engineering/acceptance/retired-resource-names-its-successor.md`,
// `IAM-SUC-02` · `-03` · `-09` · `-11` на НАСТОЯЩЕЙ базе).
//
// # Почему настоящая база, а не фикстура
//
// Цепочка рвалась в ЗВЕНЬЯХ ПЕРЕНОСА: колонка есть и посеяна, гейт посева её
// сверяет, читатель снятой половины жив — а `catalog.ResourceRow` преемника не
// нёс, и запрос снятой половины его не выбирал. Фикстура, кладущая преемника в
// структуру руками, обходит ровно те два звена, из-за которых значение до
// арендатора не доезжало: она доказывает, что структура умеет его хранить, и не
// доказывает, что его кто-то прочитал из базы.
//
// # Изоляция утверждается ЧИСЛОМ ОПЕРАТОРОВ, а не прочтением кода
//
// Обе половины обязаны приходить ОДНИМ снимком: собранные из двух моментов, они
// дали бы арендатору ресурс в обоих перечнях сразу либо ни в одном. Считает
// операторы наблюдатель запросов; шесть под одной транзакцией — это один снимок,
// шесть с пула — шесть.

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// TestIAMSUC02_03_SuccessorTravelsFromTheRowToTheFacts — `IAM-SUC-02` и `-03` на
// посеянном каталоге.
//
// Три снятых ресурса названы, у каждого преемник, и КАЖДЫЙ преемник — ЖИВОЙ ключ
// того же факта. Без второй половины первая была бы исполнима преемником,
// указывающим на снятое, то есть восстанавливала бы шаг, которого нет.
func TestIAMSUC02_03_SuccessorTravelsFromTheRowToTheFacts(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	pool, _, ctx := countedCatalogPool(t)
	repo := kanamepg.NewCatalogRepo(pool)

	halves, err := repo.ReadCatalogHalves(ctx)
	if err != nil {
		t.Fatalf("чтение половин каталога: %v", err)
	}
	facts, err := catalog.NewFacts(halves)
	if err != nil {
		t.Fatalf("каталожный факт: %v", err)
	}

	retired := facts.RetiredResources()
	if len(retired) == 0 {
		t.Fatalf("снятых записей ноль — посев их несёт, значит рвётся звено переноса; " +
			"утверждения ниже стали бы вакуумными")
	}

	// Живые ключи ТОГО ЖЕ факта: преемник ищется там, куда клиент за ним пойдёт.
	live := make(map[string]bool, len(facts.Resources()))
	for _, e := range facts.Resources() {
		live[e.Module+"."+e.Resource] = true
	}
	if len(live) == 0 {
		t.Fatalf("живых пар ноль — членство преемника проверять негде")
	}

	named := 0
	for _, r := range retired {
		dotted := r.Module + "." + r.Resource
		if live[dotted] {
			t.Errorf("%s назван И снятым, и живым — половины собраны из разных моментов", dotted)
		}
		if r.SupersededBy == "" {
			t.Logf("снятый %s преемника не называет — законно, но клиенту шага не даёт", dotted)
			continue
		}
		named++
		if !live[r.SupersededBy] {
			t.Errorf("преемник %s снятого %s НЕ является живым ключом каталога — "+
				"клиент отослан к тому, чего платформа не выдаёт", r.SupersededBy, dotted)
		}
		if !strings.Contains(r.SupersededBy, ".") {
			t.Errorf("преемник %s снятого %s не в точечной форме — отказ называет тип "+
				"точечным именем, и клиент сравнивает именно его", r.SupersededBy, dotted)
		}
	}
	// Положительный контроль: хоть один преемник назван. Иначе цикл выше
	// зеленел бы на каталоге, где преемников не назвал никто.
	if named == 0 {
		t.Fatalf("ни у одной снятой строки преемник не прочитан — колонка существует "+
			"данными и не доезжает; снятых записей %d", len(retired))
	}
	t.Logf("перепись: живых пар %d · снятых записей %d · из них с преемником %d",
		len(live), len(retired), named)
}

// TestIAMSUC09_BothHalvesArriveInOneSnapshot — `IAM-SUC-09`, путь ОБНОВЛЕНИЯ.
//
// Операторов к таблицам каталога за одно чтение половин — столько же, сколько
// шлют две половины по отдельности, И ВСЕ ОНИ под одной транзакцией. Голый счёт
// операторов здесь вакуумен: он одинаков у транзакции и у пула. Различает их
// уровень изоляции, а он проверяется тем, что обе половины пришли ОДНИМ вызовом
// порта — второго вызова у порта нет by construction.
func TestIAMSUC09_BothHalvesArriveInOneSnapshot(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	pool, counter, ctx := countedCatalogPool(t)
	repo := kanamepg.NewCatalogRepo(pool)

	// K — операторов у двух половин, прочитанных ПОРОЗНЬ.
	counter.reset()
	if _, err := repo.ReadLiveCatalog(ctx); err != nil {
		t.Fatalf("живая половина: %v", err)
	}
	if _, err := repo.ReadRetiredCatalog(ctx); err != nil {
		t.Fatalf("снятая половина: %v", err)
	}
	k := counter.catalogCount()
	if k == 0 {
		t.Fatalf("за каталогом не сходили ВОВСЕ (K=0) — равенство ниже стало бы " +
			"тождественно истинным, а вердикт беспредметным")
	}

	// N — операторов за ОДНО чтение обеих половин.
	counter.reset()
	halves, err := repo.ReadCatalogHalves(ctx)
	if err != nil {
		t.Fatalf("чтение половин: %v", err)
	}
	n := counter.catalogCount()

	t.Logf("операторов к таблицам каталога: половины порознь K=%d, одним снимком N=%d", k, n)
	if n != k {
		t.Errorf("N=%d при K=%d — чтение половин одним снимком стоит не столько же, "+
			"сколько порознь: заведено лишнее обращение либо потеряна половина", n, k)
	}
	// Положительный контроль на СОДЕРЖИМОМ — обе половины непусты. Без него
	// равенство выполнялось бы снимком, не взявшим ничего.
	if len(halves.Live.Resources) == 0 {
		t.Errorf("живая половина снимка пуста при N==K")
	}
	if len(halves.Retired.Resources) == 0 {
		t.Errorf("снятая половина снимка пуста при N==K — равенство выполнено тем, " +
			"что снятое не прочитано")
	}
}

// TestIAMSUC11_StartPathCarriesRetiredRowsFromTheGuard — `IAM-SUC-11` на
// настоящей базе.
//
// Страж паритета читает снятую половину БЕЗУСЛОВНО и всегда; снимок берёт её у
// него, а не читает заново. Утверждается ПАРА: снятые записи в снимке есть И
// новых операторов старт не добавил.
func TestIAMSUC11_StartPathCarriesRetiredRowsFromTheGuard(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	pool, counter, ctx := countedCatalogPool(t)
	repo := kanamepg.NewCatalogRepo(pool)

	counter.reset()
	census, err := seed.AssertCatalogParity(ctx, repo, seed.ImageAnchor())
	if err != nil {
		t.Fatalf("страж паритета: %v", err)
	}
	k := counter.catalogCount()

	// Снимок строится из переписи — БЕЗ единого нового обращения.
	before := counter.catalogCount()
	snap, err := catalog.NewSnapshot(census.Halves(), repo, nil, nil)
	if err != nil {
		t.Fatalf("снимок: %v", err)
	}
	added := counter.catalogCount() - before

	t.Logf("перепись: операторов у стража K=%d, добавлено построением снимка %d; "+
		"снятых ресурсов у стража %d", k, added, census.RetiredResources)
	if added != 0 {
		t.Errorf("построение снимка добавило %d оператор(ов) к таблицам каталога — "+
			"снимок завёл СВОЁ чтение вместо доноса уже прочитанного", added)
	}
	if census.RetiredResources == 0 {
		t.Fatalf("страж насчитал ноль снятых ресурсов — утверждение ниже вакуумно")
	}
	got := snap.Facts().RetiredResources()
	if len(got) != census.RetiredResources {
		t.Errorf("в снимке снятых записей %d, страж насчитал %d — половина потеряна "+
			"по дороге от переписи к снимку", len(got), census.RetiredResources)
	}
	// Положительный контроль: живая половина снимка тоже доехала.
	if len(snap.Facts().Resources()) == 0 {
		t.Errorf("живая половина снимка пуста — снимок собран не из обеих половин")
	}
}
