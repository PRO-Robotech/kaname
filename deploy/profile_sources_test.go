// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// profile_sources_test.go — откуда пробы этого каталога берут цепочки `-f`, по
// которым служба ставится.
//
// Файл выделен из переписи хопов к поставщику личности (прежний
// `provider_hops_test.go`), когда перепись ушла вместе с последним хопом —
// дорогой обмена у прежнего издателя (kaname#494). Чтение цепочек у переписи
// было общим с соседями (`offered_chains_declare_production_posture_test.go`,
// `stack_chains_read_the_table_test.go`, `image_coordinate_test.go`,
// `prod_profile_test.go`), и оно остаётся: предмет у него свой — ЧТО ставится, —
// а не хоп, ради которого его когда-то завели.
//
// ОТКУДА БЕРУТСЯ ЦЕПОЧКИ. Каталог уезжает клиенту отдельным чартом, и оба дерева
// исполняют этот файл, поэтому источники читаются из дерева, а не называются
// фиксированным числом `..` (см. tree_root_test.go):
//
//	chart      собственные профили чарта рядом с этим файлом — есть в обоих
//	           деревьях, и именно с ними ставит оператор вне нашего облака;
//	umbrella   цепочки `-f` нашего стенда под корнем внешнего дерева — есть
//	           только там, где есть внешнее дерево.
package deploy_test

import (
	"os"
	"path/filepath"
	"testing"
)

// profileSource — одно место, где дерево держит цепочки `-f` для службы.
type profileSource struct {
	label string
	dir   string
	// chains — цепочки `-f` по порядку. Собственные профили чарта всегда
	// ложатся на values.yaml, потому что так делает helm.
	chains map[string][]string
}

// chartChains — цепочки `-f`, которые поставляемый чарт предлагает сам.
// `values.yaml` назван первым в каждой, потому что helm сливает его первым,
// назовут его или нет.
//
// ЦЕПОЧКИ `dev` НЕТ, и её снятие — предмет, а не уборка (задача #2473). Чарт
// предлагал ставить `values.yaml + values.dev.yaml`, и эта цепочка объявляла
// `authMode: dev`, оставляя канал к базе на небезопасном значении базовых.
// ban #16 разрешает небезопасную посадку только во внутрипроцессных фикстурах и
// запрещает её на поднятом кластере, а профиль helm относится к поднятому
// кластеру по построению. Потребителя у цепочки в дереве не было, значит её
// единственным возможным потребителем был клиент, которому чарт уезжает.
//
// Сам `values.dev.yaml` в поставке ОСТАЁТСЯ: двум поставляемым гейтам нужен
// открытый конец их оси (ведомость в
// offered_chains_declare_production_posture_test.go читает эту карту и держит
// цепочку с небоевой посадкой от повторного предложения).
var chartChains = map[string][]string{
	"prod": {"values.yaml", "values.prod.yaml"},
}

// profileSources читает дерево и говорит, какие источники в нём есть.
//
// Корни находятся ПОДЪЁМОМ до маркера модуля, а не счётом `..` (см.
// tree_root_test.go): этот каталог лежит на разной глубине в двух деревьях, и
// фиксированный счёт верен в одном из них и указывает мимо репозитория в другом.
//
// Цепочки стенда ЧИТАЮТСЯ из `deploy/stacks.txt` — единственного места внешнего
// дерева, где цепочка выписана; разбор и замер расхождения выписанной копии с
// таблицей — umbrellaChainsFromTable в stack_chains_read_the_table_test.go.
func profileSources(t *testing.T) []profileSource {
	t.Helper()
	sources := []profileSource{{
		label:  "chart",
		dir:    filepath.Join(serviceRoot(t), "deploy"),
		chains: chartChains,
	}}

	// Источнику стенда нужны ОБА — его профили и таблица, объявляющая цепочки
	// над ними. Отсутствие любого значит, что внешнего дерева здесь нет: чарт
	// ставится без зонта, и это источник, которого у нас нет, а не источник,
	// прочитанный пустым.
	umbrella := filepath.Join(outerRoot(t), "deploy", "helm", "umbrella")
	chains, tablePresent := umbrellaChainsFromTable(t, outerRoot(t))
	if st, err := os.Stat(umbrella); err == nil && st.IsDir() && tablePresent {
		sources = append(sources, profileSource{
			label:  "umbrella",
			dir:    umbrella,
			chains: chains,
		})
	}
	return sources
}

// mergeInto накладывает профили так, как это делает helm: карты сливаются по
// ключу, всё прочее заменяется целиком.
func mergeInto(dst, src map[string]any) map[string]any {
	if dst == nil {
		dst = map[string]any{}
	}
	for k, v := range src {
		if sub, ok := v.(map[string]any); ok {
			if cur, ok := dst[k].(map[string]any); ok {
				dst[k] = mergeInto(cur, sub)
				continue
			}
		}
		dst[k] = v
	}
	return dst
}
