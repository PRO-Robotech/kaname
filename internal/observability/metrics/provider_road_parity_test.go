// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

// provider_road_parity_test.go — ПЕРЕПИСЬ В ДВА ЧИСЛА: дорог к поставщику,
// объявленных профилем, и дорог, имеющих счёт (kacho#2491, предикат 3).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ДВА ЧИСЛА, А НЕ ОДНО
//
// Одно число скрыло бы ровно тот случай, ради которого гейт заведён: профиль
// объявлял ТРИ дороги, счёт был у ОДНОЙ, и «дорог со счётом 1» читалось как
// исправная наблюдаемость, пока рядом не стоит «дорог объявлено 3».
//
// ─────────────────────────────────────────────────────────────────────────────
// ЕДИНИЦА СЧЁТА НАЗВАНА
//
// Дорога — ПАРА ручек профиля `KANAME_HYDRA_<ИМЯ>_URL` + `..._CA_FILE`: свой
// адрес и свой якорь доверия. Счёт по одним лишь адресам дал бы другую величину
// (адрес без якоря дорогой не является — по нему нельзя ходить с проверкой), и
// читатель сравнил бы несравнимое.
//
// ─────────────────────────────────────────────────────────────────────────────
// СУДИТСЯ ПРОВОД, А НЕ ОБЪЯВЛЕНИЕ
//
// «Дорога имеет счёт» проверяется сбором с реестра: семейство обязано отдавать
// РЯД по этой дороге. Перечень в комментарии таким доказательством не является —
// он стареет молча вместе с тем, из чего выведен.
//
// Пустой обход — находка: профиль без единой дороги означает, что гейт стережёт
// координату, которой больше нет.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"
	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kaname/internal/clients"
)

// providerRoadCounter — чем наблюдается дорога, объявленная профилем.
//
// Ключ — имя дороги В ПРОФИЛЕ (сегмент между `KANAME_HYDRA_` и `_URL`).
type providerRoadCounter struct {
	// Family — семейство на проводе.
	Family string
	// Cell — значение метки `road`, которым дорога различается внутри семейства.
	// Пусто, если у дороги СВОЁ семейство и метки дороги в нём нет.
	Cell string
	// Why — почему счёт устроен именно так. Читается человеком.
	Why string
}

// roadsWithACounter — объявление того, ЧЕМ считается каждая дорога.
//
// Запись, чьей дороги профиль больше не объявляет, — находка: утверждение о
// наблюдаемости обязано истекать вместе со своим предметом.
var roadsWithACounter = map[string]providerRoadCounter{
	"ADMIN": {
		Family: ProviderRoadOutcomesMetric,
		Cell:   clients.ProviderRoadAdmin,
		Why:    "выдача и отзыв ключа служебной учётки, интерактивный клиент, принудительный выход",
	},
	"TOKEN": {
		Family: ProviderRoadOutcomesMetric,
		Cell:   clients.ProviderRoadTokenExchange,
		Why:    "обмен подписанного утверждения на токен у прежнего издателя",
	},
	"JWKS": {
		Family: JWKSMirrorOutcomesMetric,
		Why: "у зеркала набора ключей СВОЁ семейство и свой производитель: оно ведёт " +
			"собственные счётчики и отдаётся коллектором. Метки дороги в нём нет — " +
			"дорога у него одна by construction",
	},
}

func TestIAM2491_EveryRoadTheProfileDeclaresHasACounter(t *testing.T) {
	root := moduleRootForParity(t)
	profile := filepath.Join(root, "deploy", "values.prod.yaml")
	raw, err := os.ReadFile(profile) //nolint:gosec // путь собран из корня модуля
	if err != nil {
		t.Fatalf("прочитать профиль %s: %v", profile, err)
	}
	declared, err := providerRoadsDeclaredIn(raw)
	if err != nil {
		t.Fatalf("разобрать профиль %s: %v", profile, err)
	}
	if len(declared) == 0 {
		t.Fatalf("профиль %s не объявляет НИ ОДНОЙ дороги к поставщику — вердикт "+
			"беспредметен: «ноль находок» неотличимо от «ноль прочитанного»", profile)
	}

	rows := providerRoadRowsOnTheWire(t)
	uncounted, silent, stale, counted := adjudicateRoadParity(declared, roadsWithACounter, rows)
	t.Logf("дорог объявлено профилем %d (%s) · дорог со счётом на проводе %d",
		len(declared), strings.Join(declared, ", "), counted)

	for _, road := range uncounted {
		t.Errorf("дорога %s объявлена профилем (ручки KANAME_HYDRA_%s_URL и "+
			"KANAME_HYDRA_%s_CA_FILE), а счёта у неё нет. Для дежурного это значит, "+
			"что «сломан продукт» и «оператор не создал условие» на ней не различимы "+
			"ничем: обе ошибки дают ту же картину, что и лежащий поставщик. Заведи "+
			"семейство исходов с клеткой «недоступен» отдельно от клетки «настроено "+
			"не туда» и впиши дорогу в `roadsWithACounter`.", road, road, road)
	}
	for _, road := range silent {
		entry := roadsWithACounter[road]
		t.Errorf("дорога %s объявлена счётом через %q (клетка road=%q), а семейство "+
			"НЕ ОТДАЁТ такого ряда сразу после регистрации. Счёт, которого нет на "+
			"проводе, счётом не является: %s.", road, entry.Family, entry.Cell, entry.Why)
	}
	for _, road := range stale {
		t.Errorf("`roadsWithACounter` называет дорогу %s, а профиль её больше не "+
			"объявляет — утверждение о наблюдаемости пережило свой предмет. Снимите "+
			"запись ВМЕСТЕ с дорогой.", road)
	}
}

// adjudicateRoadParity разводит объявленные профилем дороги на три исхода и
// считает сошедшиеся. Чистая функция: инъекция подаёт синтетический профиль и
// синтетический провод, не трогая ни дерева, ни реестра.
func adjudicateRoadParity(
	declared []string, counters map[string]providerRoadCounter, rows map[string]bool,
) (uncounted, silent, stale []string, counted int) {
	for _, road := range declared {
		entry, ok := counters[road]
		switch {
		case !ok:
			uncounted = append(uncounted, road)
		case !rows[entry.Family+"/"+entry.Cell]:
			silent = append(silent, road)
		default:
			counted++
		}
	}
	for road := range counters {
		if !containsRoad(declared, road) {
			stale = append(stale, road)
		}
	}
	sort.Strings(uncounted)
	sort.Strings(silent)
	sort.Strings(stale)
	return uncounted, silent, stale, counted
}

// providerRoadRowsOnTheWire строит ОБА семейства на свежем реестре и отдаёт
// множество рядов вида `<семейство>/<значение метки road>`; для семейства без
// метки дороги значение пусто.
func providerRoadRowsOnTheWire(t *testing.T) map[string]bool {
	t.Helper()
	reg := NewRegistry()
	reg.NewProviderRoadRecorder()
	reg.NewJWKSMirrorCollector(func() JWKSMirrorCounts { return JWKSMirrorCounts{} })

	// Собирается ПРОВОД, а не объявление: семейство обязано отдать ряд.
	var gathered []*dto.MetricFamily
	gathered, err := reg.reg.Gather()
	if err != nil {
		t.Fatalf("собрать семейства реестра: %v", err)
	}
	out := map[string]bool{}
	for _, mf := range gathered {
		for _, m := range mf.GetMetric() {
			road := ""
			for _, l := range m.GetLabel() {
				if l.GetName() == "road" {
					road = l.GetValue()
				}
			}
			out[mf.GetName()+"/"+road] = true
		}
	}
	return out
}

// providerRoadsDeclaredIn отдаёт ИМЕНА дорог, у которых объявлены ОБЕ ручки.
//
// Судится РАЗОБРАННЫЙ YAML, а не текст: имя ручки встречается в профиле и в
// комментариях, и предикат по подстроке краснел бы на собственном объяснении
// проверяемого. Содержимое приходит ПАРАМЕТРОМ — в живом дереве его даёт
// профиль, а инъекция подаёт синтетический.
func providerRoadsDeclaredIn(raw []byte) ([]string, error) {
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	urls, anchors := map[string]bool{}, map[string]bool{}
	collectProviderKnobs(doc, urls, anchors)
	var out []string
	for road := range urls {
		if anchors[road] {
			out = append(out, road)
		}
	}
	sort.Strings(out)
	return out, nil
}

// collectProviderKnobs обходит документ на любую глубину: раздел окружения
// профиля переезжал между уровнями, и обход по одному фиксированному пути
// перестал бы видеть предмет молча.
func collectProviderKnobs(node any, urls, anchors map[string]bool) {
	switch v := node.(type) {
	case map[string]any:
		for key, child := range v {
			if road, ok := strings.CutPrefix(key, "KANAME_HYDRA_"); ok {
				switch {
				case strings.HasSuffix(road, "_URL"):
					urls[strings.TrimSuffix(road, "_URL")] = true
				case strings.HasSuffix(road, "_CA_FILE"):
					anchors[strings.TrimSuffix(road, "_CA_FILE")] = true
				}
			}
			collectProviderKnobs(child, urls, anchors)
		}
	case []any:
		for _, child := range v {
			collectProviderKnobs(child, urls, anchors)
		}
	}
}

func containsRoad(roads []string, road string) bool {
	for _, r := range roads {
		if r == road {
			return true
		}
	}
	return false
}

// moduleRootForParity — тот же подъём до go.mod, что у соседней пробы пакета.
func moduleRootForParity(t *testing.T) string { return moduleRootFromMetrics(t) }
