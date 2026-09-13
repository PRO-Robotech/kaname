// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

// provider_road_parity_injection_test.go — доказательство, что гейт
// `TestIAM2491_EveryRoadTheProfileDeclaresHasACounter` способен упасть И
// способен смолчать.
//
// Пара «красное до · зелёное после» снята и на ЖИВОМ дереве: до починки гейт
// назвал бы ADMIN и TOKEN («дорог объявлено 3 · со счётом 1»), после —
// «3 · 3». Здесь то же свойство закреплено воспроизводимо, на синтетике.
//
// У КАЖДОГО нарушителя стоит ЗАКОННЫЙ БЛИЗНЕЦ — та же форма, отличающаяся
// РОВНО ОДНИМ фактом.

import (
	"testing"
)

// injProfileThreeRoads — ЗАКОННЫЙ БЛИЗНЕЦ: профиль, объявляющий дороги парами
// «адрес + якорь», ровно как боевой.
const injProfileThreeRoads = `
env:
  KANAME_HYDRA_ADMIN_URL: "https://a.invalid"
  KANAME_HYDRA_ADMIN_CA_FILE: /ca.crt
  KANAME_HYDRA_JWKS_URL: "https://j.invalid"
  KANAME_HYDRA_JWKS_CA_FILE: /ca.crt
  KANAME_HYDRA_TOKEN_URL: "https://t.invalid"
  KANAME_HYDRA_TOKEN_CA_FILE: /ca.crt
`

// injProfileFourthRoad — ДЕФЕКТ: заведена четвёртая дорога, счёта у неё нет.
// Ровно один факт против близнеца.
const injProfileFourthRoad = injProfileThreeRoads + `  KANAME_HYDRA_CONSENT_URL: "https://c.invalid"
  KANAME_HYDRA_CONSENT_CA_FILE: /ca.crt
`

// injProfileAddressWithoutAnchor — ЗАКОННЫЙ БЛИЗНЕЦ границы: адрес БЕЗ якоря
// дорогой не является, и гейт обязан о нём молчать. Единица счёта названа в
// шапке гейта именно затем, чтобы эта строка не стала находкой.
const injProfileAddressWithoutAnchor = injProfileThreeRoads + `  KANAME_HYDRA_CONSENT_URL: "https://c.invalid"
`

// injProfileNoRoads — пустой обход: профиль без дорог. Отказ, а не чистое дерево.
const injProfileNoRoads = `
env:
  KANAME_LOG_LEVEL: info
`

func TestIAM2491_InjectionRedsTheRoadWithoutACounterAndKeepsQuietOnTheCountedOnes(t *testing.T) {
	rows := map[string]bool{
		ProviderRoadOutcomesMetric + "/" + "admin":          true,
		ProviderRoadOutcomesMetric + "/" + "token_exchange": true,
		JWKSMirrorOutcomesMetric + "/":                      true,
	}

	twin, err := providerRoadsDeclaredIn([]byte(injProfileThreeRoads))
	if err != nil {
		t.Fatalf("%v", err)
	}
	uncounted, silent, stale, counted := adjudicateRoadParity(twin, roadsWithACounter, rows)
	if len(uncounted)+len(silent)+len(stale) != 0 || counted != 3 {
		t.Fatalf("законный близнец дал находки: без счёта %v · молчащих %v · просроченных %v · сошлось %d",
			uncounted, silent, stale, counted)
	}

	defect, err := providerRoadsDeclaredIn([]byte(injProfileFourthRoad))
	if err != nil {
		t.Fatalf("%v", err)
	}
	uncounted, _, _, counted = adjudicateRoadParity(defect, roadsWithACounter, rows)
	if len(uncounted) != 1 || uncounted[0] != "CONSENT" {
		t.Fatalf("дорога без счёта не названа: %v", uncounted)
	}
	if counted != 3 {
		t.Errorf("сошлось %d вместо 3 — инъекция уронила заодно соседа", counted)
	}
	// ВТОРОЕ ЧИСЛО ПЕРЕПИСИ И ЕСТЬ ПРЕДМЕТ ГЕЙТА: одно «со счётом 3» читалось бы
	// как исправная наблюдаемость, пока рядом не стоит «объявлено 4».
	if len(defect) != 4 {
		t.Errorf("объявленных дорог насчитано %d вместо 4", len(defect))
	}
}

func TestIAM2491_InjectionKeepsQuietOnAnAddressWithoutAnAnchor(t *testing.T) {
	roads, err := providerRoadsDeclaredIn([]byte(injProfileAddressWithoutAnchor))
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(roads) != 3 {
		t.Fatalf("адрес без якоря засчитан дорогой (насчитано %d: %v) — единица счёта "+
			"разошлась бы с объявленной в шапке", len(roads), roads)
	}
}

func TestIAM2491_InjectionRedsTheSilentFamily(t *testing.T) {
	// ДЕФЕКТ: запись счёта есть, а ряда на проводе нет — счётчик объявлен и не
	// провязан. Ровно один факт против близнеца выше.
	rows := map[string]bool{
		ProviderRoadOutcomesMetric + "/" + "admin": true,
		JWKSMirrorOutcomesMetric + "/":             true,
	}
	roads, err := providerRoadsDeclaredIn([]byte(injProfileThreeRoads))
	if err != nil {
		t.Fatalf("%v", err)
	}
	_, silent, _, counted := adjudicateRoadParity(roads, roadsWithACounter, rows)
	if len(silent) != 1 || silent[0] != "TOKEN" {
		t.Fatalf("молчащее семейство не названо: %v", silent)
	}
	if counted != 2 {
		t.Errorf("сошлось %d вместо 2", counted)
	}
}

func TestIAM2491_InjectionRedsAnEntryWhoseRoadTheProfileDropped(t *testing.T) {
	// ДЕФЕКТ: профиль снял дорогу, запись о её счёте осталась. Послабление и
	// утверждение обязаны истекать вместе со своим предметом.
	_, _, stale, _ := adjudicateRoadParity([]string{"ADMIN", "JWKS"}, roadsWithACounter,
		map[string]bool{
			ProviderRoadOutcomesMetric + "/" + "admin": true,
			JWKSMirrorOutcomesMetric + "/":             true,
		})
	if len(stale) != 1 || stale[0] != "TOKEN" {
		t.Fatalf("просроченная запись не названа: %v", stale)
	}
}

func TestIAM2491_InjectionRedsTheEmptyProfile(t *testing.T) {
	roads, err := providerRoadsDeclaredIn([]byte(injProfileNoRoads))
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(roads) != 0 {
		t.Fatalf("профиль без дорог дал %d — предпосылка отказа неверна", len(roads))
	}
	// Живой гейт на такой переписи зовёт Fatalf; здесь проверена ПРЕДПОСЫЛКА
	// этого отказа, а не его текст.
}

// TestIAM2491_InjectionProvesTheCountedRoadsAreCountedOnTheWire — предмет гейта
// это ПРОВОД: реестр без конструктора обязан дать молчащее семейство.
func TestIAM2491_InjectionProvesTheCountedRoadsAreCountedOnTheWire(t *testing.T) {
	bare := NewRegistry() // конструктор дорог НЕ позван — дефект провязки
	gathered, err := bare.reg.Gather()
	if err != nil {
		t.Fatalf("%v", err)
	}
	for _, mf := range gathered {
		if mf.GetName() == ProviderRoadOutcomesMetric {
			t.Fatalf("семейство дорог отдаётся реестром, которому его не провязывали — " +
				"тогда гейт зелен при любой провязке by construction")
		}
	}
	wired := providerRoadRowsOnTheWire(t)
	for _, road := range []string{"admin", "token_exchange"} {
		if !wired[ProviderRoadOutcomesMetric+"/"+road] {
			t.Errorf("провязанный реестр не отдаёт ряда дороги %q", road)
		}
	}
}
