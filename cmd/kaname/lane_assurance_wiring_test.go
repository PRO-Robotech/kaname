// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// lane_assurance_wiring_test.go — КОМПОЗИЦИОННЫЙ КОРЕНЬ выводит предъявимые
// уровни доверия полосы `own` ПРАВИЛОМ, а не литералом (приёмка Ф11, Р9,
// сценарии Ф11-27 и Ф11-28; задача kacho#1280).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ СУДИТСЯ, А ЧТО УЖЕ СУДИТСЯ В ДРУГОМ МЕСТЕ
//
// Требование («каждый уровень доверия каталога предъявим») объявлено строкой
// таблицы полос и проверено там же — `config.ValidateLaneWiring` отвергает
// старт, когда каталог требует уровень, которого в перечне нет. Само правило
// вывода проверено по всей таблице в `internal/assurance`. Эти пробы о третьем:
// что корень СТАВИТ В ПОЛЕ ПЕРЕЧЕНЬ, ВЫВЕДЕННЫЙ ПРАВИЛОМ из провязанных
// способов, а не литерал.
//
// До этой правки поле было литералом `nil`. Литерал не мог покраснеть ни при
// какой провязке, то есть наблюдатель отчитывался о намерении вместо исхода —
// ровно тот класс, ради которого самоотчёт о посадке и заведён.
//
// ─────────────────────────────────────────────────────────────────────────────
// «ДАНО» СТРОИТСЯ ПРОБОЙ, И ЭТО НАЗВАНО
//
// Хранилищ способов входа и сессии в корне ещё нет (Ф2 — kacho#1268, Ф3 —
// kacho#1269), поэтому провязанные способы подаются наблюдателю ПАРАМЕТРОМ, а
// флаги провязки хранилищ проба ставит сама — как строит «Дано» приёмка
// (§3.0а). Что корень подаёт наблюдателю на живом старте, — его наблюдение, и
// сегодня оно пусто; сценарии Ф11-27/28 на ЖИВОМ старте исполняются в DoD фаз,
// которые провяжут способы.
//
// Отрицание (Ф11-27) стоит в паре с положительным близнецом (Ф11-28); единственное
// отличие — провязан второй фактор.
package main

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/assurance"
)

// ownLaneWiring — наблюдение корня на посадке `own` с названными способами и
// с провязанными хранилищами (условие Ф11-27/28).
func ownLaneWiring(t *testing.T, wired []assurance.Method) (config.Config, config.LaneWiring) {
	t.Helper()
	cfg := roadCfg(config.IdentityProviderOwn, "9097")
	cfg.AuthN.TokenSigning.Enabled = true
	w := observeLaneWiring(context.Background(), cfg, nil, wired, quietLogger())
	w.OwnMintSignerWired = true
	w.HumanCredentialsWired = true
	w.HumanSessionsWired = true
	if !w.CatalogFloors.Readable {
		t.Fatal("проба НЕ ИСПОЛНЯЛАСЬ: встроенный каталог прав не прочитан — Дано не построено")
	}
	return cfg, w
}

// Ф11-27: провязан только пароль → отказ старта; текст называет число записей
// каталога, требующих «2», и перечень предъявимых уровней — «1».
func TestF11_27_OwnLaneWithOnlyPasswordRefusesToStartNamingLevel1(t *testing.T) {
	cfg, w := ownLaneWiring(t, []assurance.Method{assurance.MethodPassword})
	demandingTwo := w.CatalogFloors.ByLevel["2"]
	if demandingTwo == 0 {
		t.Fatal("проба НЕ ИСПОЛНЯЛАСЬ: каталог не требует уровня «2» ни одной записью — противоречия нет")
	}

	err := config.ValidateLaneWiring(cfg, w)
	if err == nil {
		t.Fatal("ValidateLaneWiring() = nil: каталог требует «2», полоса предъявляет только «1», а старт разрешён")
	}
	for _, want := range []string{
		fmt.Sprintf("%d catalog entr", demandingTwo),
		"demand assurance level(s) 2",
		"the lane offers 1,",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ обязан нести %q, получено: %q", want, err.Error())
		}
	}
	if got := w.PresentableACRs; len(got) != 1 || got[0] != "1" {
		t.Errorf("перечень предъявимых уровней при одном пароле = %v, ожидался [1]", got)
	}
}

// Ф11-28: провязан и второй фактор — единственное отличие — требование
// пройдено; самоотчёт старта называет число предъявимых уровней — 2.
func TestF11_28_OwnLaneWithPasswordAndSecondFactorPassesTheFloorRow(t *testing.T) {
	cfg, w := ownLaneWiring(t, []assurance.Method{assurance.MethodPassword, assurance.MethodTOTP})

	if err := config.ValidateLaneWiring(cfg, w); err != nil {
		t.Fatalf("ValidateLaneWiring() = %v; с паролем и вторым фактором каталог требует только то, что полоса предъявляет", err)
	}
	census := laneWiringCensus(w)
	found := false
	for i := 0; i+1 < len(census); i += 2 {
		if census[i] == "lane_presentable_acrs" {
			found = true
			if census[i+1] != 2 {
				t.Errorf("самоотчёт называет предъявимых уровней %v, ожидалось 2", census[i+1])
			}
		}
	}
	if !found {
		t.Fatal("самоотчёт старта не называет числа предъявимых уровней")
	}
}

// Перечень ВЫВОДИТСЯ правилом, а не переписан второй таблицей в корне:
// наблюдение корня побайтово равно тому, что даёт правило на тех же способах, —
// на пустой провязке, на пароле и на ключе.
func TestObserveLaneWiring_PresentableLevelsComeFromTheRule(t *testing.T) {
	cases := [][]assurance.Method{
		nil,
		{assurance.MethodPassword},
		{assurance.MethodWebAuthn},
		{assurance.MethodPassword, assurance.MethodLookupSecret},
	}
	for _, wired := range cases {
		_, w := ownLaneWiring(t, wired)
		want := assurance.PresentableLevels(wired).Strings()
		if strings.Join(w.PresentableACRs, ",") != strings.Join(want, ",") {
			t.Errorf("провязано %v: корень доложил %v, правило даёт %v", wired, w.PresentableACRs, want)
		}
	}
	// Пустая провязка — пустой перечень: страж читает его как «ни одного», и
	// это наблюдение, а не литерал: корень ничего не провязал.
	if _, w := ownLaneWiring(t, nil); len(w.PresentableACRs) != 0 {
		t.Errorf("без провязанных способов корень доложил уровни %v", w.PresentableACRs)
	}
}
