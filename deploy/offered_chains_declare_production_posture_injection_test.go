// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// offered_chains_declare_production_posture_injection_test.go — доказательство
// того, что гейт соседнего файла СПОСОБЕН упасть, и падает на своём предмете.
//
// Инъекция зовёт ТО ЖЕ ТЕЛО (`judgeOfferedChainPostures`), что исполняется на
// дереве: своя копия предиката разошлась бы с настоящим гейтом молча.
//
// У каждого отрицания стоит ЗАКОННЫЙ БЛИЗНЕЦ, отличающийся ОДНИМ фактом.
package deploy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOfferedChainPostures_ProductionChainIsSilent(t *testing.T) {
	// КОНТРОЛЬ: единственная предлагаемая цепочка боевая, непредлагаемый профиль
	// назван — гейт молчит.
	findings := judgeOfferedChainPostures(
		map[string]string{"prod": "production-strict"},
		[]string{"values.yaml", "values.prod.yaml", "values.fixture.yaml"},
		map[string]bool{"values.yaml": true, "values.prod.yaml": true},
		map[string]string{"values.fixture.yaml": "фикстура открытого текста для двусторонних гейтов"},
	)
	if len(findings) != 0 {
		t.Fatalf("гейт покраснел на целом дереве: %v", findings)
	}
}

func TestOfferedChainPostures_DevChainIsAFinding(t *testing.T) {
	// ИНЪЕКЦИЯ, ОДИН ФАКТ против контроля: та же раскладка, но цепочка объявляет
	// небезопасную посадку.
	findings := judgeOfferedChainPostures(
		map[string]string{"prod": "production-strict", "dev": "dev"},
		[]string{"values.yaml", "values.prod.yaml", "values.fixture.yaml"},
		map[string]bool{"values.yaml": true, "values.prod.yaml": true},
		map[string]string{"values.fixture.yaml": "фикстура открытого текста для двусторонних гейтов"},
	)
	if len(findings) != 1 {
		t.Fatalf("небезопасная предлагаемая цепочка не найдена: %v", findings)
	}
	if !strings.Contains(findings[0], "dev") {
		t.Fatalf("находка не называет цепочку: %q", findings[0])
	}
}

func TestOfferedChainPostures_UndeclaredPostureIsAFinding(t *testing.T) {
	// ПУСТАЯ ПОСАДКА — тоже находка, и текст её отличает: «не объявлена вовсе»
	// и «объявлена небезопасной» чинятся по-разному.
	findings := judgeOfferedChainPostures(
		map[string]string{"prod": ""},
		[]string{"values.yaml"},
		map[string]bool{"values.yaml": true},
		map[string]string{},
	)
	if len(findings) != 1 || !strings.Contains(findings[0], "НЕ ОБЪЯВЛЕННУЮ") {
		t.Fatalf("необъявленная посадка не найдена либо названа неотличимо: %v", findings)
	}
}

func TestOfferedChainPostures_UnofferedProfileWithoutAReasonIsAFinding(t *testing.T) {
	// ИНЪЕКЦИЯ: поставляемый профиль вне всех цепочек и без записи в ведомости.
	findings := judgeOfferedChainPostures(
		map[string]string{"prod": "production"},
		[]string{"values.yaml", "values.stray.yaml"},
		map[string]bool{"values.yaml": true},
		map[string]string{},
	)
	if len(findings) != 1 || !strings.Contains(findings[0], "values.stray.yaml") {
		t.Fatalf("непредлагаемый профиль без причины не найден: %v", findings)
	}
}

func TestOfferedChainPostures_StaleRegisterEntryIsAFinding(t *testing.T) {
	// САМОИСТЕЧЕНИЕ (первая сторона): запись называет профиль, которого в
	// поставке нет.
	findings := judgeOfferedChainPostures(
		map[string]string{"prod": "production"},
		[]string{"values.yaml"},
		map[string]bool{"values.yaml": true},
		map[string]string{"values.gone.yaml": "причина, у которой не осталось предмета"},
	)
	if len(findings) != 1 || !strings.Contains(findings[0], "values.gone.yaml") {
		t.Fatalf("протухшая запись ведомости не найдена: %v", findings)
	}
}

func TestOfferedChainPostures_ExcusedProfileBackInAChainIsAFinding(t *testing.T) {
	// САМОИСТЕЧЕНИЕ (вторая сторона): прощённый профиль ВЕРНУЛСЯ в предлагаемую
	// цепочку. Без этой стороны прощение пережило бы свой предмет молча.
	findings := judgeOfferedChainPostures(
		map[string]string{"prod": "production"},
		[]string{"values.yaml", "values.fixture.yaml"},
		map[string]bool{"values.yaml": true, "values.fixture.yaml": true},
		map[string]string{"values.fixture.yaml": "фикстура открытого текста"},
	)
	if len(findings) != 1 || !strings.Contains(findings[0], "тому, кого теперь судят") {
		t.Fatalf("возвращённый в цепочку прощённый профиль не найден: %v", findings)
	}
}

// TestOfferedChainPostures_MergeFollowsHelmOverlayRules — предпосылка гейта:
// посадку задаёт НАЛОЖЕНИЕ, а не отдельный файл. Без этого гейт судил бы
// базовые значения, которые в одиночку не устанавливаются.
func TestOfferedChainPostures_MergeFollowsHelmOverlayRules(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("синтетический профиль не записан: %v", err)
		}
	}
	write("base.yaml", "authMode: production\nrepository:\n  postgres:\n    sslMode: disable\n")
	write("overlay.yaml", "authMode: dev\n")

	posture, read := chainPosture(t, dir, []string{"base.yaml", "overlay.yaml"})
	if read != 2 {
		t.Fatalf("прочитано наложений %d, ожидалось 2", read)
	}
	if posture != "dev" {
		t.Fatalf("накладка не понизила посадку: %q — гейт молчал бы о понижающей накладке", posture)
	}

	// ЗАКОННЫЙ БЛИЗНЕЦ: та же база без понижающей накладки остаётся боевой.
	posture, _ = chainPosture(t, dir, []string{"base.yaml"})
	if posture != "production" {
		t.Fatalf("база без накладки прочитана как %q, ожидалось production", posture)
	}
}
