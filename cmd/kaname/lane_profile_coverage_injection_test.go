// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// lane_profile_coverage_injection_test.go — способность гейта покрытия полос
// упасть и смолчать, доказанная инъекцией В ОБЕ СТОРОНЫ.
//
// Инъекция зовёт ТУ ЖЕ функцию, что исполняется на дереве (judgeLaneCoverage),
// а не свою копию предиката: копия разошлась бы с настоящим гейтом молча — и
// разошлась бы там, где расхождение не видно.
//
// Каждый отрицательный случай отличается от своего положительного близнеца
// РОВНО ОДНИМ фактом. Дельта в два факта не сказала бы, который из них дал
// красное.
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Дефект: полосу умеют поднять, и ни один профиль её не объявляет. Обязано
// находиться — иначе возможность есть, а узнать о ней арендатору неоткуда.
func TestInjection_AReachableLaneWithNoProfileIsFound(t *testing.T) {
	_, _, findings := judgeLaneCoverage([]laneFact{
		{Lane: "synthetic", Reachable: true, Profiled: false},
	})
	if len(findings) != 1 || !strings.Contains(findings[0], "synthetic") {
		t.Fatalf("достижимая полоса без профиля не найдена: %v", findings)
	}
	if !strings.Contains(findings[0], "НИ ОДИН профиль") {
		t.Fatalf("находка обязана называть предмет, получено: %q", findings[0])
	}
}

// Законный близнец: та же полоса, объявленная профилем, — молчание. РОВНО ОДИН
// изменённый факт против случая выше.
func TestInjection_AReachableLaneWithAProfileIsSilent(t *testing.T) {
	profiled, reachable, findings := judgeLaneCoverage([]laneFact{
		{Lane: "synthetic", Reachable: true, Profiled: true, ProfileNames: []string{"values.synthetic.yaml"}},
	})
	if len(findings) != 0 {
		t.Fatalf("достижимая объявленная полоса объявлена находкой: %v", findings)
	}
	if profiled != 1 || reachable != 1 {
		t.Fatalf("перепись не засчитала полосу: объявлено %d, поднимается %d", profiled, reachable)
	}
}

// Дефект С ДРУГОЙ СТОРОНЫ: профиль обещает посадку, которую корень отвергает.
// Без этого случая гейт чинился бы профилем-обещанием.
func TestInjection_AnUnreachableLaneWithAProfileIsFound(t *testing.T) {
	_, _, findings := judgeLaneCoverage([]laneFact{
		{
			Lane: "synthetic", Reachable: false, Profiled: true,
			ProfileNames: []string{"values.synthetic.yaml"},
			Refusal:      "нечем впустить человека",
		},
	})
	if len(findings) != 1 || !strings.Contains(findings[0], "values.synthetic.yaml") {
		t.Fatalf("недостижимая объявленная полоса не найдена: %v", findings)
	}
	if !strings.Contains(findings[0], "нечем впустить человека") {
		t.Fatalf("находка обязана нести ОТКАЗ корня, иначе читателю нечем её проверить: %q", findings[0])
	}
}

// Законный близнец второго рода: недостижимая полоса, которую никто не
// объявляет, находкой не является — и в обе величины переписи не входит.
// Одно число скрыло бы ровно этот случай.
func TestInjection_AnUnreachableLaneWithNoProfileIsSilentAndNotCounted(t *testing.T) {
	profiled, reachable, findings := judgeLaneCoverage([]laneFact{
		{Lane: "synthetic", Reachable: false, Profiled: false, Refusal: "нечем впустить человека"},
	})
	if len(findings) != 0 {
		t.Fatalf("недостижимая необъявленная полоса объявлена находкой: %v", findings)
	}
	if profiled != 0 || reachable != 0 {
		t.Fatalf("перепись засчитала то, чего нет: объявлено %d, поднимается %d", profiled, reachable)
	}
}

// Пустой вход не производит находок И не производит переписи: «ноль находок»
// на пустом обходе обязано быть отличимо от «ноль прочитанного», и различает их
// падение самого гейта по дереву (t.Fatal на пустом перечне полос).
func TestInjection_AnEmptyWalkProducesNothingToJudge(t *testing.T) {
	profiled, reachable, findings := judgeLaneCoverage(nil)
	if len(findings) != 0 || profiled != 0 || reachable != 0 {
		t.Fatalf("пустой вход обязан не производить ничего: находок %v, объявлено %d, поднимается %d",
			findings, profiled, reachable)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ЧТЕНИЕ ОБЪЯВЛЕНИЙ: корней два, и слепота на одном из них — тихая (задача #2101)
//
// Инъекции ниже зовут readLaneDeclarations — ТО ЖЕ тело, что исполняется на
// дереве. Оси разведены по одному факту: корень · значение · читаемость файла.
//
// Живая инъекция, которой эти оси выведены, названа здесь, чтобы её можно было
// повторить: посадка `own`, вписанная в боевой профиль ЧАРТА ПРОДУКТА, до
// правки оставляла гейт зелёным (профилей он читал 11, все — зонтичные), после
// правки даёт находку, НАЗЫВАЮЩУЮ координату этого профиля.

// writeValues — файл значений с названным содержимым.
func writeValues(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "values.prod.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	return p
}

// productSource — источник корня ПРОДУКТА с ключами чарта продукта.
func productSource(path, label string) profileSource {
	return profileSource{
		Root: productRootName, Label: label, Path: path,
		Keys: []string{"authn", "identityProvider"},
	}
}

// Дефект: профиль ЧАРТА ПРОДУКТА объявил посадку. До правки этот корень не
// читался вовсе, и объявление не доезжало до судьи ни при каком значении.
func TestInjection_AProductChartProfileDeclaringALaneIsRead(t *testing.T) {
	src := productSource(writeValues(t, "authn:\n  identityProvider: own\n"),
		"services/iam/deploy/values.prod.yaml")

	declared, census := readLaneDeclarations([]profileSource{src})
	if got := declared["own"]; len(got) != 1 || got[0] != src.Label {
		t.Fatalf("объявление продуктового профиля не доехало до судьи: %v", declared)
	}
	if len(census) != 1 || census[0].Root != productRootName || census[0].Parsed != 1 {
		t.Fatalf("перепись не назвала корень продукта: %+v", census)
	}

	_, _, findings := judgeLaneCoverage([]laneFact{{
		Lane: "own", Reachable: false, Profiled: true,
		ProfileNames: declared["own"], Refusal: "нечем впустить человека",
	}})
	if len(findings) != 1 || !strings.Contains(findings[0], src.Label) {
		t.Fatalf("находка не назвала КООРДИНАТУ продуктового профиля: %v", findings)
	}
}

// Законный близнец: тот же файл того же корня с ПОДЪЁМНЫМ значением — полоса
// `own` не объявлена никем, судить нечего. Отличается ровно одним фактом.
func TestInjection_AProductChartProfileDeclaringARaisableLaneIsSilent(t *testing.T) {
	src := productSource(writeValues(t, "authn:\n  identityProvider: external\n"),
		"services/iam/deploy/values.prod.yaml")

	declared, _ := readLaneDeclarations([]profileSource{src})
	if len(declared["own"]) != 0 {
		t.Fatalf("подъёмное значение прочитано как неподъёмное: %v", declared)
	}
	if got := declared["external"]; len(got) != 1 || got[0] != src.Label {
		t.Fatalf("подъёмная полоса не засчитана объявленной: %v", declared)
	}
}

// Ось КЛЮЧЕЙ: у корней они разные, и ключи зонта на файле продукта не находят
// ничего. Без этой оси перепутанные местами ключи дали бы «полосу не объявляет»
// — то есть слепоту, неотличимую от исправной работы.
func TestInjection_UmbrellaKeysDoNotReadAProductChartProfile(t *testing.T) {
	path := writeValues(t, "authn:\n  identityProvider: own\n")
	wrong := profileSource{
		Root: umbrellaRootName, Label: "values.prod.yaml", Path: path,
		Keys: []string{"kaname", "config", "authn", "identityProvider"},
	}
	declared, census := readLaneDeclarations([]profileSource{wrong})
	if len(declared) != 0 {
		t.Fatalf("ключи чужого корня прочитали объявление: %v", declared)
	}
	if census[0].Parsed != 1 || len(census[0].Unreadable) != 0 {
		t.Fatalf("файл разобран, но объявления в нём нет — перепись обязана это показать: %+v", census)
	}
}

// «НЕ ПРОЧИТАН» НЕ ОЗНАЧАЕТ «ПОЛОСУ НЕ ОБЪЯВЛЯЕТ», и различает их только
// перепись: оба случая дают ноль объявлений.
func TestInjection_AnUnparsableProfileIsCountedApartFromOneDeclaringNothing(t *testing.T) {
	broken := productSource(filepath.Join(t.TempDir(), "нет-такого.yaml"), "нет-такого.yaml")
	_, census := readLaneDeclarations([]profileSource{broken})
	if len(census) != 1 || census[0].Parsed != 0 || len(census[0].Unreadable) != 1 {
		t.Fatalf("неразобранный файл не отделён от необъявляющего: %+v", census)
	}
}

// Перепись ведётся ПО КОРНЯМ. Одно сводное число скрыло бы корень, который не
// читали вовсе, — ровно ту слепоту, ради которой правка.
func TestInjection_CensusSeparatesTheTwoRoots(t *testing.T) {
	product := productSource(writeValues(t, "authn:\n  identityProvider: external\n"), "чарт-продукта")
	umbrella := profileSource{
		Root:  umbrellaRootName,
		Label: "зонт",
		Path:  writeValues(t, "kaname:\n  config:\n    authn:\n      identityProvider: external\n"),
		Keys:  []string{"kaname", "config", "authn", "identityProvider"},
	}
	_, census := readLaneDeclarations([]profileSource{product, umbrella})
	if len(census) != 2 {
		t.Fatalf("перепись слила корни в один: %+v", census)
	}
	seen := map[string]int{}
	for _, c := range census {
		seen[c.Root] = c.Parsed
	}
	if seen[productRootName] != 1 || seen[umbrellaRootName] != 1 {
		t.Fatalf("перепись не назвала оба корня порознь: %v", seen)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// НАКЛАДКА ОПЕРАТОРА — ВТОРАЯ ЗАКОННАЯ ФОРМА ОБЪЯВЛЕНИЯ (задача kaname#232)
//
// Инъекции зовут readLaneDeclarations и judgeLaneCoverage — ТЕ ЖЕ тела, что
// исполняются на дереве. Ось одна на пару: строка посадки в накладке ·
// читаемость профиля под ней · форма строки.

// overlaySource — накладка оператора поверх названного профиля.
func overlaySource(base string, sets ...string) profileSource {
	return profileSource{
		Root: overlayRootName, Label: overlayLabel("deploy/values.prod.yaml", "synthetic"), Path: base,
		Keys: []string{"authn", "identityProvider"}, Sets: sets,
	}
}

// Законный близнец: накладка поверх разобранного профиля объявляет `own` —
// поднимаемая полоса засчитана объявленной, находок нет.
func TestInjection_AnOverlayDeclaringAReachableLaneIsSilent(t *testing.T) {
	base := writeValues(t, "authn:\n  identityProvider: external\n")
	src := overlaySource(base, "authn.identityProvider=own", "authn.clientToken.enabled=true")

	declared, census := readLaneDeclarations([]profileSource{src})
	if got := declared["own"]; len(got) != 1 || got[0] != src.Label {
		t.Fatalf("объявление накладки не доехало до судьи: %v", declared)
	}
	if len(census) != 1 || census[0].Root != overlayRootName || census[0].Parsed != 1 {
		t.Fatalf("перепись не назвала корень накладок: %+v", census)
	}
	_, _, findings := judgeLaneCoverage([]laneFact{{
		Lane: "own", Reachable: true, Profiled: len(declared["own"]) > 0, ProfileNames: declared["own"],
	}})
	if len(findings) != 0 {
		t.Fatalf("поднимаемая полоса, объявленная накладкой, объявлена находкой: %v", findings)
	}
}

// Дефект: та же накладка БЕЗ строки посадки — полосу не объявляет никто, и
// поднимаемая полоса обязана быть находкой. Отличается от близнеца ровно
// строкой посадки.
func TestInjection_AnOverlayWithoutTheLaneLeavesAReachableLaneUndeclared(t *testing.T) {
	base := writeValues(t, "authn:\n  identityProvider: external\n")
	src := overlaySource(base, "authn.clientToken.enabled=true")

	declared, census := readLaneDeclarations([]profileSource{src})
	if len(declared["own"]) != 0 {
		t.Fatalf("накладка без строки посадки засчитана объявляющей: %v", declared)
	}
	if census[0].Parsed != 1 || len(census[0].Unreadable) != 0 {
		t.Fatalf("накладка разобрана, но посадки не объявляет — перепись обязана это показать: %+v", census)
	}
	_, _, findings := judgeLaneCoverage([]laneFact{{
		Lane: "own", Reachable: true, Profiled: len(declared["own"]) > 0, ProfileNames: declared["own"],
	}})
	if len(findings) != 1 || !strings.Contains(findings[0], "ни одна накладка оператора") {
		t.Fatalf("поднимаемая полоса без объявления не найдена либо находка не называет обе формы: %v", findings)
	}
}

// Дефект С ДРУГОЙ СТОРОНЫ: накладка объявляет полосу, которую корень
// отвергает, — находка несёт координату НАКЛАДКИ, иначе читателю нечем её
// найти.
func TestInjection_AnOverlayDeclaringAnUnreachableLaneIsFoundWithItsCoordinate(t *testing.T) {
	base := writeValues(t, "authn:\n  identityProvider: external\n")
	src := overlaySource(base, "authn.identityProvider=own")

	declared, _ := readLaneDeclarations([]profileSource{src})
	_, _, findings := judgeLaneCoverage([]laneFact{{
		Lane: "own", Reachable: false, Profiled: len(declared["own"]) > 0, ProfileNames: declared["own"],
		Refusal: "нечем впустить человека",
	}})
	if len(findings) != 1 || !strings.Contains(findings[0], src.Label) {
		t.Fatalf("находка не назвала координату накладки: %v", findings)
	}
}

// «ПРОФИЛЬ ПОД НАКЛАДКОЙ НЕ ПРОЧИТАН» НЕ ОЗНАЧАЕТ «ПОСАДКУ НЕ ОБЪЯВЛЯЕТ»:
// накладка поверх профиля, которого нет, считается не разобранной и в
// объявления не входит.
func TestInjection_AnOverlayOverAMissingProfileIsCountedUnparsed(t *testing.T) {
	src := overlaySource(filepath.Join(t.TempDir(), "нет-такого.yaml"), "authn.identityProvider=own")

	declared, census := readLaneDeclarations([]profileSource{src})
	if len(declared) != 0 {
		t.Fatalf("накладка поверх отсутствующего профиля объявила посадку: %v", declared)
	}
	if len(census) != 1 || census[0].Parsed != 0 || len(census[0].Unreadable) != 1 {
		t.Fatalf("накладка поверх отсутствующего профиля не отделена от необъявляющей: %+v", census)
	}
}

// Строка не в форме `ключ=величина` — накладка не разобрана: helm её не
// примет, и засчитать объявление по ней значило бы засчитать то, что не
// ставится.
func TestInjection_AnOverlayWithAMalformedLineIsCountedUnparsed(t *testing.T) {
	base := writeValues(t, "authn:\n  identityProvider: external\n")
	src := overlaySource(base, "authn.identityProvider=own", "authn.clientToken.enabled")

	declared, census := readLaneDeclarations([]profileSource{src})
	if len(declared) != 0 {
		t.Fatalf("накладка с неразборной строкой объявила посадку: %v", declared)
	}
	if census[0].Parsed != 0 || len(census[0].Unreadable) != 1 {
		t.Fatalf("накладка с неразборной строкой не отделена от необъявляющей: %+v", census)
	}
}
