// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// surfaceaxis_injection_test.go — доказательство того, что обе пробы осей
// адреса СПОСОБНЫ упасть, и падают на своём предмете (#2479).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАЧЕМ ОТДЕЛЬНЫЙ ФАЙЛ, ЕСЛИ ГЕЙТ И ТАК ЗЕЛЁНЫЙ
//
// Шапка `surfaceaxis_test.go` называла этот файл с первого дня, а файла в
// дереве не было: способность упасть держалась ВНИМАНИЕМ, а на чистом дереве
// потерявший её гейт выглядит РОВНО ТАК ЖЕ, как исправный. Утверждение о
// доказательстве при отсутствующем доказательстве — тот самый класс, который
// корпус ловит в коде.
//
// ─────────────────────────────────────────────────────────────────────────────
// ОСЕЙ ИНЪЕКЦИИ ЧЕТЫРЕ, ПО ЧИСЛУ УТВЕРЖДЕНИЙ, КОТОРЫЕ ГЕЙТЫ ДЕЛАЮТ
//
//  1. МОЛЧАЩАЯ ОСЬ. Вызов `addrAxis` с пустым текстом причины обязан быть
//     назван координатой. Законный близнец — тот же вызов с непустым текстом:
//     разбор молчит. Без близнеца красное приходило бы от чего угодно —
//     например от разбора, краснеющего на любом вызове.
//  2. ПУСТОЙ ОБХОД. Каталог без осей обязан читаться как беспредметный вердикт,
//     а не как «все объясняют». Утверждается ЧИСЛОМ (осей 0), потому что сам
//     `t.Fatal` живёт в теле гейта и инъекции не поддаётся.
//  3. ТЕКСТ, СОБИРАЕМЫЙ НЕ ЛИТЕРАЛОМ. Причина, пришедшая переменной, за
//     объяснение НЕ засчитывается — это объявленное свойство разбора, и без
//     пробы оно неотличимо от недосмотра.
//  4. НЕНАЗВАННАЯ РУЧКА ФРОНТА. Исходник, где ось одного из фронтов не называет
//     своей ручки, обязан дать `false` по ЭТОЙ ручке и `true` по соседней.
//     Законный близнец — исходник, называющий обе.
//
// ─────────────────────────────────────────────────────────────────────────────
// ИНЪЕКЦИЯ РОНЯЕТ ТОЛЬКО ПРОВЕРЯЕМОЕ
//
// Настоящие исходники композиционного корня не правятся вовсе: обе пробы
// принимают источник ДОВОДОМ (каталог либо байты), поэтому синтетический вход
// живёт в `t.TempDir()` и ни один соседний гейт пакета его не видит.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeAxisSource кладёт один синтетический исходник композиционного корня и
// отдаёт каталог, в котором он лежит.
func writeAxisSource(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "serve.go"), []byte(body), 0o600); err != nil {
		t.Fatalf("синтетический исходник не записан: %v", err)
	}
	return dir
}

// axisSource — исходник с ОДНОЙ осью, чья причина задаётся доводом.
func axisSource(because string) string {
	return "package main\n\nfunc f() {\n\t_ = addrAxis(addr, " + because + ")\n}\n"
}

// TestSurfaceAxisInjection_SilentAxisIsCaught — ось с пустой причиной названа
// координатой.
func TestSurfaceAxisInjection_SilentAxisIsCaught(t *testing.T) {
	calls, explained, err := axisExplanations(writeAxisSource(t, axisSource(`""`)))
	if err != nil {
		t.Fatalf("обход синтетического каталога не состоялся: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("инъекция беспредметна: осей найдено %d, ожидалась 1", len(calls))
	}
	if explained[0] {
		t.Fatal("ось с ПУСТОЙ причиной зачтена объяснённой — гейт остался бы зелёным на " +
			"поверхности, которая выключается молча")
	}
	if !strings.HasPrefix(calls[0], "serve.go:") {
		t.Fatalf("находка не называет координаты: %q", calls[0])
	}
}

// TestSurfaceAxisInjection_LawfulTwinStaysSilent — законный близнец: та же
// форма вызова с непустой причиной молчит.
//
// Без него красное выше не доказывает ничего: разбор, объявляющий молчащей
// ЛЮБУЮ ось, дал бы тот же результат.
func TestSurfaceAxisInjection_LawfulTwinStaysSilent(t *testing.T) {
	_, explained, err := axisExplanations(writeAxisSource(t,
		axisSource(`"KANAME_X не задан: полоса на этой посадке не обслуживается"`)))
	if err != nil {
		t.Fatalf("обход синтетического каталога не состоялся: %v", err)
	}
	if len(explained) != 1 {
		t.Fatalf("инъекция беспредметна: осей найдено %d, ожидалась 1", len(explained))
	}
	if !explained[0] {
		t.Fatal("законная ось объявлена молчащей — гейт краснел бы на исправном дереве, " +
			"и первый же ложный срабат его отключил бы")
	}
}

// TestSurfaceAxisInjection_ConcatenatedTextCounts — склейка литералов остаётся
// объяснением: причина в этом дереве пишется в две строки чаще, чем в одну.
func TestSurfaceAxisInjection_ConcatenatedTextCounts(t *testing.T) {
	_, explained, err := axisExplanations(writeAxisSource(t,
		axisSource(`"KANAME_X не задан: " + "полоса не обслуживается"`)))
	if err != nil {
		t.Fatalf("обход синтетического каталога не состоялся: %v", err)
	}
	if len(explained) != 1 || !explained[0] {
		t.Fatalf("склейка литералов не зачтена объяснением: осей %d", len(explained))
	}
}

// TestSurfaceAxisInjection_NonLiteralTextIsNotAnExplanation — причина,
// пришедшая переменной, объяснением не считается.
//
// Это ОБЪЯВЛЕННОЕ свойство разбора («причина обязана читаться в месте
// объявления»), и без пробы оно неотличимо от недосмотра.
func TestSurfaceAxisInjection_NonLiteralTextIsNotAnExplanation(t *testing.T) {
	_, explained, err := axisExplanations(writeAxisSource(t, axisSource(`because`)))
	if err != nil {
		t.Fatalf("обход синтетического каталога не состоялся: %v", err)
	}
	if len(explained) != 1 {
		t.Fatalf("инъекция беспредметна: осей найдено %d, ожидалась 1", len(explained))
	}
	if explained[0] {
		t.Fatal("причина, собранная где-то ещё, зачтена объяснением — оператор читает при " +
			"старте текст, которого в месте объявления нет")
	}
}

// TestSurfaceAxisInjection_EmptyWalkIsAFinding — каталог без осей даёт НОЛЬ
// осмотренного, а гейт на нуле объявляет вердикт беспредметным.
//
// Утверждается число, а не исход гейта: `t.Fatal` живёт в его теле и инъекции
// не поддаётся. Число — то самое, по которому гейт и решает.
func TestSurfaceAxisInjection_EmptyWalkIsAFinding(t *testing.T) {
	calls, _, err := axisExplanations(writeAxisSource(t, "package main\n\nfunc f() {}\n"))
	if err != nil {
		t.Fatalf("обход синтетического каталога не состоялся: %v", err)
	}
	if len(calls) != 0 {
		t.Fatalf("каталог без осей дал %d осей — предпосылка инъекции неверна", len(calls))
	}
}

// TestSurfaceAxisInjection_TestFilesAreNotJudged — пробы каталога осями не
// считаются: этот файл и его соседи содержат слово `addrAxis` в синтетических
// исходниках, и разбор, судящий их, краснел бы на собственной инъекции.
func TestSurfaceAxisInjection_TestFilesAreNotJudged(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x_test.go"), []byte(axisSource(`""`)), 0o600); err != nil {
		t.Fatalf("синтетическая проба не записана: %v", err)
	}
	calls, _, err := axisExplanations(dir)
	if err != nil {
		t.Fatalf("обход синтетического каталога не состоялся: %v", err)
	}
	if len(calls) != 0 {
		t.Fatalf("ось, объявленная в файле пробы, зачтена предметом: %v", calls)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ОСЬ 4 — ручки фронтов.

// frontSource — исходник, чьи оси называют переданные ручки.
func frontSource(knobs ...string) string {
	body := "package main\n\nfunc f() {\n"
	for _, k := range knobs {
		body += "\t_ = addrAxis(addr, \"" + k + " не задан профилем развёртывания\")\n"
	}
	return body + "}\n"
}

// TestSurfaceAxisInjection_UnnamedFrontKnobIsCaught — исходник, где ось одного
// фронта не называет своей ручки, даёт `false` РОВНО по ней.
func TestSurfaceAxisInjection_UnnamedFrontKnobIsCaught(t *testing.T) {
	named, err := frontKnobsNamedByAxes("serve.go",
		[]byte(frontSource("KANAME_API_SERVER__REST_ENDPOINT")), restFrontKnobs)
	if err != nil {
		t.Fatalf("синтетический исходник не разбирается: %v", err)
	}
	if !named["KANAME_API_SERVER__REST_ENDPOINT"] {
		t.Fatal("названная ручка прочитана как неназванная — разбор не находит того, что есть")
	}
	if named["KANAME_API_SERVER__INTERNAL_REST_ENDPOINT"] {
		t.Fatal("ручка внутреннего фронта прочитана как названная, хотя ни одна ось её не " +
			"называет — состояние этого фронта при старте не сообщалось бы, а гейт молчал")
	}
}

// TestSurfaceAxisInjection_BothFrontKnobsTwinStaysSilent — законный близнец:
// исходник, называющий обе ручки, даёт `true` по обеим.
func TestSurfaceAxisInjection_BothFrontKnobsTwinStaysSilent(t *testing.T) {
	named, err := frontKnobsNamedByAxes("serve.go", []byte(frontSource(restFrontKnobs...)), restFrontKnobs)
	if err != nil {
		t.Fatalf("синтетический исходник не разбирается: %v", err)
	}
	for knob, found := range named {
		if !found {
			t.Fatalf("законно названная ручка %s прочитана как неназванная", knob)
		}
	}
}

// TestSurfaceAxisInjection_KnobInACommentIsNotAnAxis — имя ручки, встреченное
// комментарием, осью НЕ является: гейт судит разобранное дерево, а предикат по
// подстроке краснел бы на собственном объяснении.
func TestSurfaceAxisInjection_KnobInACommentIsNotAnAxis(t *testing.T) {
	body := "package main\n\n// KANAME_API_SERVER__INTERNAL_REST_ENDPOINT — про это ниже.\nfunc f() {\n" +
		"\t_ = addrAxis(addr, \"KANAME_API_SERVER__REST_ENDPOINT не задан\")\n}\n"
	named, err := frontKnobsNamedByAxes("serve.go", []byte(body), restFrontKnobs)
	if err != nil {
		t.Fatalf("синтетический исходник не разбирается: %v", err)
	}
	if named["KANAME_API_SERVER__INTERNAL_REST_ENDPOINT"] {
		t.Fatal("имя ручки из КОММЕНТАРИЯ зачтено осью — гейт судил бы прозу, а не объявление")
	}
}
