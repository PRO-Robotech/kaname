// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// checklimit_test.go — СКОЛЬКО читает обход дерева.
//
// Читатель, у которого предела нет, кладёт в память ровно столько, сколько ему
// подали. Обход дерева подаёт то, что в дереве лежит, а не то, что мы
// задумали, — и файл с именем манифеста бывает порождён сборкой, слит из
// журнала, склеен по ошибке. Проверка, легшая на таком файле, не даёт вердикта
// НИ ПО ОДНОМУ манифесту дерева, включая прочитанные до него.
//
// Свойство: чтение ограничено по размеру, а превышение есть НАХОДКА С
// ВЕЛИЧИНОЙ — не отказ проверки и не молчание. Величина в тексте обязательна:
// без неё читателю нечем решить, чинить ли файл или поднять предел.
//
// Граница проверяется С ОБЕИХ СТОРОН: ровно предел проходит, предел плюс байт —
// находка. Одностороннее утверждение зеленело бы на читателе, отвергающем всё.
package manifest

import (
	"strconv"
	"strings"
	"testing"
)

// manifestOfSize — годный манифест, дополненный комментарием до РОВНО size байт.
//
// Дополняется именно годный, а не произвольный мусор: негодный дал бы находку и
// без всякого предела, и проба зеленела бы на отказе разбора, ничего не сказав о
// размере.
func manifestOfSize(t *testing.T, size int) string {
	t.Helper()
	good := goodManifest(t)
	pad := size - len(good)
	if pad < 2 {
		t.Fatalf("предел %d не больше фикстуры (%d байт) хотя бы на два байта — "+
			"вход не произвести", size, len(good))
	}
	body := good + "\n" + strings.Repeat("#", pad-1)
	if len(body) != size {
		t.Fatalf("вход НЕ ПРОИЗВЕДЁН: получено %d байт при заказанных %d", len(body), size)
	}
	return body
}

// TestCheckTreeRefusesAManifestOverTheLimitAndNamesTheValue — файл сверх предела
// есть находка, называющая место и обе величины; годный рядом читается.
func TestCheckTreeRefusesAManifestOverTheLimitAndNamesTheValue(t *testing.T) {
	oversized := manifestOfSize(t, manifestSizeLimit+1)

	root := writeTree(t, map[string]string{
		"services/vpc/manifest.yaml":  goodManifest(t),
		"services/huge/manifest.yaml": oversized,
	})

	report := CheckTree(root)

	if report.ExitCode() != CheckFailed {
		t.Fatalf("манифест сверх предела дал код %d, ожидался %d — предела нет: "+
			"перепись %s", report.ExitCode(), CheckFailed, report.Summary())
	}
	if report.ManifestsRead != 1 {
		t.Errorf("прочитано манифестов %d, положен 1 — превысивший предел не прочитан "+
			"и в число прочитанных не входит: %v", report.ManifestsRead, report.Paths)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("находок %d, ожидалась 1: %v", len(report.Findings), report.Findings)
	}
	fault := report.Findings[0]
	if !strings.Contains(fault, "services/huge/manifest.yaml") {
		t.Errorf("находка не называет места: %q", fault)
	}
	for _, want := range []string{strconv.Itoa(len(oversized)), strconv.Itoa(manifestSizeLimit)} {
		if !strings.Contains(fault, want) {
			t.Errorf("находка не называет величины %s — читателю нечем решить, "+
				"чинить файл или поднимать предел: %q", want, fault)
		}
	}
	t.Logf("находка: %s", fault)
}

// TestCheckTreeReadsAManifestExactlyAtTheLimit — законный близнец: ровно предел
// проходит МОЛЧА.
//
// Граница принадлежит годной стороне намеренно: предел есть верхняя допустимая
// величина, а не первая запрещённая, и «не больше предела» читается однозначно.
func TestCheckTreeReadsAManifestExactlyAtTheLimit(t *testing.T) {
	root := writeTree(t, map[string]string{
		"services/vpc/manifest.yaml": manifestOfSize(t, manifestSizeLimit),
	})

	report := CheckTree(root)

	if report.ExitCode() != CheckOK {
		t.Fatalf("манифест РОВНО в предел дал код %d, ожидался %d: %v",
			report.ExitCode(), CheckOK, report.Findings)
	}
	if report.ManifestsRead != 1 {
		t.Errorf("прочитано манифестов %d, положен 1: %v", report.ManifestsRead, report.Paths)
	}
	t.Logf("перепись: %s (предел %d байт)", report.Summary(), manifestSizeLimit)
}
