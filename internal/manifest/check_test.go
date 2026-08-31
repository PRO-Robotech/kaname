// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// check_test.go — ТРИ исхода проверки дерева (MOD-MF-17, 18, 19; приёмка §5.5).
//
// Проверяющий манифесты по дереву — прод-потребитель загрузчика: без него
// загрузчик вестигиален, а с ним негодный манифест роняет прогон, а не доезжает
// до посева.
//
// Исходов ТРИ, и третий обязателен. «Манифестов ноль» — не успех: дерево, в
// котором проверять нечего, отчитывалось бы зелёным ровно так же уверенно, как
// проверенное, и первый же манифест, положенный мимо ожидаемого имени, остался
// бы невидимым навсегда. Сегодня дерево именно пустое — манифестов в нём ноль, —
// поэтому третий исход не гипотетический, а тот, который цель отдаёт СЕЙЧАС.
package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTree — синтетическое дерево: путь относительно корня → содержимое.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("каталог %s: %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatalf("файл %s: %v", full, err)
		}
	}
	return root
}

// goodManifest — годный манифест: та же фикстура, что у остальных проб пакета.
func goodManifest(t *testing.T) string {
	t.Helper()
	return string(mustReadFixture(t))
}

// TestMODMF17GoodTreeExitsZeroAndNamesTheVolume — годное дерево: ноль и число
// прочитанных манифестов.
func TestMODMF17GoodTreeExitsZeroAndNamesTheVolume(t *testing.T) {
	root := writeTree(t, map[string]string{
		"services/vpc/manifest.yaml":     goodManifest(t),
		"services/compute/manifest.yaml": strings.Replace(goodManifest(t), "module: vpc", "module: compute", 1),
		"services/vpc/README.md":         "не манифест",
	})

	report := CheckTree(root)
	if report.ExitCode() != CheckOK {
		t.Fatalf("годное дерево дало код %d, ожидался %d; находки: %v",
			report.ExitCode(), CheckOK, report.Findings)
	}
	if report.ManifestsRead != 2 {
		t.Errorf("прочитано манифестов %d, положено 2 — «ноль находок» обязано быть "+
			"отличимо от «ноль прочитанного»", report.ManifestsRead)
	}
	if !strings.Contains(report.Summary(), "2") {
		t.Errorf("итог не называет числа прочитанных манифестов: %q", report.Summary())
	}
	t.Logf("перепись: %s", report.Summary())
}

// TestMODMF18BadManifestFailsTheRunAndNamesTheFix — негодный манифест роняет
// прогон и называет путь, предмет и способ починки.
func TestMODMF18BadManifestFailsTheRunAndNamesTheFix(t *testing.T) {
	root := writeTree(t, map[string]string{
		"services/vpc/manifest.yaml": goodManifest(t),
		"services/nlb/manifest.yaml": strings.Replace(goodManifest(t), "module: vpc", "module: nlb", 1),
	})

	report := CheckTree(root)
	if report.ExitCode() != CheckFailed {
		t.Fatalf("дерево с незнакомым модулем дало код %d, ожидался %d",
			report.ExitCode(), CheckFailed)
	}
	if report.ManifestsRead != 2 {
		t.Errorf("прочитано манифестов %d, положено 2: негодный манифест не должен "+
			"обрывать обход — иначе о следующих не известно ничего", report.ManifestsRead)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("находок %d, ожидалась 1: %v", len(report.Findings), report.Findings)
	}
	fault := report.Findings[0]
	for _, want := range []string{"services/nlb/manifest.yaml", "nlb", "loadbalancer"} {
		if !strings.Contains(fault, want) {
			t.Errorf("находка не называет %q — читателю нечем чинить: %q", want, fault)
		}
	}
	t.Logf("находка: %s", fault)
}

// TestMODMF19EmptyTreeIsVoidNotSuccess — манифестов ноль есть ТРЕТИЙ исход.
func TestMODMF19EmptyTreeIsVoidNotSuccess(t *testing.T) {
	root := writeTree(t, map[string]string{
		"services/vpc/README.md":  "манифеста здесь нет",
		"services/iam/Makefile":   "build:\n\ttrue\n",
		"deploy/values.prod.yaml": "manifest: не то, что ищем\n",
	})

	report := CheckTree(root)
	code := report.ExitCode()
	if code == CheckOK || code == CheckFailed {
		t.Fatalf("пустое дерево дало код %d — он обязан отличаться и от %d, и от %d: "+
			"иначе «проверять нечего» неотличимо от «проверено и годно»",
			code, CheckOK, CheckFailed)
	}
	if report.ManifestsRead != 0 {
		t.Errorf("прочитано манифестов %d при пустом дереве", report.ManifestsRead)
	}

	// Текст обязан ОТЛИЧАТЬСЯ от текста годного дерева: код возврата читает
	// оболочка, а человек читает строку, и она не вправе выглядеть успехом.
	good := writeTree(t, map[string]string{"services/vpc/manifest.yaml": goodManifest(t)})
	if report.Summary() == CheckTree(good).Summary() {
		t.Errorf("итог пустого дерева дословно совпал с итогом годного: %q", report.Summary())
	}
	if !strings.Contains(report.Summary(), "нечего") {
		t.Errorf("итог пустого дерева не говорит, что проверять нечего: %q", report.Summary())
	}
	t.Logf("перепись: %s (код %d)", report.Summary(), code)
}

// TestCheckTreeSkipsWhatIsNotOurs — обход не заглядывает туда, где манифеста
// быть не может, и не считает манифестом файл по одному лишь совпадению слова.
//
// Положительный контроль стоит рядом намеренно: без него проба зеленела бы на
// обходе, не находящем НИЧЕГО.
func TestCheckTreeSkipsWhatIsNotOurs(t *testing.T) {
	root := writeTree(t, map[string]string{
		"services/vpc/manifest.yaml":            goodManifest(t),
		"node_modules/pkg/manifest.yaml":        "мусор: не наш",
		"vendor/foreign/manifest.yaml":          "мусор: не наш",
		"ui-future/dist/assets/manifest.yaml":   "мусор: не наш",
		"services/vpc/manifest.yaml.bak":        "мусор: не наш",
		"services/vpc/deploy/app.manifest.yaml": "мусор: не наш",
	})
	// .git отдельно: имя каталога начинается с точки.
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatalf("каталог .git: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".git", "manifest.yaml"), []byte("мусор"), 0o644); err != nil {
		t.Fatalf("файл в .git: %v", err)
	}

	report := CheckTree(root)
	if report.ManifestsRead != 1 {
		t.Fatalf("прочитано манифестов %d, положен 1 — обход берёт лишнее либо "+
			"не берёт своего: %v", report.ManifestsRead, report.Paths)
	}
	if report.ExitCode() != CheckOK {
		t.Errorf("код %d при единственном годном манифесте: %v", report.ExitCode(), report.Findings)
	}
	t.Logf("перепись: осмотрено путей %d, взято %v", report.PathsSeen, report.Paths)
}

// TestCheckTreeReportsAnUnreadableRootRatherThanCallingItEmpty — корень, который
// не открылся, есть ОТКАЗ, а не пустое дерево.
//
// Без этого различия опечатка в пути превращается в «проверять нечего» и
// печатает успокоительную строку вместо находки.
func TestCheckTreeReportsAnUnreadableRootRatherThanCallingItEmpty(t *testing.T) {
	report := CheckTree(filepath.Join(t.TempDir(), "такого-каталога-нет"))
	if report.ExitCode() != CheckFailed {
		t.Fatalf("несуществующий корень дал код %d, ожидался %d", report.ExitCode(), CheckFailed)
	}
	if len(report.Findings) == 0 {
		t.Fatal("несуществующий корень не дал ни одной находки")
	}
	t.Logf("находка: %s", report.Findings[0])
}
