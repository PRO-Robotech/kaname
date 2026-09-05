// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

// checkroot_unix_test.go — ЧТО ИМЕННО читает обход дерева.
//
// Обход порождает путь сам, и потому кажется, что читать по нему безопасно.
// Между тем, как обход прочитал запись каталога, и тем, как читатель открыл
// путь, лежит окно: подменённая ссылка уводит чтение за корень, а именованный
// канал с тем же именем кладёт чтение навсегда. Ни то, ни другое не гипотеза —
// обход дерева встречает то, что в дереве лежит, а не то, что мы задумали.
//
// Свойство, которое здесь утверждается, одно: читается ТОЛЬКО обычный файл,
// лежащий ПОД КОРНЕМ обхода; всё прочее есть НАХОДКА, а не молчание и не отказ
// целиком.
//
// Пробы под `unix`, потому что производители входа — именованный канал и
// символическая ссылка — заводятся средствами unix. Продукт разворачивается на
// linux, и свойство держится там, где он работает.
package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// checkTreeWithin — CheckTree с пределом ожидания.
//
// Зависание — отдельный исход, и его надо ОТЛИЧАТЬ от находки: проба, просто
// вызвавшая CheckTree, на зависании молчала бы до общего предела прогона и
// сообщила бы «panic: test timed out», не назвав ни предмета, ни места.
func checkTreeWithin(t *testing.T, root string, limit time.Duration) CheckReport {
	t.Helper()
	type result struct{ r CheckReport }
	done := make(chan result, 1)
	go func() { done <- result{CheckSyntheticTree(root)} }()
	select {
	case res := <-done:
		return res.r
	case <-time.After(limit):
		t.Fatalf("CheckTree не вернулся за %s — обход ЗАВИС: чтение открыло то, "+
			"что обычным файлом не является, и ждёт писателя. Зависшая проверка хуже "+
			"упавшей: её нельзя отличить от медленной", limit)
		return CheckReport{}
	}
}

// TestCheckTreeReadsOnlyWhatLiesUnderTheRoot — ссылка, уводящая за корень, есть
// НАХОДКА, а её содержимое в отчёт не попадает.
//
// Годный манифест рядом — положительный контроль: без него проба зеленела бы на
// проверке, отвергающей всё, а «прочитано ноль» неотличимо от «прочитано и
// отвергнуто».
func TestCheckTreeReadsOnlyWhatLiesUnderTheRoot(t *testing.T) {
	outside := t.TempDir()
	// Содержимое за корнем — ГОДНЫЙ манифест другого модуля. Выбор намеренный:
	// негодное дало бы находку и без всякого ограничения корнем, и проба
	// зеленела бы на отказе разбора, ничего не сказав о том, читали мы за
	// корнем или нет.
	beyond := strings.Replace(goodManifest(t), "module: vpc", "module: loadbalancer", 1)
	beyondPath := filepath.Join(outside, "за-корнем.yaml")
	if err := os.WriteFile(beyondPath, []byte(beyond), 0o600); err != nil {
		t.Fatalf("файл за корнем: %v", err)
	}

	root := writeTree(t, map[string]string{
		"services/vpc/manifest.yaml": goodManifest(t),
	})
	if err := os.MkdirAll(filepath.Join(root, "services", "escape"), 0o755); err != nil {
		t.Fatalf("каталог: %v", err)
	}
	link := filepath.Join(root, "services", "escape", "manifest.yaml")
	if err := os.Symlink(beyondPath, link); err != nil {
		t.Fatalf("ссылка за корень: %v", err)
	}

	report := checkTreeWithin(t, root, 20*time.Second)

	if report.ExitCode() != CheckFailed {
		t.Fatalf("ссылка за корень дала код %d, ожидался %d: чтение ушло за корень "+
			"и никто этого не заметил; перепись: %s, взято %v",
			report.ExitCode(), CheckFailed, report.Summary(), report.Paths)
	}
	if report.ManifestsRead != 1 {
		t.Errorf("прочитано манифестов %d, положен 1 — за корнем читать нечего: %v",
			report.ManifestsRead, report.Paths)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("находок %d, ожидалась 1: %v", len(report.Findings), report.Findings)
	}
	fault := report.Findings[0]
	if !strings.Contains(fault, "services/escape/manifest.yaml") {
		t.Errorf("находка не называет места: %q", fault)
	}
	if !strings.Contains(fault, "корн") {
		t.Errorf("находка не называет предмета — читателю нечем чинить: %q", fault)
	}
	// Содержимое из-за корня не вправе доехать до отчёта даже строкой отказа:
	// иначе проверка сама выносит наружу то, что лежит за корнем.
	if strings.Contains(strings.Join(report.Findings, "\n"), "loadbalancer") {
		t.Errorf("отчёт вынес содержимое из-за корня: %v", report.Findings)
	}
	t.Logf("находка: %s", fault)
}

// TestCheckTreeReadsAManifestReachedByALinkInsideTheRoot — законный близнец
// предыдущей пробы: ссылка, остающаяся ПОД корнем, читается.
//
// Без неё «ссылка за корень отвергнута» было бы неотличимо от «ссылки
// запрещены вообще», а это другое свойство и другая политика.
func TestCheckTreeReadsAManifestReachedByALinkInsideTheRoot(t *testing.T) {
	root := writeTree(t, map[string]string{
		// Имя источника НЕ manifest.yaml: иначе обход посчитал бы его сам, и
		// «прочитан 1» получилось бы даром, мимо ссылки.
		"shared/vpc.source.yaml": goodManifest(t),
	})
	if err := os.MkdirAll(filepath.Join(root, "services", "vpc"), 0o755); err != nil {
		t.Fatalf("каталог: %v", err)
	}
	link := filepath.Join(root, "services", "vpc", "manifest.yaml")
	if err := os.Symlink(filepath.Join("..", "..", "shared", "vpc.source.yaml"), link); err != nil {
		t.Fatalf("ссылка под корнем: %v", err)
	}

	report := checkTreeWithin(t, root, 20*time.Second)

	if report.ExitCode() != CheckOK {
		t.Fatalf("ссылка ПОД корнем дала код %d, ожидался %d — отвергнуты ссылки "+
			"как таковые, а не выход за корень; находки: %v",
			report.ExitCode(), CheckOK, report.Findings)
	}
	if report.ManifestsRead != 1 {
		t.Errorf("прочитано манифестов %d, положен 1: %v", report.ManifestsRead, report.Paths)
	}
	t.Logf("перепись: %s, взято %v", report.Summary(), report.Paths)
}

// TestCheckTreeRefusesWhatIsNotARegularFileInsteadOfHanging — именованный канал
// с именем манифеста есть НАХОДКА, а не вечное ожидание.
//
// Открытие такого канала на чтение ждёт писателя БЕЗ СРОКА. Зависшая проверка
// хуже упавшей: у неё нет вердикта вовсе, и отличить её от медленной нечем.
func TestCheckTreeRefusesWhatIsNotARegularFileInsteadOfHanging(t *testing.T) {
	root := writeTree(t, map[string]string{
		"services/vpc/manifest.yaml": goodManifest(t),
	})
	if err := os.MkdirAll(filepath.Join(root, "services", "pipe"), 0o755); err != nil {
		t.Fatalf("каталог: %v", err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "services", "pipe", "manifest.yaml"), 0o600); err != nil {
		t.Fatalf("именованный канал: %v", err)
	}

	report := checkTreeWithin(t, root, 20*time.Second)

	if report.ExitCode() != CheckFailed {
		t.Fatalf("именованный канал дал код %d, ожидался %d; перепись: %s",
			report.ExitCode(), CheckFailed, report.Summary())
	}
	if report.ManifestsRead != 1 {
		t.Errorf("прочитано манифестов %d, положен 1 — годный рядом обязан быть "+
			"прочитан, канал прочитан быть не может: %v", report.ManifestsRead, report.Paths)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("находок %d, ожидалась 1: %v", len(report.Findings), report.Findings)
	}
	fault := report.Findings[0]
	if !strings.Contains(fault, "services/pipe/manifest.yaml") {
		t.Errorf("находка не называет места: %q", fault)
	}
	if !strings.Contains(fault, "обычн") {
		t.Errorf("находка не называет предмета: %q", fault)
	}
	t.Logf("находка: %s", fault)
}
