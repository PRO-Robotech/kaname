// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// seed_identity_census_test.go — числа §0 приёмки посевной идентичности
// обязаны воспроизводиться ЕЁ СОБСТВЕННЫМ предикатом.
//
// Разбор, довод и граница — годок `seed_identity_census.go`. Здесь то, что
// добавляет прогон: он ЗОВЁТ предикат, а не пересказывает его вывод.
package check_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/treeroot"
)

const (
	// seedCensusDoc — единственный дом объявления, ОТ КОРНЯ своего модуля.
	seedCensusDoc = "docs/engineering/acceptance/seed-identity-names-its-own-service.md"
	// seedCensusPredicate — единственный дом предиката, рядом с приёмкой.
	seedCensusPredicate = "docs/engineering/acceptance/seed-identity-names-its-own-service.py"
)

// TestSeedIdentityCensusMatchesItsAcceptance — объявление §0 сверяется с
// выводом предиката ПО КАЖДОМУ ведру.
//
// # ТРИ ИСХОДА, И ТРЕТИЙ НЕ ЗАСЧИТЫВАЕТСЯ В УСПЕХ
//
// Нет корня модуля, нет приёмки, нет предиката, нет `python3`, предикат
// отказал своим кодом 2 — это «НЕ ВЫПОЛНИЛОСЬ»: проба не исполнялась, и
// молчание здесь не означает «сошлось». Пропуска нет ни у одного из пяти
// намеренно: каждый — поломка условий прогона, а не факт расписания.
//
// # ЧТО СУДИТСЯ, А ЧТО ПЕЧАТАЕТСЯ ПЕРЕПИСЬЮ
//
// Судится равенство объявленного и произведённого. Печатаются — всегда, а не
// при находке — объём осмотренного предикатом и число прочитанных строк
// объявляющего блока: «ноль расхождений» обязано быть отличимо от «ноль
// прочитанного», и без обеих величин эти два исхода выглядят одинаково.
func TestSeedIdentityCensusMatchesItsAcceptance(t *testing.T) {
	root, err := treeroot.ModuleRootFrom(".")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не назван: %v", err)
	}

	docPath := filepath.Join(root, seedCensusDoc)
	// Координата константна и берётся от корня модуля: чтения по пути из чужого
	// ввода здесь нет.
	doc, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: приёмка %s не прочитана: %v", seedCensusDoc, err)
	}
	if _, err := os.Stat(filepath.Join(root, seedCensusPredicate)); err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: предиката %s нет: %v — сверять объявление "+
			"не с чем, и это не ноль находок", seedCensusPredicate, err)
	}

	rep := runSeedCensusPredicate(t, root)
	decl := check.ParseSeedCensusDeclaration(string(doc), rep.Order)

	if decl.Revision == "" {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: приёмка не называет ревизию измерения — "+
			"числа §0 не привязаны ни к чему, и сверять их не с чем.\n"+
			"починить: назвать ревизию строкой «**Ревизия измерения: `<хеш>`**» в шапке %s",
			seedCensusDoc)
	}
	if decl.BlockLines == 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: в приёмке нет блока, объявляющего числа при "+
			"ревизии %s — обход пуст, вердикт беспредметен.\n"+
			"починить: прогнать предикат и положить его вывод блоком, чья шапка называет "+
			"эту ревизию", decl.Revision)
	}

	t.Logf("осмотрено: предикат прочитал %d файлов из %d в индексе (двоичных %d) · "+
		"объявляющий блок при ревизии %s — %d строк · вёдер у предиката %d, объявлено %d",
		rep.Read, rep.Indexed, rep.Binary, decl.Revision, decl.BlockLines,
		len(rep.Buckets), len(decl.Buckets))

	requireSeedCensusRevisionIsOurs(t, root, decl.Revision)

	findings := check.AdjudicateSeedCensus(decl, rep)
	if len(findings) == 0 {
		return
	}
	t.Fatalf("числа §0 приёмки разошлись с её собственным предикатом — %d:\n  %s\n\n"+
		"починить ОДНИМ изменением, как велит сама приёмка:\n"+
		"    python3 %s\n"+
		"перенести вывод в блок §0 и переписать строку ревизии измерения на ревизию "+
		"этого замера.\n\n"+
		"почему это находка, а не устаревание: числа §0 объявлены выводом ЭТОГО "+
		"предиката. Пока их никто не сверяет, «перемерено» и «переписано по памяти» "+
		"выглядят одинаково — расхождение, ради которого гейт заведён, уже наступало: "+
		"объявление называло по ведру ПРЕДМЕТА 130 · 54 ф., предикат давал 130 · 56 ф., "+
		"и вхождений при этом было СТОЛЬКО ЖЕ.",
		len(findings), strings.Join(findings, "\n  "), seedCensusPredicate)
}

// runSeedCensusPredicate зовёт предикат и разбирает его вывод.
//
// Предикат зовётся НА РАБОЧЕМ ДЕРЕВЕ, а не на объявленной ревизии, и это
// решение, а не удобство: замер на своей ревизии верен вечно и потому не
// краснеет никогда — то есть не держит ничего. Судится утверждение приёмки о
// ТОМ ДЕРЕВЕ, которое сейчас в руках у читателя.
func runSeedCensusPredicate(t *testing.T, root string) check.SeedCensusReport {
	t.Helper()

	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: python3 не найден: %v — предикат приёмки "+
			"написан на нём, и без него о числах §0 не известно ничего", err)
	}

	// Обе части команды константны — имя интерпретатора и координата предиката.
	cmd := exec.Command(python, seedCensusPredicate)
	cmd.Dir = root
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 2 {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: предикат ОТКАЗАЛ по беспредметности "+
				"(код 2): %s — мерить оказалось нечего, и это не ноль находок",
				strings.TrimSpace(stderr.String()))
		}
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: предикат не отработал: %v\n%s",
			err, strings.TrimSpace(stderr.String()))
	}

	rep, perr := check.ParseSeedCensusOutput(string(out))
	if perr != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: вывод предиката не разобран: %v\n%s", perr, out)
	}
	return rep
}

// requireSeedCensusRevisionIsOurs — ревизия измерения обязана входить в историю
// ЭТОГО дерева.
//
// Резолва мало: у рабочих копий одного клона общая база объектов, поэтому
// `cat-file -t` отвечает «да» о коммите чужой линии. Тот же класс держит
// `TestDocsMeasurementIsDatedByRevision`; здесь он повторён для ОДНОЙ строки —
// той, к которой привязаны все числа §0.
//
// Недоступность git — «НЕ ВЫПОЛНИЛОСЬ», а не проход: неполученный ответ не
// означает «предок».
func requireSeedCensusRevisionIsOurs(t *testing.T, root, rev string) {
	t.Helper()

	// `rev` приходит из документа и уже проверен формой (`revPattern` — только
	// шестнадцатеричные), поэтому в командную строку уходит хеш, а не чужая строка.
	cmd := exec.Command("git", "-C", root, "merge-base", "--is-ancestor", rev, "HEAD")
	err := cmd.Run()
	if err == nil {
		return
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: git не ответил о ревизии %s: %v", rev, err)
	}
	if exitErr.ExitCode() == 1 {
		t.Fatalf("ревизия измерения %s НЕ ВХОДИТ в историю этого дерева: числа §0 "+
			"относятся к чужой линии, и перемерить их здесь нельзя.\n"+
			"починить: прогнать предикат на этом дереве и назвать ревизию его замера", rev)
	}
	t.Fatalf("ревизия измерения %s не разрешается в этом дереве (git: код %d) — "+
		"строка, к которой привязаны все числа §0, не является координатой",
		rev, exitErr.ExitCode())
}
