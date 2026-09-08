// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package refusaldomain_test

// tree_inject_test.go — ДОКАЗАТЕЛЬСТВО того, что гейт соседнего файла способен
// упасть и способен смолчать.
//
// Инъекция гоняет ТУ ЖЕ функцию обхода (`scanTree`), что и гейт: проверка,
// доказанная на своей копии разбора, доказывает свойство копии, а не гейта.
//
// Каждая проба меняет РОВНО ОДИН факт против своего положительного близнеца —
// иначе неизвестно, какая из правок дала красное, и «покраснел» перестаёт быть
// доказательством.

import (
	"os"
	"path/filepath"
	"testing"
)

// producerWiredSrc — законный близнец: домен БЕРЁТСЯ вызовом.
const producerWiredSrc = `package probe

import "google.golang.org/genproto/googleapis/rpc/errdetails"

func refuse() *errdetails.ErrorInfo {
	return &errdetails.ErrorInfo{Reason: "R", Domain: refusaldomain.For(refusaldomain.ServiceIAM)}
}
`

// producerHardcodedSrc — тот же файл, изменён РОВНО ОДИН факт: домен зашит
// именем константы.
const producerHardcodedSrc = `package probe

import "google.golang.org/genproto/googleapis/rpc/errdetails"

const legacyDomain = "iam.kacho.cloud"

func refuse() *errdetails.ErrorInfo {
	return &errdetails.ErrorInfo{Reason: "R", Domain: legacyDomain}
}
`

// producerNamelessSrc — тот же файл, изменён РОВНО ОДИН факт: домена нет вовсе.
const producerNamelessSrc = `package probe

import "google.golang.org/genproto/googleapis/rpc/errdetails"

func refuse() *errdetails.ErrorInfo {
	return &errdetails.ErrorInfo{Reason: "R"}
}
`

// producerInTestFileSrc — тот же дефект, но в ПРОБНОМ файле: гейт судит
// прод-дерево, и синтетика соседней пробы не обязана его ронять.
const producerInTestFileSrc = producerHardcodedSrc

// syntheticTree — дерево из одного файла. Заводится ВНЕ репозитория
// (`t.TempDir()` читает TMPDIR), поэтому обход не встречает чужого индекса.
func syntheticTree(t *testing.T, name, src string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "internal", "probe"), 0o750); err != nil {
		t.Fatalf("синтетическое дерево: %v", err)
	}
	path := filepath.Join(root, "internal", "probe", name)
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("запись %s: %v", path, err)
	}
	return root
}

// TestInject_WiredProducerIsSilent — положительный контроль. Без него всякое
// «покраснел» ниже доказывало бы лишь то, что гейт краснеет всегда.
func TestInject_WiredProducerIsSilent(t *testing.T) {
	scan, err := scanTree(syntheticTree(t, "refusal.go", producerWiredSrc))
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	if scan.Producers != 1 || scan.Wired != 1 {
		t.Fatalf("производителей %d (берут у объявления %d), ожидалось 1 и 1", scan.Producers, scan.Wired)
	}
	if len(scan.Hardcoded) != 0 || len(scan.Nameless) != 0 {
		t.Fatalf("законный производитель назван находкой: зашито %v, безымянно %v",
			scan.Hardcoded, scan.Nameless)
	}
}

// TestInject_HardcodedProducerIsFound — несущее отрицание: домен, зашитый по
// месту, назван, и назван С КООРДИНАТОЙ.
func TestInject_HardcodedProducerIsFound(t *testing.T) {
	scan, err := scanTree(syntheticTree(t, "refusal.go", producerHardcodedSrc))
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	if len(scan.Hardcoded) != 1 {
		t.Fatalf("зашитых доменов найдено %d, ожидался 1 (перепись: производителей %d)",
			len(scan.Hardcoded), scan.Producers)
	}
	if scan.Hardcoded[0] != "internal/probe/refusal.go" {
		t.Fatalf("находка не называет координату: %q", scan.Hardcoded[0])
	}
	if scan.Wired != 0 {
		t.Fatalf("зашитый домен зачтён как взятый у объявления")
	}
}

// TestInject_NamelessProducerIsFound — вторая ось отрицания: производитель без
// домена вовсе. Отдельная от предыдущей: «зашит» и «не назван» суть разные
// состояния, и общая ветвь смешала бы их в одну находку.
func TestInject_NamelessProducerIsFound(t *testing.T) {
	scan, err := scanTree(syntheticTree(t, "refusal.go", producerNamelessSrc))
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	if len(scan.Nameless) != 1 || scan.Nameless[0] != "internal/probe/refusal.go" {
		t.Fatalf("безымянный домен не назван: %v", scan.Nameless)
	}
	if len(scan.Hardcoded) != 0 {
		t.Fatalf("безымянный домен зачтён зашитым: %v", scan.Hardcoded)
	}
}

// TestInject_TestFilesAreOutOfScope — граница обхода названа утверждением, а не
// умолчанием: синтетика соседней пробы гейт не роняет.
func TestInject_TestFilesAreOutOfScope(t *testing.T) {
	scan, err := scanTree(syntheticTree(t, "refusal_test.go", producerInTestFileSrc))
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	if scan.Parsed != 0 || scan.Producers != 0 || len(scan.Hardcoded) != 0 {
		t.Fatalf("пробный файл попал в обход: разобрано %d, производителей %d, находок %v",
			scan.Parsed, scan.Producers, scan.Hardcoded)
	}
}

// TestInject_EmptyTreeIsNotAPass — обход, ничего не прочитавший, зелёным быть
// не вправе: «ноль находок» обязано быть отличимо от «ноль прочитанного».
// Здесь утверждается ПРЕДПОСЫЛКА гейта — та, на которой стоят его пороги.
func TestInject_EmptyTreeIsNotAPass(t *testing.T) {
	scan, err := scanTree(t.TempDir())
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	if scan.Parsed != 0 || scan.Producers != 0 {
		t.Fatalf("пустое дерево дало разобрано %d, производителей %d", scan.Parsed, scan.Producers)
	}
	// Именно на этих двух величинах гейт и роняет прогон: порог переписи и
	// «ни одного производителя». Проба закрепляет, что обе они наблюдаемы.
	if scan.Parsed >= censusFloor {
		t.Fatalf("пустое дерево прошло бы порог переписи (%d)", censusFloor)
	}
}

// TestInject_LedgerEntryWithoutSubjectIsAFinding — самоистечение ведомости.
//
// Прощение живёт, пока у него есть предмет: запись, которой больше нечего
// прощать, унаследует следующую слепую зону. Утверждается тем же способом, каким
// это делает гейт, — сверкой перечня прощений с найденным.
func TestInject_LedgerEntryWithoutSubjectIsAFinding(t *testing.T) {
	scan, err := scanTree(syntheticTree(t, "refusal.go", producerWiredSrc))
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	found := map[string]bool{}
	for _, rel := range scan.Hardcoded {
		found[rel] = true
	}
	stale := 0
	for _, e := range ledger {
		if !found[e.File] {
			stale++
		}
	}
	if stale != len(ledger) {
		t.Fatalf("на дереве без прощаемых записей ведомость дала %d устаревших из %d — "+
			"самоистечение не наблюдается", stale, len(ledger))
	}
}
