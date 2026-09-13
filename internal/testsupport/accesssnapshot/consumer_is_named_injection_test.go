// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package accesssnapshot

// consumer_is_named_injection_test.go — доказательство, что гейт
// `TestIAM2640_ToolConsumersAreNamed` способен упасть по КАЖДОЙ своей оси и
// способен смолчать на законном близнеце.
//
// Осей две, и у каждой свой близнец, отличающийся РОВНО ОДНИМ фактом:
//
//	внешний импортёр  — дефект: файл вне каталога инструмента импортирует его;
//	                    близнец: тот же файл импортирует СОСЕДНИЙ путь;
//	                    близнец прозы: путь стоит в комментарии и в строке, а
//	                    импорта нет — предикат по подстроке краснел бы здесь;
//	свой потребитель  — дефект: в файлах пакета нет ни одного обращения к API;
//	                    близнец: обращение есть.
//
// Синтетика подаётся тем же распознавателем, каким судится живое дерево:
// доказательство, требующее испортить рабочую копию, в конвейере не
// исполняется никогда.

import (
	"os"
	"path/filepath"
	"testing"
)

// injExternalImporter — ДЕФЕКТ: у инструмента появился внешний потребитель.
const injExternalImporter = `package elsewhere

import "github.com/PRO-Robotech/kaname/internal/testsupport/accesssnapshot"

func use() { _ = accesssnapshot.BatchSize }
`

// injNeighbourImporter — ЗАКОННЫЙ БЛИЗНЕЦ: та же форма, отличается ровно одним
// фактом — импортируется СОСЕДНИЙ пакет, а не инструмент.
const injNeighbourImporter = `package elsewhere

import "github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"

func use() { _ = catalogfixture.Source }
`

// injPathOnlyMentioned — БЛИЗНЕЦ ПРОЗЫ: путь инструмента стоит в комментарии и
// в строковом литерале, импорта нет. Импортёром это не является.
const injPathOnlyMentioned = `package elsewhere

// github.com/PRO-Robotech/kaname/internal/testsupport/accesssnapshot — про него
// здесь только написано.
const doc = "github.com/PRO-Robotech/kaname/internal/testsupport/accesssnapshot"
`

// injOwnWithoutCalls — ДЕФЕКТ второй оси: файл САМОГО пакета не зовёт API.
const injOwnWithoutCalls = `package accesssnapshot

func nothing() {}
`

// injOwnWithCalls — ЗАКОННЫЙ БЛИЗНЕЦ: тот же файл пакета, отличается ровно одним
// фактом — инструмент вызван.
const injOwnWithCalls = `package accesssnapshot

func use() {
	s, _ := Take(nil, nil, nil, "", "", "")
	_, _ = Compare(s, s)
}
`

// writeConsumerInjTree раскладывает синтетику на два каталога: «свой» и внешний.
func writeConsumerInjTree(t *testing.T, own, outside map[string]string) (files []string, ownDir string) {
	t.Helper()
	root := t.TempDir()
	ownDir = filepath.Join(root, "accesssnapshot")
	outsideDir := filepath.Join(root, "elsewhere")
	for dir, sources := range map[string]map[string]string{ownDir: own, outsideDir: outside} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatalf("завести каталог синтетики %s: %v", dir, err)
		}
		for name, body := range sources {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatalf("положить синтетику %s: %v", path, err)
			}
			files = append(files, path)
		}
	}
	return files, ownDir
}

// TestIAM2640_InjectionRedsTheExternalImporterAndKeepsQuietOnTheNeighbour — ось
// «внешний потребитель появился».
func TestIAM2640_InjectionRedsTheExternalImporterAndKeepsQuietOnTheNeighbour(t *testing.T) {
	files, ownDir := writeConsumerInjTree(t,
		map[string]string{"tool.go": injOwnWithCalls},
		map[string]string{
			"defect.go": injExternalImporter,
			"twin.go":   injNeighbourImporter,
			"prose.go":  injPathOnlyMentioned,
		})
	importers, census, err := scanToolConsumers(files, ownDir)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if census.Importers != 1 {
		t.Fatalf("внешних импортёров ожидался РОВНО один (дефект; сосед и проза "+
			"импортёрами не являются), насчитано %d: %v — либо гейт не видит импорта, "+
			"либо считает им упоминание", census.Importers, importers)
	}
	if filepath.Base(importers[0]) != "defect.go" {
		t.Fatalf("находка названа файлом %q, а импорт внесён в defect.go — гейт "+
			"краснеет не на том, на чём проверяется", importers[0])
	}
	if census.OwnCalls == 0 {
		t.Fatalf("вторая ось сработала заодно: обращений к API в файлах пакета " +
			"насчитано 0. Инъекция, роняющая соседнюю ось, доказательством не является")
	}
}

// TestIAM2640_InjectionRedsTheToolNobodyCalls — ось «потребителей не осталось».
func TestIAM2640_InjectionRedsTheToolNobodyCalls(t *testing.T) {
	files, ownDir := writeConsumerInjTree(t,
		map[string]string{"tool.go": injOwnWithoutCalls},
		map[string]string{"twin.go": injNeighbourImporter})
	_, census, err := scanToolConsumers(files, ownDir)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if census.OwnFiles != 1 {
		t.Fatalf("файлов пакета ожидался 1, насчитано %d — распознаватель «своего» "+
			"каталога судит не то: %s", census.OwnFiles, census.Summary())
	}
	if census.OwnCalls != 0 {
		t.Fatalf("обращений к API ожидался 0 (дефект), насчитано %d — гейт не увидел бы "+
			"инструмента, которого никто не зовёт", census.OwnCalls)
	}
	if census.Importers != 0 {
		t.Fatalf("первая ось сработала заодно: внешних импортёров %d", census.Importers)
	}
}
