// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// boot_seeds_no_synthetic_object_injection_test.go — инъекция в обе стороны для
// TestProductionTreeCarriesNoSyntheticMirrorSmoke (#148).
//
// Каждая форма, которой механизм выражался в дереве, подаётся на синтетике в
// t.TempDir() и обязана покраснеть с координатой; законные близнецы той же формы
// — имя в комментарии, в строковом литерале, соседнее имя, тестовый файл — обязаны
// молчать. Пустой обход и неразборный файл — отказ, а не зелёное.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeSmokeFixture(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("каталог фикстуры: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("запись фикстуры %s: %v", name, err)
	}
	return path
}

func TestSyntheticMirrorSmokeInjection_EveryFormIsFoundWithItsCoordinate(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string // имя, которое обязано попасть в находку
	}{
		{"method_declaration", "package p\n\ntype A struct{}\n\nfunc (A) SeedSmokeMirrorObject() {}\n", "SeedSmokeMirrorObject"},
		{"port_method", "package p\n\ntype P interface {\n\tLedgerHasObject() bool\n}\n", "LedgerHasObject"},
		{"spec_type", "package p\n\ntype ForwardSmokeSpec struct{}\n", "ForwardSmokeSpec"},
		// Значение метода без вызова: прежний гейт по подстроке «имя(» его не видел.
		{"method_value_without_call", "package p\n\ntype G struct{}\n\nfunc (G) Run() {}\n\nvar g G\n\nvar f = g.ForwardSmoke\n", "ForwardSmoke"},
		{"call_in_boot", "package p\n\nfunc boot() { RunBootForwardSmoke() }\n", "RunBootForwardSmoke"},
		{"lowercase_helper", "package p\n\nfunc fgaObjectForSmoke() string { return \"\" }\n", "fgaObjectForSmoke"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeSmokeFixture(t, dir, "sub/prod.go", tc.body)
			census, findings, err := judgeSyntheticMirrorSmoke([]string{path})
			if err != nil {
				t.Fatalf("разбор синтетики не должен отказывать: %v", err)
			}
			if census.filesRead != 1 {
				t.Fatalf("прочитано %d файлов, ждали 1", census.filesRead)
			}
			if len(findings) == 0 {
				t.Fatalf("форма %q не найдена: гейт слеп к ней", tc.name)
			}
			hit := false
			for _, f := range findings {
				if strings.HasPrefix(f, path+":") && strings.HasSuffix(f, ": "+tc.want) {
					hit = true
				}
			}
			if !hit {
				t.Fatalf("находка не называет координату и имя %q: %v", tc.want, findings)
			}
		})
	}
}

func TestSyntheticMirrorSmokeInjection_LawfulTwinsAreSilent(t *testing.T) {
	dir := t.TempDir()
	prod := writeSmokeFixture(t, dir, "prod.go", "package p\n\n"+
		"// ForwardSmoke( и SeedSmokeMirrorObject( сняты (#148) — имя в прозе не механизм.\n"+
		"const why = \"LedgerHasObject( больше не порт\"\n\n"+
		"// Соседнее имя той же формы — не предмет перечня.\n"+
		"func ForwardSmokeless() {}\n")
	test := writeSmokeFixture(t, dir, "prod_test.go", "package p\n\n"+
		"func helper() { SeedSmokeMirrorObject() }\n\n"+
		"func SeedSmokeMirrorObject() {}\n")
	fixture := writeSmokeFixture(t, dir, "testdata/input.go", "package p\n\nfunc ForwardSmoke() {}\n")

	census, findings, err := judgeSyntheticMirrorSmoke([]string{prod, test, fixture})
	if err != nil {
		t.Fatalf("разбор близнецов не должен отказывать: %v", err)
	}
	if census.filesRead != 1 {
		t.Fatalf("прочитано %d не-тестовых файлов, ждали 1 (тестовый и testdata — вне предмета)", census.filesRead)
	}
	if census.nodesSeen == 0 {
		t.Fatal("идентификаторов осмотрено 0: близнец не прочитан, молчание беспредметно")
	}
	if len(findings) != 0 {
		t.Fatalf("законный близнец покраснел: %v", findings)
	}
}

func TestSyntheticMirrorSmokeInjection_EmptyWalkIsARefusal(t *testing.T) {
	dir := t.TempDir()
	onlyTest := writeSmokeFixture(t, dir, "x_test.go", "package p\n")
	for name, files := range map[string][]string{
		"no_files":        nil,
		"only_test_files": {onlyTest},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := judgeSyntheticMirrorSmoke(files)
			if err == nil || !strings.Contains(err.Error(), "обход пуст") {
				t.Fatalf("пустой обход обязан быть отказом «обход пуст», получено: %v", err)
			}
		})
	}
}

func TestSyntheticMirrorSmokeInjection_UnparsableFileIsARefusal(t *testing.T) {
	dir := t.TempDir()
	broken := writeSmokeFixture(t, dir, "broken.go", "package p\n\nfunc (\n")
	_, _, err := judgeSyntheticMirrorSmoke([]string{broken})
	if err == nil || !strings.Contains(err.Error(), broken) {
		t.Fatalf("неразборный файл обязан быть отказом с его именем, получено: %v", err)
	}
}
