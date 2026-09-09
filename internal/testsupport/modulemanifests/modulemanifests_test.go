// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modulemanifests_test

// modulemanifests_test.go — ОПЫТ: отвечает ли источник манифестов в ОБЕИХ
// посадках и способен ли он отказать там, где отвечать нечем (#2377).
//
// Ось несущая. Прежде обе стороны сверки «объявлено ↔ лежит в базе» брались
// обходом каталога модулей ПЛАТФОРМЫ. После разреза службы этот каталог рядом с
// модулем не резолвится: сверка становилась невыразимой, а расхождение
// объявления с фактом переставало находиться — молча.
//
// Каждая инъекция меняет РОВНО ОДИН факт против законного близнеца: лежит ли
// модуль в каталоге модулей платформы, есть ли рядом его собственный манифест,
// есть ли в дереве платформы хоть один манифест.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/testsupport/modulemanifests"
)

// mkModule — модуль (каталог с go.mod) по пути rel внутри base.
func mkModule(t *testing.T, base, rel string) string {
	t.Helper()
	dir := filepath.Join(base, filepath.FromSlash(rel))
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func writeManifest(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.yaml"), []byte("module: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// platformTwin — законный близнец ПЕРВОЙ посадки: модуль лежит среди модулей
// платформы, у соседей есть манифесты.
func platformTwin(t *testing.T) (base, mod string) {
	t.Helper()
	base = t.TempDir()
	mod = mkModule(t, base, "services/iam")
	for _, s := range []string{"iam", "vpc", "compute"} {
		writeManifest(t, filepath.Join(base, "services", s))
	}
	return base, mod
}

// TestPlatformPosture_ReadsEveryModuleManifest — КОНТРОЛЬ первой посадки.
func TestPlatformPosture_ReadsEveryModuleManifest(t *testing.T) {
	base, mod := platformTwin(t)

	set, err := modulemanifests.Available(mod)
	if err != nil {
		t.Fatalf("законный близнец объявлен отказом: %v", err)
	}
	if set.Posture != modulemanifests.PlatformTree {
		t.Fatalf("посадка названа %q, ожидалась %q", set.Posture, modulemanifests.PlatformTree)
	}
	if set.Root != base {
		t.Fatalf("корнем назван %s, ожидался %s", set.Root, base)
	}
	want := []string{"services/compute/manifest.yaml", "services/iam/manifest.yaml", "services/vpc/manifest.yaml"}
	if strings.Join(set.Files, ",") != strings.Join(want, ",") {
		t.Fatalf("перечень %v, ожидался %v", set.Files, want)
	}
	if !strings.Contains(set.Census(), "манифестов прочитано 3") {
		t.Fatalf("перепись не называет объём осмотренного: %q", set.Census())
	}
}

// TestStandalonePosture_ReadsTheModulesOwnManifest — ИНЪЕКЦИЯ: тот же модуль,
// тот же манифест, отличие РОВНО ОДНО — он лежит не в каталоге модулей платформы.
//
// Здесь и есть предмет задачи: прежний обход в этой посадке отказывал из
// os.ReadDir, то есть выглядел поломкой пробы, а не сдвигом дерева.
func TestStandalonePosture_ReadsTheModulesOwnManifest(t *testing.T) {
	base := t.TempDir()
	mod := mkModule(t, base, "kaname-0.1.0")
	writeManifest(t, mod)

	set, err := modulemanifests.Available(mod)
	if err != nil {
		t.Fatalf("самостоятельный клон объявлен отказом: %v — сверка исчезла бы вместе "+
			"с деревом платформы", err)
	}
	if set.Posture != modulemanifests.StandaloneModule {
		t.Fatalf("посадка названа %q, ожидалась %q", set.Posture, modulemanifests.StandaloneModule)
	}
	if set.Root != mod {
		t.Fatalf("корнем назван %s, ожидался модуль %s", set.Root, mod)
	}
	if strings.Join(set.Files, ",") != "manifest.yaml" {
		t.Fatalf("перечень %v, ожидался собственный манифест модуля", set.Files)
	}
	if !strings.Contains(set.Census(), "манифестов прочитано 1") {
		t.Fatalf("перепись не назвала СУЖЕННЫЙ объём: %q — «расхождений 0» на одном "+
			"манифесте и на шести обязаны быть различимы", set.Census())
	}
}

// TestStandalonePosture_WithoutOwnManifestIsARefusal — ИНЪЕКЦИЯ: та же посадка,
// отличие РОВНО ОДНО — собственного манифеста рядом нет.
//
// Молчаливый пустой перечень здесь означал бы сверку, которая ничего не сверяет
// и об этом не говорит.
func TestStandalonePosture_WithoutOwnManifestIsARefusal(t *testing.T) {
	base := t.TempDir()
	mod := mkModule(t, base, "kaname-0.1.0")

	set, err := modulemanifests.Available(mod)
	if err == nil {
		t.Fatalf("клон без собственного манифеста принят: %+v", set)
	}
	if !strings.Contains(err.Error(), "собственного манифеста") {
		t.Fatalf("отказ не назвал предпосылку словами: %v", err)
	}
}

// TestPlatformPosture_WithoutAnyManifestIsARefusal — ИНЪЕКЦИЯ с ДРУГОЙ стороны:
// дерево платформы есть, а манифестов в нём нет ни одного.
//
// Отличие от близнеца ровно одно: соседям не написан ни один манифест.
func TestPlatformPosture_WithoutAnyManifestIsARefusal(t *testing.T) {
	base := t.TempDir()
	mod := mkModule(t, base, "services/iam")
	if err := os.MkdirAll(filepath.Join(base, "services", "vpc"), 0o750); err != nil {
		t.Fatal(err)
	}

	set, err := modulemanifests.Available(mod)
	if err == nil {
		t.Fatalf("дерево платформы без единого манифеста принято: %+v", set)
	}
	if !strings.Contains(err.Error(), "ни одного") {
		t.Fatalf("отказ не назвал предпосылку словами: %v", err)
	}
}

// TestNoModuleRootIsNotAPosture — третий исход представим отдельно: «корня
// модуля нет» не выдаётся ни за одну из двух посадок.
func TestNoModuleRootIsNotAPosture(t *testing.T) {
	deep := filepath.Join(t.TempDir(), "а", "б")
	if err := os.MkdirAll(deep, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := modulemanifests.Available(deep); err == nil {
		t.Fatal("отсутствие корня модуля выдано за вердикт о посадке")
	} else if !strings.Contains(err.Error(), "посадка не установлена") {
		t.Fatalf("отказ не отличил «посадки нет» от «манифестов нет»: %v", err)
	}
}
