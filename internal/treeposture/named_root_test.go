// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package treeposture_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/treeposture"
)

// Корень дерева платформы приходит из ручки окружения, и вход СУЖЕН, а не помечен
// (kaname#162): принимается только абсолютный путь без сегментов `..`. Всё прочее
// отвергается словами, называющими ручку и причину.
//
// Дефект и законный близнец отличаются ровно одним фактом — записью пути: каталог
// модулей внутри названного дерева существует во всех трёх пробах, поэтому отказ
// не может прийти от его отсутствия.

// platformTree — дерево с каталогом модулей: признак годности на месте.
func platformTree(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	tree := filepath.Join(base, "platform")
	if err := os.MkdirAll(filepath.Join(tree, treeposture.SiblingsDir), 0o750); err != nil {
		t.Fatalf("фикстура не создана: %v", err)
	}
	return tree
}

// TestNamedPlatformRootAcceptsAnAbsoluteRoot — положительный контроль.
func TestNamedPlatformRootAcceptsAnAbsoluteRoot(t *testing.T) {
	tree := platformTree(t)
	t.Setenv(treeposture.PlatformTreeEnv, tree)

	root, why := treeposture.NamedPlatformRoot()
	if why != "" || root != tree {
		t.Fatalf("законный абсолютный корень отвергнут: root=%q, причина %q", root, why)
	}
}

// TestNamedPlatformRootRefusesARelativeRoot — ИНЪЕКЦИЯ: тот же корень, записанный
// относительно рабочего каталога.
func TestNamedPlatformRootRefusesARelativeRoot(t *testing.T) {
	tree := platformTree(t)
	t.Chdir(filepath.Dir(tree))
	t.Setenv(treeposture.PlatformTreeEnv, filepath.Base(tree))

	root, why := treeposture.NamedPlatformRoot()
	if root != "" {
		t.Fatalf("относительный корень %q принят: вердикт зависел бы от рабочего каталога", root)
	}
	if !strings.Contains(why, treeposture.PlatformTreeEnv) || !strings.Contains(why, "абсолютн") {
		t.Fatalf("отказ не назвал ручку и причину словами: %q", why)
	}
}

// TestNamedPlatformRootRefusesADotDotSegment — ИНЪЕКЦИЯ: абсолютный путь, который
// приводится к законному корню только через `..`.
func TestNamedPlatformRootRefusesADotDotSegment(t *testing.T) {
	tree := platformTree(t)
	detour := filepath.Dir(tree) + string(filepath.Separator) + "elsewhere" +
		string(filepath.Separator) + ".." + string(filepath.Separator) + filepath.Base(tree)
	t.Setenv(treeposture.PlatformTreeEnv, detour)

	root, why := treeposture.NamedPlatformRoot()
	if root != "" {
		t.Fatalf("корень с сегментом `..` принят как %q", root)
	}
	if !strings.Contains(why, treeposture.PlatformTreeEnv) || !strings.Contains(why, "..") {
		t.Fatalf("отказ не назвал ручку и сегмент `..`: %q", why)
	}
}
