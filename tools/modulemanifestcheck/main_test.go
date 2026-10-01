// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// main_test.go — строка манифеста `notifications` судится ТОЙ ЖЕ командой, что
// зовёт конвейер (приёмка NTF-1, сценарии NTF1-F02, NTF1-F03; замысел З17).
//
// Проба зовёт исполнитель команды (`manifestcheckrun.Run`) над синтетическим
// РЕПОЗИТОРИЕМ: полоса дерева берёт перечень манифестов из индекса git, и
// каталог без индекса был бы не тем предметом, который судит конвейер.
//
// Каждое отрицание стоит рядом с положительным близнецом NTF1-F01 — той же
// строкой с `namespace` своего модуля и `readers: [notify]`. Без близнеца проба
// зеленела бы на команде, отвергающей всякую строку `notifications`.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/gitenv"
	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/manifestcheckrun"
)

// probeManifest — манифест фикстурного модуля `probe` со строкой `notifications`,
// подставляемой случаем. Разделов прав у него нет: предмет пробы — одна строка.
func probeManifest(notifications string) string {
	return "apiVersion: iam/v1\nmodule: probe\nresources: []\n" + notifications + "\n"
}

// runOnTree кладёт один манифест в индекс синтетического репозитория и зовёт
// исполнитель команды. Возвращает код и оба потока.
func runOnTree(t *testing.T, body string) (code int, stdout, stderr string) {
	t.Helper()
	if msg := treecorpus.CachedVerdictRefusal(); msg != "" {
		t.Fatalf("%s — вердикт стал бы свойством рабочего каталога", msg)
	}
	root := t.TempDir()
	const rel = "services/probe/manifest.yaml"
	abs := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o750); err != nil {
		t.Fatalf("каталог фикстуры: %v", err)
	}
	if err := os.WriteFile(abs, []byte(body), 0o600); err != nil {
		t.Fatalf("манифест фикстуры: %v", err)
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "--", rel}} {
		// gitenv, а не exec напрямую: GIT_DIR окружения сильнее рабочего
		// каталога, и фикстура писала бы индекс копии, из которой идёт прогон.
		if out, err := gitenv.Command(root, args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	var out, errb bytes.Buffer
	code = manifestcheckrun.Run(root, &out, &errb)
	t.Logf("код %d\nвывод:\n%s\nошибки:\n%s", code, out.String(), errb.String())
	if !strings.Contains(out.String(), "прочитан: "+rel) {
		t.Fatalf("команда не прочитала манифест фикстуры — вердикт о строке беспредметен:\n%s", out.String())
	}
	return code, out.String(), errb.String()
}

// TestNTF1F01_OwnNamespaceAndNotifyReaderIsAccepted — положительный близнец F02 и
// F03: строка своего модуля с единственным читателем `notify` принимается.
func TestNTF1F01_OwnNamespaceAndNotifyReaderIsAccepted(t *testing.T) {
	code, _, stderr := runOnTree(t, probeManifest("notifications: {namespace: probe, readers: [notify]}"))
	if code != manifest.CheckOK {
		t.Fatalf("строка своего модуля с читателем notify отвергнута (код %d):\n%s", code, stderr)
	}
}

// TestNTF1F02_ForeignNamespaceIsRefused — `namespace: vpc` в манифесте модуля
// `probe`: находка «пространство не своего модуля» с именем модуля и строкой.
func TestNTF1F02_ForeignNamespaceIsRefused(t *testing.T) {
	for name, line := range map[string]string{
		"чужое пространство":      "notifications: {namespace: vpc, readers: [notify]}",
		"пространство не названо": "notifications: {readers: [notify]}",
	} {
		t.Run(name, func(t *testing.T) {
			code, _, stderr := runOnTree(t, probeManifest(line))
			if code != manifest.CheckFailed {
				t.Fatalf("строка %q принята (код %d), ожидалась находка", line, code)
			}
			for _, want := range []string{"пространство не своего модуля", `"probe"`, "notifications:"} {
				if !strings.Contains(stderr, want) {
					t.Fatalf("находка не называет %q:\n%s", want, stderr)
				}
			}
		})
	}
}

// TestNTF1F03_ReaderOtherThanNotifyIsRefused — читатель ленты вне `notify`
// (один чужой либо вместе с notify): находка «reader ленты — только notify».
func TestNTF1F03_ReaderOtherThanNotifyIsRefused(t *testing.T) {
	for name, line := range map[string]string{
		"чужой читатель":        "notifications: {namespace: probe, readers: [compute]}",
		"notify и чужой вместе": "notifications: {namespace: probe, readers: [notify, compute]}",
		"читателей нет":         "notifications: {namespace: probe, readers: []}",
	} {
		t.Run(name, func(t *testing.T) {
			code, _, stderr := runOnTree(t, probeManifest(line))
			if code != manifest.CheckFailed {
				t.Fatalf("строка %q принята (код %d), ожидалась находка", line, code)
			}
			for _, want := range []string{"reader ленты — только notify", `"probe"`, "notifications:"} {
				if !strings.Contains(stderr, want) {
					t.Fatalf("находка не называет %q:\n%s", want, stderr)
				}
			}
		})
	}
}
