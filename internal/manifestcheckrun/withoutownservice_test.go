// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifestcheckrun_test

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
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

// withoutownservice_test.go — судья формы манифеста ЦЕЛИКОМ на дереве с
// манифестом registry новой редакции (kaname#872, предикат kacho#3274 S1).
//
// Пара та же, что у пакета roleexport, но вход — то, что видит команда:
// отслеживаемый `services/registry/manifest.yaml`, встроенный каталог прав и
// канон модели. Близнец меняет РОВНО ОДИН факт — добавляет класс `create`,
// которого у типа репозитория нет, — и судья обязан покраснеть.

// registryTree — синтетический РЕПОЗИТОРИЙ с одним отслеживаемым манифестом.
//
// Индекс обязателен: судья берёт состав дерева у git, и дерево без индекса
// отвергается раньше, чем дойдёт до прав ролей.
func registryTree(t *testing.T, doc []byte) string {
	t.Helper()
	if msg := treecorpus.CachedVerdictRefusal(); msg != "" {
		t.Fatalf("%s — вердикт зависел бы от рабочего каталога", msg)
	}
	root := t.TempDir()
	rel := filepath.Join("services", "registry", "manifest.yaml")
	if err := os.MkdirAll(filepath.Join(root, "services", "registry"), 0o755); err != nil {
		t.Fatalf("подготовка входа: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, rel), doc, 0o600); err != nil {
		t.Fatalf("подготовка входа: %v", err)
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "--", rel}} {
		// gitenv, а не exec напрямую: GIT_DIR в окружении сильнее cmd.Dir, и
		// индекс писался бы в копию, из которой запущен прогон.
		if out, err := gitenv.Command(root, args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v в %s: %v\n%s", args, root, err, out)
		}
	}
	return root
}

func newEditionDoc(t *testing.T) []byte {
	t.Helper()
	doc, err := publicreadfixture.Read(publicreadfixture.NewEditionFile)
	if err != nil {
		t.Fatalf("фикстура новой редакции: %v", err)
	}
	// Пробные роли kaname#874 вычеркнуты: перепись ниже — свойство роли
	// `registry.public.read`, а не состава фикстуры.
	doc, err = publicreadfixture.OnlyPublicReadRole(doc)
	if err != nil {
		t.Fatalf("фикстура новой редакции: %v", err)
	}
	return doc
}

// TestRegistryNewEditionPassesTheManifestJudge — предмет: код 0, находок 0, и
// права ролей ДЕЙСТВИТЕЛЬНО судились (перепись называет пары по модели).
func TestRegistryNewEditionPassesTheManifestJudge(t *testing.T) {
	root := registryTree(t, newEditionDoc(t))

	var out, errOut bytes.Buffer
	code := manifestcheckrun.Run(root, &out, &errOut)
	t.Logf("код %d\nвывод:\n%s\nошибки:\n%s", code, out.String(), errOut.String())

	if code != manifest.CheckOK {
		t.Fatalf("судья вернул код %d на манифесте registry новой редакции, ожидался 0", code)
	}
	if strings.Contains(errOut.String(), "НАХОДКА") {
		t.Fatalf("находки на манифесте новой редакции:\n%s", errOut.String())
	}
	if !strings.Contains(out.String(), "манифестов прочитано 1") {
		t.Fatalf("манифест не прочитан — «находок 0» без прочитанного не вердикт:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "по глаголам модели 2") {
		t.Fatalf("перепись не называет пар, судимых по глаголам модели:\n%s", out.String())
	}
}

// TestRegistryRuleWithAClassOutsideModelVerbsFailsTheManifestJudge — близнец:
// класс `create` над repositories даёт находку и код 1.
func TestRegistryRuleWithAClassOutsideModelVerbsFailsTheManifestJudge(t *testing.T) {
	doc := newEditionDoc(t)
	// Заменяется класс ВЛОЖЕННОГО правила над repositories (форма kaname#874).
	const old, repl = "            classes: [get, list]", "            classes: [get, list, create]"
	if n := bytes.Count(doc, []byte(old)); n != 1 {
		t.Fatalf("близнец: заменяемая строка встречается %d раз, нужна ровно одна", n)
	}
	root := registryTree(t, bytes.Replace(doc, []byte(old), []byte(repl), 1))

	var out, errOut bytes.Buffer
	code := manifestcheckrun.Run(root, &out, &errOut)
	t.Logf("код %d\nошибки:\n%s", code, errOut.String())

	if code != manifest.CheckFailed {
		t.Fatalf("судья вернул код %d на классе вне глаголов модели, ожидался %d", code, manifest.CheckFailed)
	}
	want := `класс "create" на ресурсе "repositories"`
	if !strings.Contains(errOut.String(), want) {
		t.Fatalf("находка не называет %q:\n%s", want, errOut.String())
	}
}
