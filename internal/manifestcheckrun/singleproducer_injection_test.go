// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifestcheckrun_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
)

// singleproducer_injection_test.go — доказательство, что гейт единственной
// композиции СПОСОБЕН упасть и способен смолчать.
//
// Гейт, чью способность падать никто не проверял, неотличим от мёртвого: на
// честном дереве оба зелены. Поэтому дефект вносится настоящим входом — деревом
// той же формы, — а рядом стоит ЗАКОННЫЙ БЛИЗНЕЦ, отличающийся от него РОВНО
// ОДНИМ фактом. Без близнеца красное доказывало бы лишь то, что гейт краснеет
// на чём угодно.

// lawfulTree — дерево, на котором гейт обязан МОЛЧАТЬ: одна композиция, у
// каждой точки входа один вызывающий, у композиции — объявленные двое.
func lawfulTree() map[string]string {
	return map[string]string{
		"go.mod": "module probe\n\ngo 1.26\n",
		"services/iam/internal/manifestcheckrun/run.go": `package manifestcheckrun

import "probe/manifest"

func Run(root string) int { return manifest.CheckTree(root) }
`,
		"services/iam/internal/authzmapgen/authzmapgen.go": `package authzmapgen

import "probe/manifest"

func Collect(root string) int { return manifest.CheckTreeForGeneration(root) }
`,
		"services/iam/tools/modulemanifestcheck/main.go": `package main

import "probe/manifestcheckrun"

func main() { _ = manifestcheckrun.Run(".") }
`,
		// Второй вызывающий обращается к композиции ЗНАЧЕНИЕМ, а не вызовом:
		// именно эта форма и была слепой зоной распознавателя при заведении
		// гейта, поэтому законный близнец несёт её, а не удобную.
		"services/iam/cmd/iamctl/main.go": `package main

import "probe/manifestcheckrun"

var validate = manifestcheckrun.Run

func main() { _ = validate(".") }
`,
	}
}

func writeTree(t *testing.T, files map[string]string) *treecorpus.Tree {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("подготовка входа: %v", err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("подготовка входа: %v", err)
		}
	}
	// Синтетическое дерево репозиторием не является: состав у него берётся
	// отдельным конструктором — осознанно и по имени, а не молчаливым откатом.
	tree, err := treecorpus.SyntheticTree(root)
	if err != nil {
		t.Fatalf("подготовка входа: состав синтетического дерева не собран: %v", err)
	}
	return tree
}

// Законный близнец: гейт молчит, и обход НЕ пуст.
//
// Второе утверждение несущее: молчание на пустом обходе доказывало бы, что
// гейт ничего не читал, а не что дерево цело.
func TestSingleProducerGateStaysSilentOnALawfulTree(t *testing.T) {
	findings, filesRead := auditCallers(t, writeTree(t, lawfulTree()))
	if filesRead == 0 {
		t.Fatal("обход законного близнеца прочитал НОЛЬ файлов — молчание беспредметно")
	}
	if len(findings) != 0 {
		t.Fatalf("гейт краснеет на ЗАКОННОМ дереве (прочитано файлов %d):\n\t%s",
			filesRead, strings.Join(findings, "\n\t"))
	}
	t.Logf("перепись законного близнеца: прочитано файлов Go %d · находок 0", filesRead)
}

// Инъекция: каждый дефект вносится ОДНИМ фактом против законного близнеца, и
// гейт обязан не просто покраснеть, а НАЗВАТЬ предмет.
func TestSingleProducerGateFindsEachDefectByName(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(map[string]string)
		needs  []string
	}{
		{
			name: "вторая композиция обошла пакет — чистую функцию зовут дважды",
			mutate: func(f map[string]string) {
				f["services/iam/cmd/iamctl/validate.go"] = `package main

import "probe/manifest"

func ownCheck(root string) int { return manifest.CheckTree(root) }
`
			},
			needs: []string{"CheckTree", "ОДИН", "молча"},
		},
		{
			name: "третий вызывающий композиции не объявлен",
			mutate: func(f map[string]string) {
				f["services/vpc/cmd/vpcctl/main.go"] = `package main

import "probe/manifestcheckrun"

func main() { _ = manifestcheckrun.Run(".") }
`
			},
			needs: []string{"композицию зовут", "services/vpc/cmd/vpcctl"},
		},
		{
			name: "объявленный вызывающий композицию звать перестал",
			mutate: func(f map[string]string) {
				f["services/iam/cmd/iamctl/main.go"] = `package main

func main() {}
`
			},
			needs: []string{"композицию зовут", "services/iam/cmd/iamctl"},
		},
		{
			name: "точку входа зовут не из своего пакета",
			mutate: func(f map[string]string) {
				delete(f, "services/iam/internal/authzmapgen/authzmapgen.go")
				f["services/iam/internal/somewhereelse/x.go"] = `package somewhereelse

import "probe/manifest"

func Collect(root string) int { return manifest.CheckTreeForGeneration(root) }
`
			},
			needs: []string{"CheckTreeForGeneration", "somewhereelse"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := lawfulTree()
			tc.mutate(files)
			findings, filesRead := auditCallers(t, writeTree(t, files))
			if filesRead == 0 {
				t.Fatal("обход прочитал НОЛЬ файлов — вердикт беспредметен")
			}
			if len(findings) == 0 {
				t.Fatalf("гейт МОЛЧИТ на внесённом дефекте (прочитано файлов %d)", filesRead)
			}
			joined := strings.Join(findings, "\n\t")
			for _, n := range tc.needs {
				if !strings.Contains(joined, n) {
					t.Fatalf("находка не называет %q — читатель пойдёт искать не там:\n\t%s", n, joined)
				}
			}
		})
	}
}
