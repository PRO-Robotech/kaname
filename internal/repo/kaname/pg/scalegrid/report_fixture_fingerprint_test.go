// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package scalegrid

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Все изменения выполняются только в t.TempDir. Обязательные файлы берутся
// из настоящего дерева: проверяется полный файловый путь семейного отпечатка.
func reportFixtureTree(t *testing.T, standalone bool) string {
	t.Helper()
	root := buildPostureTree(t, standalone, postureVerdictSource)
	actual := repoRootFromPackageDir(t)
	for _, ref := range readReportFixtureClosure {
		source, err := under(actual, ref.file)
		if err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		dest, err := under(root, ref.file)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dest, string(body))
	}
	return root
}

func TestReadReportFingerprintTracksEveryFixtureFile(t *testing.T) {
	for _, family := range []struct {
		name    string
		compute func(string) (Fingerprint, error)
	}{
		{"fullgrid", ComputeFullGridFingerprint},
		{"strength", ComputeStrengthGridFingerprint},
	} {
		t.Run(family.name, func(t *testing.T) {
			root := reportFixtureTree(t, true)
			before, err := family.compute(root)
			if err != nil {
				t.Fatal(err)
			}
			for _, ref := range readReportFixtureClosure {
				t.Run(ref.file, func(t *testing.T) {
					file, err := under(root, ref.file)
					if err != nil {
						t.Fatal(err)
					}
					body, err := os.ReadFile(file)
					if err != nil {
						t.Fatal(err)
					}
					defer writeFile(t, file, string(body))
					injection := "\nfixture-fingerprint-probe\n"
					if strings.HasSuffix(file, ".go") {
						injection = "\nconst fixtureFingerprintProbe = 1729\n"
					}
					writeFile(t, file, string(body)+injection)
					after, err := family.compute(root)
					if err != nil {
						t.Fatal(err)
					}
					if after.Content == before.Content || after.Composition != before.Composition {
						t.Fatalf("значащая правка %s: содержимое должно сдвинуться при прежнем составе", ref.file)
					}
					writeFile(t, file, string(body))
					twin, err := family.compute(root)
					if err != nil || twin.Content != before.Content || twin.Composition != before.Composition {
						t.Fatalf("восстановленная копия %s не совпала: %v", ref.file, err)
					}
					if err := os.Remove(file); err != nil {
						t.Fatal(err)
					}
					if _, err := family.compute(root); err == nil {
						t.Fatalf("отсутствующий обязательный файл %s принят", ref.file)
					}
				})
			}
		})
	}
}

func TestReadReportFingerprintPreservesPostureAndProductBoundary(t *testing.T) {
	platform := reportFixtureTree(t, false)
	standalone := reportFixtureTree(t, true)
	for _, compute := range []func(string) (Fingerprint, error){ComputeFullGridFingerprint, ComputeStrengthGridFingerprint} {
		a, err := compute(platform)
		if err != nil {
			t.Fatal(err)
		}
		b, err := compute(standalone)
		if err != nil || a.Composition != b.Composition || a.Content != b.Content {
			t.Fatalf("один состав в двух посадках разошёлся: %v", err)
		}
	}
	before, err := ComputeFingerprint(standalone)
	if err != nil {
		t.Fatal(err)
	}
	file, err := under(standalone, verdictDir+"/report_bounded_seed_integration_test.go")
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	familyBefore, err := ComputeFullGridFingerprint(standalone)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, file, string(body)+"\n// Изменена только проза фикстуры.\n")
	familyComment, err := ComputeFullGridFingerprint(standalone)
	if err != nil || familyBefore.Content != familyComment.Content || familyBefore.Composition != familyComment.Composition {
		t.Fatalf("комментарий изменил значащий отпечаток: %v", err)
	}
	writeFile(t, file, string(body)+"\nconst fixtureOutsideProduct = 1\n")
	after, err := ComputeFingerprint(standalone)
	if err != nil || before.Composition != after.Composition || before.Content != after.Content {
		t.Fatalf("семейный helper изменил старую границу продуктового отпечатка: %v", err)
	}
	// Неизвестная роль и новый продуктовый файл остаются различимыми.
	if _, err := fileIdentity("services/iam/internal/unknown/family.go"); err == nil {
		t.Fatal("неизвестная роль принята")
	}
	newFile, err := under(standalone, verdictDir+"/new_product_subject.go")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, newFile, "package relverdict\nconst newProductSubject = 1\n")
	added, err := ComputeFingerprint(standalone)
	if err != nil || added.Composition == before.Composition {
		t.Fatalf("новый продуктовый файл не сдвинул состав: %v", err)
	}
}
