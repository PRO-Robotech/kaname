// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// standalonedelivery_test.go — самостоятельная поставка модуля даёт «проверка НЕ
// ИСПОЛНЯЛАСЬ», а не находку о продукте.
//
// Инъекция в ОБЕ стороны, и каждая пара отличается РОВНО ОДНИМ фактом:
//
//	канон из копии модуля  + нет манифестов соседей → 3 (условие не создано);
//	канон из ДЕРЕВА КОНТРАКТОВ + нет манифестов соседей → 1 (находка);
//	канон из копии модуля  + РАСХОЖДЕНИЕ блоков      → 1 (находка).
//
// Второй случай — законный близнец первого: без него послабление зеленело бы на
// всяком дереве без манифестов, включая монорепо с удалённым манифестом соседа.
// Третий — вторая сторона той же оси: послабление не вправе накрывать сверку,
// которая ДОШЛА и нашла расхождение.
package modelrender_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzplan"
	"github.com/PRO-Robotech/kaname/internal/modelrender"
)

// shippedOnlyTree — дерево САМОСТОЯТЕЛЬНОЙ ПОСТАВКИ: канон лежит там, куда его
// кладёт модуль, и дерева контрактов нет вовсе.
func shippedOnlyTree(t *testing.T, canon string) string {
	t.Helper()
	root := t.TempDir()
	dst := filepath.Join(root, filepath.FromSlash(authzplan.ShippedModelRelPath()))
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		t.Fatalf("каталог копии канона: %v", err)
	}
	if err := os.WriteFile(dst, []byte(canon), 0o600); err != nil {
		t.Fatalf("запись копии канона: %v", err)
	}
	return root
}

// TestStandaloneDeliveryIsNotRunNotAFinding — ИНЪЕКЦИЯ.
func TestStandaloneDeliveryIsNotRunNotAFinding(t *testing.T) {
	root := shippedOnlyTree(t, twoBlockCanon)
	writeManifest(t, root, "vpc", manifestFor("vpc", "vpc_network", "vpc_subnet"))

	census, findings, code := modelrender.Sweep(seed.LiteralRows().Resources, root, nil)

	if code != modelrender.SweepNotRun {
		t.Fatalf("исход %d, ожидался %d (проверка НЕ ИСПОЛНЯЛАСЬ): в самостоятельной "+
			"поставке манифестов соседних модулей нет by construction, и красное о них "+
			"есть вердикт о продукте там, где вердикта нет.\nперепись: %s\nнаходки: %v",
			code, modelrender.SweepNotRun, census, findings)
	}
	if len(findings) != 1 {
		t.Fatalf("исход назван %d строками, ожидалась одна: %v", len(findings), findings)
	}
	got := findings[0].String()
	for _, want := range []string{"условие сверки НЕ СОЗДАНО", authzplan.ShippedModelRelPath()} {
		if !strings.Contains(got, want) {
			t.Errorf("строка исхода не называет предпосылки (%q): %s", want, got)
		}
	}
	if strings.HasPrefix(got, "модуль ") {
		t.Errorf("строка исхода приписана модулю, которого не назвали: %s — читатель "+
			"ищет виновника там, где его нет", got)
	}
}

// TestContractTreePresentKeepsTheMissingManifestAFinding — ЗАКОННЫЙ БЛИЗНЕЦ.
//
// Отличие от инъекции выше РОВНО ОДНО: канон лежит в дереве контрактов. Значит
// это монорепо, манифесты соседей сюда поставляются, и их отсутствие — находка.
func TestContractTreePresentKeepsTheMissingManifestAFinding(t *testing.T) {
	root := helperTree(t, twoBlockCanon)
	writeManifest(t, root, "vpc", manifestFor("vpc", "vpc_network", "vpc_subnet"))

	_, findings, code := modelrender.Sweep(seed.LiteralRows().Resources, root, nil)

	if code != modelrender.SweepFinding {
		t.Fatalf("исход %d, ожидался %d: дерево контрактов ЕСТЬ, значит отсутствие "+
			"манифеста соседа — находка, и послабление её накрывать не вправе. "+
			"Без этого утверждения послабление зеленело бы и на монорепо с удалённым "+
			"манифестом", code, modelrender.SweepFinding)
	}
	if len(findings) == 0 {
		t.Fatal("находок ноль при исходе «находка» — вердикт себе противоречит")
	}
}

// TestStandaloneDeliveryStillReportsARealMismatch — ВТОРАЯ СТОРОНА оси.
//
// Отличие от инъекции РОВНО ОДНО: сверка ДОШЛА до блоков и нашла расхождение.
// Послабление накрывает только «манифестов соседей нет», и ничего сверх этого.
func TestStandaloneDeliveryStillReportsARealMismatch(t *testing.T) {
	root := shippedOnlyTree(t, twoBlockCanon)
	// Манифест объявляет блок, которого в каноне нет: расхождение НАСТОЯЩЕЕ.
	writeManifest(t, root, "vpc", manifestFor("vpc", "vpc_network", "vpc_nosuchblock"))

	_, findings, code := modelrender.Sweep(seed.LiteralRows().Resources, root, nil)

	if code != modelrender.SweepFinding {
		t.Fatalf("исход %d, ожидался %d: сверка дошла до блоков и нашла расхождение — "+
			"послабление самостоятельной поставки его накрывать не вправе.\nнаходки: %v",
			code, modelrender.SweepFinding, findings)
	}
}

func contains(s, sub string) bool { return len(sub) == 0 || indexOf(s, sub) >= 0 }
func hasPrefix(s, p string) bool  { return len(s) >= len(p) && s[:len(p)] == p }
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
