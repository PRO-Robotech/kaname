// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package service

// object_ref_test.go — разбор строки объекта «тип:идентификатор».
//
// Проба переехала сюда из cascade_fallback_test.go, снятого вместе со своим
// предметом (структурный запасной путь). Сам разбор предмета не потерял: его
// зовёт readSubjectRelations, чтобы спросить у решающей стороны, какие
// отношения субъект УЖЕ держит на объекте, — то есть от него зависит хвост
// текста отказа, который читает человек.

import "testing"

func TestSplitFGAObject_KeepsColonsInsideTheID(t *testing.T) {
	// registry_repository ids carry their own colon (`<reg>/<repo>:<tag>`), so only
	// the FIRST colon separates type from id.
	for _, tc := range []struct{ in, wantType, wantID string }{
		{"iam_access_binding:abn_1", "iam_access_binding", "abn_1"},
		{"registry_repository:reg_1/app:v1", "registry_repository", "reg_1/app:v1"},
	} {
		gotType, gotID, ok := splitFGAObject(tc.in)
		if !ok || gotType != tc.wantType || gotID != tc.wantID {
			t.Fatalf("splitFGAObject(%q) = (%q, %q, %v)", tc.in, gotType, gotID, ok)
		}
	}
	for _, bad := range []string{"", "no_colon", ":leading", "trailing:"} {
		if _, _, ok := splitFGAObject(bad); ok {
			t.Fatalf("splitFGAObject(%q) must not parse", bad)
		}
	}
}
