// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import (
	"strings"
	"testing"
)

// F4d-52: форма идентичности субъекта полосы `own` — голова называет полосу,
// хвост — идентификатор фундамента; длина ≤ 128; два заведения дают два
// разных значения; форма проходит проверку контракта.
func TestOwnLaneSubject_F4d52_FormIsSelfDescribingAndUnique(t *testing.T) {
	a, b := NewOwnLaneSubject(), NewOwnLaneSubject()
	for _, s := range []ExternalSubject{a, b} {
		if !s.IsOwnLane() {
			t.Fatalf("голова полосы не читается: %q", s)
		}
		if !strings.HasPrefix(string(s), OwnLaneSubjectHead+ownLaneSubjectPrefix+"-") {
			t.Fatalf("хвост не в дефисном каноне: %q", s)
		}
		if len(s) > 128 {
			t.Fatalf("длина %d выше предела контракта 128: %q", len(s), s)
		}
		if err := s.Validate(); err != nil {
			t.Fatalf("форма не проходит проверку контракта: %v", err)
		}
	}
	if a == b {
		t.Fatalf("два заведения дали одно значение: %q", a)
	}
	// Законный близнец: значение полосы поставщика головы не несёт.
	if ExternalSubject("ext-provider-1").IsOwnLane() {
		t.Fatal("чужая идентичность прочитана как наша")
	}
}
