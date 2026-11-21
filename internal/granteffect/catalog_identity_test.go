// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package granteffect

import (
	"slices"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/catalog"
)

func TestCompilerCatalogIdentitySurvivesSQLRowPermutation(t *testing.T) {
	h := rows()
	a, err := New(modelFixture, h)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(h.Live.Modules)
	slices.Reverse(h.Live.Resources)
	slices.Reverse(h.Live.Verbs)
	h.Retired = catalog.Rows{Modules: []string{}, Resources: []catalog.ResourceRow{}, Verbs: []catalog.VerbRow{}}
	b, err := New(modelFixture, h)
	if err != nil {
		t.Fatal(err)
	}
	left := complete(t, a.Compile(binding(box("get"))))
	right := complete(t, b.Compile(binding(box("get"))))
	if left.Identity() != right.Identity() {
		t.Fatal("одинаковые строки из разных SQL порядков получили разные identity")
	}
	proves(t, left, right, true)
	proves(t, right, left, true)
}

func TestCompilerCatalogIdentityChangesWithSemanticRowAndRejectsDuplicates(t *testing.T) {
	a := compiler(t)
	h := rows()
	h.Live.Verbs[0].PerObject = !h.Live.Verbs[0].PerObject
	b, err := New(modelFixture, h)
	if err != nil {
		t.Fatal(err)
	}
	if a.identity == b.identity {
		t.Fatal("изменение producer semantics не изменило identity")
	}
	for _, reverse := range []bool{false, true} {
		h = rows()
		dup := h.Live.Resources[0]
		dup.ObjectType = "other_box"
		h.Live.Resources = append(h.Live.Resources, dup)
		if reverse {
			slices.Reverse(h.Live.Resources)
		}
		if c, err := New(modelFixture, h); err == nil || c != nil {
			t.Fatal("неоднозначный снимок не должен стать компилятором", err)
		}
	}
}
