// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modelrender_test

// prior_edition_test.go — переходный приём прежней редакции блоков registry
// (Р10, до kaname#858) — одно правило на двух судей: сборку модели и сверку
// дерева. Здесь — само правило: рендер манифеста прежней редакции принимается,
// рендер с одним изменённым словом примечания — нет, чужой тип с тем же
// содержимым — нет.

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/modelrender"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

func TestIsPriorEditionAcceptsExactlyThePriorBytes(t *testing.T) {
	doc, err := publicreadfixture.Read(publicreadfixture.PriorEditionFile)
	if err != nil {
		t.Fatalf("фикстура: %v", err)
	}
	m, err := manifest.Load(doc)
	if err != nil {
		t.Fatalf("фикстура: %v", err)
	}
	for _, r := range m.Resources {
		blk, err := modelrender.Render(r)
		if err != nil {
			t.Fatalf("рендер %s: %v", r.ObjectType, err)
		}
		if !modelrender.IsPriorEdition(r.ObjectType, blk) {
			t.Errorf("близнец: рендер прежней редакции %s не признан", r.ObjectType)
		}
		changed := []byte(strings.Replace(string(blk), "owner", "ownerx", 1))
		if modelrender.IsPriorEdition(r.ObjectType, changed) {
			t.Errorf("%s: блок, отличный от прежней редакции, признан", r.ObjectType)
		}
		if modelrender.IsPriorEdition("vpc_network", blk) {
			t.Errorf("%s: байты прежней редакции признаны у чужого типа", r.ObjectType)
		}
	}
}
