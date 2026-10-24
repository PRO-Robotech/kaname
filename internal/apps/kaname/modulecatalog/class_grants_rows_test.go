// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modulecatalog_test

// class_grants_rows_test.go — ключ оболочки S7 доезжает от разобранного
// манифеста до строки модуля каталога (kaname#950, Р11 п. 7): `RowsOf` несёт
// его в `Declared`, а применитель — в `UpsertModule`.

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

func TestRowsOf_SC80_KeyReachesTheModuleRow(t *testing.T) {
	p6, err := publicreadfixture.Read(publicreadfixture.NewEditionFile)
	if err != nil {
		t.Fatalf("фикстура: %v", err)
	}
	p7, err := publicreadfixture.WithClassGrantsKey(p6)
	if err != nil {
		t.Fatalf("фикстура: документ П7: %v", err)
	}
	for _, c := range []struct {
		name string
		doc  []byte
		want bool
	}{
		{"П6 без ключа", p6, false},
		{"П7 с ключом", p7, true},
	} {
		m, err := manifest.Load(c.doc)
		if err != nil {
			t.Fatalf("%s: загрузка: %v", c.name, err)
		}
		if got := m.DeclaresClassGrantsOnlyOnContainers(); got != c.want {
			t.Fatalf("%s: манифест объявляет ключ = %v, ожидалось %v", c.name, got, c.want)
		}
		d, err := modulecatalog.RowsOf(m)
		if err != nil {
			t.Fatalf("%s: RowsOf: %v", c.name, err)
		}
		if d.ClassGrantsOnlyOnContainers != c.want {
			t.Fatalf("%s: строка модуля несёт ключ = %v, ожидалось %v", c.name, d.ClassGrantsOnlyOnContainers, c.want)
		}
	}
}
