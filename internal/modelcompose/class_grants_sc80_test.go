// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modelcompose_test

// class_grants_sc80_test.go — SC-80 (а), половина сборки: ключ оболочки S7
// `classGrantsOnlyOnContainers` модель прав не трогает (задача
// PRO-Robotech/kaname#950).
//
// Приёмка docs/engineering/acceptance/anonymous-and-authenticated-are-subject-classes.md,
// редакция 17, отпечаток d44a9bbbdfef42e5f33d0ded13754ff103a4ae33f7ad6d7695be3865b65f9ae7.
// Половина загрузки и (б) — `internal/manifest`, `TestLoadDelivered_SC80_…`.
//
// Путь — тот же, что у старта: `manifest.LoadDelivered`, затем
// `modelcompose.Compose` над вшитым каноном. Сначала фикстура — документ П6
// доставляется и собирается, — потом предмет: документ П7.

import (
	"bytes"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	"github.com/PRO-Robotech/kaname/internal/modelrender"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

// sc80Renders — рендер блоков registry доставленного документа по типу модели.
func sc80Renders(t *testing.T, ms []*manifest.Manifest) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, res := range ms[0].Resources {
		blk, err := modelrender.Render(res)
		if err != nil {
			t.Fatalf("рендер %s: %v", res.ObjectType, err)
		}
		out[res.ObjectType] = blk
	}
	return out
}

// TestCompose_SC80_a_KeyStartsWithoutChangingTheModel — SC-80 (а): старт с
// документом П7 успешен; блоки registry в переписи `Reaffirmed`, их рендер
// равен рендеру документа П6 байт в байт. Близнец — документ П6 (SC-70 (б)).
func TestCompose_SC80_a_KeyStartsWithoutChangingTheModel(t *testing.T) {
	p6 := sc70Fixture(t, publicreadfixture.NewEditionFile)
	twin := sc70DeliverSubject(t, "SC-80 (а) близнец П6", p6)
	if _, _, err := modelcompose.Compose(authzmodel.DSL, twin); err != nil {
		t.Fatalf("фикстура: документ П6 обязан собираться: %v", err)
	}
	p7, err := publicreadfixture.WithClassGrantsKey(p6)
	if err != nil {
		t.Fatalf("фикстура: документ П7: %v", err)
	}

	rep, err := manifest.LoadDelivered(sc70Deliver(t, p7))
	if err != nil {
		t.Fatalf("SC-80 (а): доставка документа П7 отвергнута (ключа %s у загрузчика нет — предмета S7 нет): %v",
			publicreadfixture.ClassGrantsKey, err)
	}
	_, crep, err := modelcompose.Compose(authzmodel.DSL, rep.Manifests)
	if err != nil {
		t.Fatalf("SC-80 (а): старт с документом П7 обязан быть успешен, отказ: %v", err)
	}
	want, got := sc80Renders(t, twin), sc80Renders(t, rep.Manifests)
	for _, typ := range []string{"registry_registry", "registry_repository"} {
		found := false
		for _, r := range crep.Reaffirmed {
			found = found || r == typ
		}
		if !found {
			t.Fatalf("SC-80 (а): %s нет в переписи Reaffirmed (%s)", typ, crep.Census())
		}
		if len(want[typ]) == 0 || !bytes.Equal(want[typ], got[typ]) {
			t.Fatalf("SC-80 (а): рендер %s документа П7 не равен рендеру документа П6 (%d Б против %d Б) — ключ тронул модель",
				typ, len(got[typ]), len(want[typ]))
		}
	}
}
