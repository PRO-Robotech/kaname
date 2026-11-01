// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest_test

// writes_test.go — DP-20 a–h приёмки
// docs/engineering/acceptance/kaname-derives-the-parent-of-a-registered-object.md
// (отпечаток 1f2991d64d0f8a9b90f8dbcaabeadd8e6af3d2b38e4f573c5d49dfe1a5a1f6e8,
// задача PRO-Robotech/kaname#982): загрузчик проверяет ключ `writes`.
//
// Основа — документ W (прежняя редакция registry плюс `writes` на обоих
// ресурсах); каждый вариант — правка ОДНОГО ключа W у `registries` (ресурс 0),
// и W без правки загружается (DP-20 i, загрузочная половина) — это близнец
// каждого отказа. Пример d судится на базовом документе с авторским отношением
// `auditor`; его контроль — тот же документ без записи `auditor` загружается.

import (
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

// dp20W — документ W мира ДР.
func dp20W(t *testing.T) []byte {
	t.Helper()
	p0, err := publicreadfixture.Read(publicreadfixture.PriorEditionFile)
	if err != nil {
		t.Fatalf("фикстура P0: %v", err)
	}
	if _, err := manifest.Load(p0); err != nil {
		t.Fatalf("контроль фикстуры: P0 без ключа writes обязан загружаться: %v", err)
	}
	w, err := publicreadfixture.WithWrites(p0)
	if err != nil {
		t.Fatalf("фикстура W: %v", err)
	}
	return w
}

// TestDeriveParent_DP20_i_WritesLoads — DP-20 i, загрузочная половина: W без
// правки загружается. Что запись доезжает до политики, утверждает
// интеграционная половина DP-20 i через читателя политики.
func TestDeriveParent_DP20_i_WritesLoads(t *testing.T) {
	if _, err := manifest.Load(dp20W(t)); err != nil {
		t.Fatalf("DP-20 i: документ W отвергнут загрузчиком (ключа writes нет): %v", err)
	}
}

// TestDeriveParent_DP20_LoaderRefusesMalformedWrites — DP-20 a–h.
func TestDeriveParent_DP20_LoaderRefusesMalformedWrites(t *testing.T) {
	w := dp20W(t)
	const auditor = "      - {name: auditor, definition: '[user]', position: beforeTiers}"
	withAuditor, err := publicreadfixture.WithRegistriesRelation(w, auditor)
	if err != nil {
		t.Fatalf("фикстура d: %v", err)
	}
	if _, err := manifest.Load(withAuditor); err != nil {
		t.Fatalf("контроль d: документ с отношением auditor без записи auditor обязан загружаться: %v", err)
	}

	cases := []struct {
		name  string
		base  []byte
		block string
		want  error
		coord string
	}{
		{"a", w, "    writes: []\n", manifest.ErrWritesEmpty, "resources[0].writes"},
		{"b", w, "    writes:\n      - relation: project\n        subjects: [user]\n",
			manifest.ErrWriteIsPointer, "resources[0].writes[0].relation"},
		{"c", w, "    writes:\n      - relation: maintainer\n        subjects: [user]\n",
			manifest.ErrWriteRelationUndeclared, "resources[0].writes[0].relation"},
		{"d", withAuditor, "    writes:\n      - relation: auditor\n        subjects: [user]\n",
			manifest.ErrWriteRelationNotWritable, "resources[0].writes[0].relation"},
		{"e", w, "    writes:\n      - relation: owner\n        subjects: []\n",
			manifest.ErrWriteSubjectsInvalid, "resources[0].writes[0].subjects"},
		{"f", w, "    writes:\n      - relation: owner\n        subjects: [group]\n",
			manifest.ErrWriteSubjectsInvalid, "resources[0].writes[0].subjects"},
		{"g", w, "    writes:\n      - relation: owner\n        subjects: [user, user]\n",
			manifest.ErrWriteSubjectsInvalid, "resources[0].writes[0].subjects"},
		{"h", w, "    writes:\n      - relation: owner\n        subjects: [user, service_account]\n" +
			"      - relation: owner\n        subjects: [service_account]\n",
			manifest.ErrWriteDuplicate, "resources[0].writes[1].relation"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := publicreadfixture.WithRegistriesWrites(tc.base, tc.block)
			if err != nil {
				t.Fatalf("фикстура %s: %v", tc.name, err)
			}
			_, err = manifest.Load(doc)
			if err == nil {
				t.Fatalf("DP-20 %s: загрузчик принял документ, ожидался отказ %v", tc.name, tc.want)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("DP-20 %s: отказ не того вида: ждали errors.Is(%v), получено: %v", tc.name, tc.want, err)
			}
			if !strings.Contains(err.Error(), tc.coord) {
				t.Fatalf("DP-20 %s: отказ не называет координату %q: %v", tc.name, tc.coord, err)
			}
		})
	}
}
