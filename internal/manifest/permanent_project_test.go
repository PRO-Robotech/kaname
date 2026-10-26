// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest_test

// permanent_project_test.go — PB-22 a–d (загрузочная половина) приёмки
// docs/engineering/acceptance/object-keeps-its-project-after-unregistration.md
// (отпечаток 9bd07e389bdce22cad13b556b4fe78cfda3f878285895282a5580fa211e5122a,
// задача PRO-Robotech/kaname#983): загрузчик проверяет ключ `permanentProject`.
//
// Основа — документ D-K; каждый вариант — правка ОДНОГО ключа D-K, и D-K без
// правки загружается (PB-22 d) — близнец каждого отказа. Что признак доезжает до
// строки каталога, утверждает интеграционная половина PB-22 d.

import (
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

// pb22DK — документ D-K; контроль — тот же документ без ключа загружается.
func pb22DK(t *testing.T) []byte {
	t.Helper()
	dk, err := publicreadfixture.PermanentProjectDocument()
	if err != nil {
		t.Fatalf("фикстура D-K: %v", err)
	}
	keyless, err := publicreadfixture.WithoutPermanentProject(dk)
	if err != nil {
		t.Fatalf("фикстура D-K без ключа: %v", err)
	}
	if _, err := manifest.Load(keyless); err != nil {
		t.Fatalf("контроль фикстуры: D-K без ключа permanentProject обязан загружаться: %v", err)
	}
	return dk
}

// TestPermanentProject_PB22_d_DeclarationLoads — PB-22 d, загрузочная половина.
func TestPermanentProject_PB22_d_DeclarationLoads(t *testing.T) {
	if _, err := manifest.Load(pb22DK(t)); err != nil {
		t.Fatalf("PB-22 d: документ D-K отвергнут загрузчиком (ключа permanentProject нет): %v", err)
	}
}

// TestPermanentProject_PB22_LoaderRefusesMalformedDeclaration — PB-22 a–c.
func TestPermanentProject_PB22_LoaderRefusesMalformedDeclaration(t *testing.T) {
	dk := pb22DK(t)
	cases := []struct {
		name  string
		edit  func([]byte) ([]byte, error)
		want  error
		coord string
	}{
		{"a", func(d []byte) ([]byte, error) {
			return publicreadfixture.WithRegistriesPermanentProject(d, "    permanentProject: false")
		}, manifest.ErrPermanentProjectFalse, "resources[0].permanentProject"},
		{"b", func(d []byte) ([]byte, error) {
			return publicreadfixture.WithRegistriesParents(d, "    parents: [account]")
		}, manifest.ErrPermanentProjectWithoutProject, "resources[0].permanentProject"},
		{"c", func(d []byte) ([]byte, error) {
			return publicreadfixture.WithRegistriesPermanentProject(d, "")
		}, manifest.ErrPermanentProjectParentUnbound, "resources[1].permanentProject"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := tc.edit(dk)
			if err != nil {
				t.Fatalf("фикстура %s: %v", tc.name, err)
			}
			_, err = manifest.Load(doc)
			if err == nil {
				t.Fatalf("PB-22 %s: загрузчик принял документ, ожидался отказ %v", tc.name, tc.want)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("PB-22 %s: отказ не того вида: ждали errors.Is(%v), получено: %v", tc.name, tc.want, err)
			}
			if !strings.Contains(err.Error(), tc.coord) {
				t.Fatalf("PB-22 %s: отказ не называет координату %q: %v", tc.name, tc.coord, err)
			}
		})
	}
}
