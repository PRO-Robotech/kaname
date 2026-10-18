// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest_test

// public_read_reserved_test.go — имя `public_reader` у контейнера порождает ключ
// публичного чтения (kaname#856): авторское отношение под этим именем — второе
// объявление одного отношения, загрузка его отвергает. Близнец — тот же документ
// без ключа: авторское отношение под этим именем ничему не мешает.

import (
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

func TestPublicReaderNameIsTakenByTheKey(t *testing.T) {
	doc, err := publicreadfixture.Read(publicreadfixture.ProbemodFile)
	if err != nil {
		t.Fatalf("фикстура: %v", err)
	}
	const anchor = "    publicReadToChildren: true\n"
	const authored = "    relations:\n      - {name: public_reader, definition: '[user]'}\n"
	if strings.Count(string(doc), anchor) != 1 {
		t.Fatalf("фикстура: строка ключа не найдена ровно один раз")
	}
	shadowing := []byte(strings.Replace(string(doc), anchor, anchor+authored, 1))

	twin, err := publicreadfixture.WithoutKey(shadowing)
	if err != nil {
		t.Fatalf("фикстура: близнец без ключа: %v", err)
	}
	if _, err := manifest.Load(twin); err != nil {
		t.Fatalf("близнец: без ключа авторское public_reader законно, отказ: %v", err)
	}
	_, err = manifest.Load(shadowing)
	const want = "resources[0].relations[0].name: имя \"public_reader\" порождает ключ publicReadToChildren"
	if !errors.Is(err, manifest.ErrPublicReaderShadowed) || !strings.Contains(err.Error(), want) {
		t.Fatalf("авторское public_reader при ключе обязано быть находкой %q, получено: %v", want, err)
	}
}

// TestPublicReadPointersAreDerivedOnlyForAChildOfADeclaredContainer — вывод
// третьего следствия: ребёнок объявленного контейнера получает имя своего
// указателя; без ключа — ничего.
func TestPublicReadPointersAreDerivedOnlyForAChildOfADeclaredContainer(t *testing.T) {
	doc, err := publicreadfixture.Read(publicreadfixture.ProbemodFile)
	if err != nil {
		t.Fatalf("фикстура: %v", err)
	}
	twin, err := publicreadfixture.WithoutKey(doc)
	if err != nil {
		t.Fatalf("фикстура: близнец без ключа: %v", err)
	}
	pointers := func(b []byte) map[string][]string {
		m, err := manifest.Load(b)
		if err != nil {
			t.Fatalf("загрузка: %v", err)
		}
		out := map[string][]string{}
		for _, r := range m.Resources {
			out[r.Name] = r.PublicReadPointers()
		}
		return out
	}
	for name, p := range pointers(twin) {
		if len(p) != 0 {
			t.Fatalf("близнец без ключа: у %s выведены указатели %v", name, p)
		}
	}
	got := pointers(doc)
	if len(got["boxes"]) != 0 || len(got["items"]) != 1 || got["items"][0] != "box" {
		t.Fatalf("ожидался указатель box у items и ничего у boxes, получено %v", got)
	}
}
