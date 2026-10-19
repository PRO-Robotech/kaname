// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest_test

// public_read_class_in_read_verb_test.go — PM-06 приёмки
// docs/engineering/acceptance/public-read-container-of-a-module-type-is-admitted.md
// (отпечаток a129f53c4c46525b390d5f71bda31866e43e0776c6c556326806ce313836babf,
// задача PRO-Robotech/kaname#866): класс субъекта в действии чтения контейнера С
// ключом — второе объявление того, что пишет сам ключ, и отказ ЗАГРУЗКИ (Р2).
//
// Почему загрузка, а не допуск: блок контейнера с такой записью побайтово равен
// блоку из одного ключа (замер приёмки, строка 5), и допуск их не различает.

import (
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

// pm06Verbs — строка действий контейнера `boxes` фикстуры П1.
const pm06Verbs = "    verbs: [get, list, create, update, delete]\n"

// pm06Doc — П1 с заменой ровно одного вхождения строки действий контейнера.
func pm06Doc(t *testing.T, verbs string) []byte {
	t.Helper()
	doc, err := publicreadfixture.Read(publicreadfixture.ProbemodFile)
	if err != nil {
		t.Fatalf("фикстура: %v", err)
	}
	if n := strings.Count(string(doc), pm06Verbs); n != 1 {
		t.Fatalf("фикстура: строка действий контейнера встречается %d раз, нужна одна", n)
	}
	return []byte(strings.Replace(string(doc), pm06Verbs, verbs, 1))
}

// TestPM06_ClassInAReadVerbOfAContainerWithTheKeyIsRefusedByTheLoad — три
// написания класса, оба действия чтения; близнец — П1 как есть (PM-01).
func TestPM06_ClassInAReadVerbOfAContainerWithTheKeyIsRefusedByTheLoad(t *testing.T) {
	// Близнец: П1 загружается. Без него отказ ниже неотличим от сломанной фикстуры.
	if _, err := manifest.Load(pm06Doc(t, pm06Verbs)); err != nil {
		t.Fatalf("контроль фикстуры: П1 обязан загружаться: %v", err)
	}

	const tail = "ресурса с ключом publicReadToChildren вносит сам ключ — два объявления одного следствия, из которых верно одно"
	cases := []struct {
		name, verbs, want string
	}{
		{"get, system_class",
			"    verbs: [{name: get, subjects: [system_class, user, service_account, 'group#member']}, list, create, update, delete]\n",
			"resources[0].verbs[0].subjects: класс субъекта в действии get " + tail},
		{"get, system_class:anonymous",
			"    verbs: [{name: get, subjects: ['system_class:anonymous', user, service_account, 'group#member']}, list, create, update, delete]\n",
			"resources[0].verbs[0].subjects: класс субъекта в действии get " + tail},
		{"get, user:*",
			"    verbs: [{name: get, subjects: ['user:*', user, service_account, 'group#member']}, list, create, update, delete]\n",
			"resources[0].verbs[0].subjects: класс субъекта в действии get " + tail},
		{"list, system_class",
			"    verbs: [get, {name: list, subjects: [system_class, user, service_account, 'group#member']}, create, update, delete]\n",
			"resources[0].verbs[1].subjects: класс субъекта в действии list " + tail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := manifest.Load(pm06Doc(t, c.verbs))
			if !errors.Is(err, manifest.ErrPublicReadClassInReadVerb) {
				t.Fatalf("класс в действии чтения контейнера с ключом обязан быть отказом загрузки "+
					"ErrPublicReadClassInReadVerb, получено: %v", err)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("отказ обязан нести координату и текст PM-06 дословно:\n  ждали: %s\n  получено: %v", c.want, err)
			}
		})
	}
}

// TestPM06_EveryReadVerbWithAClassIsNamed — находки копятся: оба действия чтения
// называются, а не первое.
func TestPM06_EveryReadVerbWithAClassIsNamed(t *testing.T) {
	doc := pm06Doc(t, "    verbs: [{name: get, subjects: [system_class, user]}, "+
		"{name: list, subjects: ['user:*', user]}, create, update, delete]\n")
	_, err := manifest.Load(doc)
	if !errors.Is(err, manifest.ErrPublicReadClassInReadVerb) {
		t.Fatalf("ждали ErrPublicReadClassInReadVerb, получено: %v", err)
	}
	for _, want := range []string{"resources[0].verbs[0].subjects", "resources[0].verbs[1].subjects"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("отказ обязан назвать %s — находки копятся, а не первая: %v", want, err)
		}
	}
}

// TestPM06_RuleTouchesOnlyAResourceWithTheKey — Р2 не распространяется: тот же
// состав без ключа загружается (PM-05 судит допуск), и класс в `get` РЕБЁНКА при
// ключе на контейнере загружается тоже (PM-10 судит допуск).
func TestPM06_RuleTouchesOnlyAResourceWithTheKey(t *testing.T) {
	withClass := pm06Doc(t, "    verbs: [{name: get, subjects: [system_class, user, service_account, 'group#member']}, list, create, update, delete]\n")
	keyless, err := publicreadfixture.WithoutKey(withClass)
	if err != nil {
		t.Fatalf("фикстура: близнец без ключа: %v", err)
	}
	if _, err := manifest.Load(keyless); err != nil {
		t.Fatalf("без ключа класс в get — не предмет Р2 (его судит допуск, PM-05), отказ загрузки: %v", err)
	}

	doc, err := publicreadfixture.Read(publicreadfixture.ProbemodFile)
	if err != nil {
		t.Fatalf("фикстура: %v", err)
	}
	const items = "    verbs: [get, list, update, delete]"
	if strings.Count(string(doc), items) != 1 {
		t.Fatalf("фикстура: строка действий ребёнка не найдена ровно один раз")
	}
	child := []byte(strings.Replace(string(doc), items,
		"    verbs: [{name: get, subjects: [system_class, user, service_account, 'group#member']}, list, update, delete]", 1))
	if _, err := manifest.Load(child); err != nil {
		t.Fatalf("класс в get РЕБЁНКА — не предмет Р2 (его судит допуск, PM-10), отказ загрузки: %v", err)
	}

	// Не-чтение контейнера с классом — тоже не предмет Р2: правило касается
	// только get и list (свой текст ему даёт допуск).
	update := pm06Doc(t, "    verbs: [get, list, create, {name: update, subjects: [system_class, user]}, delete]\n")
	if _, err := manifest.Load(update); errors.Is(err, manifest.ErrPublicReadClassInReadVerb) {
		t.Fatalf("Р2 касается только get и list, а сработал на update: %v", err)
	}
}
