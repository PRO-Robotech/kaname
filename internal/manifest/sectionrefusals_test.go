// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// sectionrefusals_test.go — отказы трёх разделов, у которых нет собственного
// сценария приёмки, но есть производитель в прод-коде.
//
// # Зачем отдельный файл, а не строки в соседних
//
// Приёмка перечисляет отказы, у которых есть ПРЕДМЕТ СПОРА: обязателен ли ключ,
// закрыт ли набор, чей это модуль. Рядом с ними живут отказы, о которых спорить
// не о чем — «поле не названо», — и они точно так же суть часть контракта:
// объявленный и НИ РАЗУ не проверенный отказ неотличим от отказа, которого код
// не производит. Оба вида здесь проверяются одинаково: подан вход, назван вид
// отказа, названо поле.
//
// Каждый отрицательный вход рядом со СВОИМ положительным — иначе перечень
// зеленел бы на загрузчике, отвергающем всё.
package manifest_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
)

func TestSectionRefusalsNameTheirFieldAndKind(t *testing.T) {
	for _, tc := range []struct {
		name  string
		doc   string
		kind  error
		names []string
	}{
		{
			name: "ресурс не назвал себя",
			doc: "apiVersion: iam/v1\nmodule: vpc\nresources:\n" +
				"  - {objectType: vpc_network, parent: project, producer: derived, verbs: [get]}\n",
			kind:  manifest.ErrResourceNameRequired,
			names: []string{"resources[0]"},
		},
		{
			name: "якорь области не назван",
			doc: "apiVersion: iam/v1\nmodule: vpc\nresources:\n" +
				"  - {name: network, objectType: vpc_network, producer: derived, verbs: [get]}\n",
			kind:  manifest.ErrParentRequired,
			names: []string{"resources[0].parent", "project", "account", "cluster"},
		},
		{
			name: "действие не назвало себя",
			doc: "apiVersion: iam/v1\nmodule: vpc\nresources:\n" +
				"  - name: network\n    objectType: vpc_network\n    parent: project\n    producer: derived\n" +
				"    verbs:\n      - {class: get}\n",
			kind:  manifest.ErrVerbNameRequired,
			names: []string{"resources[0].verbs[0]"},
		},
		{
			name: "отношение не назвало себя",
			doc: "apiVersion: iam/v1\nmodule: vpc\nresources:\n" +
				"  - name: network\n    objectType: vpc_network\n    parent: project\n    producer: derived\n" +
				"    relations:\n      - {definition: \"[user]\"}\n    verbs: [get]\n",
			kind:  manifest.ErrRelationNameRequired,
			names: []string{"resources[0].relations[0]"},
		},
		{
			name: "роль не назвала себя",
			doc: "apiVersion: iam/v1\nmodule: vpc\nroles:\n" +
				"  - name: Наблюдатель\n    description: Читает топологию проекта.\n" +
				"    tier: {tierType: iam.project, tierId: prj000000000000000}\n" +
				"    rules:\n      - {module: vpc, resources: [network], verbs: [get]}\n",
			kind:  manifest.ErrRoleIDRequired,
			names: []string{"roles[0]"},
		},
		{
			name: "идентификатор роли не той формы",
			doc: "apiVersion: iam/v1\nmodule: vpc\nroles:\n" +
				"  - id: viewer\n    name: Наблюдатель\n    description: Читает топологию проекта.\n" +
				"    tier: {tierType: iam.project, tierId: prj000000000000000}\n" +
				"    rules:\n      - {module: vpc, resources: [network], verbs: [get]}\n",
			kind:  manifest.ErrRoleIDMalformed,
			names: []string{"roles[0].id", "viewer"},
		},
		{
			name: "две роли под одним идентификатором",
			doc: "apiVersion: iam/v1\nmodule: vpc\nroles:\n" +
				"  - id: vpc.viewer\n    name: Наблюдатель\n    description: Читает топологию проекта.\n" +
				"    tier: {tierType: iam.project, tierId: prj000000000000000}\n" +
				"    rules:\n      - {module: vpc, resources: [network], verbs: [get]}\n" +
				"  - id: vpc.viewer\n    name: Второй наблюдатель\n    description: Тоже читает топологию.\n" +
				"    tier: {tierType: iam.account, tierId: acc000000000000000}\n" +
				"    rules:\n      - {module: vpc, resources: [subnet], verbs: [get]}\n",
			kind:  manifest.ErrRoleIDDuplicated,
			names: []string{"roles[0]", "roles[1]", "vpc.viewer"},
		},
		{
			name: "ярус роли не назван",
			doc: "apiVersion: iam/v1\nmodule: vpc\nroles:\n" +
				"  - id: vpc.viewer\n    name: Наблюдатель\n    description: Читает топологию проекта.\n" +
				"    rules:\n      - {module: vpc, resources: [network], verbs: [get]}\n",
			kind:  manifest.ErrRoleTierRequired,
			names: []string{"roles[0].tier", "iam.account", "iam.project"},
		},
		{
			name: "ярус роли вне закрытого набора",
			doc: "apiVersion: iam/v1\nmodule: vpc\nroles:\n" +
				"  - id: vpc.viewer\n    name: Наблюдатель\n    description: Читает топологию проекта.\n" +
				"    tier: {tierType: iam.folder, tierId: fld000000000000000}\n" +
				"    rules:\n      - {module: vpc, resources: [network], verbs: [get]}\n",
			kind:  manifest.ErrRoleTierUnknown,
			names: []string{"roles[0].tier.tierType", "iam.folder"},
		},
		{
			name: "якорь яруса не назван",
			doc: "apiVersion: iam/v1\nmodule: vpc\nroles:\n" +
				"  - id: vpc.viewer\n    name: Наблюдатель\n    description: Читает топологию проекта.\n" +
				"    tier: {tierType: iam.project, tierId: \"\"}\n" +
				"    rules:\n      - {module: vpc, resources: [network], verbs: [get]}\n",
			kind:  manifest.ErrRoleTierRequired,
			names: []string{"roles[0].tier.tierId"},
		},
		{
			name: "устаревший глагол не назван",
			doc: "apiVersion: iam/v1\nmodule: vpc\ndeprecatedVerbs:\n" +
				"  \"\": {class: get, since: \"2026-08-23\", reason: синоним чтения из грамматики, removeWhen: выдач с таким правом ноль}\n",
			kind:  manifest.ErrDeprecatedVerbNameEmpty,
			names: []string{"deprecatedVerbs"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := manifest.Load([]byte(tc.doc))
			if err == nil {
				t.Fatalf("вход принят молча")
			}
			if !errors.Is(err, tc.kind) {
				t.Errorf("отказ не отнесён к своей причине: %v", err)
			}
			for _, want := range tc.names {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("отказ не называет %q: %v", want, err)
				}
			}
		})
	}

	// Парный положительный ко ВСЕМУ перечню: документ, у которого каждое из
	// названных выше полей на месте, проходит целиком. Без него весь перечень
	// зеленел бы на загрузчике, отвергающем всякий вход.
	whole := "apiVersion: iam/v1\nmodule: vpc\nresources:\n" +
		"  - name: network\n    objectType: vpc_network\n    parent: project\n    producer: derived\n" +
		"    relations:\n      - {name: use, definition: \"[user]\"}\n" +
		"    verbs:\n      - {name: get}\n" +
		"roles:\n" +
		"  - id: vpc.viewer\n    name: Наблюдатель\n    description: Читает топологию проекта.\n" +
		"    tier: {tierType: iam.project, tierId: prj000000000000000}\n" +
		"    rules:\n      - {module: vpc, resources: [network], verbs: [get]}\n" +
		"deprecatedVerbs:\n" +
		"  read: {class: get, since: \"2026-08-23\", reason: синоним чтения из грамматики, removeWhen: выдач с таким правом ноль}\n"
	if _, err := manifest.Load([]byte(whole)); err != nil {
		t.Fatalf("парный положительный ко всему перечню отвергнут: %v", err)
	}
}
