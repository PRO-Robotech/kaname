// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// public_read_container_integration_test.go — ограничения схемы публичного
// чтения контейнера (миграция 20261017020000, задача PRO-Robotech/kaname#856).
//
// Каждая строка отказа меняет против законного близнеца ровно один факт:
// субъекта факта `public_reader` (класс проходит, человек — нет) либо элемент
// перечня указателей строки каталога (имя типа проходит, пустое и с пробелом —
// нет).
package migrations_test

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// prRefused — отказ дан проверочным ограничением `constraint` (23514).
func prRefused(t *testing.T, err error, constraint, what string) {
	t.Helper()
	require.Errorf(t, err, "%s: принято", what)
	pgErr := pgErrorOf(err)
	require.NotNilf(t, pgErr, "%s: отказ не от базы: %v", what, err)
	assert.Equalf(t, "23514", pgErr.Code, "%s: код отказа (%s)", what, pgErr.Message)
	assert.Equalf(t, constraint, pgErr.ConstraintName, "%s: имя ограничения (%s)", what, pgErr.Message)
}

// TestPublicReader_RelationFactAdmitsOnlyAClassSubject — `public_reader` в
// прямом факте принимает только класс субъектов; человек на том же отношении —
// отказ 23514. Близнец — тот же человек на отношении `owner`.
func TestPublicReader_RelationFactAdmitsOnlyAClassSubject(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db, person := scMovedP2(t)

	for _, tt := range []struct {
		name, relation, subject string
		refused                 bool
	}{
		{"человек на public_reader", "public_reader", person, true},
		{"близнец: класс anonymous на public_reader", "public_reader", "system_class:anonymous", false},
		{"близнец: класс authenticated на public_reader", "public_reader", "system_class:authenticated", false},
		{"близнец: человек на owner", "owner", person, false},
	} {
		err := scInsertFact(db, "registry_registry", "reg-pr-1", tt.relation, tt.subject)
		if tt.refused {
			prRefused(t, err, "relation_fact_public_reader_subject_is_class", "вставка: "+tt.name)
			continue
		}
		require.NoErrorf(t, err, "вставка, %s: законный близнец отвергнут", tt.name)
	}
}

// prInsertResource — строка каталога ресурса с перечнем указателей, в своей
// транзакции с откатом.
//
// Имена указателей (kaname#982) позиционно парны типам, и проверка их формы
// судит парность: строка пробы несёт столько же ЗАКОННЫХ имён, сколько типов, —
// так отказ приходит только от проверки формы типов, которую проба и судит.
func prInsertResource(db *sql.DB, resource, objectType, parents string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`INSERT INTO kaname.catalog_resource (module, resource, dotted, object_type, parent_types, parent_names)
	                  VALUES ('vpc', $1, 'vpc.' || $1, $2, $3::text[],
	                          array_fill('pointer'::text, ARRAY[cardinality($3::text[])]))`, resource, objectType, parents)
	return err
}

// TestPublicReader_ParentTypesFormRefusesEmptyAndSpacedElements — каждый
// элемент перечня указателей — имя типа модели: пустой элемент и элемент с
// пробелом — отказ 23514; пустой перечень и перечень имён — приняты.
func TestPublicReader_ParentTypesFormRefusesEmptyAndSpacedElements(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db, _ := scMovedP2(t)

	for _, tt := range []struct {
		name, parents string
		refused       bool
	}{
		{"пустой элемент", `{""}`, true},
		{"пустой элемент вторым", `{"project",""}`, true},
		{"элемент с пробелом", `{"a b"}`, true},
		{"элемент не той формы", `{"Project"}`, true},
		{"близнец: пустой перечень", `{}`, false},
		{"близнец: одно имя", `{"project"}`, false},
		{"близнец: два имени", `{"project","registry_registry"}`, false},
	} {
		err := prInsertResource(db, "prform", "vpc_prform", tt.parents)
		if tt.refused {
			prRefused(t, err, "catalog_resource_parent_types_form", "строка каталога: "+tt.name)
			continue
		}
		require.NoErrorf(t, err, "строка каталога, %s: законный близнец отвергнут", tt.name)
	}
}
