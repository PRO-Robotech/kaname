// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// system_class_fact_reads_only_integration_test.go — класс субъектов
// (`system_class:…`) в прямом факте допустим только на отношениях чтения,
// которые раздаёт правило «классу — только чтение» (Р4 приёмки
// anonymous-and-authenticated-are-subject-classes.md; сужение приёма класса
// субъекта, задача PRO-Robotech/kaname#838).
//
// Ограничение выдачи (`access_binding_subjects_system_class_reads_only`) судит
// роль, но прямой факт приходит в `relation_fact` мимо выдачи: записью
// журнала (регистрация соседа, выпуск выдачи) либо вставкой. Поэтому
// последнее слово — у ограничения самой таблицы фактов, и пробы стоят на
// каждом пути записи. Каждая строка отказа меняет против законного близнеца
// ровно один факт: отношение (класс на чтении проходит) либо субъекта
// (человек на том же отношении проходит).
package migrations_test

import (
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	scClassReadsOnly     = "relation_fact_subject_class_reads_only"
	scNarrowingMigration = "20261015140000_subject_class_fact_is_a_read.sql"
)

// scClassFactRefused — отказ дан проверочным ограничением класса (23514),
// а не чем-либо ещё.
func scClassFactRefused(t *testing.T, err error, what string) {
	t.Helper()
	require.Errorf(t, err, "%s: класс субъекта принят вне чтения", what)
	pgErr := pgErrorOf(err)
	require.NotNilf(t, pgErr, "%s: отказ не от базы: %v", what, err)
	assert.Equalf(t, "23514", pgErr.Code, "%s: код отказа (%s)", what, pgErr.Message)
	assert.Equalf(t, scClassReadsOnly, pgErr.ConstraintName, "%s: имя ограничения (%s)", what, pgErr.Message)
}

// scInsertFact — прямой факт вставкой, в своей транзакции с откатом: отказ
// одной строки не роняет следующие.
func scInsertFact(db *sql.DB, objType, objID, relation, subject string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`INSERT INTO kaname.relation_fact (object_type, object_id, relation, subject)
	                  VALUES ($1, $2, $3, $4)`, objType, objID, relation, subject)
	return err
}

// scJournalWrite — запись журнала намерений (`fga.tuple.write`), которую
// проекция переносит в факт той же транзакцией; путь регистрации ресурса и
// выпуска кортежей выдачи. Возвращает, сколько фактов этой тройки стоит в
// транзакции после записи: близнец обязан быть спроецирован, а не проглочен.
func scJournalWrite(db *sql.DB, subject, relation, object string) (int, error) {
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
	                  VALUES ('fga.tuple.write',
	                          jsonb_build_object('user', $1::text, 'relation', $2::text,
	                                             'object', $3::text,
	                                             'source_version', '-infinity'::timestamptz),
	                          now())`, subject, relation, object)
	if err != nil {
		return 0, err
	}
	var n int
	err = tx.QueryRow(`SELECT count(*) FROM kaname.relation_fact
	                    WHERE object_type || ':' || object_id = $1 AND relation = $2 AND subject = $3`,
		object, relation, subject).Scan(&n)
	return n, err
}

// Прямой факт вставкой: класс на отношении иерархии и на пишущем отношении
// отвергнут; тот же класс на отношении чтения и человек на том же отношении
// иерархии — приняты.
func TestSystemClass_RelationFactAdmitsAClassOnlyOnReads(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db, person := scMovedP2(t)

	for _, tt := range []struct {
		name, objType, objID, relation, subject string
		refused                                 bool
	}{
		{"класс предком проекта", "vpc_network", "net-ro-1", "project", "system_class:anonymous", true},
		{"близнец: человек тем же отношением", "vpc_network", "net-ro-1", "project", person, false},
		{"класс родителем", "vpc_subnet", "sub-ro-1", "parent", "system_class:authenticated", true},
		{"класс владельцем", "vpc_network", "net-ro-2", "owner", "system_class:authenticated", true},
		{"близнец: человек владельцем", "vpc_network", "net-ro-2", "owner", person, false},
		{"класс на пишущем отношении", "project", "prj-ro-1", "editor", "system_class:authenticated", true},
		{"класс администратором", "project", "prj-ro-1", "admin", "system_class:authenticated", true},
		{"класс на пишущем глаголе", "registry_repository", "r-ro-1", "v_update", "system_class:anonymous", true},
		{"класс множеством", "registry_repository", "r-ro-1", "v_get", "system_class:anonymous#member", true},
		{"класс вне словаря", "registry_repository", "r-ro-1", "v_get", "system_class:nobody", true},
		{"близнец: класс на чтении публикации", "registry_repository", "r-ro-1", "v_get", "system_class:anonymous", false},
		{"близнец: класс на ярусе чтения", "project", "prj-ro-1", "viewer", "system_class:authenticated", false},
		{"близнец: класс на ярусе чтения кластера", "cluster", "c-ro-1", "system_viewer", "system_class:authenticated", false},
	} {
		err := scInsertFact(db, tt.objType, tt.objID, tt.relation, tt.subject)
		if tt.refused {
			scClassFactRefused(t, err, "вставка: "+tt.name)
			continue
		}
		require.NoErrorf(t, err, "вставка, %s: законный близнец отвергнут", tt.name)
	}
}

// Журнал (регистрация соседа и выпуск выдачи): класс на отношении иерархии и
// на пишущем ярусе не проецируется в факт; класс на ярусе чтения и человек на
// отношении иерархии — проецируются.
func TestSystemClass_JournalProjectionAdmitsAClassOnlyOnReads(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db, person := scMovedP2(t)

	for _, tt := range []struct {
		name, subject, relation, object string
		refused                         bool
	}{
		{"регистрация: класс предком", "system_class:anonymous", "project", "vpc_network:net-roj-1", true},
		{"близнец: регистрация человеком", person, "project", "vpc_network:net-roj-1", false},
		{"регистрация: класс владельцем", "system_class:authenticated", "owner", "vpc_network:net-roj-2", true},
		{"выдача: класс пишущим ярусом", "system_class:authenticated", "editor", "project:prj-roj-1", true},
		{"близнец: выдача классу ярусом чтения", "system_class:authenticated", "viewer", "project:prj-roj-1", false},
	} {
		n, err := scJournalWrite(db, tt.subject, tt.relation, tt.object)
		if tt.refused {
			scClassFactRefused(t, err, "журнал: "+tt.name)
			continue
		}
		require.NoErrorf(t, err, "журнал, %s: законный близнец отвергнут", tt.name)
		assert.Equalf(t, 1, n, "журнал, %s: близнец не спроецирован в факт", tt.name)
	}
}

// Откат снимает ограничение, повторный накат возвращает его.
func TestSystemClass_ClassReadsOnlyCheckRoundTrips(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db, _ := scMovedP2(t)
	_, beforeNarrowing := versionsOf(t, scNarrowingMigration)
	require.NoError(t, goose.DownTo(db, ".", beforeNarrowing), "откат сужения")
	require.NoError(t, scInsertFact(db, "vpc_network", "net-rod-1", "project", "system_class:anonymous"),
		"после отката ограничения нет — прежняя схема принимала класс")

	require.NoError(t, goose.Up(db, "."), "повторный накат")
	scClassFactRefused(t, scInsertFact(db, "vpc_network", "net-rod-1", "project", "system_class:anonymous"),
		"после повторного наката")
}
