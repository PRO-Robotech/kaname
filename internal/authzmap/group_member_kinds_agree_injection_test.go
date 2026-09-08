// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmap_test

// ИНЪЕКЦИЯ В ОБЕ СТОРОНЫ ДЛЯ РАЗБОРЩИКОВ ГЕЙТА СОГЛАСИЯ.
//
// Гейт над деревом утверждает РАВЕНСТВО двух списков. Такое утверждение зеленеет
// и тогда, когда оба разборщика читают пустоту либо одно и то же не то, —
// поэтому способность каждого различать проверяется отдельно, на синтетическом
// входе, где верный ответ известен заранее.
//
// Верхний гейт при этом остаётся на дереве: здесь проверяется ПРИБОР, там —
// СВОЙСТВО. Подменять второе первым нельзя — синтетика зеленела бы при любом
// состоянии продукта.

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSchemaKindReaderTellsDeclarationFromProse(t *testing.T) {
	// (а) НАСТОЯЩЕЕ ОБЪЯВЛЕНИЕ — виды обязаны быть прочитаны.
	const decl = `
CREATE TABLE kaname.group_members (
    group_id text NOT NULL,
    member_type text NOT NULL,
    CONSTRAINT group_members_type_check CHECK ((member_type = ANY (ARRAY['user'::text, 'service_account'::text])))
);`
	got, ok := exportedConstraintCheckBody(decl, "group_members_type_check")
	require.True(t, ok, "объявление не опознано — гейт не прочитал бы своего предмета")
	require.Contains(t, got, "'user'")
	require.Contains(t, got, "'service_account'")

	// (б) ЗАКОННЫЙ БЛИЗНЕЦ: имя стоит в ПРОЗЕ, объявления нет. Разборщик обязан
	//     ПРОМОЛЧАТЬ. Это и был дефект первой редакции: она вычитывала из такой
	//     миграции литералы соседней вставки и объявляла их видами члена.
	const prose = `
-- ('user' / 'service_account', enforced by group_members_type_check), so it maps
INSERT INTO kaname.fga_outbox (object, relation, subject)
VALUES ('group:grp-1', 'member', 'user:usr-1');`
	_, ok = exportedConstraintCheckBody(exportedStripSQLComments(prose), "group_members_type_check")
	require.False(t, ok, "имя в комментарии принято за объявление — прибор судит прозу, а не код")

	// (в) ОТМЕНЁННАЯ РЕДАКЦИЯ: разборщик обязан уметь прочитать и вторую форму,
	//     иначе «последняя касавшаяся миграция» ничего не значит.
	const redecl = `
ALTER TABLE kaname.group_members
  ADD CONSTRAINT group_members_type_check CHECK (member_type IN ('user', 'service_account', 'robot'));`
	got, ok = exportedConstraintCheckBody(redecl, "group_members_type_check")
	require.True(t, ok)
	require.Contains(t, got, "'robot'", "переобъявление не прочитано — гейт судил бы отменённое")
}

func TestModelKindReaderSeesNestingAsAKind(t *testing.T) {
	// Вложенность записывается как `group#member`. Разборщик обязан привести её к
	// ВИДУ (`group`), иначе сравнение со схемой не состоится: схема написаний
	// модели не знает.
	got := exportedModelMemberKinds(`
type group
  relations
    define member: [user, service_account, federated_subject, group#member]
`)
	require.Equal(t, []string{"federated_subject", "group", "service_account", "user"}, got)

	// Законный близнец — суженная форма: гейт обязан на ней молчать.
	got = exportedModelMemberKinds(`
type group
  relations
    define member: [user, service_account]
`)
	require.Equal(t, []string{"service_account", "user"}, got)

	// Пустой вход НЕ должен читаться как «виды совпали»: пустой список у обеих
	// сторон сделал бы равенство тождественно истинным.
	require.Empty(t, exportedModelMemberKinds("type user\n"),
		"разборщик вернул виды там, где типа group нет вовсе")
}
