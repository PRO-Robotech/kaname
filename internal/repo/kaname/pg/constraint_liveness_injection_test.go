// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// constraint_liveness_injection_test.go — доказательство, что гейт живости
// ограничений СПОСОБЕН упасть и способен смолчать.
//
// Вход подаётся СИНТЕТИЧЕСКИЙ, а не находкой из дерева: проба, опирающаяся на
// живой дефект, исчезает вместе с ним — то есть ровно тогда, когда дерево
// починено, и удостоверять ей становится нечего.
//
// Оси проверяются ПО ОДНОЙ (каждая инъекция роняет ровно своё): имя, снятое по
// имени · имя, унесённое сносом таблицы · имя, которого не заводили вовсе ·
// законный близнец (живое имя — молчание).

import (
	"go/token"
	"strings"
	"testing"
)

func factsFrom(t *testing.T, upHalves ...string) schemaFacts {
	t.Helper()
	f := schemaFacts{
		constraintOwner: map[string]string{},
		aliveConstraint: map[string]bool{},
		aliveTable:      map[string]bool{},
	}
	for _, up := range upHalves {
		applyUp(&f, upHalf(up))
	}
	return f
}

func mappedFrom(names ...string) map[string]token.Position {
	out := map[string]token.Position{}
	for _, n := range names {
		out[n] = token.Position{Filename: "synthetic.go", Line: 1}
	}
	return out
}

func TestConstraintLivenessGateInjection(t *testing.T) {
	const created = `
-- +goose Up
CREATE TABLE kaname.widgets (id text primary key);
ALTER TABLE kaname.widgets ADD CONSTRAINT widgets_owner_fk FOREIGN KEY (owner) REFERENCES owners(id);
CREATE UNIQUE INDEX widgets_name_uniq ON kaname.widgets (name);
-- +goose Down
DROP TABLE kaname.widgets;
`

	t.Run("контроль: живое имя — молчание", func(t *testing.T) {
		dead := deadMappedConstraints(factsFrom(t, created), mappedFrom("widgets_owner_fk", "widgets_name_uniq"))
		if len(dead) != 0 {
			t.Fatalf("гейт краснеет на живых именах: %v", dead)
		}
	})

	t.Run("инъекция: имя снято ПО ИМЕНИ", func(t *testing.T) {
		const dropped = `
-- +goose Up
ALTER TABLE kaname.widgets DROP CONSTRAINT widgets_owner_fk;
-- +goose Down
`
		dead := deadMappedConstraints(factsFrom(t, created, dropped),
			mappedFrom("widgets_owner_fk", "widgets_name_uniq"))
		if len(dead) != 1 || !strings.Contains(dead[0], "widgets_owner_fk") {
			t.Fatalf("гейт не назвал снятое имя, вернул %v", dead)
		}
		if !strings.Contains(dead[0], "снято миграцией") {
			t.Errorf("находка не называет ПРИЧИНУ (снято, а не «не заводили»): %q", dead[0])
		}
	})

	t.Run("инъекция: имя унесено СНОСОМ ТАБЛИЦЫ — тот самый случай, что был в дереве", func(t *testing.T) {
		const tableGone = `
-- +goose Up
DROP TABLE IF EXISTS kaname.widgets;
-- +goose Down
`
		dead := deadMappedConstraints(factsFrom(t, created, tableGone), mappedFrom("widgets_owner_fk"))
		if len(dead) != 1 || !strings.Contains(dead[0], "widgets_owner_fk") {
			t.Fatalf("снос таблицы не унёс её ограничение — гейт вернул %v", dead)
		}
	})

	t.Run("инъекция: имя, которого не заводили вовсе", func(t *testing.T) {
		dead := deadMappedConstraints(factsFrom(t, created), mappedFrom("widgets_never_existed_fk"))
		if len(dead) != 1 || !strings.Contains(dead[0], "ни одна миграция") {
			t.Fatalf("гейт не отличил «не заводили» от «снято»: %v", dead)
		}
	})

	t.Run("контроль: снос читается ТОЛЬКО из Up-половины", func(t *testing.T) {
		// Down-половина `created` сносит таблицу. Если бы гейт читал её, живое
		// имя объявлялось бы мёртвым — и он краснел бы на каждой миграции,
		// умеющей откатываться.
		dead := deadMappedConstraints(factsFrom(t, created), mappedFrom("widgets_owner_fk"))
		if len(dead) != 0 {
			t.Fatalf("гейт прочитал Down-половину как факт схемы: %v", dead)
		}
	})

	t.Run("контроль: имя в SQL-комментарии фактом схемы не является", func(t *testing.T) {
		const onlyProse = `
-- +goose Up
-- Здесь когда-то было ограничение widgets_ghost_fk, и оно снято.
CREATE TABLE kaname.gadgets (id text primary key);
-- +goose Down
`
		dead := deadMappedConstraints(factsFrom(t, onlyProse), mappedFrom("widgets_ghost_fk"))
		if len(dead) != 1 {
			t.Fatalf("имя, встреченное только в прозе, зачтено как заведённое: %v", dead)
		}
	})
}
