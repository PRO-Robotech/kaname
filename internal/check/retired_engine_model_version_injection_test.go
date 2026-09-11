// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// retired_engine_model_version_injection_test.go — доказательство того, что
// разбор способен упасть (таблица создана и не снята) и способен смолчать
// (создана и снята позже, либо не заводилась вовсе).
//
// Инъекция синтетическая: настоящие миграции kaname не заводили и не снимали
// эту таблицу видимо (см. шапку основного файла), поэтому «настоящий вход»
// здесь — та же форма записи (`CREATE TABLE`/`DROP TABLE`), какой бы её
// написал goose, а не текст, взятый из дерева.
package check_test

import (
	"strings"
	"testing"
)

// retiredEngineFold — свёртка синтетической цепочки миграций в порядке имён.
func retiredEngineFold(t *testing.T, ordered map[string]string) *retiredEngineVersionSite {
	t.Helper()
	names := make([]string, 0, len(ordered))
	for n := range ordered {
		names = append(names, n)
	}
	// сортировка как у goose — лексикографическая
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	var alive *retiredEngineVersionSite
	for _, name := range names {
		src := ordered[name]
		if !strings.Contains(src, "-- +goose Up") {
			continue
		}
		for i, raw := range strings.Split(src, "\n") {
			line := stripEngineVersionLineComment(raw)
			if engineVersionCreateRe.MatchString(line) {
				s := retiredEngineVersionSite{File: name, Line: i + 1}
				alive = &s
			}
			if engineVersionDropRe.MatchString(line) {
				alive = nil
			}
		}
	}
	return alive
}

// TestRetiredEngineVersion_CreatedAndNeverDropped_IsAlive — НАРУШЕНИЕ: создана
// и живёт.
func TestRetiredEngineVersion_CreatedAndNeverDropped_IsAlive(t *testing.T) {
	t.Parallel()
	alive := retiredEngineFold(t, map[string]string{
		"0001_initial.sql": "-- +goose Up\n" +
			"CREATE TABLE kaname.fga_model_version (id text PRIMARY KEY, applied_at timestamptz);\n",
	})
	if alive == nil {
		t.Fatal("разбор НЕ СПОСОБЕН упасть: таблица создана и никогда не снята, а признана мёртвой")
	}
	if alive.File != "0001_initial.sql" || alive.Line == 0 {
		t.Errorf("находка не называет координату верно: %+v", *alive)
	}
}

// TestRetiredEngineVersion_CreatedThenDropped_IsSilent — КОНТРОЛЬ: создана
// одной миграцией, снята следующей — гейт МОЛЧИТ.
func TestRetiredEngineVersion_CreatedThenDropped_IsSilent(t *testing.T) {
	t.Parallel()
	alive := retiredEngineFold(t, map[string]string{
		"0001_initial.sql": "-- +goose Up\n" +
			"CREATE TABLE kaname.fga_model_version (id text PRIMARY KEY);\n",
		"0002_drop_fga_model_version.sql": "-- +goose Up\n" +
			"DROP TABLE IF EXISTS kaname.fga_model_version;\n",
	})
	if alive != nil {
		t.Fatalf("гейт краснеет на СНЯТОЙ таблице: %+v — такой гейт снимут первым же "+
			"ложным срабатыванием", *alive)
	}
}

// TestRetiredEngineVersion_NeverCreated_IsSilent — ЗАКОННЫЙ БЛИЗНЕЦ: таблица
// не заводилась вовсе — ровно сегодняшнее состояние дерева kaname.
func TestRetiredEngineVersion_NeverCreated_IsSilent(t *testing.T) {
	t.Parallel()
	alive := retiredEngineFold(t, map[string]string{
		"0001_initial.sql": "-- +goose Up\nCREATE TABLE kaname.accounts (id text PRIMARY KEY);\n",
	})
	if alive != nil {
		t.Fatalf("гейт нашёл живую таблицу там, где её никто не заводил: %+v", *alive)
	}
}

// TestRetiredEngineVersion_ProseMentionIsNotAStatement — законный близнец:
// оператор, ЗАКОММЕНТИРОВАННЫЙ целиком, — не оператор.
//
// Комментарий здесь несёт ТУ ЖЕ подпоследовательность символов, что и
// настоящий `CREATE TABLE`: распознаватель по подстроке (без снятия
// комментария) нашёл бы её и покраснел на собственном объяснении. Разбор
// обязан судить исполняемую часть строки, а не весь её текст
// (`testing.md` §«Гейт читает исполняемую часть, а не текст»).
func TestRetiredEngineVersion_ProseMentionIsNotAStatement(t *testing.T) {
	t.Parallel()
	alive := retiredEngineFold(t, map[string]string{
		"0001_initial.sql": "-- +goose Up\n" +
			"-- было бы неверно писать здесь: CREATE TABLE kaname.fga_model_version (id text);\n" +
			"CREATE TABLE kaname.accounts (id text PRIMARY KEY);\n",
	})
	if alive != nil {
		t.Fatalf("оператор в КОММЕНТАРИИ принят за настоящее создание: %+v — распознаватель "+
			"судит подстроку, а не исполняемую часть строки", *alive)
	}
}
