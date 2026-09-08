// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzplan"
	"github.com/PRO-Robotech/kaname/internal/manifest"
)

// verb_relation_name_test.go — правило «имя отношения из имени глагола» ОДНО, и
// сверяется оно с тем, что канон НЕСЁТ, а не с тем, как правило записано.
//
// Функция объявлена единственным источником этого вывода (её godoc: «тот же вывод
// делает рендер блоков модели (#1089): вторая копия правила разошлась бы с первой
// молча»). Значит её обязана держать проба против ДЕРЕВА, а не против литерала
// рядом — иначе обе стороны согласятся друг с другом и разойдутся с продуктом.

// TestVerbRelationNameLowercasesTheAuthoredVerb — авторский глагол пишется
// верблюжьим, отношение модели — строчным.
//
// Замер, из которого выведено: канон несёт `define v_addtargets`, тогда как глагол
// роли зовётся `addTargets`; тот же вывод уже сделан эмиттером — `authzmap`
// объявляет набор `nlb_target_group` именами `v_addtargets`/`v_removetargets` и
// говорит об этом дословно: «имя, написанное иначе, чем его собирает эмиттер,
// адресовало бы отношение, по которому никто не постучится».
//
// Цена расхождения не косметическая: сравнение сторон без одинакового приведения
// не совпадёт НИ РАЗУ и отнимет живое право, выглядя рабочим.
func TestVerbRelationNameLowercasesTheAuthoredVerb(t *testing.T) {
	if got := manifest.VerbRelationName("addTargets"); got != "v_addtargets" {
		t.Errorf("VerbRelationName(\"addTargets\") = %q, ожидалось \"v_addtargets\"", got)
	}
	if got := manifest.VerbRelationName("removeTargets"); got != "v_removetargets" {
		t.Errorf("VerbRelationName(\"removeTargets\") = %q, ожидалось \"v_removetargets\"", got)
	}
	// Законный близнец: канонический глагол уже строчный, и приведение его не трогает.
	if got := manifest.VerbRelationName("get"); got != "v_get" {
		t.Errorf("VerbRelationName(\"get\") = %q, ожидалось \"v_get\"", got)
	}
}

// TestEveryVerbRelationOfTheCanonIsProducibleByTheRule — ВСЯКОЕ `v_*`-отношение
// канона производимо правилом.
//
// Отношение, которое правило произвести не может, есть отношение, по которому
// эмиттер не постучится: право объявлено моделью и не выдаётся никогда. Проба
// читает КАНОН ИЗ ДЕРЕВА, а не перечень рядом с собой: перечень есть снимок, и
// снимок каноном не является.
func TestEveryVerbRelationOfTheCanonIsProducibleByTheRule(t *testing.T) {
	path, dsl, err := authzplan.ResolveCanonicalModel()
	if err != nil {
		t.Fatalf("канон не резолвится: %v", err)
	}
	seen, bad := 0, 0
	for _, line := range strings.Split(string(dsl), "\n") {
		s := strings.TrimSpace(line)
		if !strings.HasPrefix(s, "define v_") {
			continue
		}
		name := strings.SplitN(strings.TrimPrefix(s, "define "), ":", 2)[0]
		seen++
		if manifest.VerbRelationName(strings.TrimPrefix(name, "v_")) != name {
			t.Errorf("отношение %s правилом не производится", name)
			bad++
		}
	}
	if seen == 0 {
		t.Fatalf("осмотрено 0 отношений — обход пуст, вердикт беспредметен (канон %s)", path)
	}
	t.Logf("перепись: отношений `v_*` осмотрено %d · непроизводимых %d · канон %s", seen, bad, path)
}
