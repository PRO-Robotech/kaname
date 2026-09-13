// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// role_effective_verbs_test.go — redesign-2026 F6 (IAM-1-15). The honest
// effective-verb preview: authoredVerbs is the deduped canonical union of the
// role's rule verbs; effectiveVerbs adds the editor `delete*` qualifier (an editor
// may delete the in-scope leaf objects it edits, NOT the anchor); the verbNote
// spells that out verbatim.

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const editorDeleteNote = "co-materialized on in-scope leaf objects, NOT on the account/project anchor itself"

func TestRole_IAM_1_15_EffectiveVerbs(t *testing.T) {
	cases := []struct {
		name           string
		verbs          []string
		wantAuthored   []string
		wantEffective  []string
		wantDeleteNote bool
	}{
		{
			name:          "viewer (read-only) — no delete*",
			verbs:         []string{"get", "list"},
			wantAuthored:  []string{"get", "list"},
			wantEffective: []string{"get", "list"},
		},
		{
			name:           "editor — delete* co-materialized",
			verbs:          []string{"get", "list", "create", "update"},
			wantAuthored:   []string{"get", "list", "create", "update"},
			wantEffective:  []string{"get", "list", "create", "update", "delete*"},
			wantDeleteNote: true,
		},
		{
			name:          "admin (wildcard) — full CRUD, no delete* qualifier",
			verbs:         []string{"*"},
			wantAuthored:  []string{"get", "list", "create", "update", "delete"},
			wantEffective: []string{"get", "list", "create", "update", "delete"},
		},
		{
			name:          "already has delete — not editor-tier, no delete*",
			verbs:         []string{"get", "update", "delete"},
			wantAuthored:  []string{"get", "update", "delete"},
			wantEffective: []string{"get", "update", "delete"},
		},
		{
			name:           "dedupe + canonical order",
			verbs:          []string{"update", "get", "get", "list"},
			wantAuthored:   []string{"get", "list", "update"},
			wantEffective:  []string{"get", "list", "update", "delete*"},
			wantDeleteNote: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Role{Rules: Rules{{Module: "compute", Resources: []string{"instance"}, Verbs: tc.verbs}}}
			assert.Equal(t, tc.wantAuthored, r.AuthoredVerbs(lookupFive), "authoredVerbs")
			assert.Equal(t, tc.wantEffective, r.EffectiveVerbs(lookupFive), "effectiveVerbs")
			notes := r.VerbNotes(lookupFive)
			if tc.wantDeleteNote {
				assert.Equal(t, editorDeleteNote, notes["delete*"], "delete* note verbatim")
			} else {
				assert.NotContains(t, notes, "delete*", "no delete* note when not editor-tier")
			}
		})
	}
}

// F6: verbs union across multiple rules.
func TestRole_IAM_1_15_AuthoredVerbs_MultiRule(t *testing.T) {
	r := Role{Rules: Rules{
		{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get", "list"}},
		{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"create", "update"}},
	}}
	assert.Equal(t, []string{"get", "list", "create", "update"}, r.AuthoredVerbs(lookupFive))
	assert.Equal(t, []string{"get", "list", "create", "update", "delete*"}, r.EffectiveVerbs(lookupFive))
}

// TestRole_PreviewOfARetiredResourceShowsNoVerb — превью роли, назвавшей СНЯТЫЙ
// ресурс, не показывает по нему НИ ОДНОГО глагола (`PRO-Robotech/kacho#2051`
// соседняя половина — `kacho#1814`, предикат снятия, половина 3).
//
// # Почему проба заведена, хотя свойство уже выполняется
//
// Задача утверждала обратное: «правило, не резолвящееся ни в один тип, берёт ВСЕ
// глаголы платформы, то есть после снятия превью показывает не меньше, а больше».
// Перемер ИСПОЛНЕНИЕМ опроверг посылку: именованный снятый ресурс даёт пустой
// набор. Свойство верно — и держалось ничем, то есть было верно СЛУЧАЙНО по
// отношению к этому предикату.
//
// # Что именно разделяют три случая
//
// Запасной набор (`WithCommonFallback`) отдаёт весь словарь ТОЛЬКО подстановке.
// Именованный ресурс, которого нет среди живых, подстановкой не является и
// уходит в `ok=false`, а `ruleVerbSet` такую пару ПРОПУСКАЕТ. Разница между
// строкой 1 и строкой 2 — ровно один факт: имя против подстановки.
//
// Без строки 2 проба зеленела бы и на запасном наборе, снятом целиком, — то есть
// утверждала бы отсутствие там, где отсутствует всё.
func TestRole_PreviewOfARetiredResourceShowsNoVerb(t *testing.T) {
	// Живой каталог знает `compute.instance`; `compute.disk` снят и живой
	// строки не имеет — ровно то, что делает снятие (#1861).
	live := func(module, resource string) ([]string, bool) {
		if module == "compute" && resource == "instance" {
			return []string{"get", "list", "create", "update", "delete"}, true
		}
		return nil, false
	}
	lookup := WithCommonFallback(live, []string{
		"get", "list", "create", "update", "delete", "addTargets",
	})

	retired := Role{Rules: Rules{{
		Module: "compute", Resources: []string{"disk"}, Verbs: []string{"*"},
	}}}
	assert.Empty(t, retired.EffectiveVerbs(lookup),
		"снятый ресурс, названный ПО ИМЕНИ, не даёт ни одного глагола: превью после "+
			"снятия обязано показывать МЕНЬШЕ, а не больше")

	// Положительный контроль № 1 — подстановка. Она запасной набор получает, и
	// это объявленное поведение, а не поломка: перечислить ресурсы модуля домен
	// не может. Без этой строки проба зеленела бы на снятом запасном наборе.
	wild := Role{Rules: Rules{{
		Module: "compute", Resources: []string{"*"}, Verbs: []string{"*"},
	}}}
	assert.NotEmpty(t, wild.EffectiveVerbs(lookup),
		"подстановка ресурса ПОЛУЧАЕТ запасной набор — иначе роль `*` обещала бы ничего")

	// Положительный контроль № 2 — живой ресурс. Без него «пусто у снятого» было
	// бы неотличимо от «пусто у всех».
	alive := Role{Rules: Rules{{
		Module: "compute", Resources: []string{"instance"}, Verbs: []string{"*"},
	}}}
	assert.Equal(t, []string{"get", "list", "create", "update", "delete"},
		alive.EffectiveVerbs(lookup),
		"живой ресурс отдаёт СВОЙ набор — предикат различает живое и снятое")
}
