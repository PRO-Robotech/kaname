// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// rolechildren_tier_internal_test.go — ярус иерархии для судьи вложенного
// правила берётся из ОДНОГО закрытого словаря (kaname#874, находка ревью
// круга 1).
//
// Ярусы платформы объявлены набором `scopeAnchors`; судья `children` держал
// рядом свою копию. Копия расходится молча: ярус, добавленный в набор, судья
// вложенности не узнал бы, и правило над ярусом приняло бы `children` — то есть
// вложенное правило выбирало бы там, где выбирает область выдачи.
//
// Проба вводит ярус ТОЛЬКО в `scopeAnchors` и требует находку судьи. Близнец —
// тот же манифест без ввода: находки яруса нет, значит находку даёт именно
// словарь, а не форма манифеста.
package manifest

import (
	"errors"
	"strings"
	"testing"
)

func TestRuleChildren_TierIsJudgedByTheScopeAnchorVocabulary(t *testing.T) {
	const newTier = "folder"
	m := &Manifest{
		APIVersion: "iam/v1",
		Module:     "probemod",
		Resources: []Resource{
			{Name: "folders", ObjectType: newTier},
			{Name: "items", ObjectType: "probemod_item", Parents: []Parent{{Type: newTier}}},
		},
	}
	rule := Rule{
		Module:    "probemod",
		Resources: []string{"folders"},
		Classes:   []string{"get"},
		Children:  []ChildRule{{Resources: []string{"items"}, Classes: []string{"get"}}},
	}
	const finding = `"folders" — ярус иерархии`

	tierFindings := func() []string {
		var out []string
		for _, err := range validateRuleChildren(m, rule, nil, 0, 0, nil) {
			if errors.Is(err, ErrRoleRuleNestingMalformed) && strings.Contains(err.Error(), finding) {
				out = append(out, err.Error())
			}
		}
		return out
	}

	if got := tierFindings(); len(got) != 0 {
		t.Fatalf("близнец: %q ещё не ярус, а судья уже нашёл ярус: %v", newTier, got)
	}

	saved := scopeAnchors
	scopeAnchors = append(append([]string(nil), saved...), newTier)
	t.Cleanup(func() { scopeAnchors = saved })

	if got := tierFindings(); len(got) != 1 {
		t.Fatalf("ярус %q введён в scopeAnchors, а судья вложенного правила его не узнал "+
			"(находок яруса %d: %v) — у судьи своя копия словаря ярусов", newTier, len(got), got)
	}
}
