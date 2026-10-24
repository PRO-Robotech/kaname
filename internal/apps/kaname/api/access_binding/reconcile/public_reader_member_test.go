// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

// public_reader_member_test.go — кортеж `public_reader` живёт СВОИМ членом
// состава, ключ которого выведен из ВЛОЖЕННЫХ правил над типом-ребёнком
// (kaname#856, форма роли — kaname#874, редакция 11 соседа).
//
// Предмет — снятие: приклеенный к члену правила над контейнером, кортеж пережил
// бы снятие ВЛОЖЕННОГО ПРАВИЛА (член контейнера не менял бы ни ключа, ни
// статуса, и проход счёл бы его неизменным). Роль здесь — правило над
// контейнером с вложенным правилом над ребёнком; близнец — та же роль без
// вложенного правила.

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

func TestPublicReaderMember_KeyFollowsTheChildRule(t *testing.T) {
	doc, err := publicreadfixture.Read(publicreadfixture.ProbemodFile)
	if err != nil {
		t.Fatalf("фикстура: %v", err)
	}
	cat := sc65Facts(t, doc)
	twoRules := domain.Rules{
		{Module: "probemod", Resources: []string{"boxes"}, Verbs: []string{"get", "list"},
			Children: []domain.Rule{{Resources: []string{"items"}, Verbs: []string{"get", "list"}}}},
	}
	plain := domain.Rules{{Module: "probemod", Resources: []string{"boxes"}, Verbs: []string{"get", "list"}}}
	members := func(rules domain.Rules) []DesiredMember {
		return desiredMembersForObject(cat, sc65Scope("system_class", "anonymous", rules), sc65BoxObject(), nil)
	}

	var pr []DesiredMember
	for _, m := range members(twoRules) {
		for _, tu := range m.Tuples {
			if tu.Relation == domain.PublicReaderRelation {
				pr = append(pr, m)
			}
		}
	}
	if len(pr) != 1 {
		t.Fatalf("роль с вложенным правилом над ребёнком обязана дать ровно одного члена с public_reader, получено %d: %+v", len(pr), pr)
	}
	var childFP string
	for _, sel := range twoRules.MaterializingSelectorsInScope(domain.ScopeProject) {
		if sel.Container != nil {
			childFP = sel.RuleFP
		}
	}
	if childFP == "" {
		t.Fatalf("у роли нет селектора вложенного правила — проба судила бы пустоту")
	}
	wantKey := publicReaderRuleFPPrefix + childFP + publicReaderClassesSep + "system_class:anonymous"
	if pr[0].RuleFP != wantKey || len(pr[0].Tuples) != 1 {
		t.Fatalf("член public_reader обязан нести ключ вложенного правила и классов %q и один кортеж; получено %q, кортежей %d",
			wantKey, pr[0].RuleFP, len(pr[0].Tuples))
	}
	for _, m := range members(twoRules) {
		if m.RuleFP != pr[0].RuleFP && hasRelation(m, domain.PublicReaderRelation) {
			t.Fatalf("public_reader приклеен к члену правила %q — снятие вложенного правила его не снимет", m.RuleFP)
		}
	}

	// Близнец: вложенное правило снято — члена с этим ключом в составе нет, и
	// diff снимет его кортеж, как снимает `v_*` выпавшего члена.
	for _, m := range members(plain) {
		if strings.HasPrefix(m.RuleFP, publicReaderRuleFPPrefix) || hasRelation(m, domain.PublicReaderRelation) {
			t.Fatalf("без вложенного правила член public_reader остался: %+v", m)
		}
	}
}

func hasRelation(m DesiredMember, rel string) bool {
	for _, tu := range m.Tuples {
		if tu.Relation == rel {
			return true
		}
	}
	return false
}

// TestPublicReaderMember_NarrowedChildRuleWritesNothing — публичное чтение
// наследует сужение правила роли: вложенное правило над ребёнком по меткам, по
// именам либо с одним глаголом чтения `public_reader` не пишет (ворота класса
// такую выдачу отвергают раньше, здесь — вторая стена разворачивания). Близнец —
// то же вложенное правило без сужения, `[get, list]`: пишет. Отличие каждой
// строки от близнеца — один факт.
func TestPublicReaderMember_NarrowedChildRuleWritesNothing(t *testing.T) {
	doc, err := publicreadfixture.Read(publicreadfixture.ProbemodFile)
	if err != nil {
		t.Fatalf("фикстура: %v", err)
	}
	cat := sc65Facts(t, doc)
	written := func(child domain.Rule) bool {
		rules := domain.Rules{{Module: "probemod", Resources: []string{"boxes"}, Verbs: []string{"get", "list"},
			Children: []domain.Rule{child}}}
		for _, m := range desiredMembersForObject(cat, sc65Scope("system_class", "anonymous", rules), sc65BoxObject(), nil) {
			if hasRelation(m, domain.PublicReaderRelation) {
				return true
			}
		}
		return false
	}
	whole := domain.Rule{Resources: []string{"items"}, Verbs: []string{"get", "list"}}
	if !written(whole) {
		t.Fatal("близнец: несуженное вложенное правило [get, list] над ребёнком обязано писать public_reader")
	}
	for name, child := range map[string]domain.Rule{
		"по меткам":   {Resources: []string{"items"}, Verbs: []string{"get", "list"}, MatchLabels: map[string]string{"tier": "gold"}},
		"по именам":   {Resources: []string{"items"}, Verbs: []string{"get", "list"}, ResourceNames: []string{"itm0000000000000one"}},
		"только get":  {Resources: []string{"items"}, Verbs: []string{"get"}},
		"только list": {Resources: []string{"items"}, Verbs: []string{"list"}},
	} {
		if written(child) {
			t.Errorf("вложенное правило над ребёнком %s сужено, а public_reader написан", name)
		}
	}
}
