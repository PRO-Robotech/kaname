// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

// public_reader_member_test.go — кортеж `public_reader` живёт СВОИМ членом
// состава, ключ которого выведен из правил над типом-ребёнком (kaname#856).
//
// Предмет — снятие: приклеенный к члену правила над контейнером, кортеж пережил
// бы снятие ПРАВИЛА НАД РЕБЁНКОМ (член контейнера не менял бы ни ключа, ни
// статуса, и проход счёл бы его неизменным). Роль здесь — ДВА правила: над
// контейнером и над ребёнком; близнец — та же роль без правила над ребёнком.

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
		{Module: "probemod", Resources: []string{"boxes"}, Verbs: []string{"get", "list"}},
		{Module: "probemod", Resources: []string{"items"}, Verbs: []string{"get", "list"}},
	}
	members := func(rules domain.Rules) []DesiredMember {
		return desiredMembersForObject(cat, sc65Scope("system_class", "anonymous", rules), sc65BoxObject())
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
		t.Fatalf("роль с правилом над ребёнком обязана дать ровно одного члена с public_reader, получено %d: %+v", len(pr), pr)
	}
	childFP := twoRules[1].Fingerprint()
	if pr[0].RuleFP != publicReaderRuleFPPrefix+childFP || len(pr[0].Tuples) != 1 {
		t.Fatalf("член public_reader обязан нести ключ правила над ребёнком %q и один кортеж; получено %q, кортежей %d",
			publicReaderRuleFPPrefix+childFP, pr[0].RuleFP, len(pr[0].Tuples))
	}
	for _, m := range members(twoRules) {
		if m.RuleFP != pr[0].RuleFP && hasRelation(m, domain.PublicReaderRelation) {
			t.Fatalf("public_reader приклеен к члену правила %q — снятие правила над ребёнком его не снимет", m.RuleFP)
		}
	}

	// Близнец: правило над ребёнком снято — члена с этим ключом в составе нет,
	// и diff снимет его кортеж, как снимает `v_*` выпавшего члена.
	for _, m := range members(twoRules[:1]) {
		if strings.HasPrefix(m.RuleFP, publicReaderRuleFPPrefix) || hasRelation(m, domain.PublicReaderRelation) {
			t.Fatalf("без правила над ребёнком член public_reader остался: %+v", m)
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
// наследует сужение правила роли: правило над ребёнком по меткам, по именам либо
// с одним глаголом чтения `public_reader` не пишет. Близнец — то же правило без
// сужения, `[get, list]`: пишет. Отличие каждой строки от близнеца — один факт.
func TestPublicReaderMember_NarrowedChildRuleWritesNothing(t *testing.T) {
	doc, err := publicreadfixture.Read(publicreadfixture.ProbemodFile)
	if err != nil {
		t.Fatalf("фикстура: %v", err)
	}
	cat := sc65Facts(t, doc)
	box := domain.Rule{Module: "probemod", Resources: []string{"boxes"}, Verbs: []string{"get", "list"}}
	written := func(child domain.Rule) bool {
		rules := domain.Rules{box, child}
		for _, m := range desiredMembersForObject(cat, sc65Scope("system_class", "anonymous", rules), sc65BoxObject()) {
			if hasRelation(m, domain.PublicReaderRelation) {
				return true
			}
		}
		return false
	}
	whole := domain.Rule{Module: "probemod", Resources: []string{"items"}, Verbs: []string{"get", "list"}}
	if !written(whole) {
		t.Fatal("близнец: несуженное правило [get, list] над ребёнком обязано писать public_reader")
	}
	for name, child := range map[string]domain.Rule{
		"по меткам":   {Module: "probemod", Resources: []string{"items"}, Verbs: []string{"get", "list"}, MatchLabels: map[string]string{"tier": "gold"}},
		"по именам":   {Module: "probemod", Resources: []string{"items"}, Verbs: []string{"get", "list"}, ResourceNames: []string{"itm0000000000000one"}},
		"только get":  {Module: "probemod", Resources: []string{"items"}, Verbs: []string{"get"}},
		"только list": {Module: "probemod", Resources: []string{"items"}, Verbs: []string{"list"}},
	} {
		if written(child) {
			t.Errorf("правило над ребёнком %s сужено, а public_reader написан", name)
		}
	}
}
