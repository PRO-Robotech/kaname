// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

// multi_subject_test.go — разворачивание выдачи судит КАЖДОГО её субъекта
// (kaname#880). Мир — П3 (`nested_rule_test.go`): ящик b1 назван целью,
// предмет i1 лежит в нём; роль — чтение ящиков с вложенным правилом над
// предметами.
//
// Каждая проба меняет ОДИН факт против близнеца: порядок субъектов (исход тот
// же), вид субъекта (класс или человек).

import (
	"slices"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

const (
	msAnon = "system_class:anonymous"
	msAuth = "system_class:authenticated"
	msUser = "user:usrnd08"
)

func msSubject(ref string) domain.Subject {
	kind, id, _ := strings.Cut(ref, ":")
	return domain.Subject{Type: domain.SubjectType(kind), ID: domain.SubjectID(id)}
}

// msStore — мир П3, выдача роли `rules` перечню субъектов `refs` на ящик b1.
func msStore(rules domain.Rules, refs ...string) *fakeStore {
	f := ndStore("user", "unused", rules, ndBoxTarget("b1"))
	for _, r := range refs {
		f.subjects = append(f.subjects, msSubject(r))
	}
	return f
}

// msUsers — субъекты записанных кортежей `relation` на объекте `object`.
func msUsers(f *fakeStore, relation, object string) []string {
	var out []string
	for _, tu := range allWrites(f) {
		if tu.Relation == relation && tu.Object == object {
			out = append(out, tu.User)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// TestReconcileMultiSubject_PublicReaderGoesToEveryClassInAnyOrder —
// `public_reader` на b1 получает каждый класс выдачи и никто, кроме классов;
// перестановка субъектов исхода не меняет.
func TestReconcileMultiSubject_PublicReaderGoesToEveryClassInAnyOrder(t *testing.T) {
	cases := []struct {
		subjects []string
		want     []string
	}{
		{[]string{msAnon, msAuth}, []string{msAnon, msAuth}},
		{[]string{msAuth, msAnon}, []string{msAnon, msAuth}},
		{[]string{msUser, msAnon}, []string{msAnon}},
		{[]string{msAnon, msUser}, []string{msAnon}},
		// Близнец: выдача только человеку — public_reader нет (ND-10).
		{[]string{msUser}, nil},
	}
	for _, tc := range cases {
		t.Run(strings.Join(tc.subjects, ","), func(t *testing.T) {
			f := msStore(ndReaderRules(nil, nil, "items"), tc.subjects...)
			ndReconcile(t, f)
			// Контроль: сам ящик выдача разворачивает каждому субъекту.
			if got := msUsers(f, "v_get", "probemod_box:b1"); !slices.Equal(got, sortedCopy(tc.subjects)) {
				t.Fatalf("v_get на b1 получили %v, ждали каждого субъекта %v", got, sortedCopy(tc.subjects))
			}
			if got := msUsers(f, domain.PublicReaderRelation, "probemod_box:b1"); !slices.Equal(got, tc.want) {
				t.Errorf("public_reader на b1 получили %v, ждали %v", got, tc.want)
			}
			if got := msUsers(f, domain.PublicReaderRelation, "probemod_box:b2"); len(got) != 0 {
				t.Errorf("public_reader записан на b2, не названном целью: %v", got)
			}
		})
	}
}

// TestReconcileMultiSubject_NestedRuleReachesOnlyTheNonClassSubjects — ND-10 по
// каждому субъекту: вложенное правило даёт `v_*` на предмете i1 человеку той же
// выдачи и не даёт классу, при любом порядке.
func TestReconcileMultiSubject_NestedRuleReachesOnlyTheNonClassSubjects(t *testing.T) {
	for _, order := range [][]string{{msUser, msAnon}, {msAnon, msUser}} {
		t.Run(strings.Join(order, ","), func(t *testing.T) {
			f := msStore(ndReaderRules(nil, nil, "items"), order...)
			ndReconcile(t, f)
			if got := msUsers(f, "v_get", "probemod_item:i1"); !slices.Equal(got, []string{msUser}) {
				t.Errorf("v_get на i1 получили %v, ждали только человека %v", got, msUser)
			}
		})
	}
}

// TestReconcileMultiSubject_ClassGetsOnlyReadVerbs — Р4 по каждому субъекту:
// роль с пишущим глаголом даёт его человеку выдачи и не даёт классу той же
// выдачи; чтение — обоим. Порядок не важен.
func TestReconcileMultiSubject_ClassGetsOnlyReadVerbs(t *testing.T) {
	rules := domain.Rules{{Module: "probemod", Resources: []string{"boxes"}, Verbs: []string{"get", "list", "update"}}}
	for _, order := range [][]string{{msUser, msAnon}, {msAnon, msUser}} {
		t.Run(strings.Join(order, ","), func(t *testing.T) {
			f := msStore(rules, order...)
			ndReconcile(t, f)
			if got := msUsers(f, "v_get", "probemod_box:b1"); !slices.Equal(got, []string{msAnon, msUser}) {
				t.Fatalf("близнец: v_get на b1 получили %v, ждали обоих", got)
			}
			if got := msUsers(f, "v_update", "probemod_box:b1"); !slices.Equal(got, []string{msUser}) {
				t.Errorf("v_update на b1 получили %v, ждали только человека", got)
			}
		})
	}
}

// TestPublicReaderMember_KeyCarriesTheClassSet — ключ члена `public_reader`
// несёт множество классов: перестановка его не меняет, иной состав классов —
// меняет (член, развёрнутый прежде меньшему составу, выпадет и будет записан
// заново, а не сочтётся неизменным).
func TestPublicReaderMember_KeyCarriesTheClassSet(t *testing.T) {
	key := func(refs ...string) string {
		var subjects []domain.Subject
		for _, r := range refs {
			subjects = append(subjects, msSubject(r))
		}
		bs := BindingScope{
			Scope:     domain.ScopeAnchor{Type: "project", ID: ndPrj},
			Subjects:  subjects,
			Selectors: ndReaderRules(nil, nil, "items").MaterializingSelectorsInScope(domain.ScopeProject),
			Target:    ndBoxTarget("b1"),
		}
		for _, m := range desiredMembersForObject(ndFacts(t), bs, ndObj("probemod.boxes", "b1", map[string]string{"team": "a"}), nil) {
			if strings.HasPrefix(m.RuleFP, publicReaderRuleFPPrefix) {
				return m.RuleFP
			}
		}
		t.Fatalf("выдача %v не дала члена public_reader", refs)
		return ""
	}
	if a, b := key(msAnon, msAuth), key(msAuth, msAnon); a != b {
		t.Errorf("перестановка классов сменила ключ: %q против %q", a, b)
	}
	if a, b := key(msAuth, msAnon), key(msAuth); a == b {
		t.Errorf("ключ не различает состав классов: %q", a)
	}
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	slices.Sort(out)
	return out
}
