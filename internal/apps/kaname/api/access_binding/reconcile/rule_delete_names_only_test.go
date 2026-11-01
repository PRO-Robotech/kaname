// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

// rule_delete_names_only_test.go — материализация правила с глаголом удаления
// (приёмка role-rights-stay-within-what-is-named.md, Р1, В1, ESC-30;
// задачи PRO-Robotech/kaname#1035, PRO-Robotech/kaname#1039).
//
// Правило, все глаголы которого — `delete`, пишет на объекте только `v_delete`:
// ни `admin`, ни `editor`, ни `viewer`. Выдача, материализованная прежним выводом
// (ярус `admin` рядом с `v_delete` под той же координатой члена), сводящим
// проходом приходит к новому набору: строка `admin` снимается и с движка, и с
// реестра выпущенного, прочие строки не трогаются.

import (
	"context"
	"slices"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

const dnBinding domain.AccessBindingID = "acb-dn-1"

// dnStore — выдача роли платформы с одним правилом над сетями проекта.
func dnStore(verbs ...string) *fakeStore {
	rule := domain.Rule{Module: "vpc", Resources: []string{"network"}, Verbs: verbs}
	policy := domain.PolicyOfRole(true, "")
	return &fakeStore{
		scope:       domain.ScopeAnchor{Type: "project", ID: "prj-1"},
		subjectType: "user", subjectID: "usr-1", active: true,
		policy: &policy,
		selectors: []domain.RuleSelector{{
			Arm: domain.ArmAnchor, RuleFP: rule.Fingerprint(),
			ObjectTypes: []string{"vpc.network"},
			Verbs:       rule.Verbs,
		}},
		mirror: map[string][]domain.MirrorObject{
			"vpc.network": {{ObjectType: "vpc.network", ObjectID: "net-1", ParentProjectID: "prj-1"}},
		},
	}
}

func dnRun(t *testing.T, f *fakeStore, converge bool) {
	t.Helper()
	rec := New(fakeRunner{s: f}, nil, catalogfixture.Source())
	var err error
	if converge {
		err = rec.ConvergeBinding(context.Background(), dnBinding)
	} else {
		err = rec.ReconcileBinding(context.Background(), dnBinding)
	}
	if err != nil {
		t.Fatalf("проход: %v", err)
	}
}

// TestReconcile_DeleteOnlyRuleMaterializesOnlyVDelete — строки отличаются от
// соседней ровно глаголами правила.
func TestReconcile_DeleteOnlyRuleMaterializesOnlyVDelete(t *testing.T) {
	const object = "vpc_network:net-1"
	cases := []struct {
		name    string
		verbs   []string
		present []string
		absent  []string
	}{
		{"одно удаление", []string{"delete"}, []string{"v_delete"}, []string{"admin", "editor", "viewer"}},
		{"правка и удаление", []string{"update", "delete"}, []string{"v_update", "v_delete", "editor"}, []string{"admin"}},
		{"подстановка", []string{"*"}, []string{"v_delete", "admin"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := dnStore(c.verbs...)
			dnRun(t, f, false)
			w := allWrites(f)
			for _, rel := range c.present {
				if !hasTuple(w, rel, object) {
					t.Errorf("правило %v не записало %s на %s: %v", c.verbs, rel, object, w)
				}
			}
			for _, rel := range c.absent {
				if hasTuple(w, rel, object) {
					t.Errorf("правило %v записало %s на %s — из одного удаления ярус не выводится", c.verbs, rel, object)
				}
			}
		})
	}
}

// TestReconcile_StaleDeleteTierIsRevokedOnTheConvergingPass — прежнее состояние
// выдачи с одним удалением: строка `admin` под координатой члена `v_delete`.
// Сводящий проход снимает её; `v_delete` остаётся, неизменный член не
// переписывается. Близнец — та же выдача с подстановкой: её `admin` проход не
// трогает (на него претендует желаемый член).
func TestReconcile_StaleDeleteTierIsRevokedOnTheConvergingPass(t *testing.T) {
	const object = "vpc_network:net-1"
	stale := func(verbs ...string) *fakeStore {
		fresh := dnStore(verbs...)
		dnRun(t, fresh, false)
		ledger := slices.Clone(fresh.ledgerNow())
		var coord MemberCoord
		found := false
		for _, r := range ledger {
			if r.Tuple.Relation == "v_delete" && r.Tuple.Object == object {
				coord, found = r.Member, true
			}
		}
		if !found {
			t.Fatalf("предпосылка: свежая выдача %v не выпустила v_delete на %s", verbs, object)
		}
		admin := LedgerRow{Member: coord, Tuple: domain.MembershipTuple{User: "user:usr-1", Relation: "admin", Object: object}}
		if !slices.Contains(ledger, admin) {
			ledger = append(ledger, admin)
		}
		f := dnStore(verbs...)
		f.current = slices.Clone(fresh.upserts)
		f.ledger = ledger
		return f
	}

	twin := stale("*")
	dnRun(t, twin, true)
	if hasTuple(miFlatten(twin.tdeletes), "admin", object) {
		t.Fatalf("близнец: проход снял admin у выдачи с подстановкой: %v", miFlatten(twin.tdeletes))
	}

	f := stale("delete")
	dnRun(t, f, true)
	if !hasTuple(miFlatten(f.tdeletes), "admin", object) {
		t.Errorf("сводящий проход не снял admin с %s у выдачи с одним удалением: снятий %v", object, miFlatten(f.tdeletes))
	}
	if miLedgerHas(f, "admin", object) {
		t.Errorf("реестр выпущенного по-прежнему несёт admin на %s", object)
	}
	if hasTuple(miFlatten(f.tdeletes), "v_delete", object) || !miLedgerHas(f, "v_delete", object) {
		t.Errorf("проход снял v_delete на %s — право удалять обязано остаться", object)
	}
	if len(f.writes) != 0 {
		t.Errorf("проход переписал неизменного члена: записей %v", f.writes)
	}
}
