// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

// journal_one_statement_test.go — проход, который и выдаёт, и снимает, кладёт журнал
// прав ОДНИМ обращением в конце прохода (kaname#617).
//
// Замки строк прямого факта свёртка берёт в общем порядке лишь внутри одного
// оператора; проход, писавший журнал по члену и снятия отдельно, сходился с проходом
// соседней выдачи того же субъекта встречно (40P01) — интеграционная проба
// `TestReconcilePassesOfOneSubjectCommitWhenOneRevokesWhatTheOtherWrites` в
// internal/repo/kaname/pg. Здесь — форма прохода: обращений к журналу ровно одно, и
// в нём оба набора.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

func TestFullPassWritesAndRevokesInOneJournalCall(t *testing.T) {
	rule := domain.Rule{
		Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"team": "a"},
	}
	fp := rule.Fingerprint()
	f := &fakeStore{
		scope:       domain.ScopeAnchor{Type: "project", ID: "prj-1"},
		subjectType: "user", subjectID: "usr-1", active: true,
		selectors: []domain.RuleSelector{{
			Arm: domain.ArmLabels, RuleFP: fp, ObjectTypes: []string{"compute.instance"},
			MatchLabels: map[string]string{"team": "a"}, Verbs: []string{"get"},
		}},
		// i-a вошёл в отбор (член новый — выдача), i-b из него выпал (снятие).
		mirror: map[string][]domain.MirrorObject{
			"compute.instance": {
				{ObjectType: "compute.instance", ObjectID: "i-a", ParentProjectID: "prj-1", Labels: map[string]string{"team": "a"}},
				{ObjectType: "compute.instance", ObjectID: "i-b", ParentProjectID: "prj-1", Labels: map[string]string{"team": "b"}},
			},
		},
		current: []domain.TargetMember{
			{BindingID: "acb-1", RuleFP: fp, ObjectType: "compute.instance", ObjectID: "i-b", VerificationStatus: domain.VerificationActive},
		},
		ledger: memberLedger("compute.instance",
			domain.MembershipTuple{User: "user:usr-1", Relation: "v_get", Object: "compute_instance:i-b"},
			domain.MembershipTuple{User: "user:usr-1", Relation: "viewer", Object: "compute_instance:i-b"},
		),
	}
	rec := New(fakeRunner{s: f}, nil, catalogfixture.Source())
	require.NoError(t, rec.ReconcileBinding(context.Background(), "acb-1"))

	require.Equal(t, 1, f.journalCalls, "проход пишет журнал одним обращением: выдачи и снятия вместе")
	require.Len(t, f.writes, 1)
	require.Len(t, f.tdeletes, 1)
	require.True(t, hasTuple(f.writes[0], "viewer", "compute_instance:i-a"), "выдача вошедшего объекта: %v", f.writes[0])
	require.True(t, hasTuple(f.tdeletes[0], "viewer", "compute_instance:i-b"), "снятие выпавшего объекта: %v", f.tdeletes[0])
}
