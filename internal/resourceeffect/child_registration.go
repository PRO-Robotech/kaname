// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package resourceeffect

import (
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// childRegistrationMember хранит право на самом выбранном родителе.
// Наличие потомков не влияет на его выдачу или отзыв.
func childRegistrationMember(cat *catalog.Facts, bs ObjectBinding, sel domain.RuleSelector, parent domain.MirrorObject) (ObjectDesiredMember, bool) {
	actions := cat.ChildRegistrationActions(sel)
	if len(actions) == 0 || !containerSelected(sel, bs, parent) {
		return ObjectDesiredMember{}, false
	}
	var tuples []domain.MembershipTuple
	seen := make(map[domain.MembershipTuple]bool)
	for _, action := range actions {
		for _, subject := range bs.Subjects {
			if subject.Type != domain.SubjectTypeUser {
				continue
			}
			tuple := domain.MembershipTuple{
				User:     domain.FGASubjectRef(string(subject.Type), string(subject.ID)),
				Relation: action.Relation,
				Object:   action.ParentType + ":" + parent.ObjectID,
			}
			if !seen[tuple] {
				seen[tuple] = true
				tuples = append(tuples, tuple)
			}
		}
	}
	if len(tuples) == 0 {
		return ObjectDesiredMember{}, false
	}
	return ObjectDesiredMember{
		Derivation: "child_registration", RuleFP: sel.RuleFP,
		ObjectType: parent.ObjectType, ObjectID: parent.ObjectID,
		Status: domain.VerificationActive, Tuples: tuples,
	}, true
}
