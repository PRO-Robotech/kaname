// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package granteffect

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
)

func TestMetadataServiceAccountDeltaUsesHeldCreator(t *testing.T) {
	c := compiler(t)
	owner := domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: "sva-creator-a"}
	old, next := metadataPair("iam_service_account", "sva-focus")
	old.CreatorKnown, next.CreatorKnown = true, true
	old.Creator, next.Creator = owner, owner
	for _, protected := range []bool{false, true} {
		rule := domain.Rule{Module: "iam", Resources: []string{"serviceAccount"}, Verbs: []string{"get"}}
		before, after := old, next
		if protected {
			before.AccessLabels, after.AccessLabels = before.Labels, after.Labels
			before.Labels, after.Labels = nil, nil
			rule.MatchAccessLabels = map[string]string{"env": "new"}
		} else {
			rule.MatchLabels = map[string]string{"env": "new"}
		}
		b := binding(rule)
		b.Recipient = owner
		delta := completeMetadata(t, c.compileMetadataDelta(b, before, after))
		if len(delta.Before.Effects()) != 0 || len(delta.After.Effects()) == 0 {
			t.Fatal("new holder effect was lost")
		}
		proves(t, delta.Before, delta.After, false)
		creator := binding(domain.Rule{Module: "iam", Resources: []string{"serviceAccount"}, Verbs: []string{"get"}, CreatedBySubject: true})
		creator.Recipient = owner
		held := completeMetadata(t, c.compileMetadataDelta(creator, before, after))
		// Селектор создателя выдаёт v_get, но не обычный ярус viewer.
		// Проверяем покрытие get отдельно и запрещаем считать покрытой всю выдачу.
		getOnly := delta.After
		getOnly.effects = nil
		viewerFound := false
		for _, effect := range delta.After.Effects() {
			switch effect.Action {
			case (grantcoverage.Action{Kind: grantcoverage.Verb, Name: "get"}):
				getOnly.effects = append(getOnly.effects, effect)
			case (grantcoverage.Action{Kind: grantcoverage.Relation, Name: "viewer"}):
				viewerFound = true
			default:
				t.Fatalf("неожиданный эффект чтения serviceAccount: %+v", effect)
			}
		}
		if len(getOnly.Effects()) == 0 || !viewerFound {
			t.Fatal("обычная выдача чтения должна сохранять get и viewer")
		}
		proves(t, held.Before, getOnly, true)
		proves(t, held.Before, delta.After, false)
		creator.Recipient.ID = "sva-creator-b"
		foreign := completeMetadata(t, c.compileMetadataDelta(creator, before, after))
		if len(foreign.Before.Effects()) != 0 || len(foreign.After.Effects()) != 0 {
			t.Fatal("foreign creator selected the focal service account")
		}
		creator.Recipient = owner
		before.Creator, after.Creator = domain.Subject{Type: domain.SubjectTypeUser, ID: owner.ID}, domain.Subject{Type: domain.SubjectTypeUser, ID: owner.ID}
		crossType := completeMetadata(t, c.compileMetadataDelta(creator, before, after))
		if len(crossType.Before.Effects()) != 0 || len(crossType.After.Effects()) != 0 {
			t.Fatal("same creator ID of another type became authority")
		}
		before.Creator, after.Creator = domain.Subject{}, domain.Subject{}
		absent := completeMetadata(t, c.compileMetadataDelta(creator, before, after))
		if len(absent.Before.Effects()) != 0 || len(absent.After.Effects()) != 0 {
			t.Fatal("known absent legacy creator became authority")
		}
	}
	b := binding(domain.Rule{Module: "iam", Resources: []string{"serviceAccount"}, Verbs: []string{"get"}})
	for _, broken := range []MetadataObject{
		{Type: old.Type, ID: old.ID},
		{Type: old.Type, ID: old.ID, CreatorKnown: true, Creator: domain.Subject{Type: domain.SubjectTypeUser, ID: "other"}},
		{Type: "service_account", ID: old.ID, CreatorKnown: true, Creator: owner},
	} {
		d := c.compileMetadataDelta(b, old, broken)
		if d.Before.Complete() || d.After.Complete() {
			t.Fatal("unconfirmed identity/creator accepted")
		}
	}
}
