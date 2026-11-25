// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package granteffect

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
)

const accessLabelModel = `
type iam_grant_access_label
  relations
    define apply: [user, service_account, group#member]
`

func TestAccessLabelEffectRequiresExactDefinitionAndScope(t *testing.T) {
	r := domain.Rule{
		Module: "iam", Resources: []string{"accessLabel"}, Verbs: []string{"apply"},
		ResourceNames: []string{"3d9cd5bf-906f-4bbe-8a8b-234ba2efa54a"},
	}
	data := rows()
	data.Live.Resources = append(data.Live.Resources, catalog.ResourceRow{Module: "iam", Resource: "accessLabel", ObjectType: grantcapability.AccessLabelObjectType})
	data.Live.Verbs = append(data.Live.Verbs, catalog.VerbRow{Module: "iam", Resource: "accessLabel", Verb: "apply"})
	c, err := New(modelFixture+accessLabelModel, data)
	if err != nil {
		t.Fatal(err)
	}
	input := binding(r)
	held := complete(t, c.Compile(input))
	effects := held.Effects()
	if len(effects) != 1 || effects[0].Kind != ApplyAccessLabel ||
		effects[0].Anchor != input.Scope || string(effects[0].DefinitionID) != r.ResourceNames[0] || effects[0].RoleID != "" {
		t.Fatalf("неожиданный эффект применения: %+v", effects)
	}
	named := func(id string) domain.Rule {
		copy := r
		copy.ResourceNames = []string{id}
		return copy
	}
	otherDefinition := binding(named("4d9cd5bf-906f-4bbe-8a8b-234ba2efa54a"))
	otherAccount := binding(r)
	otherAccount.Scope.ID = "acc-b"
	project := binding(r)
	project.Scope = domain.ScopeAnchor{Type: "project", ID: "prj-a"}
	proves(t, held, complete(t, c.Compile(input)), true)
	for _, changed := range []Binding{otherDefinition, otherAccount, project} {
		proves(t, held, complete(t, c.Compile(changed)), false)
	}
	for _, unrelated := range []domain.Rule{
		{Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"create"}},
		{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{"role-a"}},
		{Module: "iam", Resources: []string{"account"}, Verbs: []string{"update"}},
		{Module: "iam", Resources: []string{"accessLabel"}, Verbs: []string{"*"}},
	} {
		proves(t, complete(t, c.Compile(binding(unrelated))), held, false)
	}
	admin := c.CompileDirect(Direct{SourceID: "admin", ObjectType: "account", ObjectID: input.Scope.ID, Relation: "admin", Recipient: input.Recipient})
	proves(t, complete(t, admin), held, false)
	legacy := input
	legacy.CapabilityVersion = 0
	for _, effect := range c.Compile(legacy).Effects() {
		if effect.Kind == ApplyAccessLabel {
			t.Fatal("исторический носитель выдал новое управляющее право")
		}
	}
	ref, err := grantcapability.Encode(grantcapability.Coordinate{
		Kind: domain.GrantCapabilityApplyAccessLabel, Anchor: input.Scope,
		DefinitionID: domain.AccessLabelDefinitionID(r.ResourceNames[0]),
	})
	if err != nil {
		t.Fatal(err)
	}
	direct := c.CompileDirect(Direct{SourceID: "plain-fact", ObjectType: ref.ObjectType, ObjectID: ref.ObjectID, Relation: ref.Relation, Recipient: input.Recipient})
	if direct.Complete() || len(direct.Effects()) != 0 {
		t.Fatal("обычная строка отношения удостоверила выдачу права на ключ")
	}
	withoutPlan, err := New(modelFixture, data)
	if err != nil {
		t.Fatal(err)
	}
	if unavailable := withoutPlan.Compile(input); unavailable.Complete() || len(unavailable.Effects()) != 0 {
		t.Fatal("строка каталога без плана породила доказательство полномочий")
	}
}
