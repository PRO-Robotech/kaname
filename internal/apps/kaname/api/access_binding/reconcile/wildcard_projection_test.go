// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

import (
	"slices"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestWildcardProjection_ActualMaterializerStaticAndLiveTypeTwins(t *testing.T) {
	cat := ndFacts(t)
	for _, tc := range []struct {
		name     string
		dotted   string
		fga      string
		module   string
		resource string
		inStatic bool
	}{
		{name: "static-known-network", dotted: "vpc.network", fga: "vpc_network", module: "vpc", resource: "network", inStatic: true},
		{name: "live-manifest-outside-static-list", dotted: "probemod.boxes", fga: "probemod_box", module: "probemod", resource: "boxes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := cat.FGAObjectType(tc.dotted); !ok || got != tc.fga {
				t.Fatalf("fixture catalog: %s/%v", got, ok)
			}
			object := sc65BoxObject()
			object.ObjectType = tc.dotted
			readers := func(rule domain.Rule) []string {
				bs := sc65Scope("user", "typed-reader", domain.Rules{rule})
				bs.Target = domain.AccessTarget{Resources: []domain.ResourceRef{{Type: tc.dotted, ID: object.ObjectID}}}
				var users []string
				for _, m := range desiredMembersForObject(cat, bs, object, nil) {
					for _, tuple := range m.Tuples {
						if tuple.Relation == "v_get" && tuple.Object == tc.fga+":"+object.ObjectID {
							users = append(users, tuple.User)
						}
					}
				}
				return users
			}
			explicit := domain.Rule{Module: tc.module, Resources: []string{tc.resource}, Verbs: []string{"get"}}
			if got := readers(explicit); !slices.Equal(got, []string{"user:typed-reader"}) {
				t.Fatalf("explicit positive control: %v", got)
			}
			for _, rule := range []domain.Rule{
				{Module: "*", Resources: []string{"*"}, Verbs: []string{"get"}},
				{Module: tc.module, Resources: []string{"*"}, Verbs: []string{"get"}},
			} {
				projection := rule.MaterializedTypeProjection(domain.ScopeProject)
				if !projection.UsesStaticRegistry() {
					t.Fatalf("static provenance lost: %+v", projection)
				}
				got := readers(rule)
				if tc.inStatic {
					if !slices.Equal(got, []string{"user:typed-reader"}) {
						t.Fatalf("static positive: %v", got)
					}
				} else if len(got) != 0 || slices.Contains(projection.ObjectTypes, tc.dotted) {
					t.Fatalf("producer behavior changed to live expansion: %v / %+v", got, projection)
				}
			}
		})
	}
}
