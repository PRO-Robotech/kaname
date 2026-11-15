// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

func TestResourcePredicateProtectsAbsentFiniteObjectsWithoutGlobal(t *testing.T) {
	for _, tc := range []struct {
		name      string
		predicate resourceSelectorPredicate
		want      []domain.ResourceRef
	}{
		{"names", resourceSelectorPredicate{RuleFP: "rule-a", Arm: domain.ArmNames, Names: []string{"missing-b", "missing-a", "missing-b"}, Scope: domain.ScopeAnchor{Type: "account", ID: "a"}}, []domain.ResourceRef{{Type: "vpc.box", ID: "missing-a"}, {Type: "vpc.box", ID: "missing-b"}}},
		{"labels with finite targets", resourceSelectorPredicate{RuleFP: "rule-a", Arm: domain.ArmLabels, Targets: []string{"missing-a"}, Labels: map[string]string{"kind": "desired"}, Scope: domain.ScopeAnchor{Type: "account", ID: "a"}}, []domain.ResourceRef{{Type: "vpc.box", ID: "missing-a"}}},
		{"cluster anchor with finite target", resourceSelectorPredicate{RuleFP: "rule-a", Arm: domain.ArmAnchor, Targets: []string{"missing-a"}, Scope: domain.ScopeAnchor{Type: "cluster", ID: "root"}}, []domain.ResourceRef{{Type: "vpc.box", ID: "missing-a"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.predicate)
			if err != nil {
				t.Fatal(err)
			}
			got, err := classifyResourcePredicate(resourceSourceKey{kind: resourceSourceSelectorObjects, typ: "vpc.box", id: "binding-a", projection: string(raw)})
			if err != nil {
				t.Fatal(err)
			}
			if got.Global || !reflect.DeepEqual(got.Objects, tc.want) || len(got.Scopes) != 0 || len(got.Children) != 0 {
				t.Fatalf("unexpected protection: %+v", got)
			}
		})
	}
}

func TestResourcePredicateScopeAndBroadCensusAreDistinct(t *testing.T) {
	for _, tc := range []struct {
		name   string
		arm    domain.Arm
		scope  domain.ScopeAnchor
		global bool
	}{
		{"account anchor", domain.ArmAnchor, domain.ScopeAnchor{Type: "account", ID: "a"}, false},
		{"project anchor", domain.ArmAnchor, domain.ScopeAnchor{Type: "project", ID: "p"}, false},
		{"whole labels preserves foreign rejected", domain.ArmLabels, domain.ScopeAnchor{Type: "account", ID: "a"}, true},
		{"whole cluster anchor", domain.ArmAnchor, domain.ScopeAnchor{Type: "cluster", ID: "root"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(resourceSelectorPredicate{RuleFP: "rule-a", Arm: tc.arm, Scope: tc.scope})
			if err != nil {
				t.Fatal(err)
			}
			got, err := classifyResourcePredicate(resourceSourceKey{kind: resourceSourceSelectorObjects, typ: "vpc.box", id: "binding-a", projection: string(raw)})
			if err != nil {
				t.Fatal(err)
			}
			if got.Global != tc.global || len(got.Objects) != 0 || len(got.Children) != 0 {
				t.Fatalf("unexpected protection: %+v", got)
			}
			if !tc.global && !reflect.DeepEqual(got.Scopes, []domain.ScopeAnchor{tc.scope}) {
				t.Fatalf("lost scope predicate: %+v", got)
			}
			if tc.global && len(got.Scopes) != 0 {
				t.Fatalf("broad census hidden behind local scope: %+v", got)
			}
		})
	}
}

func TestResourcePredicateNestedEdgesProtectExactParents(t *testing.T) {
	raw, err := json.Marshal(resourceNestedPredicate{RuleFP: "nested-rule-a", ContainerType: "vpc.box", ContainerIDs: []string{"b", "a", "b"}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := classifyResourcePredicate(resourceSourceKey{kind: resourceSourceNestedDescendants, typ: "vpc.item", id: "binding-a", projection: string(raw)})
	if err != nil {
		t.Fatal(err)
	}
	want := []domain.ResourceRef{{Type: "vpc.box", ID: "a"}, {Type: "vpc.box", ID: "b"}}
	if got.Global || !reflect.DeepEqual(got.Children, want) || len(got.Objects) != 0 || len(got.Scopes) != 0 {
		t.Fatalf("unexpected protection: %+v", got)
	}
}

func TestResourcePredicateInvalidShapeDoesNotSelectGlobal(t *testing.T) {
	for _, key := range []resourceSourceKey{
		{kind: resourceSourceSelectorObjects, typ: "vpc.box", id: "binding-a", projection: `{"arm":999,"scope":{"type":"account","id":"a"}}`},
		{kind: resourceSourceSelectorObjects, typ: "vpc.box", id: "binding-a", projection: `{`},
		{kind: resourceSourceNestedDescendants, typ: "vpc.item", id: "binding-a", projection: `{"container_type":"vpc.box","container_ids":[]}`},
		{kind: resourceSourceMirror, typ: "vpc.box", id: "a"},
	} {
		got, err := classifyResourcePredicate(key)
		if !errors.Is(err, kaname.ErrSourceUnconfirmed) || got.Global {
			t.Fatalf("invalid shape became protection: %+v, %v", got, err)
		}
	}
}
