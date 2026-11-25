// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grantcapability_test

import (
	"errors"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
)

func TestAccessLabelCoordinateBindsExactScopeAndDefinition(t *testing.T) {
	base := grantcapability.Coordinate{
		Kind:         domain.GrantCapabilityApplyAccessLabel,
		Anchor:       domain.ScopeAnchor{Type: "account", ID: "accA"},
		DefinitionID: "3d9cd5bf-906f-4bbe-8a8b-234ba2efa54a",
	}
	otherScope, otherKey := base, base
	otherScope.Anchor.ID = "accB"
	otherKey.DefinitionID = "4d9cd5bf-906f-4bbe-8a8b-234ba2efa54a"
	seen := map[grantcapability.Reference]bool{}
	for _, coord := range []grantcapability.Coordinate{base, otherScope, otherKey} {
		ref, err := grantcapability.Encode(coord)
		if err != nil || seen[ref] || ref.ObjectType != grantcapability.AccessLabelObjectType || ref.Relation != grantcapability.ApplyAccessLabelRelation {
			t.Fatalf("некорректная координата применения: %+v, %v", ref, err)
		}
		seen[ref] = true
		decoded, err := grantcapability.Decode(ref)
		if err != nil || decoded != coord {
			t.Fatalf("потеряна область или определение: %+v, %v", decoded, err)
		}
		for _, mismatch := range []grantcapability.Reference{
			{ObjectType: grantcapability.RoleObjectType, Relation: grantcapability.BindRelation, ObjectID: ref.ObjectID},
			{ObjectType: grantcapability.ScopeObjectType, Relation: grantcapability.CreateRelation, ObjectID: ref.ObjectID},
			{ObjectType: ref.ObjectType, Relation: "v_update", ObjectID: ref.ObjectID},
		} {
			if _, err := grantcapability.Decode(mismatch); !errors.Is(err, grantcapability.ErrInvalidCoordinate) {
				t.Fatalf("подмена вида или отношения принята: %+v, %v", mismatch, err)
			}
		}
	}
	if !grantcapability.IsInternalObjectType(grantcapability.AccessLabelObjectType) {
		t.Fatal("координата применения должна оставаться внутренней")
	}
	for _, malformed := range []domain.AccessLabelDefinitionID{"", "*", "rolA", "00000000-0000-0000-0000-000000000000", "3D9cd5bf-906f-4bbe-8a8b-234ba2efa54a"} {
		candidate := base
		candidate.DefinitionID = malformed
		if _, err := grantcapability.Encode(candidate); !errors.Is(err, grantcapability.ErrInvalidCoordinate) {
			t.Fatalf("неканонический идентификатор принят: %v", err)
		}
	}
	base.RoleID = "rolA"
	for _, kind := range []domain.GrantCapabilityKind{domain.GrantCapabilityApplyAccessLabel, domain.GrantCapabilityBindRole} {
		base.Kind = kind
		if _, err := grantcapability.Encode(base); !errors.Is(err, grantcapability.ErrInvalidCoordinate) {
			t.Fatalf("форма приняла идентификаторы двух видов: %v", err)
		}
	}
}
