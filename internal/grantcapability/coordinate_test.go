// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grantcapability_test

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
)

func TestGrantCoordinate_ExactAxesRoundTrip(t *testing.T) {
	seen := map[grantcapability.Reference]bool{}
	for _, anchor := range []domain.ScopeAnchor{{Type: "cluster", ID: "cluster_root"}, {Type: "account", ID: "accA"}, {Type: "account", ID: "accB"}, {Type: "project", ID: "prjP"}, {Type: "project", ID: "prjQ"}} {
		for _, role := range []domain.RoleID{"", "rolA", "rolB"} {
			c := grantcapability.Coordinate{Kind: domain.GrantCapabilityCreateBinding, Anchor: anchor}
			if role != "" {
				c.Kind, c.RoleID = domain.GrantCapabilityBindRole, role
			}
			r, err := grantcapability.Encode(c)
			if err != nil {
				t.Fatal(err)
			}
			back, err := grantcapability.Decode(r)
			if err != nil || back != c || seen[r] {
				t.Fatalf("разные координаты слились или не пережили round-trip: %+v %+v %v", c, back, err)
			}
			seen[r] = true
		}
	}
	if len(seen) != 15 {
		t.Fatal("потеряна ось scope/role/kind")
	}
}

func TestGrantCoordinate_TypeAndRelationCannotBeSubstituted(t *testing.T) {
	c := grantcapability.Coordinate{Kind: domain.GrantCapabilityBindRole, Anchor: domain.ScopeAnchor{Type: "project", ID: "prjP"}, RoleID: "rolA"}
	r, err := grantcapability.Encode(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, changed := range []grantcapability.Reference{
		{ObjectType: grantcapability.ScopeObjectType, Relation: grantcapability.CreateRelation, ObjectID: r.ObjectID},
		{ObjectType: r.ObjectType, Relation: grantcapability.CreateRelation, ObjectID: r.ObjectID},
		{ObjectType: "iam_role", Relation: r.Relation, ObjectID: r.ObjectID},
	} {
		if _, err := grantcapability.Decode(changed); !errors.Is(err, grantcapability.ErrInvalidCoordinate) {
			t.Fatalf("подмена вида/отношения принята: %+v %v", changed, err)
		}
	}
}

func TestGrantCoordinate_NoncanonicalAndTruncatedPayloadsAreErrors(t *testing.T) {
	r, err := grantcapability.Encode(grantcapability.Coordinate{Kind: domain.GrantCapabilityCreateBinding, Anchor: domain.ScopeAnchor{Type: "account", ID: "accA"}})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := base64.RawURLEncoding.DecodeString(r.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	bad := []string{"", r.ObjectID + "=", r.ObjectID + "\n", " " + r.ObjectID, base64.RawURLEncoding.EncodeToString(append(append([]byte{}, wire...), 0))}
	for i := range wire {
		bad = append(bad, base64.RawURLEncoding.EncodeToString(wire[:i]))
	}
	for _, index := range []int{0, 1, 2, 3} {
		changed := append([]byte{}, wire...)
		changed[index] = 255
		bad = append(bad, base64.RawURLEncoding.EncodeToString(changed))
	}
	for _, id := range bad {
		changed := r
		changed.ObjectID = id
		if _, err := grantcapability.Decode(changed); !errors.Is(err, grantcapability.ErrInvalidCoordinate) {
			t.Fatalf("неканонический ввод принят: %v", err)
		}
	}
}

func TestGrantCoordinate_InvalidTypedInputsFailBeforeEncoding(t *testing.T) {
	valid := grantcapability.Coordinate{Kind: domain.GrantCapabilityCreateBinding, Anchor: domain.ScopeAnchor{Type: "account", ID: "accA"}}
	for _, changed := range []grantcapability.Coordinate{
		{},
		{Kind: "other", Anchor: valid.Anchor},
		{Kind: valid.Kind, Anchor: domain.ScopeAnchor{Type: "iam.account", ID: "accA"}},
		{Kind: valid.Kind, Anchor: domain.ScopeAnchor{Type: "account", ID: "prjP"}},
		{Kind: valid.Kind, Anchor: domain.ScopeAnchor{Type: "cluster", ID: "other"}},
		{Kind: valid.Kind, Anchor: valid.Anchor, RoleID: "rolA"},
		{Kind: domain.GrantCapabilityBindRole, Anchor: valid.Anchor},
		{Kind: domain.GrantCapabilityBindRole, Anchor: valid.Anchor, RoleID: "*"},
		{Kind: domain.GrantCapabilityBindRole, Anchor: valid.Anchor, RoleID: "rol A"},
		{Kind: domain.GrantCapabilityBindRole, Anchor: valid.Anchor, RoleID: domain.RoleID("rol\x00A")},
	} {
		if _, err := grantcapability.Encode(changed); !errors.Is(err, grantcapability.ErrInvalidCoordinate) {
			t.Fatalf("некорректная координата принята: %+v %v", changed, err)
		}
	}
}
