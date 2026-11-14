// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grantcapability_test

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
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

// kaname#1034: длина поля — байты, не руны; uint16 prefix и версия
// остаются прежними, переполнение не возвращает частичную reference.
func TestGrantCoordinate_FieldByteBoundsPreserveWireFormat(t *testing.T) {
	for _, tc := range []struct {
		name, anchor, role string
		size               uint16
	}{
		{"below", "acc" + strings.Repeat("a", 4092), "rol" + strings.Repeat("r", 4092), 4095},
		{"maximum", "acc" + strings.Repeat("a", 4093), "rol" + strings.Repeat("r", 4093), 4096},
		{"utf8_bytes", "acc" + strings.Repeat("a", 4093), "rol" + strings.Repeat("я", 2046) + "x", 4096},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := grantcapability.Coordinate{Kind: domain.GrantCapabilityBindRole, Anchor: domain.ScopeAnchor{Type: "account", ID: tc.anchor}, RoleID: domain.RoleID(tc.role)}
			r, err := grantcapability.Encode(c)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := base64.RawURLEncoding.DecodeString(r.ObjectID)
			if err != nil {
				t.Fatal(err)
			}
			if len(raw) != 15+2*int(tc.size) {
				t.Fatalf("неверная полная длина wire: %d", len(raw))
			}
			// Независимый известный префикс version=1/kind=bind(2), type=account.
			if string(raw[:11]) != string([]byte{1, 2, 0, 7, 'a', 'c', 'c', 'o', 'u', 'n', 't'}) {
				t.Fatalf("изменён wire prefix: %x", raw[:11])
			}
			if binary.BigEndian.Uint16(raw[11:13]) != tc.size {
				t.Fatal("неверная byte length anchor")
			}
			roleOffset := 13 + int(tc.size)
			if binary.BigEndian.Uint16(raw[roleOffset:roleOffset+2]) != tc.size || len(raw) != roleOffset+2+int(tc.size) {
				t.Fatal("неверная byte length role или лишний хвост")
			}
			back, err := grantcapability.Decode(r)
			if err != nil || back != c {
				t.Fatalf("пограничный round-trip: %v", err)
			}
		})
	}
	for _, n := range []int{4097, 65536} {
		for _, roleOverflow := range []bool{false, true} {
			c := grantcapability.Coordinate{Kind: domain.GrantCapabilityBindRole, Anchor: domain.ScopeAnchor{Type: "account", ID: "accA"}, RoleID: "rolA"}
			if roleOverflow {
				c.RoleID = domain.RoleID("rol" + strings.Repeat("r", n-3))
			} else {
				c.Anchor.ID = "acc" + strings.Repeat("a", n-3)
			}
			r, err := grantcapability.Encode(c)
			if !errors.Is(err, grantcapability.ErrInvalidCoordinate) || r != (grantcapability.Reference{}) {
				t.Fatalf("oversized field %d принят или вернул partial result", n)
			}
		}
	}
	// Полный, не усечённый wire с допустимым uint16, но сверх codec budget.
	raw := []byte{1, 2, 0, 7, 'a', 'c', 'c', 'o', 'u', 'n', 't'}
	raw = binary.BigEndian.AppendUint16(raw, 4097)
	raw = append(raw, []byte("acc"+strings.Repeat("a", 4094))...)
	raw = binary.BigEndian.AppendUint16(raw, 4)
	raw = append(raw, []byte("rolA")...)
	_, err := grantcapability.Decode(grantcapability.Reference{ObjectType: grantcapability.RoleObjectType, Relation: grantcapability.BindRelation, ObjectID: base64.RawURLEncoding.EncodeToString(raw)})
	if !errors.Is(err, grantcapability.ErrInvalidCoordinate) {
		t.Fatal("Decode принял поле сверх общего codec budget")
	}
}
