// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package grantcapability адресует точное управляющее право в native-модели.
// Codec не проверяет наличие права, существование роли или assignability.
package grantcapability

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

const (
	ScopeObjectType = "iam_grant_scope"
	RoleObjectType  = "iam_grant_role"
	CreateRelation  = "create_binding"
	BindRelation    = "bind"

	coordinateVersion = byte(1)
	maxFieldBytes     = 4096
	maxWireBytes      = 2 + 3*(2+maxFieldBytes)
)

var ErrInvalidCoordinate = errors.New("invalid grant capability coordinate")

// Coordinate не наследует anchor из home-tier роли или родительской области.
type Coordinate struct {
	Kind   domain.GrantCapabilityKind
	Anchor domain.ScopeAnchor
	RoleID domain.RoleID
}

type Reference struct {
	ObjectType string
	ObjectID   string
	Relation   string
}

func (r Reference) Object() string { return r.ObjectType + ":" + r.ObjectID }

// Encode использует version/kind и три length-prefixed поля. Base64url без
// padding оставляет идентификатор одним непрерывным непрозрачным токеном.
func Encode(c Coordinate) (Reference, error) {
	if err := validate(c); err != nil {
		return Reference{}, err
	}
	r, kind, err := slot(c.Kind)
	if err != nil {
		return Reference{}, err
	}
	wire := []byte{coordinateVersion, kind}
	for _, field := range []string{c.Anchor.Type, c.Anchor.ID, string(c.RoleID)} {
		wire = binary.BigEndian.AppendUint16(wire, uint16(len(field)))
		wire = append(wire, field...)
	}
	r.ObjectID = base64.RawURLEncoding.EncodeToString(wire)
	return r, nil
}

// Decode принимает только каноническую форму собственного Encode. Другой
// object type/relation, будущая версия, скрытый хвост и неоднозначное base64
// представление являются ошибкой, а не вопросом о соседнем праве.
func Decode(r Reference) (Coordinate, error) {
	if len(r.ObjectID) > base64.RawURLEncoding.EncodedLen(maxWireBytes) {
		return Coordinate{}, invalid("encoded size")
	}
	wire, err := base64.RawURLEncoding.Strict().DecodeString(r.ObjectID)
	if err != nil || len(wire) < 2 || wire[0] != coordinateVersion {
		return Coordinate{}, invalid("encoding or version")
	}
	var kind domain.GrantCapabilityKind
	switch wire[1] {
	case 1:
		kind = domain.GrantCapabilityCreateBinding
	case 2:
		kind = domain.GrantCapabilityBindRole
	default:
		return Coordinate{}, invalid("kind")
	}
	fields := make([]string, 0, 3)
	rest := wire[2:]
	for range 3 {
		if len(rest) < 2 {
			return Coordinate{}, invalid("field length")
		}
		n := int(binary.BigEndian.Uint16(rest))
		rest = rest[2:]
		if n > maxFieldBytes || n > len(rest) {
			return Coordinate{}, invalid("field bounds")
		}
		fields = append(fields, string(rest[:n]))
		rest = rest[n:]
	}
	if len(rest) != 0 {
		return Coordinate{}, invalid("trailing payload")
	}
	c := Coordinate{Kind: kind, Anchor: domain.ScopeAnchor{Type: fields[0], ID: fields[1]}, RoleID: domain.RoleID(fields[2])}
	canonical, err := Encode(c)
	if err != nil {
		return Coordinate{}, err
	}
	if canonical != r {
		return Coordinate{}, invalid("noncanonical reference")
	}
	return c, nil
}

func validate(c Coordinate) error {
	if !domain.IsScopeAnchorKind(c.Anchor.Type) ||
		domain.DeriveFromResourceType(c.Anchor.Type).ValidateAgainst(c.Anchor.Type, c.Anchor.ID) != nil {
		return invalid("scope")
	}
	if !token(c.Anchor.ID) {
		return invalid("scope ID")
	}
	switch c.Kind {
	case domain.GrantCapabilityCreateBinding:
		if c.RoleID != "" {
			return invalid("create payload")
		}
	case domain.GrantCapabilityBindRole:
		if !token(string(c.RoleID)) || c.RoleID == "*" {
			return invalid("role ID")
		}
	default:
		return invalid("kind")
	}
	return nil
}

func slot(kind domain.GrantCapabilityKind) (Reference, byte, error) {
	switch kind {
	case domain.GrantCapabilityCreateBinding:
		return Reference{ObjectType: ScopeObjectType, Relation: CreateRelation}, 1, nil
	case domain.GrantCapabilityBindRole:
		return Reference{ObjectType: RoleObjectType, Relation: BindRelation}, 2, nil
	default:
		return Reference{}, 0, invalid("kind")
	}
}

func token(s string) bool {
	return s != "" && len(s) <= maxFieldBytes && utf8.ValidString(s) &&
		!strings.ContainsAny(s, ":#") && strings.IndexFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) == -1
}

func invalid(part string) error {
	// Не включаем сырой ID в ошибку внутреннего codec.
	return fmt.Errorf("%w: %s", ErrInvalidCoordinate, part)
}
