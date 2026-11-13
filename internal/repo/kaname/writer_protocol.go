// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package kaname

import (
	"context"
	"errors"

	"github.com/PRO-Robotech/kaname/internal/granteffect"
)

// kaname#1034: описание операции не является разрешением её эффектов.
// Accounts — полный первоначальный план; Owners — реальные источники ownership,
// включая явно названные account anchors новых объектов. Перенос требует OLD+NEW.
type AuthorityWriteIntent struct {
	Plan   AuthorityFencePlan
	Owners []AuthorityOwnerRef
	Kind   AuthorityOperation
	Bundle *granteffect.Bundle
}
type AuthorityOwnerRef struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}
type AuthorityOperation string

const (
	AuthorityBinding          AuthorityOperation = "binding"
	AuthorityRole             AuthorityOperation = "role"
	AuthorityGroup            AuthorityOperation = "group"
	AuthorityMembership       AuthorityOperation = "membership"
	AuthorityDelegation       AuthorityOperation = "delegation"
	AuthorityResource         AuthorityOperation = "resource"
	AuthorityIdentity         AuthorityOperation = "identity"
	AuthorityCatalog          AuthorityOperation = "catalog"
	AuthorityCluster          AuthorityOperation = "cluster"
	MaxAuthorityOwnershipRefs                    = 256
)

var ErrAuthorityClassificationChanged = errors.New("authority ownership changed during bounded writer entry")

// CoordinatedAuthorityWriterFactory возвращает writer только после DB entry:
// xact fences, fresh ownership, bundle/protocol compare и decision_at.
// Аттестация подтверждает протокол TX, не D1/D2/D3 или полноту sources.
type CoordinatedAuthorityWriterFactory interface {
	CoordinatedAuthorityWriter(context.Context, AuthorityWriteIntent) (SemanticAuthorityWriter, error)
}

// TransitionalAuthorityWriterFactory переводит старые adapters на fences до
// cutover. Здесь намеренно нет SemanticBundle/checker и нет grant decision proof.
type TransitionalAuthorityWriterFactory interface {
	TransitionalAuthorityWriter(context.Context, AuthorityWriteIntent) (AuthorityWriter, error)
}
