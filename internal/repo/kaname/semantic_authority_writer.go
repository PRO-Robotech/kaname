// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package kaname

import (
	"context"
	"errors"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
)

var ErrSemanticIdentityUnavailable = errors.New("active semantic identity unavailable or mismatched")

// SemanticAuthorityWriter — сравнение с активной DB identity после fence.
// Это не attestation и не strict mode: coordinator, drain старых writers и
// DB backstop обязательны до публичного cutover. Старый Writer не переключён.
// SemanticBundle и checker используют ровно один immutable bundle.
type SemanticAuthorityWriter interface {
	AuthorityWriter
	SemanticBundle() *granteffect.Bundle
	SemanticRelationChecker() RelationChecker
}

type SemanticAuthorityWriterFactory interface {
	SemanticAuthorityWriter(context.Context, AuthorityFencePlan, *granteffect.Bundle) (SemanticAuthorityWriter, error)
}
