// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package kaname

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
	ab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
)

// RoleTupleBuilder — чистый штатный построитель уровня выдачи. Он не читает
// authority и не получает Writer; все субъекты принадлежат одному RR снимку.
type RoleTupleBuilder interface {
	BuildRoleTuples(domain.AccessBinding, []domain.Subject, domain.Role) []ab.RelationTuple
}

// RoleMutationRequest описывает реальное тело операции до первого решения.
// Rules=false не запускает fanout или promotion при правке метаданных.
type RoleMutationRequest struct {
	Role   domain.Role
	Create bool
	Rules  bool
	Tuples RoleTupleBuilder
}

type RoleMutationWriterFactory interface {
	RoleMutationWriter(context.Context, RoleMutationRequest, domain.Subject) (SemanticAuthorityWriter, error)
}

// PreparedRoleTupleWriter применяет только сохранённый OLD/NEW diff той роли,
// которая подготовлена фабрикой. Повторное применение запрещено.
type PreparedRoleTupleWriter interface {
	ApplyPreparedRoleTuples(context.Context, domain.RoleID) error
}
