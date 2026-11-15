// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package kaname

import (
	"context"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// AccountCreateAuthority фиксирует новые идентификаторы до любых физических ожиданий.
// Системная owner binding создаётся только вместе с новым корневым аккаунтом.
type AccountCreateAuthority struct {
	Account          domain.Account
	DefaultProjectID domain.ProjectID
	OwnerBindingID   domain.AccessBindingID
	IDSource         string
}

// AccountCreateWriterFactory — отдельное подготовленное публичное действие.
type AccountCreateWriterFactory interface {
	AccountCreateWriter(context.Context, AccountCreateAuthority, domain.Subject) (SemanticAuthorityWriter, error)
}

// AccountDeleteWriterFactory — отдельное подготовленное публичное действие.
type AccountDeleteWriterFactory interface {
	AccountDeleteWriter(context.Context, domain.AccountID, domain.Subject) (SemanticAuthorityWriter, error)
}

// ProjectCreateWriterFactory — отдельное подготовленное публичное действие.
type ProjectCreateWriterFactory interface {
	ProjectCreateWriter(context.Context, domain.Project, domain.Subject) (SemanticAuthorityWriter, error)
}

// ProjectDeleteWriterFactory — отдельное подготовленное публичное действие.
type ProjectDeleteWriterFactory interface {
	ProjectDeleteWriter(context.Context, domain.ProjectID, domain.Subject) (SemanticAuthorityWriter, error)
}

// ServiceAccountCreateWriterFactory — отдельное подготовленное публичное действие.
type ServiceAccountCreateWriterFactory interface {
	ServiceAccountCreateWriter(context.Context, domain.ServiceAccount, domain.Subject) (SemanticAuthorityWriter, error)
}

// ServiceAccountDeleteWriterFactory — отдельное подготовленное публичное действие.
type ServiceAccountDeleteWriterFactory interface {
	ServiceAccountDeleteWriter(context.Context, domain.ServiceAccountID, domain.Subject) (SemanticAuthorityWriter, error)
}

// RoleDeleteWriterFactory — отдельное подготовленное публичное действие.
type RoleDeleteWriterFactory interface {
	RoleDeleteWriter(context.Context, domain.RoleID, domain.Subject) (SemanticAuthorityWriter, error)
}

// CRUDWriterFactory объединяет ровно семь закрытых команд; общего raw входа нет.
type CRUDWriterFactory interface {
	AccountCreateWriterFactory
	AccountDeleteWriterFactory
	ProjectCreateWriterFactory
	ProjectDeleteWriterFactory
	ServiceAccountCreateWriterFactory
	ServiceAccountDeleteWriterFactory
	RoleDeleteWriterFactory
}
