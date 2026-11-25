// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package kaname

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// These ports admit only a prepared metadata UPDATE of the named object.
// They preserve OLD native authority until all physical preflight waits finish.
type AccountMetadataWriterFactory interface {
	AccountMetadataWriter(context.Context, domain.Account, []string, domain.Subject) (SemanticAuthorityWriter, error)
}
type ProjectMetadataWriterFactory interface {
	ProjectMetadataWriter(context.Context, domain.Project, []string, domain.Subject) (SemanticAuthorityWriter, error)
}
type ServiceAccountMetadataWriterFactory interface {
	ServiceAccountMetadataWriter(context.Context, domain.ServiceAccount, []string, domain.Subject) (SemanticAuthorityWriter, error)
}

// Порты защищённой правки открываются только для подготовленной транзакции,
// которая подтверждает точный состав accessLabels и изменение выдач.
type AccountAccessLabelsWriterFactory interface {
	AccountAccessLabelsWriter(context.Context, domain.Account, []string, domain.Subject) (SemanticAuthorityWriter, error)
}

type ProjectAccessLabelsWriterFactory interface {
	ProjectAccessLabelsWriter(context.Context, domain.Project, []string, domain.Subject) (SemanticAuthorityWriter, error)
}

type ServiceAccountAccessLabelsWriterFactory interface {
	ServiceAccountAccessLabelsWriter(context.Context, domain.ServiceAccount, []string, domain.Subject) (SemanticAuthorityWriter, error)
}

// GroupAccessLabelsWriterFactory открывает точную подготовленную правку меток
// группы и завершает её в том же транзакционном исполнителе.
type GroupAccessLabelsWriterFactory interface {
	PreparedWriteExecutor
	GroupAccessLabelsWriter(context.Context, domain.Group, []string, domain.Subject) (SemanticAuthorityWriter, error)
}

// MetadataUpdateEffects сообщает изменённые поля из принятого OLD и маски
// подготовленной транзакции. Список относится только к этой попытке записи.
type MetadataUpdateEffects interface {
	MetadataChangedFields() []string
}
