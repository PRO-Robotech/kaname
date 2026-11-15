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
