// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Закрытые фабрики получают одно опубликованное поколение и его закреплённый
// контекст. Общий ExecutePreparedWrite сохраняет этот контекст до конца UC.
func (r *publishedWriterGenerations) AccountMetadataWriter(ctx context.Context, account domain.Account, mask []string, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return generation.metadata.AccountMetadataWriter(pinned, account, mask, actor)
}

func (r *publishedWriterGenerations) ProjectMetadataWriter(ctx context.Context, project domain.Project, mask []string, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return generation.metadata.ProjectMetadataWriter(pinned, project, mask, actor)
}

func (r *publishedWriterGenerations) ServiceAccountMetadataWriter(ctx context.Context, account domain.ServiceAccount, mask []string, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return generation.metadata.ServiceAccountMetadataWriter(pinned, account, mask, actor)
}

func (r *publishedWriterGenerations) ServiceAccountStateWriter(ctx context.Context, id domain.ServiceAccountID, enabled bool, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return generation.state.ServiceAccountStateWriter(pinned, id, enabled, actor)
}

func (r *publishedWriterGenerations) AccountCreateWriter(ctx context.Context, request kaname.AccountCreateAuthority, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return generation.crud.AccountCreateWriter(pinned, request, actor)
}

func (r *publishedWriterGenerations) AccountDeleteWriter(ctx context.Context, id domain.AccountID, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return generation.crud.AccountDeleteWriter(pinned, id, actor)
}

func (r *publishedWriterGenerations) ProjectCreateWriter(ctx context.Context, project domain.Project, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return generation.crud.ProjectCreateWriter(pinned, project, actor)
}

func (r *publishedWriterGenerations) ProjectDeleteWriter(ctx context.Context, id domain.ProjectID, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return generation.crud.ProjectDeleteWriter(pinned, id, actor)
}

func (r *publishedWriterGenerations) ServiceAccountCreateWriter(ctx context.Context, account domain.ServiceAccount, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return generation.crud.ServiceAccountCreateWriter(pinned, account, actor)
}

func (r *publishedWriterGenerations) ServiceAccountDeleteWriter(ctx context.Context, id domain.ServiceAccountID, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return generation.crud.ServiceAccountDeleteWriter(pinned, id, actor)
}

func (r *publishedWriterGenerations) RoleDeleteWriter(ctx context.Context, id domain.RoleID, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return generation.crud.RoleDeleteWriter(pinned, id, actor)
}

var (
	_ kaname.AccountMetadataWriterFactory        = (*publishedWriterGenerations)(nil)
	_ kaname.ProjectMetadataWriterFactory        = (*publishedWriterGenerations)(nil)
	_ kaname.ServiceAccountMetadataWriterFactory = (*publishedWriterGenerations)(nil)
	_ kaname.ServiceAccountStateWriterFactory    = (*publishedWriterGenerations)(nil)
	_ kaname.AccountCreateWriterFactory          = (*publishedWriterGenerations)(nil)
	_ kaname.AccountDeleteWriterFactory          = (*publishedWriterGenerations)(nil)
	_ kaname.ProjectCreateWriterFactory          = (*publishedWriterGenerations)(nil)
	_ kaname.ProjectDeleteWriterFactory          = (*publishedWriterGenerations)(nil)
	_ kaname.ServiceAccountCreateWriterFactory   = (*publishedWriterGenerations)(nil)
	_ kaname.ServiceAccountDeleteWriterFactory   = (*publishedWriterGenerations)(nil)
	_ kaname.RoleDeleteWriterFactory             = (*publishedWriterGenerations)(nil)
)
