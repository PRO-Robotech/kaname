// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/authzsnapshot"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

type publishedMetadataPorts interface {
	kaname.AccountMetadataWriterFactory
	kaname.ProjectMetadataWriterFactory
	kaname.ServiceAccountMetadataWriterFactory
}

// Обёртки объявляют лишь порты, установленные при старте. При каждой записи
// проверяем тот же порт уже в поколении закреплённой публикации.
type publishedAccessLabels struct{ *publishedWriterGenerations }
type publishedServiceAccountAccessLabels struct{ publishedAccessLabels }

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

func (r publishedAccessLabels) AccountAccessLabelsWriter(ctx context.Context, value domain.Account, mask []string, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return nil, err
	}
	writer, ok := generation.metadataPorts.(kaname.AccountAccessLabelsWriterFactory)
	if !ok {
		return nil, kaname.ErrSemanticIdentityUnavailable
	}
	return writer.AccountAccessLabelsWriter(pinned, value, mask, actor)
}

func (r publishedAccessLabels) ProjectAccessLabelsWriter(ctx context.Context, value domain.Project, mask []string, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return nil, err
	}
	writer, ok := generation.metadataPorts.(kaname.ProjectAccessLabelsWriterFactory)
	if !ok {
		return nil, kaname.ErrSemanticIdentityUnavailable
	}
	return writer.ProjectAccessLabelsWriter(pinned, value, mask, actor)
}

func (r publishedServiceAccountAccessLabels) ServiceAccountAccessLabelsWriter(ctx context.Context, value domain.ServiceAccount, mask []string, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return nil, err
	}
	writer, ok := generation.metadataPorts.(kaname.ServiceAccountAccessLabelsWriterFactory)
	if !ok {
		return nil, kaname.ErrSemanticIdentityUnavailable
	}
	return writer.ServiceAccountAccessLabelsWriter(pinned, value, mask, actor)
}

func (r *publishedWriterGenerations) userLabelsForRequest(ctx context.Context) (context.Context, kaname.UserAccessLabelsWriter, error) {
	if err := ctx.Err(); err != nil {
		return ctx, nil, err
	}
	if _, ok := authzsnapshot.FromContext(ctx); !ok {
		return ctx, nil, errors.Join(iamerr.ErrUnavailable, authzsnapshot.ErrUnconfirmed)
	}
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return pinned, nil, err
	}
	if generation.userLabels == nil {
		return pinned, nil, iamerr.ErrUnavailable
	}
	return pinned, generation.userLabels, nil
}

func (r *publishedWriterGenerations) CreateUserAccessLabelsOperation(ctx context.Context, pending operations.Operation) error {
	pinned, writer, err := r.userLabelsForRequest(ctx)
	if err != nil {
		return err
	}
	return writer.CreateUserAccessLabelsOperation(pinned, pending)
}

func (r *publishedWriterGenerations) UpdateUserAccessLabels(ctx context.Context, id domain.UserID, labels, accessLabels domain.Labels, actor domain.Subject, pending operations.Operation) (operations.Operation, bool, error) {
	pinned, writer, err := r.userLabelsForRequest(ctx)
	if err != nil {
		return operations.Operation{}, false, err
	}
	return writer.UpdateUserAccessLabels(pinned, id, labels, accessLabels, actor, pending)
}

func (r *publishedWriterGenerations) GroupAccessLabelsWriter(ctx context.Context, value domain.Group, mask []string, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return nil, err
	}
	writer := generation.groupLabels
	if writer == nil {
		return nil, kaname.ErrSemanticIdentityUnavailable
	}
	return writer.GroupAccessLabelsWriter(pinned, value, mask, actor)
}

func (r *publishedWriterGenerations) InstalledResourceMetadataUpdate(ctx context.Context) (kaname.ResourceMetadataUpdateWriter, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := generation.metadata.InstalledResourceMetadataUpdate(pinned); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *publishedWriterGenerations) UpdateResourceMetadata(ctx context.Context, root domain.ResourceRef, labels, access domain.Labels, mask []string, pending operations.Operation) (*operations.Operation, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return nil, err
	}
	writer, err := generation.metadata.InstalledResourceMetadataUpdate(pinned)
	if err != nil {
		return nil, err
	}
	return writer.UpdateResourceMetadata(pinned, root, labels, access, mask, pending)
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
