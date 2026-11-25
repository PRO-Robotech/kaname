// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const mirrorMetadataUpdateABI = "resource-metadata-update/v1"

type installedMirrorMetadataWriter struct{ factory *MetadataMutationWriters }

var _ kaname.ResourceMetadataUpdateWriter = (*installedMirrorMetadataWriter)(nil)

func (p *MetadataMutationWriters) InstalledResourceMetadataUpdate(ctx context.Context) (kaname.ResourceMetadataUpdateWriter, error) {
	if p == nil || p.policy == nil || p.policy.repo == nil || p.policy.repo.master == nil {
		return nil, kaname.ErrSemanticIdentityUnavailable
	}
	var ready bool
	err := p.policy.repo.master.QueryRow(ctx, `SELECT kaname.authority_metadata_mirror_update_ready_v1($1)`, mirrorMetadataUpdateABI).Scan(&ready)
	if err != nil || !ready {
		return nil, errors.Join(kaname.ErrSemanticIdentityUnavailable, err)
	}
	return &installedMirrorMetadataWriter{p}, nil
}

type mirrorMetadataOperation struct {
	pending  operations.Operation
	finished operations.Operation
}

func (w *installedMirrorMetadataWriter) UpdateResourceMetadata(ctx context.Context, root domain.ResourceRef, labels, access domain.Labels, mask []string, pending operations.Operation) (*operations.Operation, error) {
	principal, verified := authzguard.VerifiedPublicPrincipal(ctx)
	if !verified || principal.Type != pending.Principal.Type || principal.ID != pending.Principal.ID {
		return nil, iamerr.ErrPermissionDenied
	}
	actor := domain.Subject{Type: domain.SubjectType(principal.Type), ID: domain.SubjectID(principal.ID)}
	key, ok := kaname.MirrorMetadataOperationKey(root)
	expected, err := anypb.New(&iamv1.UpdateResourceMetadataMetadata{ResourceType: root.Type, ResourceId: root.ID})
	if err != nil {
		return nil, err
	}
	if !ok || pending.ID == "" || pending.Done || pending.Response != nil || pending.Error != nil || key != pending.ResourceID || !proto.Equal(expected, pending.Metadata) {
		return nil, iamerr.ErrFailedPrecondition
	}
	op := &mirrorMetadataOperation{pending: pending}
	request := mirrorMetadataRequest(root, labels, access, mask)
	request.operation = op
	if _, err := w.factory.writeMirrorMetadata(ctx, request, actor); err != nil {
		return nil, err
	}
	return &op.finished, nil
}

func (o *mirrorMetadataOperation) lock(ctx context.Context, tx pgx.Tx, root domain.ResourceRef, actor domain.Subject) error {
	key, ok := kaname.MirrorMetadataOperationKey(root)
	if !ok || o.pending.Principal.Type != string(actor.Type) || o.pending.Principal.ID != string(actor.ID) {
		return iamerr.ErrFailedPrecondition
	}
	// Вход в authority уже подтвердил чистую транзакцию. Удерживаем запись
	// операции до вычисления финальных часов и записи метаданных.
	_, err := tx.Exec(ctx, `LOCK TABLE ONLY kaname.operations IN ROW EXCLUSIVE MODE NOWAIT`)
	if err == nil {
		var id string
		err = tx.QueryRow(ctx, `SELECT id FROM ONLY kaname.operations
 WHERE id=$1 AND NOT done AND account_id IS NULL AND resource_id=$2
 AND principal_type=$3 AND principal_id=$4 AND metadata_type=$5 AND metadata_data=$6
 AND response_type IS NULL AND error_code IS NULL FOR UPDATE NOWAIT`,
			o.pending.ID, key, string(actor.Type), string(actor.ID), o.pending.Metadata.TypeUrl, o.pending.Metadata.Value).Scan(&id)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return iamerr.ErrFailedPrecondition
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "55P03" {
		return errors.Join(kaname.ErrAuthorityClassificationChanged, err)
	}
	return err
}

func (o *mirrorMetadataOperation) finish(ctx context.Context, tx pgx.Tx, account string, actual domain.ResourceMetadata) error {
	if !nativeQuestionToken(account) {
		return kaname.ErrSourceUnconfirmed
	}
	response, err := anypb.New(&iamv1.ResourceMetadata{ResourceType: actual.ResourceType, ResourceId: actual.ResourceID, Labels: actual.Labels, AccessLabels: actual.AccessLabels})
	if err != nil {
		return err
	}
	op := o.pending
	err = tx.QueryRow(ctx, `WITH saved AS (
 UPDATE ONLY kaname.operations SET done=true, modified_at=clock_timestamp(),
 account_id=$2,response_type=$3,response_data=$4 WHERE id=$1 AND NOT done RETURNING *
 )
 SELECT created_at,modified_at FROM saved WHERE id=$1 AND done AND account_id=$2 AND response_type=$3 AND response_data=$4
 AND error_code IS NULL AND principal_type=$5 AND principal_id=$6 AND resource_id=$7
 AND metadata_type=$8 AND metadata_data=$9`, op.ID, account, response.TypeUrl, response.Value,
		op.Principal.Type, op.Principal.ID, op.ResourceID, op.Metadata.TypeUrl, op.Metadata.Value).Scan(&op.CreatedAt, &op.ModifiedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return kaname.ErrSourceUnconfirmed
	}
	if err != nil {
		return err
	}
	op.Done, op.Response = true, response
	o.finished = op
	return nil
}
