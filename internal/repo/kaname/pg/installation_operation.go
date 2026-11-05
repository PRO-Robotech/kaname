// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/anypb"
)

type pendingInstallationOperation struct {
	id, account, proposed, metadataType, principalType, principalID string
	metadataData                                                    []byte
}

// LockPendingInstallationOperation — ПЕРВАЯ блокировка транзакции записи. Штатная
// Operation создана ранее; отменённые, восстановленные или чужие строки
// не могут получить разрешение менять делегирование поздним прибытием.
func (w *writeTx) LockPendingInstallationOperation(ctx context.Context, id, account, proposed string) error {
	var state pendingInstallationOperation
	var done bool
	err := w.tx.QueryRow(ctx, `SELECT done,metadata_type,metadata_data,COALESCE(resource_id,''),COALESCE(account_id,''),principal_type,principal_id
 FROM kaname.operations WHERE id=$1 FOR UPDATE`, id).Scan(&done, &state.metadataType, &state.metadataData, &state.proposed, &state.account, &state.principalType, &state.principalID)
	if errors.Is(err, pgx.ErrNoRows) {
		return installationOperationConflict()
	}
	if err != nil {
		return err
	}
	expected, _ := anypb.New(&iamv1.CreateGrantDelegationMetadata{})
	var metadata iamv1.CreateGrantDelegationMetadata
	principal, ok := operations.PrincipalFromContextOK(ctx)
	if done || !ok || state.metadataType != expected.TypeUrl ||
		(&anypb.Any{TypeUrl: state.metadataType, Value: state.metadataData}).UnmarshalTo(&metadata) != nil ||
		state.account != account || state.proposed != proposed || metadata.GetAccountId() != account || metadata.GetGrantDelegationId() != proposed ||
		state.principalType != principal.Type || state.principalID != principal.ID {
		return installationOperationConflict()
	}
	state.id = id
	w.installationOperation = &state
	return nil
}

func installationOperationConflict() error {
	return iamerr.Wrapf(iamerr.ErrFailedPrecondition, "installation operation is not pending with its expected identity")
}

// RequireInstallationAuthority использует ТОТ ЖЕ допущенный производственный вердикт и
// метки человека в ЭТОЙ транзакции записи после блокировки пары, без ввода-вывода пула.
func (w *writeTx) RequireInstallationAuthority(ctx context.Context, plans *authzmodel.Plans) error {
	checker := authzcascade.WrapAdmitted(relverdict.NewTransactionAsker(w.tx, plans), personmarks.NewTransaction(w.tx))
	return authzguard.RequireClusterAdmin(ctx, checker)
}

// BindInstallationOperation фиксирует настоящую идентичность ресурса вместе с GD.
// Он не записывает конечное состояние: operations.Run сохраняет штатную конечную запись.
func (w *writeTx) BindInstallationOperation(ctx context.Context, id string, metadata *anypb.Any, winningID string) error {
	state := w.installationOperation
	if state == nil || state.id != id || metadata == nil || metadata.TypeUrl != state.metadataType {
		return installationOperationConflict()
	}
	var value iamv1.CreateGrantDelegationMetadata
	if metadata.UnmarshalTo(&value) != nil || value.GetAccountId() != state.account || value.GetGrantDelegationId() != winningID {
		return installationOperationConflict()
	}
	result, err := w.tx.Exec(ctx, `UPDATE kaname.operations SET metadata_type=$2,metadata_data=$3,resource_id=$4,modified_at=clock_timestamp()
 WHERE id=$1 AND NOT done AND metadata_type=$5 AND metadata_data=$6 AND resource_id=$7 AND account_id=$8
 AND principal_type=$9 AND principal_id=$10`, id, metadata.TypeUrl, metadata.Value, winningID, state.metadataType, state.metadataData, state.proposed, state.account, state.principalType, state.principalID)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return installationOperationConflict()
	}
	return nil
}
