// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
)

// Наблюдаем хранилище независимо от DTO: Get не заполняет
// денормализованный индекс ресурса. Сохраняем настоящие необработанные столбцы Any в проверке.
func requireNativeInstallationOperation(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id, account, creator, winning string) nativeInstallationOperationObservation {
	t.Helper()
	op, err := operations.NewRepo(pool, "kaname").Get(ctx, id)
	require.NoError(t, err)
	require.True(t, op.Done)
	require.Nil(t, op.Error)
	require.Equal(t, operations.Principal{Type: "service_account", ID: creator, DisplayName: creator}, op.Principal)
	require.NotNil(t, op.Metadata)
	require.NotNil(t, op.Response)
	var metadata iamv1.CreateGrantDelegationMetadata
	require.NoError(t, op.Metadata.UnmarshalTo(&metadata))
	require.Equal(t, account, metadata.AccountId)
	require.Equal(t, winning, metadata.GrantDelegationId)
	var response iamv1.GrantDelegation
	require.NoError(t, op.Response.UnmarshalTo(&response))
	require.Equal(t, winning, response.Id)
	require.Equal(t, account, response.AccountId)
	var metadataType, responseType, indexAccount, indexResource string
	var metadataBytes, responseBytes []byte
	require.NoError(t, pool.QueryRow(ctx, `SELECT metadata_type,metadata_data,response_type,response_data,account_id,resource_id
 FROM kaname.operations WHERE id=$1`, id).Scan(&metadataType, &metadataBytes, &responseType, &responseBytes, &indexAccount, &indexResource))
	require.Equal(t, account, indexAccount)
	require.Equal(t, winning, indexResource)
	require.Equal(t, op.Metadata.TypeUrl, metadataType)
	require.Equal(t, op.Metadata.Value, metadataBytes)
	require.Equal(t, op.Response.TypeUrl, responseType)
	require.Equal(t, op.Response.Value, responseBytes)
	require.NoError(t, (&anypb.Any{TypeUrl: metadataType, Value: metadataBytes}).UnmarshalTo(&metadata))
	require.Equal(t, winning, metadata.GrantDelegationId)
	var created time.Time
	require.NoError(t, pool.QueryRow(ctx, `SELECT created_at FROM kaname.grant_delegations WHERE id=$1`, winning).Scan(&created))
	require.NotNil(t, response.CreatedAt)
	requireNativePublicCreatedAt(t, created, response.CreatedAt)
	return nativeInstallationOperationObservation{ID: id, Account: account, Creator: creator, Winner: winning, CreatedAt: created, MetadataType: metadataType, Metadata: metadataBytes, ResponseType: responseType, Response: responseBytes, IndexAccount: indexAccount, IndexResource: indexResource}

}

// Неизменяемые настоящие наблюдения хранилища переживают очистку PG дочернего
// подтеста. Отдельный именованный предикат метаданных проверяет эти необработанные квитанции;
// при отдельном выборе его владелец сначала выполняет настоящие конкурентные сценарии.
type nativeInstallationOperationObservation struct {
	ID, Account, Creator, Winner                            string
	CreatedAt                                               time.Time
	MetadataType, ResponseType, IndexAccount, IndexResource string
	Metadata, Response                                      []byte
}

func requireRID02RawOperationEvidence(t *testing.T, records []nativeInstallationOperationObservation) {
	t.Helper()
	require.Len(t, records, 16, "S1 2 pairs x2 Operations plus S2 6 pairs x2 Operations")
	seen := map[string]bool{}
	winners := map[string][]nativeInstallationOperationObservation{}
	for _, record := range records {
		require.NotEmpty(t, record.ID)
		require.False(t, seen[record.ID])
		seen[record.ID] = true
		var metadata iamv1.CreateGrantDelegationMetadata
		require.NoError(t, (&anypb.Any{TypeUrl: record.MetadataType, Value: record.Metadata}).UnmarshalTo(&metadata))
		var response iamv1.GrantDelegation
		require.NoError(t, (&anypb.Any{TypeUrl: record.ResponseType, Value: record.Response}).UnmarshalTo(&response))
		require.Equal(t, record.Account, metadata.AccountId)
		require.Equal(t, record.Winner, metadata.GrantDelegationId)
		require.Equal(t, record.Account, record.IndexAccount)
		require.Equal(t, record.Winner, record.IndexResource)
		require.Equal(t, record.Winner, response.Id)
		require.Equal(t, record.Account, response.AccountId)
		require.NotNil(t, response.DelegatedBy)
		require.Equal(t, "service_account", response.DelegatedBy.Type)
		require.Equal(t, record.Creator, response.DelegatedBy.Id)
		require.NotNil(t, response.CreatedAt)
		requireNativePublicCreatedAt(t, record.CreatedAt, response.CreatedAt)
		winners[record.Winner] = append(winners[record.Winner], record)
	}
	require.Len(t, winners, 8)
	for _, pair := range winners {
		require.Len(t, pair, 2)
		require.Equal(t, pair[0].CreatedAt, pair[1].CreatedAt)
		require.Equal(t, pair[0].Metadata, pair[1].Metadata)
		require.Equal(t, pair[0].Response, pair[1].Response)
	}
}
