// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

func TestResourceMetadataUsesObjectGetAndOneSnapshot(t *testing.T) {
	if testing.Short() {
		t.Skip("требуется PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	dsn := setupTestDB(t)
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	plans, err := authzmodel.Shared()
	require.NoError(t, err)
	tenant := seedVerdictTenant(t, ctx, pool)
	const resourceType = "compute.instance"
	const objectID = "metadata-probe/old:v1"
	const emptyID = "metadata-probe/empty"
	const missingID = "metadata-probe/not-registered"
	granted := "service_account:" + tenant.granted
	bare := "service_account:" + tenant.bare

	// Регистрация создаёт пустую карту защищённых меток. Штатный триггер
	// запрещает заполнить её обычной записью, в том числе в этой фикстуре.
	_, err = pool.Exec(ctx, `INSERT INTO kaname.resource_mirror
		(object_type, object_id, parent_project_id, parent_account_id, labels)
		VALUES ($1, $2, $3, $4, '{"team":"display"}'),
		       ($1, $5, $3, $4, '{}')`, resourceType, objectID, tenant.projectID, tenant.accountID, emptyID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO kaname.relation_fact (object_type, object_id, relation, subject)
		VALUES ('compute_instance', $1, 'v_get', $4), ('compute_instance', $2, 'v_get', $4),
		       ('compute_instance', $3, 'v_get', $4), ('compute_instance', $1, 'v_list', $5)`,
		objectID, emptyID, missingID, granted, bare)
	require.NoError(t, err)

	config, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	var writerCommitted bool
	var writeErr error
	config.ConnConfig.Tracer = resourceMetadataQueryTracer(func(c context.Context, sql string) {
		// Коммит владельца происходит между решением об объекте и чтением меток.
		if writerCommitted || !strings.HasPrefix(sql, "SELECT m.object_type, m.object_id, m.parent_project_id,") {
			return
		}
		_, writeErr = pool.Exec(c, `UPDATE kaname.resource_mirror SET labels = '{"team":"new"}'
			WHERE object_type = $1 AND object_id = $2`, resourceType, objectID)
		writerCommitted = true
	})
	reader, err := pgxpool.NewWithConfig(ctx, config)
	require.NoError(t, err)
	defer reader.Close()
	repo := kanamepg.NewResourceMetadataRepo(reader, plans)

	for _, c := range []struct{ subject, typ, id string }{
		{bare, resourceType, objectID},
		{granted, "iam.project", tenant.projectID},
		{granted, "unknown.resource", objectID},
	} {
		metadata, err := repo.ReadAuthorizedMirrorMetadata(ctx, c.subject, c.typ, c.id)
		require.ErrorIs(t, err, iamerr.ErrPermissionDenied)
		require.Equal(t, domain.ResourceMetadata{}, metadata)
	}
	require.False(t, writerCommitted, "отказ не читает содержимое зеркала")

	metadata, err := repo.ReadAuthorizedMirrorMetadata(ctx, granted, resourceType, objectID)
	require.NoError(t, err)
	require.True(t, writerCommitted)
	require.NoError(t, writeErr)
	require.Equal(t, domain.ResourceMetadata{
		ResourceType: resourceType, ResourceID: objectID,
		Labels: map[string]string{"team": "display"},
	}, metadata)
	metadata, err = repo.ReadAuthorizedMirrorMetadata(ctx, granted, resourceType, objectID)
	require.NoError(t, err)
	require.Equal(t, "new", metadata.Labels["team"])
	require.Empty(t, metadata.AccessLabels)
	metadata, err = repo.ReadAuthorizedMirrorMetadata(ctx, granted, resourceType, emptyID)
	require.NoError(t, err)
	require.Empty(t, metadata.Labels)
	require.Empty(t, metadata.AccessLabels)
	metadata, err = repo.ReadAuthorizedMirrorMetadata(ctx, granted, resourceType, missingID)
	require.ErrorIs(t, err, iamerr.ErrNotFound)
	require.Equal(t, domain.ResourceMetadata{}, metadata)
}

type resourceMetadataQueryTracer func(context.Context, string)

func (trace resourceMetadataQueryTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	trace(ctx, data.SQL)
	return ctx
}

func (resourceMetadataQueryTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}
