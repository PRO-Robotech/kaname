// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
)

// Проверяем настоящий Goose Down, а не повторяем его SQL отдельной командой:
// пустой шаг обратим, принятый материал не позволяет восстановить слабый протокол.
func TestAuthorityLifecycleMigrationRollbackRequiresAbsentHandoff(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен PostgreSQL")
	}
	for _, name := range []string{"empty-roundtrip", "active-handoff-refuses"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			dsn := pgtest.NewEmptyDB(t)
			db, err := sql.Open("pgx", dsn)
			require.NoError(t, err)
			t.Cleanup(func() { _ = db.Close() })
			provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS,
				goose.WithTableName("public.goose_db_version"))
			require.NoError(t, err)
			const version int64 = 20261113190000
			_, err = provider.UpTo(ctx, version)
			require.NoError(t, err)
			pool, err := coredb.NewPool(ctx, pgtest.WithSearchPath(dsn, "kaname,public"))
			require.NoError(t, err)
			pgtest.ClosePoolAtEnd(t, pool)
			repo := kanamepg.New(pool, nil)
			if name == "active-handoff-refuses" {
				bundle := semanticBundleDB(t, ctx, pool)
				require.NoError(t, repo.StageAuthorityBundle(ctx, bundle))
				require.NoError(t, repo.ActivateAuthorityBundle(ctx, bundle))
				_, err = provider.Down(ctx)
				var pgerr *pgconn.PgError
				require.ErrorAs(t, err, &pgerr)
				require.Equal(t, "P0001", pgerr.Code)
				require.Contains(t, pgerr.Message, "requires absent handoff")
				current, err := provider.GetDBVersion(ctx)
				require.NoError(t, err)
				require.Equal(t, version, current)
				var phase, mode string
				var material int
				require.NoError(t, pool.QueryRow(ctx, `SELECT a.phase,p.enforcement,
				    (SELECT count(*) FROM kaname.authority_bundle_handoff)
				    FROM kaname.authority_semantic_identity a
				    CROSS JOIN kaname.authority_writer_protocol p`).Scan(&phase, &mode, &material))
				require.Equal(t, "active", phase)
				require.Equal(t, "strict", mode)
				require.Equal(t, 1, material)
				handed, err := repo.LoadAuthorityBundle(ctx, bundle.ModelSource())
				require.NoError(t, err)
				require.Equal(t, bundle.Identity(), handed.Identity())
				return
			}
			down, err := provider.Down(ctx)
			require.NoError(t, err)
			require.Equal(t, version, down.Source.Version)
			var removed bool
			require.NoError(t, pool.QueryRow(ctx, `SELECT
			    to_regclass('kaname.authority_bundle_handoff') IS NULL AND
			    to_regprocedure('kaname.authority_protocol_read_bundle()') IS NULL AND
			    to_regprocedure('kaname.authority_protocol_drain()') IS NULL`).Scan(&removed))
			require.True(t, removed)
			up, err := provider.UpTo(ctx, version)
			require.NoError(t, err)
			require.Len(t, up, 1)
			require.Equal(t, version, up[0].Source.Version)
			var phase, mode string
			var material int
			require.NoError(t, pool.QueryRow(ctx, `SELECT a.phase,p.enforcement,
			    (SELECT count(*) FROM kaname.authority_bundle_handoff)
			    FROM kaname.authority_semantic_identity a
			    CROSS JOIN kaname.authority_writer_protocol p`).Scan(&phase, &mode, &material))
			require.Equal(t, "uninitialized", phase)
			require.Equal(t, "compatibility", mode)
			require.Zero(t, material)
		})
	}
}
