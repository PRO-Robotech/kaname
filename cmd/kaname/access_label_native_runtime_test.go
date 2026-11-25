// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/PRO-Robotech/corelib/schemaguard"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// provisionNativeRuntime применяет права штатного развёртывания и проверяет
// минимальный доступ к журналу миграций до старта отдельно запущенной службы.
func provisionNativeRuntime(t *testing.T, f *installationNativeWorld, grantsLog string) *pgx.ConnConfig {
	t.Helper()
	runtimePool := fullStartupRuntimePool(t, f.given.ctx, f.given.pool)
	runtime := runtimePool.Config().ConnConfig
	f.secrets = append(f.secrets, runtime.Password)
	// Воспроизводим права оператора из штатного rollout на том же LOGIN.
	owner := f.given.pool.Config().ConnConfig
	// #nosec G204 -- используется локальный psql и штатный SQL из точного чекаута.
	grant := exec.CommandContext(f.given.ctx, "psql", "-X", "--no-password",
		"--set=runtime_role="+runtime.User, "--set=migration_role="+owner.User,
		"--file="+filepath.Join(f.stand.Root, "deploy", "sql", "authority-runtime-role.sql"))
	grant.Env = []string{
		"PGHOST=" + owner.Host, "PGPORT=" + strconv.Itoa(int(owner.Port)),
		"PGDATABASE=" + owner.Database, "PGUSER=" + owner.User,
		"PGPASSWORD=" + owner.Password, "PGSSLMODE=require",
	}
	grantOut, err := grant.CombinedOutput()
	require.NoError(t, os.WriteFile(grantsLog, grantOut, 0600))
	require.NoError(t, err, "штатная настройка ограниченного LOGIN, см. закрытый журнал стенда")
	require.NoError(t, schemaguard.CheckFromFS(migrations.FS, schemaguard.PgxVersionReader(runtimePool))(f.given.ctx),
		"runtime LOGIN должен читать применённую версию")
	var journalReadAll, journalWrite bool
	require.NoError(t, runtimePool.QueryRow(f.given.ctx, `SELECT
 has_table_privilege(current_user,'goose_db_version','SELECT'),
 has_table_privilege(current_user,'goose_db_version','INSERT,UPDATE,DELETE,TRUNCATE')`).
		Scan(&journalReadAll, &journalWrite))
	require.False(t, journalReadAll)
	require.False(t, journalWrite)
	return runtime
}
