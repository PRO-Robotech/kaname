// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationscene"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func TestDeclareAccessLabelThroughMigrator(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: PostgreSQL")
	}
	dsn, db := registrationOriginDB(t, "fresh")
	ctx := context.Background()
	owner, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(owner.Close)
	first := registrationscene.Seed(t, ctx, owner)
	other := registrationscene.Seed(t, ctx, owner)

	run := func(dsn, account, resource, key string, args ...string) (string, error) {
		t.Helper()
		flags := []string{"authority-bundle", "add-access-label", "--dsn", dsn,
			"--account", account, "--module", "vpc", "--resource", resource, "--key", key}
		stdout, _, err := runCommandFS(t, migrations.FS, append(flags, args...), nil)
		return stdout, err
	}
	add := func(account string, args ...string) kanamepg.AccessLabelDeclarationResult {
		t.Helper()
		out, err := run(dsn, account, "network", "team", args...)
		require.NoError(t, err)
		var result kanamepg.AccessLabelDeclarationResult
		require.NoError(t, json.Unmarshal([]byte(out), &result))
		require.NotEmpty(t, result.ID)
		return result
	}

	firstKey := add(first.Account, "--project", first.Project, "--value", "blue", "--value", "blue")
	require.EqualValues(t, 2, firstKey.Revision)
	require.Equal(t, firstKey, add(first.Account, "--project", first.Project, "--value", "blue"))
	extended := add(first.Account, "--project", first.Project, "--value", "green")
	require.Equal(t, firstKey.ID, extended.ID)
	require.EqualValues(t, 3, extended.Revision)
	fresh := add(other.Account, "--value", "red")
	require.NotEqual(t, firstKey.ID, fresh.ID)

	_, err = run(dsn, first.Account, "network", "team", "--value", "ambiguous")
	require.ErrorContains(t, err, "пересекающейся области")
	_, err = run(dsn, other.Account, "network", "team", "--project", other.Project, "--value", "ambiguous")
	require.ErrorContains(t, err, "пересекающейся области")
	_, err = run(dsn, other.Account, "network", "cross_scope", "--project", first.Project, "--value", "black")
	require.ErrorContains(t, err, "проект не найден")
	_, err = run(dsn, first.Account, "missing_resource", "unknown", "--value", "black")
	require.ErrorContains(t, err, "в действующем каталоге")
	_, err = run(dsn, first.Account, "network", "no_project", "--project=", "--value", "black")
	require.ErrorContains(t, err, "пустой идентификатор проекта")

	// Истинный LOGIN получает обычные права сервиса через production installer.
	// Колонка session_user у owner-соединения не подменяется через SET ROLE.
	login, pwd := ids.NewID("rol"), ids.NewID("pwd")
	quoted := pgx.Identifier{login}.Sanitize()
	_, err = db.Exec("CREATE ROLE " + quoted + " LOGIN NOINHERIT PASSWORD '" + pwd + "'")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := db.Exec("DROP OWNED BY " + quoted)
		require.NoError(t, err)
		_, err = db.Exec("DROP ROLE " + quoted)
		require.NoError(t, err)
	})
	_, err = db.Exec("SELECT kaname.authority_protocol_grant_runtime($1::regrole)", login)
	require.NoError(t, err)
	address, err := url.Parse(dsn)
	require.NoError(t, err)
	address.User = url.UserPassword(login, pwd)
	_, err = run(address.String(), first.Account, "network", "forbidden", "--value", "black")
	var denied *pgconn.PgError
	require.ErrorAs(t, err, &denied)
	require.Equal(t, "42501", denied.Code)

	var count int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.authority_access_label_definition
 WHERE module='vpc' AND scope_id=ANY($1::text[])`, []string{first.Account, other.Account, first.Project, other.Project}).Scan(&count))
	require.Equal(t, 2, count)
	var allowed string
	require.NoError(t, db.QueryRow(`SELECT string_agg(label_value,',' ORDER BY label_value)
 FROM kaname.authority_access_label_value WHERE definition_id=$1::uuid`, firstKey.ID).Scan(&allowed))
	require.Equal(t, "blue,green", allowed)
}
