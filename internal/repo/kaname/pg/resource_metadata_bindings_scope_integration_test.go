// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func TestAccountMetadataCensusIncludesOnlyItsProjectBindings(t *testing.T) {
	ctx := context.Background()
	db, err := pgxpool.New(ctx, pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	t.Cleanup(db.Close)
	// Запросы выполняются на минимальной схеме с намеренно одинаковыми
	// правилами. Единственное различие — принадлежность проекта аккаунту.
	_, err = db.Exec(ctx, `
		CREATE SCHEMA kaname;
		CREATE TABLE kaname.accounts(id text PRIMARY KEY, labels jsonb, access_labels jsonb);
		CREATE TABLE kaname.projects(id text PRIMARY KEY, account_id text NOT NULL);
		CREATE TABLE kaname.roles(id text PRIMARY KEY, rules jsonb, live boolean NOT NULL);
		CREATE TABLE kaname.access_bindings(id text PRIMARY KEY, role_id text, resource_type text, resource_id text, status text, revoked_at timestamptz);
		CREATE TABLE kaname.role_rule_selectors(
			role_id text, object_types text[], arm text, resource_names text[],
			match_labels jsonb, match_access_labels jsonb, container_type text, container_arm text,
			container_resource_names text[], container_match_labels jsonb, container_match_access_labels jsonb
		);
		INSERT INTO kaname.accounts VALUES ('acc-root','{}','{"team":"before"}');
		INSERT INTO kaname.projects VALUES ('prj-inside','acc-root'),('prj-foreign','acc-other');
		INSERT INTO kaname.roles VALUES (
			'rol-nested',
			'[{"module":"iam","resources":["account"],"match_access_labels":{"team":"after"},"children":[{"resources":["project"],"verbs":["get"]}]}]',
			true
		);
		INSERT INTO kaname.role_rule_selectors VALUES (
			'rol-nested',ARRAY['iam.project'],'anchor','{}','{}','{}',
			'iam.account','access_labels','{}','{}','{"team":"after"}'
		);
		INSERT INTO kaname.roles
			SELECT 'rol-historical',rules,false FROM kaname.roles WHERE id='rol-nested';
		INSERT INTO kaname.roles VALUES ('rol-unrelated','[]',false);
		INSERT INTO kaname.access_bindings VALUES
			('acb-inside','rol-nested','project','prj-inside','PENDING',NULL),
			('acb-foreign','rol-nested','project','prj-foreign','ACTIVE',NULL),
			('acb-revoked','rol-historical','project','prj-inside','REVOKED',now()),
			('acb-unrelated','rol-unrelated','project','prj-inside','REVOKED',now()),
			('acb-missing','rol-historical','project','prj-absent','REVOKED',now()),
			('acb-revoked-foreign','rol-historical','project','prj-foreign','REVOKED',now());
	`)
	require.NoError(t, err)
	for kind, name := range map[resourceSourceKind]string{
		resourceSourceMetadataBindings:         "изменения",
		resourceSourceMetadataAuthoredBindings: "авторские_правила",
		resourceSourceMetadataBindingCoverage:  "покрытие",
	} {
		t.Run(name, func(t *testing.T) {
			key := resourceSourceKey{kind: kind, typ: "iam.account", id: "acc-root",
				projection: `{"labels":{},"access_labels":{"team":"after"}}`}
			query, args, err := resourceMetadataBindingsSQL(key, 20)
			require.NoError(t, err)
			rows, err := db.Query(ctx, query, args...)
			require.NoError(t, err)
			defer rows.Close()
			var ids []string
			for rows.Next() {
				var image, evidence []byte
				require.NoError(t, rows.Scan(&image, &evidence))
				var cell struct {
					BindingID string `json:"binding_id"`
					Changes   bool   `json:"changes"`
				}
				require.NoError(t, json.Unmarshal(evidence, &cell))
				require.True(t, cell.Changes)
				ids = append(ids, cell.BindingID)
			}
			require.NoError(t, rows.Err())
			require.Equal(t, []string{"acb-inside"}, ids)
		})
	}

	t.Run("история_отзыва", func(t *testing.T) {
		// Запрос исторических носителей использует настоящие валидаторы.
		// Устанавливаем только тела функций, чтобы сохранить минимальную схему.
		for _, definition := range []struct{ migration, name string }{
			{"20261123230000_access_label_storage_is_closed_by_default.sql", "access_labels_valid_v1"},
			{"20261124190000_access_label_selector_sources.sql", "access_label_rules_valid_v1"},
		} {
			raw, err := migrations.FS.ReadFile(definition.migration)
			require.NoError(t, err)
			prefix := "CREATE FUNCTION kaname." + definition.name + "("
			_, tail, found := strings.Cut(string(raw), prefix)
			require.True(t, found, definition.name)
			body, _, found := strings.Cut(tail, "\n-- +goose StatementEnd")
			require.True(t, found, definition.name)
			_, err = db.Exec(ctx, prefix+body)
			require.NoError(t, err, definition.name)
		}
		key := resourceSourceKey{kind: resourceSourceMetadataHistoricalCarriers, typ: "iam.account", id: "acc-root",
			projection: `{"labels":{},"access_labels":{"team":"after"}}`}
		query, args, err := resourceSourceSQL(key, 20)
		require.NoError(t, err)
		rows, err := db.Query(ctx, query, args...)
		require.NoError(t, err)
		defer rows.Close()
		carriers := make(map[string]string)
		for rows.Next() {
			var image, evidence []byte
			require.NoError(t, rows.Scan(&image, &evidence))
			var cell struct {
				BindingID string `json:"binding_id"`
				RoleID    string `json:"role_id"`
			}
			require.NoError(t, json.Unmarshal(evidence, &cell))
			require.NotContains(t, carriers, cell.BindingID)
			carriers[cell.BindingID] = cell.RoleID
		}
		require.NoError(t, rows.Err())
		require.Equal(t, map[string]string{
			"acb-inside": "rol-nested", "acb-revoked": "rol-historical", "acb-missing": "rol-historical",
		}, carriers)
	})
}
