// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/PRO-Robotech/corelib/pgtest"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func TestExternalMetadataCarrierCensusUsesExactCoordinateAndScope(t *testing.T) {
	ctx := context.Background()
	db, err := pgxpool.New(ctx, pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	t.Cleanup(db.Close)
	// Дочерних зеркал здесь нет. Вложенное правило обязано попасть в
	// перепроверку уже по изменяемому контейнеру, без существующего потомка.
	_, err = db.Exec(ctx, `
		CREATE SCHEMA kaname;
		CREATE TABLE kaname.accounts(id text PRIMARY KEY, labels jsonb, access_labels jsonb);
		CREATE TABLE kaname.projects(id text PRIMARY KEY, account_id text NOT NULL);
		CREATE TABLE kaname.resource_mirror(
			object_type text, object_id text, parent_project_id text, parent_account_id text,
			labels jsonb, access_labels jsonb,
			PRIMARY KEY(object_type,object_id)
		);
		CREATE TABLE kaname.roles(id text PRIMARY KEY, rules jsonb, live boolean NOT NULL);
		CREATE TABLE kaname.access_bindings(id text PRIMARY KEY, role_id text, resource_type text, resource_id text, status text, revoked_at timestamptz);
		CREATE TABLE kaname.role_rule_selectors(
			role_id text, object_types text[], arm text, resource_names text[],
			match_labels jsonb, match_access_labels jsonb, container_type text, container_arm text,
			container_resource_names text[], container_match_labels jsonb, container_match_access_labels jsonb
		);
		-- Правила опыта заведомо корректны; эта минимальная схема не проверяет валидатор правил.
		CREATE FUNCTION kaname.access_label_rules_valid_v1(jsonb) RETURNS boolean
			LANGUAGE sql IMMUTABLE AS 'SELECT jsonb_typeof($1) = ''array''';
		INSERT INTO kaname.accounts VALUES ('acc-root','{}','{}'),('acc-neighbor','{}','{}');
		INSERT INTO kaname.projects(id,account_id) VALUES
			('prj-root','acc-root'),('prj-sibling','acc-root'),('prj-neighbor','acc-neighbor');
		-- Принадлежность первого зеркала аккаунту известна только через реальный проект.
		INSERT INTO kaname.resource_mirror(object_type,object_id,parent_project_id,parent_account_id,labels,access_labels) VALUES
			('registry.registries','metadata/shared','prj-root',NULL,'{"team":"before"}','{"team":"before"}'),
			('registry.repositories','metadata/shared','prj-neighbor','acc-neighbor','{"team":"before"}','{"team":"before"}');
		INSERT INTO kaname.roles VALUES
			('rol-direct','[{"module":"registry","resources":["registries"],"match_access_labels":{"team":"after"},"verbs":["get"]}]',true),
			('rol-nested','[{"module":"registry","resources":["registries"],"match_access_labels":{"team":"after"},"children":[{"resources":["images"],"verbs":["get"]}]}]',true),
			('rol-authored','[{"module":"registry","resources":["registries"],"match_access_labels":{"team":"after"},"verbs":["get"]}]',true),
			('rol-peer','[{"module":"registry","resources":["repositories"],"match_access_labels":{"team":"after"},"verbs":["get"]}]',true);
		INSERT INTO kaname.roles SELECT 'rol-retired',rules,false FROM kaname.roles WHERE id='rol-direct';
		INSERT INTO kaname.role_rule_selectors VALUES
			('rol-direct',ARRAY['registry.registries'],'access_labels','{}','{}','{"team":"after"}',NULL,NULL,'{}','{}','{}'),
			('rol-nested',ARRAY['registry.images'],'anchor','{}','{}','{}','registry.registries','access_labels','{}','{}','{"team":"after"}'),
			('rol-peer',ARRAY['registry.repositories'],'access_labels','{}','{}','{"team":"after"}',NULL,NULL,'{}','{}','{}');
		INSERT INTO kaname.access_bindings VALUES
			('acb-direct-account','rol-direct','account','acc-root','ACTIVE',NULL),
			('acb-direct-project','rol-direct','project','prj-root','PENDING',NULL),
			('acb-nested','rol-nested','account','acc-root','ACTIVE',NULL),
			('acb-authored','rol-authored','project','prj-root','ACTIVE',NULL),
			('acb-sibling','rol-direct','project','prj-sibling','ACTIVE',NULL),
			('acb-neighbor-account','rol-direct','account','acc-neighbor','ACTIVE',NULL),
			('acb-neighbor-project','rol-direct','project','prj-neighbor','ACTIVE',NULL),
			('acb-peer','rol-peer','project','prj-neighbor','ACTIVE',NULL),
			('acb-revoked','rol-direct','project','prj-root','REVOKED',now()),
			('acb-retired','rol-retired','account','acc-root','ACTIVE',NULL),
			('acb-missing-scope','rol-direct','project','prj-absent','REVOKED',now());
	`)
	require.NoError(t, err)

	type cell struct {
		state   string
		changes bool
		roleID  string
	}
	read := func(kind resourceSourceKind, typ string) map[string]cell {
		t.Helper()
		query, args, err := resourceSourceSQL(resourceSourceKey{
			kind: kind, typ: typ, id: "metadata/shared",
			projection: `{"labels":{"team":"after"},"access_labels":{"team":"after"}}`,
		}, 100)
		require.NoError(t, err)
		rows, err := db.Query(ctx, query, args...)
		require.NoError(t, err)
		defer rows.Close()
		out := map[string]cell{}
		for rows.Next() {
			var state, evidence []byte
			require.NoError(t, rows.Scan(&state, &evidence))
			var value struct {
				BindingID string `json:"binding_id"`
				RoleID    string `json:"role_id"`
				Changes   bool   `json:"changes"`
			}
			require.NoError(t, json.Unmarshal(evidence, &value))
			require.NotEmpty(t, value.BindingID)
			require.NotContains(t, out, value.BindingID)
			out[value.BindingID] = cell{state: string(state), changes: value.Changes, roleID: value.RoleID}
		}
		require.NoError(t, rows.Err())
		return out
	}
	ids := func(rows map[string]cell) []string {
		out := make([]string, 0, len(rows))
		for id := range rows {
			out = append(out, id)
		}
		return out
	}
	projected := []string{"acb-direct-account", "acb-direct-project", "acb-nested"}
	for _, kind := range []resourceSourceKind{resourceSourceMetadataBindings, resourceSourceMetadataBindingCoverage} {
		rows := read(kind, "registry.registries")
		require.ElementsMatch(t, projected, ids(rows))
		for id, row := range rows {
			require.True(t, row.changes, id)
		}
		// Совпадение ID не переносит метки, область или кандидатов другого типа.
		peer := read(kind, "registry.repositories")
		require.ElementsMatch(t, []string{"acb-peer"}, ids(peer))
		require.True(t, peer["acb-peer"].changes)
	}

	authored := read(resourceSourceMetadataAuthoredBindings, "registry.registries")
	require.ElementsMatch(t, append(append([]string{}, projected...), "acb-authored"), ids(authored))
	for id, row := range authored {
		require.True(t, row.changes, id)
	}
	historical := read(resourceSourceMetadataHistoricalCarriers, "registry.registries")
	require.ElementsMatch(t, []string{
		"acb-direct-account", "acb-direct-project", "acb-nested", "acb-authored",
		"acb-revoked", "acb-retired", "acb-missing-scope",
	}, ids(historical))
	require.Equal(t, "rol-retired", historical["acb-retired"].roleID)
	require.Equal(t, "rol-direct", historical["acb-revoked"].roleID)
	require.Equal(t, "rol-direct", historical["acb-missing-scope"].roleID)

	// Состав кандидатов и JSON строк прежние. Изменение только MVCC-версии владельца
	// проекта обязано изменить физическое свидетельство каждой формы чтения.
	kinds := []resourceSourceKind{resourceSourceMetadataBindings, resourceSourceMetadataBindingCoverage,
		resourceSourceMetadataAuthoredBindings, resourceSourceMetadataHistoricalCarriers}
	previous := map[resourceSourceKind]map[string]cell{}
	for _, kind := range kinds {
		previous[kind] = read(kind, "registry.registries")
	}
	_, err = db.Exec(ctx, `UPDATE kaname.projects SET account_id=account_id WHERE id='prj-root'`)
	require.NoError(t, err)
	for _, kind := range kinds {
		current := read(kind, "registry.registries")
		require.ElementsMatch(t, ids(previous[kind]), ids(current))
		for id, row := range current {
			require.NotEqual(t, previous[kind][id].state, row.state, id)
			require.Equal(t, previous[kind][id].changes, row.changes, id)
		}
		previous[kind] = current
	}
	// Версия самого зеркала также входит в состояние. Метки не меняются.
	_, err = db.Exec(ctx, `UPDATE kaname.resource_mirror SET labels=labels
		WHERE object_type='registry.registries' AND object_id='metadata/shared'`)
	require.NoError(t, err)
	for _, kind := range kinds {
		current := read(kind, "registry.registries")
		require.ElementsMatch(t, ids(previous[kind]), ids(current))
		for id, row := range current {
			require.NotEqual(t, previous[kind][id].state, row.state, id)
			require.Equal(t, previous[kind][id].changes, row.changes, id)
		}
	}

	t.Run("empty_result_requires_a_confirmed_scope", func(t *testing.T) {
		_, err := db.Exec(ctx, `
			CREATE TABLE kaname.catalog_resource (
				dotted text PRIMARY KEY, module text, object_type text, live boolean,
				parent_names text[] DEFAULT '{}', parent_types text[] DEFAULT '{}',
				writes text[] DEFAULT '{}', permanent_project boolean DEFAULT false
			);
			-- Каталог действий входит в общий census исходных таблиц даже
			-- при пустой выборке привязок этого внешнего ресурса.
			CREATE TABLE kaname.catalog_verb (
				module text, resource text, verb text, live boolean, per_object boolean,
				container_parent text, container_relation text
			);
			CREATE TABLE kaname.resource_parent_edge (object_type text,object_id text,parent_type text,parent_id text,depth int);
			CREATE TABLE kaname.resource_registration_scope (object_type text,object_id text,project_id text,account_id text);
			CREATE TABLE kaname.object_project_binding (object_type text,object_id text,project_id text);
			CREATE TABLE kaname.relation_fact (object_type text,object_id text);
			CREATE TABLE kaname.resource_registration_pointer (object_type text,object_id text);
			CREATE TABLE kaname.producer_source_receipt (object_type text,object_id text,source_version int,catalog_type text,active boolean);
			CREATE TABLE kaname.resource_registration_retirement (object_type text,object_id text,source_version int);
			INSERT INTO kaname.catalog_resource(dotted,module,object_type,live) VALUES
				('registry.registries','registry','registry_registry',true),
				('registry.repositories','registry','registry_repository',true),
				('registry.unlisted','registry','registry_unlisted',false);
			INSERT INTO kaname.resource_mirror VALUES
			('registry.registries','metadata/no-project','prj-absent','acc-root','{}','{}'),
			('registry.registries','metadata/conflicting','prj-root','acc-neighbor','{}','{}'),
			('registry.registries','metadata/no-account',NULL,'acc-absent','{}','{}'),
			('registry.registries','metadata/no-scope',NULL,NULL,'{}','{}'),
			('registry.registries','metadata/moved-parent','prj-root','acc-root','{}','{}'),
			('registry.registries','metadata/moved-scope','prj-root','acc-root','{}','{}'),
			('registry.registries','metadata/moved-edge','prj-root','acc-root','{}','{}'),
			('registry.unlisted','metadata/unlisted','prj-root','acc-root','{}','{}');
			INSERT INTO kaname.object_project_binding VALUES ('registry_registry','metadata/moved-parent','prj-sibling');
			INSERT INTO kaname.resource_registration_scope VALUES ('registry_registry','metadata/moved-scope','prj-root','acc-neighbor');
			INSERT INTO kaname.resource_parent_edge VALUES ('registry_registry','metadata/moved-edge','project','prj-sibling',1);
			INSERT INTO kaname.producer_source_receipt VALUES
				('registry_registry','metadata/shared',2,'registry.registries',false),
				('old_repository_model','metadata/alias',1,'registry.repositories',false);
			INSERT INTO kaname.resource_registration_retirement VALUES ('registry_registry','metadata/shared',1);
		`)
		require.NoError(t, err)
		tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(ctx) }()
		budget := &relverdict.AdministrativeReadBudget{}
		capture, err := newResourceSourceCapture(tx, budget, &resourceAttemptLifetime{conn: tx.Conn()})
		require.NoError(t, err)
		for _, input := range []struct{ typ, id string }{
			{"registry.registries", "metadata/absent"}, {"registry.registries", "metadata/no-project"},
			{"registry.registries", "metadata/conflicting"}, {"registry.registries", "metadata/no-account"},
			{"registry.registries", "metadata/no-scope"}, {"registry.registries", "metadata/moved-parent"},
			{"registry.registries", "metadata/moved-scope"}, {"registry.registries", "metadata/moved-edge"},
			{"registry.unlisted", "metadata/unlisted"},
		} {
			key := resourceSourceKey{kind: resourceSourceMetadataBindings, typ: input.typ, id: input.id,
				projection: `{"labels":{},"access_labels":{}}`}
			_, err := capture.read(ctx, tx, key)
			require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed, input.id)
			require.NotContains(t, capture.entries, key)
		}
		for _, tc := range []struct {
			dotted, id string
			count      int
		}{
			{"registry.registries", "metadata/shared", 1},
			{"registry.repositories", "metadata/shared", 0},
			{"registry.repositories", "metadata/alias", 1},
			{"registry.registries", "metadata/alias", 0},
		} {
			key := resourceSourceKey{kind: resourceSourceMetadataPolicyReceipt, typ: tc.dotted, id: tc.id}
			rows, err := capture.read(ctx, tx, key)
			require.NoError(t, err)
			require.Len(t, rows, tc.count)
			require.Contains(t, capture.entries, key)
		}
		confirmed := resourceSourceKey{kind: resourceSourceMetadataBindings, typ: "registry.registries", id: "metadata/shared",
			projection: `{"labels":{"team":"before"},"access_labels":{"team":"before"}}`}
		rows, err := capture.read(ctx, tx, confirmed)
		require.NoError(t, err)
		require.Empty(t, rows)
		// Эти предикаты участвуют в повторной сверке, даже если привязок нет.
		for _, key := range []resourceSourceKey{
			{kind: resourceSourceMirror, typ: confirmed.typ, id: confirmed.id},
			{kind: resourceSourceProject, typ: "project", id: "prj-root"},
			{kind: resourceSourceAccount, typ: "account", id: "acc-root"},
			{kind: resourceSourceObjectReceipts, typ: "registry_registry", id: confirmed.id},
			{kind: resourceSourceObjectRetirement, typ: "registry_registry", id: confirmed.id},
		} {
			require.Len(t, capture.entries[key], 1, key)
		}
		for _, kind := range []resourceSourceKind{resourceSourceParentEdges, resourceSourceProjectBinding,
			resourceSourceRegistrationScopes, resourceSourcePointerFacts, resourceSourceRegistrationPointers} {
			key := resourceSourceKey{kind: kind, typ: "registry_registry", id: confirmed.id}
			require.Contains(t, capture.entries, key)
			require.Empty(t, capture.entries[key])
		}
		require.Contains(t, capture.metadataParents.catalogs, confirmed.typ)
		require.Contains(t, capture.entries, confirmed)
	})
}
