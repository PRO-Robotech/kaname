// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict

import (
	"context"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/resource_mirror"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// Исполняется production-предикат, без копии его логики. Это SQL-проба
// разделения осей, а не приёмка writer или двух реплик API.
func TestAccessLabelsPredicateKeepsOrdinaryLabelsSeparate(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	defer pool.Close()
	predicate := grantArmPredicate("'probe'::text", "'probe'::text", "'object'::text", "m.labels", "m.access_labels", false, true)
	query := `WITH rs AS (SELECT $1::text AS arm, ARRAY[]::text[] AS resource_names,
 $2::jsonb AS match_labels, $3::jsonb AS match_access_labels,
 '{"probe":["get"]}'::jsonb AS verbs_by_type),
 rv AS (SELECT 'get'::text AS verb),
 m AS (SELECT $4::jsonb AS labels, $5::jsonb AS access_labels)
 SELECT COALESCE((` + predicate + `), false) FROM rs,rv,m`
	const yes = `{"trust":"yes"}`
	const no = `{"trust":"no"}`
	cases := []struct {
		name, arm                           string
		ordinary, protected, labels, access any
		want                                bool
	}{
		{"exact protected", "access_labels", `{}`, yes, no, yes, true},
		{"ordinary collision", "access_labels", `{}`, yes, yes, no, false},
		{"missing protected value", "access_labels", `{}`, yes, yes, `{}`, false},
		{"SQL NULL object", "access_labels", `{}`, yes, yes, nil, false},
		{"JSON null object", "access_labels", `{}`, yes, yes, `null`, false},
		{"NULL selector", "access_labels", `{}`, nil, yes, yes, false},
		{"JSON null selector", "access_labels", `{}`, `null`, yes, yes, false},
		{"empty selector", "access_labels", `{}`, `{}`, yes, yes, false},
		{"array selector", "access_labels", `{}`, `[]`, yes, yes, false},
		{"ordinary preserved", "labels", yes, `{}`, yes, no, true},
		{"protected cannot satisfy ordinary", "labels", yes, `{}`, no, yes, false},
		{"anchor without either object", "anchor", `{}`, `{}`, nil, nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got bool
			require.NoError(t, pool.QueryRow(ctx, query, c.arm, c.ordinary, c.protected, c.labels, c.access).Scan(&got))
			require.Equal(t, c.want, got)
		})
	}
}

func TestProtectedContainerReadsOwnAxisWithoutMirrorFallback(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	defer pool.Close()
	_, err = pool.Exec(ctx, `CREATE SCHEMA kaname`)
	require.NoError(t, err)
	for _, axis := range IAMDirectLabelAxes() {
		_, err = pool.Exec(ctx, `CREATE TABLE `+axis.Table+`(id text PRIMARY KEY,access_labels jsonb)`)
		require.NoError(t, err)
	}
	_, err = pool.Exec(ctx, `CREATE TABLE kaname.resource_mirror(object_type text,object_id text,access_labels jsonb,PRIMARY KEY(object_type,object_id));
 INSERT INTO kaname.projects VALUES('present','{"trust":"no"}');
 INSERT INTO kaname.resource_mirror VALUES
 ('iam.project','present','{"trust":"yes"}'),('iam.project','missing','{"trust":"yes"}'),
 ('probe.container','foreign','{"trust":"yes"}')`)
	require.NoError(t, err)
	query := `SELECT COALESCE((` + containerAccessLabels("$1::text", "$2::text", "$3::text") + ` @> '{"trust":"yes"}'::jsonb),false)`
	for _, c := range []struct {
		name, model, catalog, id string
		want                     bool
	}{
		{"IAM owns value", "project", "iam.project", "present", false},
		{"missing IAM cannot use mirror", "project", "iam.project", "missing", false},
		{"foreign mirror", "probe_container", "probe.container", "foreign", true},
		{"missing foreign", "probe_container", "probe.container", "absent", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			var got bool
			require.NoError(t, pool.QueryRow(ctx, query, c.model, c.catalog, c.id).Scan(&got))
			require.Equal(t, c.want, got)
		})
	}
}

func TestAccessLabelsArriveInEveryNativeReadShape(t *testing.T) {
	for name, build := range map[string]func(string, bool) (string, error){
		"check": verdictQuerySQL, "batch": verdictManyQuerySQL, "list": listQuerySQL,
		"subjects": subjectsQuerySQL, "expand": expandQuerySQL,
	} {
		for _, nested := range []bool{false, true} {
			t.Run(name+nestingName(nested), func(t *testing.T) {
				for _, table := range []string{"", "kaname.accounts", "kaname.projects"} {
					query, err := build(table, nested)
					require.NoError(t, err)
					require.Contains(t, query, "rs.match_access_labels")
					require.Contains(t, query, ".access_labels")
					require.NotContains(t, query, "{{")
					require.Equal(t, nested, strings.Contains(query, "rs.container_match_access_labels"))
					const physicalEdge = "ce.tableoid = 'kaname.resource_parent_edge'::regclass"
					wantGuards := 0
					if nested {
						wantGuards = 1
					}
					require.Equal(t, wantGuards, strings.Count(query, physicalEdge))
				}
			})
		}
	}
	for _, table := range []string{"", "kaname.accounts", "kaname.projects"} {
		source := candidateFrom(table, "$9", "$3", "$4")
		require.Contains(t, source, ".access_labels")
		require.Empty(t, boundedCandidateSource(source, "$4"))
	}
}

func TestNestedProtectedProjectRequiresSameAccount(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	defer pool.Close()
	_, err = pool.Exec(ctx, `CREATE SCHEMA kaname;
 CREATE TABLE kaname.accounts(id text PRIMARY KEY, access_labels jsonb);
 CREATE TABLE kaname.projects(id text PRIMARY KEY, account_id text NOT NULL, access_labels jsonb);
 CREATE TABLE kaname.resource_mirror(object_type text, object_id text, parent_account_id text, parent_project_id text, labels jsonb, access_labels jsonb DEFAULT '{}');
 CREATE TABLE kaname.catalog_resource(dotted text, object_type text, live boolean);
 INSERT INTO kaname.catalog_resource VALUES ('iam.project','project',true),('iam.account','account',true);
 CREATE TABLE kaname.resource_parent_edge(object_id text, parent_id text, depth integer, object_type text DEFAULT 'project', parent_type text DEFAULT 'account');
 CREATE TABLE kaname.edge_copy() INHERITS (kaname.resource_parent_edge);
 INSERT INTO kaname.accounts VALUES ('own','{"trust":"yes"}'),('foreign','{"trust":"yes"}');
 INSERT INTO kaname.projects VALUES
 ('project','own','{"trust":"yes"}'),('outdated','own','{"trust":"yes"}'),
 ('indirect','own','{"trust":"yes"}'),('repeated','own','{"trust":"yes"}'),
 ('ordinary','own','{}'),('fallback','own','{"trust":"yes"}'),('copied','own','{"trust":"yes"}');
 INSERT INTO kaname.resource_mirror VALUES
 ('iam.project','project','own','','{"trust":"yes"}'),
 ('iam.project','outdated','foreign','','{"trust":"yes"}'),
 ('iam.project','ordinary','own','','{"trust":"yes"}'),
 ('iam.project','fallback','','project','{"trust":"yes"}'),
 ('iam.project','copied','own','','{"trust":"yes"}'),
 ('iam.project','indirect','own','','{"trust":"yes"}'),('iam.project','repeated','own','','{"trust":"yes"}');
 INSERT INTO kaname.resource_parent_edge(object_id,parent_id,depth) VALUES
 ('project','own',1),('project','foreign',2),('outdated','own',1),('outdated','foreign',2),
 ('ordinary','own',1),('fallback','own',1),('indirect','own',2),('repeated','own',1),('repeated','own',2);
 INSERT INTO kaname.edge_copy(object_id,parent_id,depth) VALUES ('copied','own',1);`)
	require.NoError(t, err)
	query := `WITH rs AS (
 SELECT $4::text AS arm, $5::text AS container_type, $6::text AS container_arm,
        '{"trust":"yes"}'::jsonb AS match_access_labels, '{"trust":"yes"}'::jsonb AS container_match_access_labels
 ), b AS (SELECT $7::text AS resource_type, $8::text AS resource_id)
 SELECT EXISTS (SELECT 1 FROM kaname.resource_parent_edge ce,rs,b
 WHERE ce.object_type='project' AND ce.parent_type='account' AND ce.object_id=$1 AND ce.parent_id=$2` + nestedProtectedProjectOwnerPredicate("$3::text") + `)`
	for _, c := range []struct {
		name, project, edge, objectType, childArm, container, containerArm, scope, scopeID string
		want                                                                               bool
	}{
		{"same owner", "project", "own", "iam.project", "access_labels", "iam.account", "anchor", "account", "own", true},
		{"owner only at depth two", "indirect", "own", "iam.project", "access_labels", "iam.account", "anchor", "account", "own", false},
		{"protected container only at depth two", "indirect", "own", "iam.project", "labels", "iam.account", "access_labels", "account", "own", false},
		{"owner repeated at two depths", "repeated", "own", "iam.project", "access_labels", "iam.account", "anchor", "account", "own", false},
		{"protected container with repeated owner", "repeated", "own", "iam.project", "labels", "iam.account", "access_labels", "account", "own", false},
		{"ordinary indirect owner", "indirect", "own", "iam.project", "labels", "iam.account", "anchor", "account", "own", true},
		{"same owner through parent project", "fallback", "own", "iam.project", "access_labels", "iam.account", "anchor", "account", "own", true},
		{"same protected container owner", "project", "own", "iam.project", "labels", "iam.account", "access_labels", "account", "own", true},
		{"foreign edge", "project", "foreign", "iam.project", "access_labels", "iam.account", "anchor", "cluster", "root", false},
		{"foreign scope with real owner edge", "project", "own", "iam.project", "access_labels", "iam.account", "anchor", "account", "foreign", false},
		{"foreign mirror owner", "outdated", "own", "iam.project", "access_labels", "iam.account", "anchor", "cluster", "root", false},
		{"inherited edge alone", "copied", "own", "iam.project", "access_labels", "iam.account", "anchor", "account", "own", false},
		{"ordinary labels alone", "ordinary", "own", "iam.project", "access_labels", "iam.account", "anchor", "account", "own", false},
		{"protected container in foreign scope", "project", "own", "iam.project", "labels", "iam.account", "access_labels", "account", "foreign", false},
		{"ordinary source unchanged", "project", "foreign", "iam.project", "labels", "iam.account", "anchor", "account", "foreign", true},
		{"external source unchanged", "project", "foreign", "probe.child", "access_labels", "probe.parent", "anchor", "account", "foreign", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			var got bool
			require.NoError(t, pool.QueryRow(ctx, query, c.project, c.edge, c.objectType, c.childArm, c.container, c.containerArm, c.scope, c.scopeID).Scan(&got))
			require.Equal(t, c.want, got)
		})
	}

	for _, c := range []struct {
		name        string
		account     string
		protected   bool
		ownerLabels map[string]string
		want        []string
	}{
		{"ordinary includes indirect and repeated", "own", false, nil, []string{"copied", "fallback", "indirect", "ordinary", "outdated", "project", "repeated"}},
		{"protected child requires direct owner", "own", true, nil, []string{"fallback", "ordinary", "project"}},
		{"protected owner requires direct edge", "own", true, map[string]string{"trust": "yes"}, []string{"fallback", "ordinary", "project"}},
		{"physical owner lacks requested pair", "own", true, map[string]string{"trust": "no"}, nil},
		{"foreign candidate cannot qualify", "foreign", true, map[string]string{"trust": "yes"}, nil},
	} {
		t.Run("legacy "+c.name, func(t *testing.T) {
			rows, err := resource_mirror.DescendantsOf(ctx, pool, []string{"iam.project"}, "iam.account", []string{c.account}, c.protected, c.ownerLabels)
			require.NoError(t, err)
			var ids []string
			for _, row := range rows {
				ids = append(ids, row.ObjectID)
			}
			require.ElementsMatch(t, c.want, ids)
		})
	}
}
