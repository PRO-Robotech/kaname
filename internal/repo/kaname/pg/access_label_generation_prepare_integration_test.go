// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

const generationPrepareMigration = "20261125050000_access_label_generation_prepare.sql"
const generationPrepareSignature = "kaname._authority_access_label_generation_prepare_v1(text,text,text,integer,integer)"

// Тестовый порт вызывает приватную функцию владельца внутри реальной
// подписанной pending-транзакции обычного рабочего LOGIN.
func TestAccessLabelGenerationPrepareSignedOwnerCensus(t *testing.T) {
	for _, mode := range []string{"prepared", "full"} {
		t.Run(mode, func(t *testing.T) {
			r := writerProtocolRig(t)
			if mode == "full" {
				_, _ = fullContractActivate(t, r)
			}
			_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_dirty_root(root_type,root_id,generation,new_labels) VALUES
('iam.account',$1,'00000000-0000-4000-8000-000000000001','{}'),
('iam.project','prepare-other','00000000-0000-4000-8000-000000000002','{}');`, r.a)
			require.NoError(t, err)
			_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_dirty_fact(root_type,root_id,generation,object_type,object_id,relation,subject)
SELECT r.root_type,r.root_id,r.generation,f.typ,f.id,f.relation,f.subject
FROM (VALUES ('iam.account',$1::text,'account',$1::text,'viewer','user:one'),
 ('iam.account',$1::text,'project','prepare-extra','editor','user:two'),
 ('iam.project','prepare-other','account',$1::text,'viewer','user:one')) f(root_type,root_id,typ,id,relation,subject)
JOIN kaname.authority_access_label_dirty_root r USING(root_type,root_id)`, r.a)
			require.NoError(t, err)
			_, err = r.admin.Exec(r.ctx, `CREATE FUNCTION kaname.test_generation_prepare(
p_model text,p_id text,p_expected text,p_rows integer,p_reads integer,p_late boolean) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF p_late THEN PERFORM pg_advisory_xact_lock(1262569295,1);END IF;
 RETURN kaname._authority_access_label_generation_prepare_v1(p_model,p_id,p_expected,p_rows,p_reads);
END $$;
REVOKE ALL ON FUNCTION kaname.test_generation_prepare(text,text,text,integer,integer,boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION kaname.test_generation_prepare(text,text,text,integer,integer,boolean) TO `+pgx.Identifier{r.role}.Sanitize())
			require.NoError(t, err)
			var expected string
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT encode(sha256(convert_to(
 kaname._authority_access_label_object_generation_capture_v1('account',$1,100,20)::text,'UTF8')),'hex')`, r.a).Scan(&expected))
			for _, tc := range []struct {
				name, model, id, code string
				fingerprint           any
				rows, reads           int
				late                  bool
			}{
				{"full-census", "account", r.a, "", expected, 14, 10, false},
				{"empty-null", "project", "prepare-missing", "", nil, 0, 4, false},
				{"nonempty-cannot-be-null", "account", r.a, "40001", nil, 100, 20, false},
				{"empty-cannot-have-digest", "project", "prepare-missing", "40001", expected, 100, 20, false},
				{"invalid-digest", "account", r.a, "42501", "bad", 100, 20, false},
				{"second-census-row-budget", "account", r.a, "54000", expected, 13, 10, false},
				{"second-census-read-budget", "account", r.a, "54000", expected, 14, 9, false},
				{"late-root-hold", "account", r.a, "25001", expected, 100, 20, true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					tx, beginErr := r.runtime.Begin(r.ctx)
					require.NoError(t, beginErr)
					defer tx.Rollback(r.ctx)
					enter := "authority_resource_enter_v2"
					if mode == "full" {
						enter = "authority_resource_enter_v3"
					}
					identity := r.bundle.Identity()
					_, beginErr = tx.Exec(r.ctx, fmt.Sprintf(`SELECT kaname.%s('accounts',ARRAY[$1::text],
 jsonb_build_array(jsonb_build_object('kind','account','id',$1::text)),$2,$3,$4)`, enter),
						r.a, identity.ModelID, identity.CatalogID, identity.ProjectorVersion)
					require.NoError(t, beginErr)
					var raw []byte
					callErr := tx.QueryRow(r.ctx, `SELECT kaname.test_generation_prepare($1,$2,$3,$4,$5,$6)`,
						tc.model, tc.id, tc.fingerprint, tc.rows, tc.reads, tc.late).Scan(&raw)
					if tc.code != "" {
						var pgErr *pgconn.PgError
						require.ErrorAs(t, callErr, &pgErr)
						require.Equal(t, tc.code, pgErr.Code)
						return
					}
					require.NoError(t, callErr)
					var got struct {
						Fingerprint *string                       `json:"fingerprint"`
						Capture     accessLabelGenerationSnapshot `json:"capture"`
						Held        []json.RawMessage             `json:"held_advisory"`
						Rows        int                           `json:"rows"`
						Reads       int                           `json:"reads"`
					}
					require.NoError(t, json.Unmarshal(raw, &got))
					require.Equal(t, tc.rows, got.Rows)
					require.Equal(t, tc.reads, got.Reads)
					if tc.fingerprint == nil {
						require.Nil(t, got.Fingerprint)
						require.Empty(t, got.Capture.Roots)
						require.Len(t, got.Held, 1, "direct-root absence has a root key")
					} else {
						require.NotNil(t, got.Fingerprint)
						require.Equal(t, expected, *got.Fingerprint)
						require.Len(t, got.Capture.Roots, 2)
						require.Len(t, got.Capture.OutputStates, 2)
						require.Len(t, got.Held, 2)
					}
					var allHeld bool
					require.NoError(t, tx.QueryRow(r.ctx, `SELECT NOT EXISTS(
 SELECT 1 FROM jsonb_array_elements($1::jsonb->'held_advisory') w WHERE NOT EXISTS(
  SELECT 1 FROM pg_locks l WHERE l.pid=pg_backend_pid() AND l.locktype='advisory'
  AND l.classid=(w->>'classid')::oid AND l.objid=(w->>'objid')::oid
  AND l.objsubid=2 AND l.mode='ExclusiveLock' AND l.granted))`, raw).Scan(&allHeld))
					require.True(t, allHeld)
				})
			}
		})
	}
}

func TestAccessLabelGenerationPreparePrivateACLAndUnsignedDenial(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	tx, err := r.admin.Begin(r.ctx)
	require.NoError(t, err)
	defer tx.Rollback(r.ctx)
	raw, err := migrations.FS.ReadFile(generationPrepareMigration)
	require.NoError(t, err)
	up, down, ok := strings.Cut(string(raw), "-- +goose Down")
	require.True(t, ok)
	_, err = tx.Exec(r.ctx, down)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `ALTER DEFAULT PRIVILEGES IN SCHEMA kaname GRANT EXECUTE ON FUNCTIONS TO `+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, up)
	require.NoError(t, err)
	for _, signature := range []string{
		generationPrepareSignature,
		"kaname._authority_access_label_generation_root_keys_v1(jsonb)",
		"kaname._authority_access_label_generation_latch_require_v1(boolean)",
		"kaname._authority_access_label_generation_roots_hold_v1(jsonb)",
	} {
		var private bool
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT NOT p.prosecdef
 AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']::text[]
 AND NOT has_function_privilege($1::name,p.oid,'EXECUTE')
 AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee<>p.proowner)
 FROM pg_proc p WHERE p.oid=$2::regprocedure`, r.role, signature).Scan(&private))
		require.True(t, private)
	}
	// Даже владелец миграции входит в пересчёт через подписанную транзакцию.
	var result []byte
	err = tx.QueryRow(r.ctx, `SELECT kaname._authority_access_label_generation_prepare_v1('project','missing',NULL,0,4)`).Scan(&result)
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "42501", pgErr.Code)
}
