// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func TestMetadataAccessLabelFrontierUsesSignedPhysicalSources(t *testing.T) {
	for _, mode := range []string{"full", "prepared"} {
		t.Run(mode, func(t *testing.T) {
			w := metadataFixtureMode(t, false, mode)
			r := w.r
			// Временный вход фикстуры позволяет владельцу прочитать источники
			// в настоящей подписанной транзакции обычной runtime-роли.
			const probe = `kaname.test_metadata_access_label_frontier(text,text)`
			var runtimeCanExecute bool
			require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(
 'kaname._authority_metadata_access_label_frontier_capture_v1(text,text,integer,integer)', 'EXECUTE')`).Scan(&runtimeCanExecute))
			require.False(t, runtimeCanExecute)
			_, err := r.admin.Exec(r.ctx, `CREATE FUNCTION kaname.test_metadata_access_label_frontier(p_model text,p_id text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE first record; second record;
BEGIN
 SELECT * INTO STRICT first FROM kaname._authority_metadata_access_label_frontier_capture_v1(p_model,p_id,4096,16);
 SELECT * INTO STRICT second FROM kaname._authority_metadata_access_label_frontier_recheck_v1(
  first.frontier,first.source_index,first.cluster_states,4096,16);
 RETURN jsonb_build_object('frontier',first.frontier,'source_count',
  (SELECT count(*) FROM jsonb_object_keys(first.source_index)),'cluster_states',first.cluster_states,
  'rows',first.logical_rows,'reads',first.logical_reads,'recheck_rows',second.logical_rows,'recheck_reads',second.logical_reads);
END $$;
REVOKE ALL ON FUNCTION `+probe+` FROM PUBLIC;
GRANT EXECUTE ON FUNCTION `+probe+` TO `+pgx.Identifier{r.role}.Sanitize())
			require.NoError(t, err)
			tx, err := r.runtime.Begin(r.ctx)
			require.NoError(t, err)
			lifecycleRollback(t, tx)
			var population, epochs []byte
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT jsonb_build_object('generation',generation,'count',row_count,'revision',revision_sum)
 FROM kaname.authority_policy_population_read(4096)`).Scan(&population))
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.authority_policy_epoch_read(ARRAY['*']::text[])`).Scan(&epochs))
			enter, purpose := "authority_protocol_enter_full_v3", "decision"
			if mode == "prepared" {
				enter, purpose = "authority_protocol_enter_full_v2", "participant"
			}
			identity := r.bundle.Identity()
			_, err = tx.Exec(r.ctx, fmt.Sprintf(`SELECT kaname.%s('accounts',ARRAY[$1::text],
 jsonb_build_array(jsonb_build_object('kind','account','id',$1::text)),'resource',$2,$3,$4,$5,$6::jsonb)`, enter),
				r.a, identity.ModelID, identity.CatalogID, identity.ProjectorVersion, purpose, population)
			require.NoError(t, err)
			_, err = tx.Exec(r.ctx, `SELECT * FROM kaname.authority_policy_epoch_lock_full_v2($1::jsonb,ARRAY[]::text[],$2::jsonb,4096)`, epochs, population)
			require.NoError(t, err)

			for _, target := range []struct {
				model, id            string
				sources, reads, rows int
			}{
				{"project", string(w.project.ID), 2, 2, -1},
				{"account", r.a, 2, 3, 2},
				{"project", "prj-missing-frontier", 2, 2, 0},
			} {
				var body, expected []byte
				require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.test_metadata_access_label_frontier($1,$2)`, target.model, target.id).Scan(&body))
				require.NoError(t, tx.QueryRow(r.ctx, `SELECT coalesce(jsonb_agg(jsonb_build_array(q.parent_type,q.parent_id)
 ORDER BY q.parent_type COLLATE "C",q.parent_id COLLATE "C"),'[]'::jsonb)
 FROM (SELECT DISTINCT parent_type,parent_id FROM kaname.resource_scope_edge WHERE object_type=$1 AND object_id=$2) q`,
					target.model, target.id).Scan(&expected))
				var actual struct {
					Frontier struct {
						Parents json.RawMessage `json:"parents"`
					} `json:"frontier"`
					Sources      int `json:"source_count"`
					Rows         int `json:"rows"`
					Reads        int `json:"reads"`
					RecheckRows  int `json:"recheck_rows"`
					RecheckReads int `json:"recheck_reads"`
				}
				require.NoError(t, json.Unmarshal(body, &actual))
				require.JSONEq(t, string(expected), string(actual.Frontier.Parents))
				require.Equal(t, target.sources, actual.Sources)
				require.Equal(t, target.reads, actual.Reads)
				if target.rows >= 0 {
					require.Equal(t, target.rows, actual.Rows)
				}
				require.Equal(t, actual.Reads, actual.RecheckReads)
				require.Equal(t, actual.Rows, actual.RecheckRows)
			}
			require.NoError(t, tx.Rollback(r.ctx))
		})
	}
}
