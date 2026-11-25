// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"encoding/json"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestExternalMetadataOrdinaryHoldsBeforeFinalClock(t *testing.T) {
	const dotted, id, model = "vpc.network", "external-ordinary/hold", "vpc_network"
	w := metadataFixtureMode(t, false, "prepared")
	r := w.r
	var definition string
	require.NoError(t, r.admin.QueryRow(r.ctx, `INSERT INTO kaname.authority_access_label_definition
 (scope_kind,scope_id,module,resource,label_key) VALUES('project',$1,'vpc','network','team') RETURNING id::text`,
		string(w.project.ID)).Scan(&definition))
	_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_value(definition_id,label_value)
 VALUES($1::uuid,'after')`, definition)
	require.NoError(t, err)
	_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.resource_mirror(object_type,object_id,parent_account_id,parent_project_id)
 VALUES($1,$2,$3,$4),('compute.instance',$2,$3,$4)`, dotted, id, r.a, string(w.project.ID))
	require.NoError(t, err)
	const identity = "kaname.authority_metadata_mirror_ordinary_identity_v1(text,text)"
	const root = "kaname._authority_metadata_mirror_ordinary_root_v1(text,text,jsonb,jsonb,integer,integer,integer)"
	for _, fn := range []string{identity, root} {
		var allowed bool
		require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(current_user,$1,'EXECUTE')`, fn).Scan(&allowed))
		require.Equal(t, fn == identity, allowed, fn)
	}
	// В БД фикстуры доступ к owner body получает только ограниченная обёртка.
	role := pgx.Identifier{r.role}.Sanitize()
	_, err = r.admin.Exec(r.ctx, `CREATE FUNCTION kaname.test_external_ordinary_root(
 p_dotted text,p_id text,p_rr jsonb,p_patch jsonb,p_rows integer,p_reads integer,p_work integer)
 RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $test$
 SELECT kaname._authority_metadata_mirror_ordinary_root_v1(p_dotted,p_id,p_rr,p_patch,p_rows,p_reads,p_work)
 $test$;
 REVOKE ALL ON FUNCTION kaname.test_external_ordinary_root(text,text,jsonb,jsonb,integer,integer,integer) FROM PUBLIC;
 GRANT EXECUTE ON FUNCTION kaname.test_external_ordinary_root(text,text,jsonb,jsonb,integer,integer,integer) TO `+role)
	require.NoError(t, err)
	state := func() string {
		t.Helper()
		var out string
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_build_object(
 'roots',(SELECT jsonb_agg(jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m)) ORDER BY m.object_type)
 FROM ONLY kaname.resource_mirror m WHERE m.object_id=$1),
 'policy',kaname.authority_policy_epoch_read(ARRAY['*','scope:'||$2::text]),
 'binding',kaname.authority_binding_epoch_read(ARRAY[$2::text]),
 'audit',(SELECT count(*) FROM ONLY kaname.audit_outbox WHERE event_payload->>'resource_id'=$1),
 'reconcile',(SELECT count(*) FROM ONLY kaname.resource_reconcile_outbox WHERE object_id=$1))::text`, id, r.a).Scan(&out))
		return out
	}
	before := state()
	run := func(patch string) (kanamepg.ExternalRegistrationReceiptTrace, error) {
		return kanamepg.ProbeExternalRegistrationReceipt(r.ctx, w.factory, dotted, id, "compute_instance",
			domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(w.actor)}, false, "ordinary-root", patch)
	}
	const labels = `{"labels":{"team":"app"},"access_labels":{}}`
	for _, tc := range []struct{ patch, mode string }{
		{`{}`, "noop"}, {`{"access_labels":{}}`, "noop"}, {labels, "ordinary"},
	} {
		trace, err := run(tc.patch)
		require.NoError(t, err)
		require.True(t, trace.RRClosed)
		var held struct {
			Mode     string `json:"mode"`
			Identity struct {
				Catalog []json.RawMessage `json:"catalog"`
			} `json:"identity"`
			Old struct {
				ID string `json:"object_id"`
			} `json:"old"`
			Epoch struct {
				Policy  *string `json:"policy_write"`
				Binding *string `json:"binding_write"`
			} `json:"epoch"`
		}
		require.NoError(t, json.Unmarshal(trace.Held, &held))
		require.Equal(t, tc.mode, held.Mode)
		require.Equal(t, id, held.Old.ID)
		require.Len(t, held.Identity.Catalog, 3)
		var catalog struct {
			Model string `json:"object_type"`
		}
		require.NoError(t, json.Unmarshal(held.Identity.Catalog[2], &catalog))
		require.Equal(t, model, catalog.Model)
		if tc.mode == "ordinary" {
			require.NotNil(t, held.Epoch.Policy)
			require.NotNil(t, held.Epoch.Binding)
			require.Equal(t, "scope:"+r.a, *held.Epoch.Policy)
			require.Equal(t, r.a, *held.Epoch.Binding)
		} else {
			require.Nil(t, held.Epoch.Policy)
			require.Nil(t, held.Epoch.Binding)
		}
		require.JSONEq(t, before, state())
	}
	_, err = run(`{"access_labels":{"team":"after"}}`)
	var databaseError *pgconn.PgError
	require.ErrorAs(t, err, &databaseError)
	require.Equal(t, "42501", databaseError.Code)
	require.JSONEq(t, before, state())
}
