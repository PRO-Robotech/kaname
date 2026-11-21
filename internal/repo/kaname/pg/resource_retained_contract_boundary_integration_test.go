// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationscene"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// SQL backstop проверяется настоящим runtime LOGIN. Owner создаёт только
// существующую retained строку чужого аккаунта ДО activation, без allow facts.
// Положительный GLOBAL case подтверждает ROOT invalidation, а не local bypass.
func TestResourceRetainedScopeRequiresPreparedOrExactStagedGlobal(t *testing.T) {
	for _, tc := range []struct {
		name     string
		full     bool
		mode     string
		kind     string
		truncate bool
		allowed  bool
	}{
		{name: "FULL_without_manifest", full: true, mode: "global", kind: "resource"},
		{name: "STAGED_account_cannot_delete_foreign_scope", mode: "accounts", kind: "resource"},
		{name: "STAGED_other_kind_cannot_use_exception", mode: "global", kind: "binding"},
		{name: "STAGED_cannot_truncate", mode: "global", kind: "resource", truncate: true},
		{name: "STAGED_global_preserves_root_invalidation", mode: "global", kind: "resource", allowed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := writerProtocolRig(t)
			foreign := registrationscene.Seed(t, r.ctx, r.admin)
			const objectID = "retained-contract-boundary"
			_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.resource_registration_scope(object_type,object_id,project_id,account_id)
 VALUES('vpc_network',$1,$2,$3)`, objectID, foreign.Project, foreign.Account)
			require.NoError(t, err)
			if tc.full {
				_, _ = fullContractActivate(t, r)
			} else {
				require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
			}
			var before int64
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT revision FROM kaname.authority_binding_epoch WHERE scope=''`).Scan(&before))
			tx, err := r.runtime.Begin(r.ctx)
			require.NoError(t, err)
			lifecycleRollback(t, tx)
			accounts, refs := []string{}, `[]`
			if tc.mode == "accounts" {
				accounts = []string{r.a}
				// Ссылку на реального владельца строит SQL из отдельного параметра.
				refs = ""
			}
			identity := r.bundle.Identity()
			query := `SELECT kaname.authority_protocol_enter_typed_v2($1,$2::text[],CASE WHEN $3::text='' THEN jsonb_build_array(jsonb_build_object('kind','account','id',$4::text)) ELSE $3::text::jsonb END,$5,$6,$7,$8,'participant')`
			if tc.full {
				query = `SELECT kaname.authority_protocol_enter_typed_v3($1,$2::text[],CASE WHEN $3::text='' THEN jsonb_build_array(jsonb_build_object('kind','account','id',$4::text)) ELSE $3::text::jsonb END,$5,$6,$7,$8,'participant')`
			}
			_, err = tx.Exec(r.ctx, query, tc.mode, accounts, refs, r.a, tc.kind, identity.ModelID, identity.CatalogID, identity.ProjectorVersion)
			require.NoError(t, err, "boundary reaches authenticated entry")
			if tc.truncate {
				_, err = tx.Exec(r.ctx, `TRUNCATE kaname.resource_registration_scope`)
			} else {
				_, err = tx.Exec(r.ctx, `DELETE FROM kaname.resource_registration_scope WHERE object_type='vpc_network' AND object_id=$1`, objectID)
			}
			if tc.allowed {
				require.NoError(t, err)
				require.NoError(t, tx.Commit(r.ctx))
			} else {
				var denied *pgconn.PgError
				require.ErrorAs(t, err, &denied)
				require.Equal(t, "42501", denied.Code)
				if tc.mode == "global" {
					require.Equal(t, "signed retained write requires prepared resource manifest", denied.Message)
				}
				require.NoError(t, tx.Rollback(r.ctx))
			}
			var after int64
			var remains bool
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
 (SELECT revision FROM kaname.authority_binding_epoch WHERE scope=''),
 EXISTS(SELECT 1 FROM kaname.resource_registration_scope WHERE object_type='vpc_network' AND object_id=$1 AND project_id=$2 AND account_id=$3)`, objectID, foreign.Project, foreign.Account).Scan(&after, &remains))
			require.Equal(t, !tc.allowed, remains)
			if tc.allowed {
				require.Greater(t, after, before, "actual retained mutation invalidates ROOT")
			} else {
				require.Equal(t, before, after, "refusal rolls back both row and epoch")
			}
		})
	}
}
