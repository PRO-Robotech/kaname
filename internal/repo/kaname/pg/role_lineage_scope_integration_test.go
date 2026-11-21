// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"encoding/json"
	"testing"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// Это проба signed scope backstop, не подмена конечного разрешения UC.
// Тот же runtime LOGIN пишет parent через настоящий emitter после INSERT роли.
func TestRoleCanonicalParentSameTransactionAndForeignNegative(t *testing.T) {
	r := writerProtocolRig(t)
	foreign := ids.NewID(domain.PrefixRole)
	_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.roles(id,account_id,name,permissions,rules) VALUES($1,$2,$3,'["iam.account.*.get"]'::jsonb,'[{"module":"iam","resources":["account"],"verbs":["get"]}]'::jsonb)`, foreign, r.b, "foreign_parent_probe")
	require.NoError(t, err)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	in := r.intent(r.a)
	in.Kind = kaname.AuthorityRole
	id := domain.RoleID(ids.NewID(domain.PrefixRole))
	writer, err := r.repo.ParticipantAuthorityWriter(r.ctx, in)
	if writer != nil {
		roleFinalCleanup(t, writer)
	}
	require.NoError(t, err)
	_, err = writer.RolesW().Insert(r.ctx, domain.Role{ID: id, AccountID: domain.AccountID(r.a), Name: "canonical_parent_probe", Permissions: domain.Permissions{"iam.account.*.get"}, Rules: domain.Rules{{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}}}})
	require.NoError(t, err)
	require.NoError(t, writer.EmitFGARelationWrite(r.ctx, []service.RelationTuple{{User: "account:" + r.a, Relation: "account", Object: "iam_role:" + string(id)}}))
	require.NoError(t, writer.Commit(r.ctx))
	var facts int
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT count(*) FROM kaname.relation_fact WHERE object_type='iam_role' AND object_id=$1 AND relation='account' AND subject=$2`, id, "account:"+r.a).Scan(&facts))
	require.Equal(t, 1, facts, "положительное Given материализовано настоящим emitter")
	for _, tc := range []struct {
		name, object, subject, relation string
		extra                           bool
	}{
		{"wrong_account", "iam_role:" + string(id), "account:" + r.b, "account", false},
		{"foreign_role", "iam_role:" + foreign, "account:" + r.b, "account", false},
		{"permission_relation", "iam_role:" + string(id), "account:" + r.a, "viewer", false},
		{"unknown_role", "iam_role:" + ids.NewID(domain.PrefixRole), "account:" + r.a, "account", false},
		{"extra_payload", "iam_role:" + string(id), "account:" + r.a, "account", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, e := r.runtime.Begin(r.ctx)
			if tx != nil {
				roleFinalCleanup(t, tx)
			}
			require.NoError(t, e)
			r.enter(t, tx, in, "participant")
			body := map[string]any{"user": tc.subject, "relation": tc.relation, "object": tc.object}
			if tc.extra {
				body["condition_name"] = "unexpected"
			}
			raw, e := json.Marshal(body)
			require.NoError(t, e)
			_, e = tx.Exec(r.ctx, `INSERT INTO kaname.fga_outbox(event_type,payload) VALUES('fga.tuple.write',$1::jsonb)`, raw)
			var pe *pgconn.PgError
			require.ErrorAs(t, e, &pe)
			require.Equal(t, "42501", pe.Code, "неизвестная/чужая связь не становится локальной")
			require.NoError(t, tx.Rollback(r.ctx))
		})
	}
	authorityWaitReleased(t, r.runtime)
}
