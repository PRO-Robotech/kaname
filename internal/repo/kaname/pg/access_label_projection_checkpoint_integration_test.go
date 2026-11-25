// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/stretchr/testify/require"
)

func TestAccessLabelRoleProjectionCheckpointReadsExactPrivateProjectionThroughRuntime(t *testing.T) {
	r, owner := writerProtocolRigBeforePreparation(t)
	first := seedAccessDefinition(t, r, "account", r.a, "checkpoint_first")
	second := seedAccessDefinition(t, r, "account", r.a, "checkpoint_second")
	extra := seedAccessDefinition(t, r, "account", r.a, "checkpoint_extra")
	var user string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, r.a).Scan(&user))
	applyRules := domain.Rules{accessRoleApply(first.id, second.id)}
	_, expectedPairs, err := domain.SplitGrantCapabilityRules(applyRules)
	require.NoError(t, err)
	require.Len(t, expectedPairs, 2)
	ordinary := domain.Rules{{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}}}
	type fixture struct {
		name       string
		rules      domain.Rules
		pairs      []domain.GrantCapabilityRule
		confirmed  bool
		role       domain.Role
		checkpoint granteffect.ProjectionCheckpoint
	}
	wrongDefinition := append([]domain.GrantCapabilityRule{}, expectedPairs...)
	wrongDefinition[0].DefinitionID = domain.AccessLabelDefinitionID(extra.id)
	wrongFingerprint := append([]domain.GrantCapabilityRule{}, expectedPairs...)
	wrongFingerprint[0].RuleFP = "0000000000000000000000000000000000000000000000000000000000000000"
	require.NotEqual(t, expectedPairs[0].RuleFP, wrongFingerprint[0].RuleFP)
	additional := append([]domain.GrantCapabilityRule{}, expectedPairs...)
	additional = append(additional, domain.GrantCapabilityRule{
		RuleFP: expectedPairs[0].RuleFP, Kind: domain.GrantCapabilityApplyAccessLabel,
		DefinitionID: domain.AccessLabelDefinitionID(extra.id),
	})
	cases := []fixture{
		{name: "exact-two-definition-projection", rules: applyRules, pairs: expectedPairs, confirmed: true},
		{name: "absent-projection", rules: applyRules},
		{name: "missing-one-pair", rules: applyRules, pairs: expectedPairs[:1]},
		{name: "mismatched-definition", rules: applyRules, pairs: wrongDefinition},
		{name: "mismatched-fingerprint", rules: applyRules, pairs: wrongFingerprint},
		{name: "additional-pair", rules: applyRules, pairs: additional},
		{name: "legacy-ordinary-projection", rules: ordinary, confirmed: true},
	}

	// Каталог и модель взяты из установленного bundle. Авторские роли и их
	// обычные проекции сохраняются до handoff штатными owner adapters.
	seed, err := owner.Writer(r.ctx)
	require.NoError(t, err)
	defer func() { _ = seed.Rollback(context.WithoutCancel(r.ctx)) }()
	for i := range cases {
		c := &cases[i]
		c.role = domain.Role{ID: domain.RoleID(ids.NewID(domain.PrefixRole)),
			AccountID: domain.AccountID(r.a), Name: domain.RoleName("checkpoint_" + strconv.Itoa(i+1)), Rules: c.rules}
		ordinaryRules, _, err := domain.SplitGrantCapabilityRules(c.rules)
		require.NoError(t, err)
		c.role.Permissions, err = domain.CompileRules(ordinaryRules)
		require.NoError(t, err)
		projection, err := r.bundle.Projection(c.role)
		require.NoError(t, err)
		c.checkpoint = projection.Checkpoint
		_, err = seed.RolesW().Insert(r.ctx, c.role)
		require.NoError(t, err)
		require.NoError(t, seed.RolesW().ReplaceRuleSelectors(r.ctx, c.role.ID, projection.Selectors))
		require.NoError(t, seed.RolesW().ReplaceRoleVerbs(r.ctx, c.role.ID, projection.Verbs))
	}
	require.NoError(t, seed.Commit(r.ctx))

	// Только trusted owner fixture наполняет private таблицу. Guard возвращён
	// до COMMIT; настоящий LOGIN ниже видит уже сохранённое состояние. Это не
	// проверка продуктового writer и не выдача runtime права на private DML.
	privateSeed, err := r.admin.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, privateSeed)
	_, err = privateSeed.Exec(r.ctx, `ALTER TABLE kaname.authority_role_access_label_rule DISABLE TRIGGER authority_role_access_label_rule_closed`)
	require.NoError(t, err)
	for _, c := range cases {
		for _, pair := range c.pairs {
			_, err = privateSeed.Exec(r.ctx, accessRoleProjectionInsert, c.role.ID, pair.RuleFP, pair.DefinitionID)
			require.NoError(t, err)
		}
	}
	_, err = privateSeed.Exec(r.ctx, `ALTER TABLE kaname.authority_role_access_label_rule ENABLE TRIGGER authority_role_access_label_rule_closed`)
	require.NoError(t, err)
	require.NoError(t, privateSeed.Commit(r.ctx))
	require.NoError(t, owner.PrepareAuthorityBundle(r.ctx, r.bundle))
	require.NoError(t, owner.ActivateAuthorityBundle(r.ctx, r.bundle))

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			intent := kaname.SemanticReadIntent{
				Actor: domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(user)},
				Roles: []domain.RoleID{c.role.ID},
			}
			w, err := r.repo.PlannedSemanticAuthorityWriter(r.ctx,
				kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}, r.bundle, intent)
			require.NoError(t, err)
			defer func() { _ = w.Rollback(context.WithoutCancel(r.ctx)) }()
			checkpoint, cost, err := w.(kaname.SemanticSourceReader).RoleProjectionCheckpoint(r.ctx, c.role.ID)
			if c.confirmed {
				require.NoError(t, err)
				require.Equal(t, c.checkpoint, checkpoint)
			} else {
				require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
				require.Equal(t, granteffect.ProjectionCheckpoint{}, checkpoint)
			}
			// Отрицательное сравнение также возвращает стоимость уже прочитанных
			// строк; пустая или лишняя проекция не превращает snapshot в бесплатный.
			require.Positive(t, cost.Rows)
			require.LessOrEqual(t, cost.Rows, 4096)
			require.Positive(t, cost.Reads)
			require.LessOrEqual(t, cost.Reads, 5)
			if c.name == "legacy-ordinary-projection" {
				require.Equal(t, 2, cost.Reads)
			} else {
				require.Equal(t, 5, cost.Reads)
			}
			require.NoError(t, w.Rollback(r.ctx))
		})
	}
}

func TestAccessLabelRoleCheckpointRuntimeRegrantPreservesPrivateBoundary(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	role := seedAccountRole(t, r.ctx, r.admin, domain.AccountID(r.a), "checkpoint_stamps")
	var oldXmin, oldCtid, currentXmin, currentCtid string
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT xmin::text,ctid::text FROM kaname.roles WHERE id=$1`, role).Scan(&oldXmin, &oldCtid))
	_, err := r.admin.Exec(r.ctx, `UPDATE kaname.roles SET description='changed checkpoint row' WHERE id=$1`, role)
	require.NoError(t, err)
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT xmin::text,ctid::text FROM kaname.roles WHERE id=$1`, role).Scan(&currentXmin, &currentCtid))
	require.NotEqual(t, oldXmin, currentXmin)
	require.NotEqual(t, oldCtid, currentCtid)
	for attempt := 0; attempt < 2; attempt++ {
		_, err := r.admin.Exec(r.ctx, `SELECT kaname.authority_protocol_grant_runtime($1::regrole)`, r.role)
		require.NoError(t, err)
		var allowed bool
		require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(current_user,
		 'kaname.authority_access_label_role_checkpoint_read_v1(text,text,text,integer)','EXECUTE')`).Scan(&allowed))
		require.True(t, allowed, "повторная выдача сохраняет узкий checkpoint getter")
		// У getter нет caller-supplied образа правил: отдельно устаревший xmin
		// или ctid закрывает сравнение после одного чтения существующей роли.
		for _, stamps := range [][2]string{{oldXmin, currentCtid}, {currentXmin, oldCtid}} {
			var raw json.RawMessage
			require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT kaname.authority_access_label_role_checkpoint_read_v1($1,$2,$3,4096)`,
				role, stamps[0], stamps[1]).Scan(&raw))
			var result struct {
				Matches bool `json:"matches"`
				Rows    int  `json:"rows"`
				Reads   int  `json:"reads"`
			}
			require.NoError(t, json.Unmarshal(raw, &result))
			require.False(t, result.Matches)
			require.Equal(t, 1, result.Rows)
			require.Equal(t, 1, result.Reads)
		}
		for _, signature := range []string{
			"authority_access_label_role_projection_matches_v1(text,integer)",
			"authority_access_label_source_check_v1(text,text,text,text,uuid,text,text,text,text,timestamptz,integer)",
			"authority_access_label_role_compile_v1(jsonb)",
			"authority_access_label_role_transition_prepare_v1(jsonb,jsonb,integer,integer)",
			"authority_access_label_role_projection_apply_v1(jsonb,text,text)",
		} {
			require.NoError(t, r.runtime.QueryRow(r.ctx,
				`SELECT has_function_privilege(current_user,$1::text,'EXECUTE')`, "kaname."+signature).Scan(&allowed))
			require.False(t, allowed, signature)
		}
		for _, table := range []string{
			"kaname.authority_role_access_label_rule",
			"kaname.authority_access_label_definition",
			"kaname.authority_access_label_value",
		} {
			require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_table_privilege(current_user,$1::text,
			 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')`, table).Scan(&allowed))
			require.False(t, allowed, table)
		}
		// Проверяем и настоящий отказ SQL, а не только декларацию ACL.
		_, err = r.runtime.Exec(r.ctx, `SELECT kaname.authority_access_label_role_projection_matches_v1('absent-role',4096)`)
		requireAccessDefinitionSQLState(t, err, "42501")
		_, err = r.runtime.Exec(r.ctx, `SELECT * FROM kaname.authority_role_access_label_rule LIMIT 1`)
		requireAccessDefinitionSQLState(t, err, "42501")
	}
}
