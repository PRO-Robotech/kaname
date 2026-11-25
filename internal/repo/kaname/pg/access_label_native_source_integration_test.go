// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

const accessLabelNativeSourceSQL = `SELECT kaname.authority_access_label_source_check_v1(
 $1::text,$2::text,$3::text,$4::text,$5::uuid,$6::text,$7::text,$8::text,$9::text,$10::timestamptz,$11::integer)`

type accessLabelSourceQuestion struct {
	actorType, actorID, scopeKind, scopeID, definition string
	binding, recipientType, recipientID, fingerprint   string
	at                                                 time.Time
	rows                                               int
}

func (q accessLabelSourceQuestion) args() []any {
	return []any{q.actorType, q.actorID, q.scopeKind, q.scopeID, q.definition,
		q.binding, q.recipientType, q.recipientID, q.fingerprint, q.at, q.rows}
}

type accessLabelSourceResult struct {
	Allowed bool `json:"allowed"`
	Rows    int  `json:"rows"`
	Reads   int  `json:"reads"`
}

func accessLabelCheckSource(ctx context.Context, tx pgx.Tx, q accessLabelSourceQuestion) (accessLabelSourceResult, error) {
	var raw json.RawMessage
	var result accessLabelSourceResult
	if err := tx.QueryRow(ctx, accessLabelNativeSourceSQL, q.args()...).Scan(&raw); err != nil {
		return result, err
	}
	err := json.Unmarshal(raw, &result)
	return result, err
}

func TestAccessLabelNativeSourceChecksCurrentExactAuthority(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	role := seedAccountRole(t, r.ctx, r.admin, domain.AccountID(r.a), "native_access_source")
	definition := seedAccessDefinition(t, r, "account", r.a, "native_source")
	otherDefinition := seedAccessDefinition(t, r, "account", r.b, "native_source")
	actor := seedSAID(t, r.ctx, r.admin, r.a, "native-access-source")
	otherActor := seedSAID(t, r.ctx, r.admin, r.a, "native-access-other")
	group := seedGroupID(t, r.ctx, r.admin, r.a, "native-access-source")
	var user string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, r.a).Scan(&user))
	rules := domain.Rules{accessRoleApply(definition.id)}
	rawRules, err := domain.EncodeRules(rules)
	require.NoError(t, err)
	_, caps, err := domain.SplitGrantCapabilityRules(rules)
	require.NoError(t, err)
	require.Len(t, caps, 1)

	// Проверяется owner-only native primitive, а не public Authorize или
	// завершённый semantic proof. Вся авторская выдача остаётся в rollback TX.
	tx, err := r.admin.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	_, err = tx.Exec(r.ctx, `UPDATE kaname.roles SET rules=$2::jsonb,permissions='[]'::jsonb WHERE id=$1`, role, rawRules)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=$1`, user)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `INSERT INTO kaname.group_members(group_id,member_type,member_id) VALUES($1,'service_account',$2)`, group, actor)
	require.NoError(t, err)
	binding := func(subjectType, subjectID string) string {
		t.Helper()
		id := ids.NewID("acb")
		_, err := tx.Exec(r.ctx, bindingset.With(`INSERT INTO kaname.access_bindings
		 (id,subject_type,subject_id,role_id,resource_type,resource_id,status,scope,grant_capability_version,target)
		 VALUES($1,$2,$3,$4,'account',$5,'ACTIVE',2,1,'{"allInScope":true}'::jsonb)`), id, subjectType, subjectID, role, r.a)
		require.NoError(t, err)
		return id
	}
	directBinding := binding("service_account", actor)
	userBinding := binding("user", user)
	groupBinding := binding("group", group)
	// Разрешённая trusted fixture: owner временно снимает только statement
	// guard, возвращает его до чтения; продуктовый принимающий путь не открыт.
	_, err = tx.Exec(r.ctx, `ALTER TABLE kaname.authority_role_access_label_rule DISABLE TRIGGER authority_role_access_label_rule_closed`)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, accessRoleProjectionInsert, role, caps[0].RuleFP, definition.id)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `ALTER TABLE kaname.authority_role_access_label_rule ENABLE TRIGGER authority_role_access_label_rule_closed`)
	require.NoError(t, err)
	var decision time.Time
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT clock_timestamp()`).Scan(&decision))
	direct := accessLabelSourceQuestion{"service_account", actor, "account", r.a, definition.id,
		directBinding, "service_account", actor, caps[0].RuleFP, decision, 1000}
	groupQuestion := direct
	groupQuestion.binding, groupQuestion.recipientType, groupQuestion.recipientID = groupBinding, "group", group
	userQuestion := direct
	userQuestion.binding, userQuestion.actorType, userQuestion.actorID = userBinding, "user", user
	userQuestion.recipientType, userQuestion.recipientID = "user", user

	for name, question := range map[string]accessLabelSourceQuestion{
		"direct-enabled-sa": direct, "direct-verified-user": userQuestion, "one-level-group": groupQuestion,
	} {
		t.Run(name, func(t *testing.T) {
			result, err := accessLabelCheckSource(r.ctx, tx, question)
			require.NoError(t, err)
			require.True(t, result.Allowed)
			require.Positive(t, result.Rows)
			require.LessOrEqual(t, result.Rows, question.rows)
			require.Equal(t, 2, result.Reads)
		})
	}

	for _, tc := range []struct {
		name   string
		change func(*accessLabelSourceQuestion)
	}{
		{"wrong-definition-uuid", func(q *accessLabelSourceQuestion) { q.definition = otherDefinition.id }},
		{"wrong-scope", func(q *accessLabelSourceQuestion) { q.scopeID = r.b }},
		{"wrong-recipient", func(q *accessLabelSourceQuestion) { q.recipientID = otherActor }},
		{"other-actor-cannot-use-recipient", func(q *accessLabelSourceQuestion) { q.actorID = otherActor }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			question := direct
			tc.change(&question)
			result, err := accessLabelCheckSource(r.ctx, tx, question)
			require.NoError(t, err)
			require.False(t, result.Allowed)
		})
	}

	for _, tc := range []struct {
		name, sql, state string
		args             []any
		question         accessLabelSourceQuestion
	}{
		{"expired-at-decision", `UPDATE kaname.access_bindings SET expires_at=$2 WHERE id=$1`, "", []any{directBinding, decision}, direct},
		{"legacy-version-zero", `UPDATE kaname.access_bindings SET grant_capability_version=0 WHERE id=$1`, "", []any{directBinding}, direct},
		{"disabled-sa", `UPDATE kaname.service_accounts SET enabled=false WHERE id=$1`, "", []any{actor}, direct},
		{"unverified-user", `UPDATE kaname.users SET email_verified_at=NULL WHERE id=$1`, "", []any{user}, userQuestion},
		{"group-membership-removed", `DELETE FROM kaname.group_members WHERE group_id=$1 AND member_type='service_account' AND member_id=$2`, "", []any{group, actor}, groupQuestion},
		{"stale-authored-origin", `UPDATE kaname.roles SET rules='[]'::jsonb,permissions='["iam.role.*.get"]'::jsonb WHERE id=$1`, "40001", []any{role}, direct},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attempt, err := tx.Begin(r.ctx)
			require.NoError(t, err)
			defer func() { _ = attempt.Rollback(context.WithoutCancel(r.ctx)) }()
			_, err = attempt.Exec(r.ctx, tc.sql, tc.args...)
			require.NoError(t, err)
			result, err := accessLabelCheckSource(r.ctx, attempt, tc.question)
			if tc.state != "" {
				requireAccessDefinitionSQLState(t, err, tc.state)
			} else {
				require.NoError(t, err)
				require.False(t, result.Allowed)
			}
			require.NoError(t, attempt.Rollback(r.ctx))
		})
	}

	t.Run("row-bound-does-not-return-partial-allow", func(t *testing.T) {
		attempt, err := tx.Begin(r.ctx)
		require.NoError(t, err)
		defer func() { _ = attempt.Rollback(context.WithoutCancel(r.ctx)) }()
		question := direct
		question.rows = 8 // Точный origin — девятая строка сверх базового source census.
		_, err = accessLabelCheckSource(r.ctx, attempt, question)
		requireAccessDefinitionSQLState(t, err, "54000")
		require.NoError(t, attempt.Rollback(r.ctx))
	})

	// Полный checkpoint должен видеть не только наличие запрошенной пары,
	// но также отсутствие лишней и недостающей private projection строки.
	for _, mode := range []string{"exact", "extra", "missing"} {
		t.Run("projection-checkpoint-"+mode, func(t *testing.T) {
			attempt, err := tx.Begin(r.ctx)
			require.NoError(t, err)
			defer func() { _ = attempt.Rollback(context.WithoutCancel(r.ctx)) }()
			if mode != "exact" {
				_, err = attempt.Exec(r.ctx, `ALTER TABLE kaname.authority_role_access_label_rule DISABLE TRIGGER authority_role_access_label_rule_closed`)
				require.NoError(t, err)
				if mode == "extra" {
					_, err = attempt.Exec(r.ctx, accessRoleProjectionInsert, role, caps[0].RuleFP, otherDefinition.id)
				} else {
					_, err = attempt.Exec(r.ctx, `DELETE FROM kaname.authority_role_access_label_rule WHERE role_id=$1`, role)
				}
				require.NoError(t, err)
				_, err = attempt.Exec(r.ctx, `ALTER TABLE kaname.authority_role_access_label_rule ENABLE TRIGGER authority_role_access_label_rule_closed`)
				require.NoError(t, err)
			}
			var raw json.RawMessage
			require.NoError(t, attempt.QueryRow(r.ctx, `SELECT kaname.authority_access_label_role_projection_matches_v1($1,1000)`, role).Scan(&raw))
			var result struct {
				Matches bool `json:"matches"`
				Rows    int  `json:"rows"`
				Reads   int  `json:"reads"`
			}
			require.NoError(t, json.Unmarshal(raw, &result))
			require.Equal(t, mode == "exact", result.Matches)
			require.Positive(t, result.Rows)
			require.LessOrEqual(t, result.Rows, 1000)
			require.Positive(t, result.Reads)
			require.NoError(t, attempt.Rollback(r.ctx))
		})
	}

	t.Run("runtime-cannot-execute-private-readers", func(t *testing.T) {
		var exposed bool
		require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT
		 has_function_privilege(current_user,'kaname.authority_access_label_source_check_v1(text,text,text,text,uuid,text,text,text,text,timestamptz,integer)','EXECUTE')
		 OR has_function_privilege(current_user,'kaname.authority_access_label_role_projection_matches_v1(text,integer)','EXECUTE')`).Scan(&exposed))
		require.False(t, exposed)
		_, err := r.runtime.Exec(r.ctx, accessLabelNativeSourceSQL, direct.args()...)
		requireAccessDefinitionSQLState(t, err, "42501")
		_, err = r.runtime.Exec(r.ctx, `SELECT kaname.authority_access_label_role_projection_matches_v1($1,1000)`, role)
		requireAccessDefinitionSQLState(t, err, "42501")
	})
	require.NoError(t, tx.Rollback(r.ctx))
}
