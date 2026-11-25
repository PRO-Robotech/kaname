// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

const accessRolePrepareMigration = "20261124030000_access_label_role_projection_prepares_exact_rules.sql"
const accessRoleCompileSQL = `SELECT rule_fp,definition_id::text FROM kaname.authority_access_label_role_compile_v1($1::jsonb)`
const accessRolePrepareSQL = `SELECT rule_fp,definition_id::text FROM kaname.authority_access_label_role_prepare_v1($1::jsonb)`

type accessRoleProjectionQuery interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func accessRoleProjectionRows(ctx context.Context, query accessRoleProjectionQuery, sql string, raw []byte) (map[string]bool, error) {
	rows, err := query.Query(ctx, sql, raw)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var fingerprint, definition string
		if err := rows.Scan(&fingerprint, &definition); err != nil {
			return nil, err
		}
		key := fingerprint + "/" + definition
		if out[key] {
			return nil, fmt.Errorf("duplicate projection row %s", key)
		}
		out[key] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func accessRoleApply(ids ...string) domain.Rule {
	return domain.Rule{Module: "iam", Resources: []string{"accessLabel"}, Verbs: []string{"apply"}, ResourceNames: ids}
}

func TestAccessLabelRoleCompilerMatchesDomainExactSet(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	a, b := "12345678-1234-1234-1234-123456789abc", "abcdef01-2345-6789-abcd-0123456789ab"
	duplicateRules := make(domain.Rules, domain.MaxRules)
	for i := range duplicateRules {
		duplicateRules[i] = accessRoleApply(b, a, a)
	}
	cases := map[string]domain.Rules{
		"legacy-empty":           {},
		"one":                    {accessRoleApply(a)},
		"ordinary-selector-only": {{Module: "iam", Resources: []string{"group"}, Verbs: []string{"get"}, MatchAccessLabels: map[string]string{"env": "prod"}}},
		"order-and-duplicates":   {accessRoleApply(b, a, a), accessRoleApply(a, b)},
		"distinct-origins":       {accessRoleApply(a), accessRoleApply(a, b)},
		"maximum-rule-count":     duplicateRules,
		"legacy-pairs": {
			{Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"create"}},
			{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{"rol-one"}},
			accessRoleApply(a),
		},
		"ordinary-and-selectors": {
			{Module: "iam", Resources: []string{"group"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"env": "prod"}},
			{Module: "iam", Resources: []string{"serviceAccount"}, Verbs: []string{"get"}, CreatedBySubject: true},
			{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}, Children: []domain.Rule{{Resources: []string{"project"}, Verbs: []string{"get"}}}},
			accessRoleApply(a),
		},
		"wildcards-and-other-module": {
			{Module: "*", Resources: []string{"accessLabel"}, Verbs: []string{"apply"}},
			{Module: "iam", Resources: []string{"*"}, Verbs: []string{"apply"}},
			{Module: "iam", Resources: []string{"accessLabel"}, Verbs: []string{"*"}},
			{Module: "other", Resources: []string{"accessLabel"}, Verbs: []string{"apply"}},
		},
	}
	for name, rules := range cases {
		t.Run(name, func(t *testing.T) {
			raw, err := domain.EncodeRules(rules)
			require.NoError(t, err)
			ordinary, capabilities, err := domain.SplitGrantCapabilityRules(rules)
			require.NoError(t, err)
			_, remaining, err := domain.SplitGrantCapabilityRules(ordinary)
			require.NoError(t, err)
			require.Empty(t, remaining, "управляющие пары не остаются в ordinary")
			_, err = domain.CompileRules(rules)
			require.NoError(t, err)
			want := map[string]bool{}
			for _, capability := range capabilities {
				if capability.Kind == domain.GrantCapabilityApplyAccessLabel {
					want[capability.RuleFP+"/"+string(capability.DefinitionID)] = true
				}
			}
			got, err := accessRoleProjectionRows(r.ctx, r.admin, accessRoleCompileSQL, raw)
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}
}

func TestAccessLabelRoleCompilerRejectsDedicatedShapeAndUUIDDrift(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	id := "12345678-1234-1234-1234-123456789abc"
	changes := map[string]func(*domain.Rule){
		"mixed-resource":     func(rule *domain.Rule) { rule.Resources = append(rule.Resources, "group") },
		"duplicate-resource": func(rule *domain.Rule) { rule.Resources = append(rule.Resources, "accessLabel") },
		"mixed-verb":         func(rule *domain.Rule) { rule.Verbs = append(rule.Verbs, "get") },
		"duplicate-verb":     func(rule *domain.Rule) { rule.Verbs = append(rule.Verbs, "apply") },
		"wildcard-mixed":     func(rule *domain.Rule) { rule.Verbs = append(rule.Verbs, "*") },
		"verb-case":          func(rule *domain.Rule) { rule.Verbs = []string{"Apply"} },
		"verb-space":         func(rule *domain.Rule) { rule.Verbs = []string{"\u2003apply\u00a0"} },
		"no-names":           func(rule *domain.Rule) { rule.ResourceNames = nil },
		"wildcard-id":        func(rule *domain.Rule) { rule.ResourceNames = []string{"*"} },
		"zero-id":            func(rule *domain.Rule) { rule.ResourceNames = []string{"00000000-0000-0000-0000-000000000000"} },
		"uppercase-id":       func(rule *domain.Rule) { rule.ResourceNames = []string{strings.ToUpper(id)} },
		"bad-second-id":      func(rule *domain.Rule) { rule.ResourceNames = append(rule.ResourceNames, "bad") },
		"too-many-names": func(rule *domain.Rule) {
			rule.ResourceNames = make([]string, 257)
			for i := range rule.ResourceNames {
				rule.ResourceNames[i] = id
			}
		},
		"labels":  func(rule *domain.Rule) { rule.MatchLabels = map[string]string{"env": "prod"} },
		"creator": func(rule *domain.Rule) { rule.CreatedBySubject = true },
		"children": func(rule *domain.Rule) {
			rule.Children = []domain.Rule{{Resources: []string{"group"}, Verbs: []string{"get"}}}
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			rule := accessRoleApply(id)
			change(&rule)
			_, _, err := domain.SplitGrantCapabilityRules(domain.Rules{rule})
			require.Error(t, err)
			raw, err := domain.EncodeRules(domain.Rules{rule})
			require.NoError(t, err)
			_, err = accessRoleProjectionRows(r.ctx, r.admin, accessRoleCompileSQL, raw)
			requireAccessDefinitionSQLState(t, err, "23514")
		})
	}
	child := accessRoleApply(id)
	child.Module = ""
	nested := domain.Rules{{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}, Children: []domain.Rule{child}}}
	_, _, err := domain.SplitGrantCapabilityRules(nested)
	require.Error(t, err)
	raw, err := domain.EncodeRules(nested)
	require.NoError(t, err)
	_, err = accessRoleProjectionRows(r.ctx, r.admin, accessRoleCompileSQL, raw)
	requireAccessDefinitionSQLState(t, err, "23514")
	// Дополнительное поле не теряется из raw JSON при typed decode.
	for _, extra := range []string{`"metadata":{}`, `"match_labels":null`, `"match_access_labels":{}`, `"children":[]`, `"created_by_subject":false`} {
		raw := []byte(`[{"module":"iam","resources":["accessLabel"],"verbs":["apply"],"resource_names":["` + id + `"],` + extra + `}]`)
		_, err := accessRoleProjectionRows(r.ctx, r.admin, accessRoleCompileSQL, raw)
		requireAccessDefinitionSQLState(t, err, "23514")
	}
}

func TestAccessLabelRoleCompilerKeepsWholeInputBudget(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	names := make([]string, 256)
	for i := range names {
		names[i] = fmt.Sprintf("00000000-0000-0000-0000-%012x", i+1)
	}
	ordinary := domain.Rule{Module: "iam", Resources: []string{"account", "project", "group", "user"}, Verbs: []string{"get"}, ResourceNames: names}
	for _, extra := range []bool{false, true} {
		rules := domain.Rules{ordinary, ordinary}
		if extra {
			rules = append(rules, accessRoleApply(names[0]))
		}
		raw, err := domain.EncodeRules(rules)
		require.NoError(t, err)
		_, domainErr := domain.CompileRules(rules)
		got, sqlErr := accessRoleProjectionRows(r.ctx, r.admin, accessRoleCompileSQL, raw)
		if extra {
			require.Error(t, domainErr)
			requireAccessDefinitionSQLState(t, sqlErr, "23514")
		} else {
			require.NoError(t, domainErr)
			require.NoError(t, sqlErr)
			require.Empty(t, got)
		}
	}
	boundaryOrdinary := ordinary
	boundaryOrdinary.ResourceNames = names[:255]
	boundary := domain.Rules{boundaryOrdinary, boundaryOrdinary, accessRoleApply(names[:4]...)}
	permissions, err := domain.CompileRules(boundary)
	require.NoError(t, err)
	require.Len(t, permissions, domain.MaxCompiledPermissions)
	boundaryRaw, err := domain.EncodeRules(boundary)
	require.NoError(t, err)
	boundaryRows, err := accessRoleProjectionRows(r.ctx, r.admin, accessRoleCompileSQL, boundaryRaw)
	require.NoError(t, err)
	require.Len(t, boundaryRows, 4)
	tooMany := make(domain.Rules, domain.MaxRules+1)
	for i := range tooMany {
		tooMany[i] = accessRoleApply(names[0])
	}
	raw, err := domain.EncodeRules(tooMany)
	require.NoError(t, err)
	_, err = accessRoleProjectionRows(r.ctx, r.admin, accessRoleCompileSQL, raw)
	requireAccessDefinitionSQLState(t, err, "23514")
}

func TestAccessLabelRolePreparationRechecksDefinitionAfterWait(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	for _, commit := range []bool{false, true} {
		t.Run(fmt.Sprintf("commit=%t", commit), func(t *testing.T) {
			definition := seedAccessDefinition(t, r, "account", r.a, fmt.Sprintf("prepare-wait-%t", commit))
			raw, err := domain.EncodeRules(domain.Rules{accessRoleApply(definition.id)})
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(r.ctx, 15*time.Second)
			defer cancel()
			changer, err := r.admin.Begin(ctx)
			require.NoError(t, err)
			lifecycleRollback(t, changer)
			_, err = changer.Exec(ctx, `INSERT INTO kaname.authority_access_label_value(definition_id,label_value) VALUES($1::uuid,'new')`, definition.id)
			require.NoError(t, err)
			waiter, err := r.admin.Begin(ctx)
			require.NoError(t, err)
			type result struct {
				rows map[string]bool
				err  error
			}
			done := make(chan result, 1)
			joined := false
			defer func() {
				cancel()
				cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
				defer stop()
				_ = changer.Rollback(cleanup)
				if !joined {
					select {
					case <-done:
						joined = true
					case <-cleanup.Done():
						t.Error("prepare worker did not stop after cancellation")
					}
				}
				if joined {
					_ = waiter.Rollback(cleanup)
				}
			}()
			waiterPID, changerPID := waiter.Conn().PgConn().PID(), changer.Conn().PgConn().PID()
			go func() {
				rows, err := accessRoleProjectionRows(ctx, waiter, accessRolePrepareSQL, raw)
				done <- result{rows, err}
			}()
			require.Eventually(t, func() bool {
				var blocked bool
				err := r.admin.QueryRow(ctx, `SELECT $2::integer=ANY(pg_catalog.pg_blocking_pids($1::integer))`, waiterPID, changerPID).Scan(&blocked)
				return err == nil && blocked
			}, 3*time.Second, 10*time.Millisecond, "prepare ждёт изменение именно своего определения")
			if commit {
				require.NoError(t, changer.Commit(ctx))
			} else {
				require.NoError(t, changer.Rollback(ctx))
			}
			select {
			case outcome := <-done:
				joined = true
				if commit {
					requireAccessDefinitionSQLState(t, outcome.err, "40001")
					require.Nil(t, outcome.rows)
				} else {
					require.NoError(t, outcome.err)
					require.Len(t, outcome.rows, 1)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			require.NoError(t, waiter.Rollback(ctx))
		})
	}
}

func TestAccessLabelRolePreparationHoldsDefinitionsWithoutPublishing(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	a := seedAccessDefinition(t, r, "account", r.a, "prepare-a")
	b := seedAccessDefinition(t, r, "account", r.b, "prepare-b")
	raw, err := domain.EncodeRules(domain.Rules{accessRoleApply(b.id, a.id, a.id), accessRoleApply(a.id)})
	require.NoError(t, err)
	want, err := accessRoleProjectionRows(r.ctx, r.admin, accessRoleCompileSQL, raw)
	require.NoError(t, err)
	tx, err := r.admin.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	got, err := accessRoleProjectionRows(r.ctx, tx, accessRolePrepareSQL, raw)
	require.NoError(t, err)
	require.Equal(t, want, got)
	require.Len(t, got, 3)
	for _, definition := range []accessDefinitionWitness{a, b} {
		competitor, err := r.admin.Begin(r.ctx)
		require.NoError(t, err)
		lifecycleRollback(t, competitor)
		_, err = competitor.Exec(r.ctx, `SET LOCAL lock_timeout='250ms'`)
		require.NoError(t, err)
		_, err = competitor.Exec(r.ctx, `UPDATE kaname.authority_access_label_definition SET revision=revision+1 WHERE id=$1::uuid`, definition.id)
		requireAccessDefinitionSQLState(t, err, "55P03")
		require.NoError(t, competitor.Rollback(r.ctx))
	}
	var published int
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT count(*) FROM kaname.authority_role_access_label_rule`).Scan(&published))
	require.Zero(t, published)
	require.NoError(t, tx.Commit(r.ctx))
	// Конец транзакции освобождает удержание; prepare не оставляет прав/записей.
	require.Equal(t, a.revision, readAccessDefinition(t, r, a).revision)
	missing, err := domain.EncodeRules(domain.Rules{accessRoleApply("00000000-0000-0000-0000-000000000001")})
	require.NoError(t, err)
	_, err = accessRoleProjectionRows(r.ctx, r.admin, accessRolePrepareSQL, missing)
	requireAccessDefinitionSQLState(t, err, "23503")
	snapshot, err := r.admin.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	require.NoError(t, err)
	lifecycleRollback(t, snapshot)
	_, err = accessRoleProjectionRows(r.ctx, snapshot, accessRolePrepareSQL, raw)
	requireAccessDefinitionSQLState(t, err, "25001")
	require.NoError(t, snapshot.Rollback(r.ctx))
}

func TestAccessLabelRolePreparationMigrationKeepsPrivateClosure(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	raw, err := migrations.FS.ReadFile(accessRolePrepareMigration)
	require.NoError(t, err)
	up, down, ok := strings.Cut(string(raw), "-- +goose Down")
	require.True(t, ok)
	tx, err := r.admin.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	_, err = tx.Exec(r.ctx, down)
	require.NoError(t, err)
	quoted := pgx.Identifier{r.role}.Sanitize()
	_, err = tx.Exec(r.ctx, `ALTER DEFAULT PRIVILEGES IN SCHEMA kaname GRANT EXECUTE ON FUNCTIONS TO `+quoted)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, up)
	require.NoError(t, err)
	var private, closure bool
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT
	 NOT has_function_privilege($1,'kaname.authority_access_label_role_compile_v1(jsonb)','EXECUTE')
	 AND NOT has_function_privilege($1,'kaname.authority_access_label_role_prepare_v1(jsonb)','EXECUTE'),
	 kaname._authority_full_contract_storage_v3()`, r.role).Scan(&private, &closure))
	require.True(t, private)
	require.True(t, closure, "подготовка не изменяет signed census")
	require.NoError(t, tx.Rollback(r.ctx))
	for pass := 0; pass < 2; pass++ {
		_, err := r.admin.Exec(r.ctx, `SELECT kaname.authority_protocol_grant_runtime($1::regrole)`, r.role)
		require.NoError(t, err)
		for _, query := range []string{accessRoleCompileSQL, accessRolePrepareSQL} {
			_, err := accessRoleProjectionRows(r.ctx, r.runtime, query, json.RawMessage(`[]`))
			requireAccessDefinitionSQLState(t, err, "42501")
		}
	}
}
