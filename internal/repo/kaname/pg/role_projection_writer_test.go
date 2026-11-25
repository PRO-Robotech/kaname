// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestPreparedRoleAuthoringAxesRequireExactCapability(t *testing.T) {
	captured := domain.GrantCapabilityRule{
		Kind:         domain.GrantCapabilityApplyAccessLabel,
		RuleFP:       "captured-rule",
		DefinitionID: "0a8326e4-52c8-4e78-b82b-c6a7039b7b2d",
	}
	stage := &roleMutationStage{}
	stage.projection.Capabilities = []domain.GrantCapabilityRule{captured}
	raw := &roleWriter{}
	writer := &preparedRoleRowWriter{
		WriterIface: raw,
		owner:       &preparedRoleWriteTx{stage: stage},
	}

	t.Run("изменилось определение", func(t *testing.T) {
		changed := captured
		changed.DefinitionID = "9ca1658c-1ce8-408b-b051-9002f91cba51"
		require.ErrorIs(t, writer.LockGrantAuthoringAxes(context.Background(), []domain.GrantCapabilityRule{changed}),
			kaname.ErrInvalidAuthorityFencePlan)
	})
	t.Run("изменился отпечаток", func(t *testing.T) {
		changed := captured
		changed.RuleFP = "other-rule"
		require.ErrorIs(t, writer.LockGrantAuthoringAxes(context.Background(), []domain.GrantCapabilityRule{changed}),
			kaname.ErrInvalidAuthorityFencePlan)
	})
	t.Run("точное правило требует подтверждённого prepared writer", func(t *testing.T) {
		require.ErrorIs(t, writer.LockGrantAuthoringAxes(context.Background(), []domain.GrantCapabilityRule{captured}),
			kaname.ErrSourceUnconfirmed)
	})
}

type roleProjectionStatement struct {
	SQL  string
	Args []any
}

type roleProjectionRecordingTx struct {
	pgx.Tx
	statements []roleProjectionStatement
	failAt     int
	failure    error
}

func (tx *roleProjectionRecordingTx) Exec(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	values := make([]any, len(args))
	for i, arg := range args {
		if p, ok := arg.(*string); ok {
			if p != nil {
				values[i] = *p
			}
		} else {
			values[i] = arg
		}
	}
	tx.statements = append(tx.statements, roleProjectionStatement{SQL: query, Args: values})
	if len(tx.statements) == tx.failAt {
		return pgconn.CommandTag{}, tx.failure
	}
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

func roleProjectionCommand(t *testing.T, table, kind string, rows []json.RawMessage) resourceRegistrationCommand {
	t.Helper()
	encoded, err := json.Marshal(map[string]any{"table": table, "role_id": "rol00000000000000001", "rows": rows})
	require.NoError(t, err)
	return resourceRegistrationCommand{Kind: kind, Encoded: encoded}
}

func TestRoleProjectionCanonicalWriterPreservesClosedOrdinals(t *testing.T) {
	ctx := context.Background()
	for _, table := range []string{"role_verb", "role_rule_ref"} {
		t.Run(table, func(t *testing.T) {
			ordinary, closed := &roleProjectionRecordingTx{}, &roleProjectionRecordingTx{}
			writer := &roleWriter{roleReader{tx: ordinary}}
			var rows []json.RawMessage
			if table == "role_verb" {
				require.NoError(t, writer.ReplaceRoleVerbs(ctx, "rol00000000000000001", []domain.RoleVerb{
					{ObjectType: "storage.volume", Verb: "read"},
					{ObjectType: "storage.volume", Verb: "read"},
					{ObjectType: "storage.volume", Verb: "write"},
				}))
				rows = []json.RawMessage{
					[]byte(`{"role_id":"rol00000000000000001","object_type":"storage.volume","verb":"read","live":true}`),
					[]byte(`{"role_id":"rol00000000000000001","object_type":"storage.volume","verb":"read","live":true}`),
					[]byte(`{"role_id":"rol00000000000000001","object_type":"storage.volume","verb":"write","live":true}`),
				}
				require.Equal(t, []any{"rol00000000000000001", "storage.volume", "read"}, ordinary.statements[1].Args)
				require.Contains(t, ordinary.statements[1].SQL, "ON CONFLICT (role_id, object_type, verb) DO NOTHING")
			} else {
				require.NoError(t, writer.ReplaceRuleRefs(ctx, "rol00000000000000001", []domain.RoleRuleRef{
					{Module: "storage", Resource: "volume"},
					{Module: "storage", Resource: "volume", Verb: "read"},
					{Module: "storage", Resource: "volume", Verb: "read"},
				}))
				rows = []json.RawMessage{
					[]byte(`{"role_id":"rol00000000000000001","module":"storage","resource":"volume","verb":null,"live":true}`),
					[]byte(`{"role_id":"rol00000000000000001","module":"storage","resource":"volume","verb":"read","live":true}`),
					[]byte(`{"role_id":"rol00000000000000001","module":"storage","resource":"volume","verb":"read","live":true}`),
				}
				require.Equal(t, []any{"rol00000000000000001", "storage", "volume", nil}, ordinary.statements[1].Args)
				require.Contains(t, ordinary.statements[1].SQL, "ON CONFLICT DO NOTHING")
			}
			tx := &resourceDecisionTx{Tx: closed}
			require.NoError(t, applyResourceWithdrawalProjection(ctx, tx, roleProjectionCommand(t, table, "withdrawal_projection_delete", nil)))
			for _, row := range rows {
				require.NoError(t, applyResourceWithdrawalProjection(ctx, tx, roleProjectionCommand(t, table, "withdrawal_projection_insert", []json.RawMessage{row})))
			}
			require.Len(t, ordinary.statements, 4, "delete and every prepared insert keep their statement ordinal, including duplicates")
			require.Equal(t, ordinary.statements, closed.statements, "both callers execute the same SQL and physical row")
			require.Contains(t, closed.statements[0].SQL, "DELETE FROM ONLY kaname."+table)
			require.Equal(t, []any{"rol00000000000000001"}, closed.statements[0].Args)
			// Второй ряд одного закрытого шага не создаёт нового пакетного писателя.
			before := len(closed.statements)
			err := applyResourceWithdrawalProjection(ctx, tx, roleProjectionCommand(t, table, "withdrawal_projection_insert", rows[:2]))
			require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
			require.Len(t, closed.statements, before)
		})
	}
}

func TestRoleProjectionCanonicalWriterPreservesNullAndEmpty(t *testing.T) {
	ctx := context.Background()
	tx := &roleProjectionRecordingTx{}
	for _, row := range []json.RawMessage{
		[]byte(`{"role_id":"rol00000000000000001","module":"storage","resource":"volume","verb":null}`),
		[]byte(`{"role_id":"rol00000000000000001","module":"storage","resource":"volume","verb":""}`),
	} {
		require.NoError(t, applyResourceWithdrawalProjection(ctx, &resourceDecisionTx{Tx: tx}, roleProjectionCommand(t, "role_rule_ref", "withdrawal_projection_insert", []json.RawMessage{row})))
	}
	require.Nil(t, tx.statements[0].Args[3], "compiled anchor remains SQL NULL")
	require.Equal(t, "", tx.statements[1].Args[3], "executor must not reinterpret an explicit empty physical value as an anchor")
	// Обычный адаптер передаёт негодный текст базе без незаметной нормализации.
	writer := &roleWriter{roleReader{tx: tx}}
	invalid := string([]byte{0xff})
	require.NoError(t, writer.ReplaceRoleVerbs(ctx, "rol00000000000000001", []domain.RoleVerb{{ObjectType: invalid}}))
	require.Equal(t, []any{"rol00000000000000001", invalid, ""}, tx.statements[3].Args)
}

func TestRoleProjectionCanonicalWriterPreservesErrorBoundary(t *testing.T) {
	ctx := context.Background()
	for _, constraint := range []string{"role_rule_ref_res_fk", "role_rule_ref_verb_fk"} {
		t.Run(constraint, func(t *testing.T) {
			cause := &pgconn.PgError{Code: "23503", ConstraintName: constraint}
			ordinary := &roleProjectionRecordingTx{failAt: 3, failure: cause}
			writer := &roleWriter{roleReader{tx: ordinary}}
			err := writer.ReplaceRuleRefs(ctx, "rol00000000000000001", []domain.RoleRuleRef{
				{Module: "storage", Resource: "first", Verb: "read"},
				{Module: "storage", Resource: "second", Verb: "write"},
				{Module: "storage", Resource: "third", Verb: "delete"},
			})
			require.ErrorIs(t, err, iamerr.ErrReferenceMissing)
			want := "resources: second is not a live platform resource"
			if constraint == "role_rule_ref_verb_fk" {
				want = "verbs: write is not a live verb of resource second"
			}
			require.Equal(t, want, iamerr.StripSentinel(err), "failure keeps the precise failing row hint")
			require.Len(t, ordinary.statements, 3, "no later row executes after refusal")
			for _, kind := range []string{"withdrawal_projection_delete", "withdrawal_projection_insert"} {
				closed := &roleProjectionRecordingTx{failAt: 1, failure: cause}
				row := json.RawMessage(`{"role_id":"rol00000000000000001","module":"storage","resource":"second","verb":"write"}`)
				err = applyResourceWithdrawalProjection(ctx, &resourceDecisionTx{Tx: closed}, roleProjectionCommand(t, "role_rule_ref", kind, []json.RawMessage{row}))
				require.Same(t, cause, err, "closed runner retains raw SQLSTATE for its transaction boundary")
				require.Len(t, closed.statements, 1)
			}
		})
	}
}
