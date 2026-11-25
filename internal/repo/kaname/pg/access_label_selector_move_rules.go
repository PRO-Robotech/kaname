// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
)

type selectorMovePosition struct {
	Rule  int `json:"rule_index"`
	Child int `json:"child_index"`
}

// PostgreSQL независимо перестраивает ровно запрошенные позиции в захваченном
// JSONB. Сохраняются порядок и поля, которых перенос не касается. Счётчик
// отличает несуществующую позицию или смешанный селектор от успешного переноса.
const selectorMoveRulesSQL = `
WITH selected AS (
    SELECT DISTINCT rule_index, child_index FROM jsonb_to_recordset($2::jsonb) AS m(rule_index integer, child_index integer)
),
roots AS (
    SELECT r.value, r.ordinality - 1 AS rule_index,
           (m.rule_index IS NOT NULL
                AND jsonb_typeof(r.value->'match_labels') = 'object'
                AND r.value->'match_labels' <> '{}'::jsonb
                AND coalesce(nullif(r.value->'match_access_labels', 'null'::jsonb), '{}'::jsonb) = '{}'::jsonb
                AND coalesce(nullif(r.value->'resource_names', 'null'::jsonb), '[]'::jsonb) = '[]'::jsonb
                AND coalesce(nullif(r.value->'created_by_subject', 'null'::jsonb), 'false'::jsonb) = 'false'::jsonb) AS moved
    FROM jsonb_array_elements($1::jsonb) WITH ORDINALITY r
    LEFT JOIN selected m ON m.rule_index = r.ordinality - 1 AND m.child_index = -1
),
children AS (
    SELECT r.rule_index, c.value, c.ordinality,
           (m.rule_index IS NOT NULL
                AND jsonb_typeof(c.value->'match_labels') = 'object'
                AND c.value->'match_labels' <> '{}'::jsonb
                AND coalesce(nullif(c.value->'match_access_labels', 'null'::jsonb), '{}'::jsonb) = '{}'::jsonb
                AND coalesce(nullif(c.value->'resource_names', 'null'::jsonb), '[]'::jsonb) = '[]'::jsonb
                AND coalesce(nullif(c.value->'created_by_subject', 'null'::jsonb), 'false'::jsonb) = 'false'::jsonb) AS moved
    FROM roots r
    CROSS JOIN LATERAL jsonb_array_elements(coalesce(nullif(r.value->'children', 'null'::jsonb), '[]'::jsonb))
        WITH ORDINALITY c
    LEFT JOIN selected m ON m.rule_index = r.rule_index AND m.child_index = c.ordinality - 1
),
child_images AS (
    SELECT rule_index, count(*) FILTER (WHERE moved) AS applied,
           jsonb_agg(CASE WHEN moved THEN value - ARRAY['match_labels', 'resource_names', 'created_by_subject']
               || jsonb_build_object('match_access_labels', value->'match_labels')
               ELSE value END ORDER BY ordinality) AS image
    FROM children GROUP BY rule_index
),
root_images AS (
    SELECT r.rule_index, (CASE WHEN r.moved THEN r.value - ARRAY['match_labels', 'resource_names', 'created_by_subject']
               || jsonb_build_object('match_access_labels', r.value->'match_labels')
               ELSE r.value END) AS image, r.moved, coalesce(c.applied, 0) AS child_count, c.image AS children
    FROM roots r LEFT JOIN child_images c USING (rule_index)
),
proposal AS (
    SELECT coalesce(jsonb_agg(CASE WHEN child_count > 0 THEN
               jsonb_set(image, '{children}', children, false) ELSE image END ORDER BY rule_index), '[]'::jsonb) AS image,
           (count(*) FILTER (WHERE moved) + coalesce(sum(child_count), 0))::integer AS applied
    FROM root_images
)
SELECT image, CASE WHEN kaname.access_label_rules_valid_v1(image) THEN applied ELSE -1 END
FROM proposal`

// verifySelectorMoveRules проверяет предложение Go независимым преобразованием
// исходной строки. Итоговый writer должен ещё удержать и сверить саму строку
// (xmin/ctid), область копирования и полномочия до записи.
func verifySelectorMoveRules(
	ctx context.Context, tx pgx.Tx, raw json.RawMessage, before, proposed domain.Rules,
	moves []domain.ValidatedAccessLabelSelectorMove, budget *relverdict.AdministrativeReadBudget,
) (json.RawMessage, error) {
	cost := len(before) + len(moves)
	for _, rule := range before {
		cost += len(rule.Children)
	}
	if tx == nil || budget == nil || len(moves) == 0 || len(raw) == 0 {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if len(raw) > granteffect.MaxInputBytes {
		return nil, relverdict.ErrAdministrativeSourceLimit
	}
	if err := budget.Charge(cost, 1); err != nil {
		return nil, err
	}
	positions := make([]selectorMovePosition, 0, len(moves))
	for _, move := range moves {
		rule, child := move.Position()
		positions = append(positions, selectorMovePosition{Rule: rule, Child: child})
	}
	request, err := json.Marshal(positions)
	if err != nil {
		return nil, err
	}
	var after json.RawMessage
	var count int
	if err = tx.QueryRow(ctx, selectorMoveRulesSQL, raw, request).Scan(&after, &count); err != nil {
		return nil, err
	}
	if count != len(moves) {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if len(after) > granteffect.MaxInputBytes {
		return nil, relverdict.ErrAdministrativeSourceLimit
	}
	result, err := rulesFromJSON(after)
	if err != nil {
		return nil, kaname.ErrSourceUnconfirmed
	}
	compiled, err := rulesToJSON(result)
	if err != nil {
		return nil, err
	}
	expected, err := rulesToJSON(proposed)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(compiled, expected) {
		return nil, kaname.ErrSourceUnconfirmed
	}
	return after, ctx.Err()
}
