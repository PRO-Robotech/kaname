// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Один private ordinal соответствует одному исходному SQL statement.
// Имена таблиц и SET/CONFLICT формы закрыты здесь; command не задаёт SQL.
func applyResourceWithdrawalProjection(ctx context.Context, tx *resourceDecisionTx, c resourceRegistrationCommand) error {
	var v struct {
		Table  string            `json:"table"`
		RoleID string            `json:"role_id"`
		Before json.RawMessage   `json:"before"`
		Row    json.RawMessage   `json:"row"`
		Rows   []json.RawMessage `json:"rows"`
	}
	if err := json.Unmarshal(c.Encoded, &v); err != nil {
		return err
	}
	if c.Kind == "withdrawal_role" {
		tag, err := tx.Exec(ctx, `UPDATE ONLY kaname.roles r
SET rules=n.rules,permissions=n.permissions,updated_at=n.updated_at
FROM jsonb_populate_record(NULL::kaname.roles,$1::jsonb) old,
jsonb_populate_record(NULL::kaname.roles,$2::jsonb) n
WHERE r.id=old.id AND n.id=old.id AND r.rules=old.rules`, v.Before, v.Row)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return kaname.ErrAuthorityClassificationChanged
		}
		return nil
	}
	query := ""
	if c.Kind == "withdrawal_projection_delete" {
		if v.RoleID == "" {
			return kaname.ErrSourceUnconfirmed
		}
		switch v.Table {
		case "role_rule_selectors":
			query = `DELETE FROM ONLY kaname.role_rule_selectors WHERE role_id=$1`
		case "role_verb":
			return writeRoleVerbProjection(ctx, tx, v.RoleID, nil)
		case "role_rule_ref":
			return writeRoleRuleRefProjection(ctx, tx, v.RoleID, nil)
		case "role_create_binding_rule":
			query = `DELETE FROM ONLY kaname.role_create_binding_rule WHERE role_id=$1`
		case "role_bind_role_rule":
			query = `DELETE FROM ONLY kaname.role_bind_role_rule WHERE role_id=$1`
		case "role_selector_verbs_pending":
			query = `DELETE FROM ONLY kaname.role_selector_verbs_pending WHERE role_id=$1`
		default:
			return kaname.ErrSourceUnconfirmed
		}
		_, err := tx.Exec(ctx, query, v.RoleID)
		return err
	}
	if c.Kind != "withdrawal_projection_insert" || len(v.Rows) == 0 || len(v.Rows) > 512 {
		return kaname.ErrSourceUnconfirmed
	}
	// Только capabilities исходно выполняются пакетами; selectors/verbs/refs
	// сохраняют по одному statement, включая повторный FP и DO NOTHING.
	if v.Table != "role_create_binding_rule" && v.Table != "role_bind_role_rule" && len(v.Rows) != 1 {
		return kaname.ErrSourceUnconfirmed
	}
	switch v.Table {
	case "role_rule_selectors":
		query = `INSERT INTO kaname.role_rule_selectors
(role_id,rule_fp,arm,object_types,resource_names,match_labels,container_type,container_arm,
container_resource_names,container_match_labels,verbs_by_type,created_by_subject,created_at,updated_at)
SELECT r.role_id,r.rule_fp,r.arm,r.object_types,r.resource_names,r.match_labels,r.container_type,r.container_arm,
r.container_resource_names,r.container_match_labels,r.verbs_by_type,r.created_by_subject,r.created_at,r.updated_at
FROM jsonb_populate_record(NULL::kaname.role_rule_selectors,$1::jsonb->'rows'->0) r
ON CONFLICT(role_id,rule_fp) DO UPDATE SET arm=EXCLUDED.arm,object_types=EXCLUDED.object_types,
resource_names=EXCLUDED.resource_names,match_labels=EXCLUDED.match_labels,container_type=EXCLUDED.container_type,
container_arm=EXCLUDED.container_arm,container_resource_names=EXCLUDED.container_resource_names,
container_match_labels=EXCLUDED.container_match_labels,verbs_by_type=EXCLUDED.verbs_by_type,
created_by_subject=EXCLUDED.created_by_subject,updated_at=EXCLUDED.updated_at`
	case "role_verb":
		var row roleVerbProjectionRow
		if err := json.Unmarshal(v.Rows[0], &row); err != nil {
			return err
		}
		return writeRoleVerbProjection(ctx, tx, v.RoleID, &row)
	case "role_rule_ref":
		var row roleRuleRefProjectionRow
		if err := json.Unmarshal(v.Rows[0], &row); err != nil {
			return err
		}
		return writeRoleRuleRefProjection(ctx, tx, v.RoleID, &row)
	case "role_create_binding_rule":
		query = `INSERT INTO kaname.role_create_binding_rule(role_id,rule_fp)
SELECT r.role_id,r.rule_fp FROM jsonb_array_elements($1::jsonb->'rows') WITH ORDINALITY x(v,n)
CROSS JOIN LATERAL jsonb_populate_record(NULL::kaname.role_create_binding_rule,x.v) r
ORDER BY x.n ON CONFLICT DO NOTHING`
	case "role_bind_role_rule":
		query = `INSERT INTO kaname.role_bind_role_rule(role_id,rule_fp,bound_role_id)
SELECT r.role_id,r.rule_fp,r.bound_role_id FROM jsonb_array_elements($1::jsonb->'rows') WITH ORDINALITY x(v,n)
CROSS JOIN LATERAL jsonb_populate_record(NULL::kaname.role_bind_role_rule,x.v) r
ORDER BY x.n ON CONFLICT DO NOTHING`
	default:
		return kaname.ErrSourceUnconfirmed
	}
	_, err := tx.Exec(ctx, query, c.Encoded)
	return err
}
