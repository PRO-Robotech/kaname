// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// kaname#1034: preview проверяет полный набор исходных meta правил и живые
// ссылки. Это состояние проекции, не действующее право carrier и не Ready.
func (r *roleReader) resolveGrantSegments(ctx context.Context, declared []domain.RoleSegment, out map[domain.RoleID][]domain.RoleSegment) error {
	ids := []string{}
	seen := map[domain.RoleID]bool{}
	for _, d := range declared {
		if (d.ObjectType == "iam.role" && d.Verb == "bind") || (d.ObjectType == "iam.accessBinding" && d.Verb == "create") {
			if !seen[d.RoleID] {
				seen[d.RoleID] = true
				ids = append(ids, string(d.RoleID))
			}
		}
	}
	if len(ids) == 0 {
		return nil
	}
	rows, err := r.tx.Query(ctx, grantPreviewSQL, ids, maxProjectionRows+1)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id domain.RoleID
		var raw, actual []byte
		var valid bool
		var count int
		if err = rows.Scan(&id, &raw, &actual, &valid, &count); err != nil {
			return err
		}
		if count > maxProjectionRows {
			return kaname.ErrSourceReadLimit
		}
		rules, e := domain.DecodeRules(raw)
		if e != nil {
			return e
		}
		_, want, e := domain.SplitGrantCapabilityRules(rules)
		if e != nil {
			continue
		}
		var got []domain.GrantCapabilityRule
		if e = json.Unmarshal(actual, &got); e != nil {
			return e
		}
		if !valid {
			continue
		}
		// Сегмент считается живым только при точном наборе строк своей пары.
		for _, kind := range []domain.GrantCapabilityKind{domain.GrantCapabilityCreateBinding, domain.GrantCapabilityBindRole} {
			filter := func(in []domain.GrantCapabilityRule) []domain.GrantCapabilityRule {
				v := []domain.GrantCapabilityRule{}
				for _, c := range in {
					if c.Kind == kind {
						v = append(v, c)
					}
				}
				return v
			}
			expected := filter(want)
			if len(expected) == 0 {
				continue
			}
			a, e := granteffect.ProjectionJSON(nil, nil, expected)
			if e != nil {
				return e
			}
			b, e := granteffect.ProjectionJSON(nil, nil, filter(got))
			if e != nil {
				return e
			}
			if string(a) != string(b) {
				continue
			}
			pending := out[id][:0]
			for _, d := range out[id] {
				matched := (kind == domain.GrantCapabilityCreateBinding && d.ObjectType == "iam.accessBinding" && d.Verb == "create") || (kind == domain.GrantCapabilityBindRole && d.ObjectType == "iam.role" && d.Verb == "bind")
				if !matched {
					pending = append(pending, d)
				}
			}
			if len(pending) == 0 {
				delete(out, id)
			} else {
				out[id] = pending
			}
		}
	}
	return rows.Err()
}

const grantPreviewSQL = `
WITH caps AS MATERIALIZED (
 SELECT * FROM (
 SELECT role_id,rule_fp,'create_binding'::text AS kind,''::text AS target FROM kaname.role_create_binding_rule WHERE role_id=ANY($1::text[])
 UNION ALL SELECT role_id,rule_fp,'bind_role',bound_role_id FROM kaname.role_bind_role_rule WHERE role_id=ANY($1::text[])
 ) c LIMIT $2
), checked AS (
 SELECT c.*, (r.live AND cv.live AND
 (c.kind='create_binding' OR (t.live AND (r.is_system OR t.is_system OR
 (coalesce(r.account_id,p.account_id)=coalesce(t.account_id,tp.account_id)
 AND (r.project_id IS NULL OR t.project_id IS NULL OR r.project_id=t.project_id)))))) IS TRUE AS valid
 FROM caps c JOIN kaname.roles r ON r.id=c.role_id
 LEFT JOIN kaname.roles t ON t.id=c.target
 LEFT JOIN kaname.projects p ON p.id=r.project_id LEFT JOIN kaname.projects tp ON tp.id=t.project_id
 LEFT JOIN kaname.catalog_verb cv ON cv.module='iam' AND cv.resource=CASE c.kind WHEN 'create_binding' THEN 'accessBinding' ELSE 'role' END AND cv.verb=CASE c.kind WHEN 'create_binding' THEN 'create' ELSE 'bind' END
)
SELECT r.id,r.rules,coalesce((SELECT jsonb_agg(jsonb_build_object('RuleFP',rule_fp,'Kind',kind,'BoundRoleID',target)) FROM checked WHERE role_id=r.id),'[]'),
 r.live AND NOT EXISTS(SELECT 1 FROM checked WHERE role_id=r.id AND NOT valid),(SELECT count(*)::int FROM caps)
FROM kaname.roles r WHERE r.id=ANY($1::text[])`
