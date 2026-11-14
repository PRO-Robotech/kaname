// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"sort"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	rolerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
)

func (w *roleWriter) RetainGrantCapabilities(ctx context.Context, id domain.RoleID, before, after []domain.GrantCapabilityRule) error {
	// kaname#1034: все lifecycle ожидания идут ДО повторного чтения исходных meta rows.
	// Иначе retire→revive во время ожидания мог бы воскресить уже снятый FP.
	owner, err := w.LockGrantReference(ctx, id)
	if err != nil {
		return err
	}
	if !owner.Live {
		return kaname.ErrSourceUnconfirmed
	}
	targets := map[domain.RoleID]bool{}
	for _, c := range after {
		if c.Kind == domain.GrantCapabilityBindRole {
			targets[c.BoundRoleID] = true
		}
	}
	ordered := make([]domain.RoleID, 0, len(targets))
	for id := range targets {
		ordered = append(ordered, id)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	for _, target := range ordered {
		ref, e := w.LockGrantReference(ctx, target)
		if e != nil {
			if errors.Is(e, iamerr.ErrNotFound) {
				targets[target] = false
				continue
			}
			return e
		}
		targets[target] = ref.Live && rolerepo.CommonGrantAnchor(owner.Role, owner.AccountID, ref.Role, ref.AccountID)
	}
	axes := map[domain.GrantCapabilityKind]bool{}
	for _, pair := range []struct {
		kind           domain.GrantCapabilityKind
		resource, verb string
	}{{domain.GrantCapabilityCreateBinding, "accessBinding", "create"}, {domain.GrantCapabilityBindRole, "role", "bind"}} {
		var live bool
		e := w.tx.QueryRow(ctx, `SELECT live FROM kaname.catalog_verb WHERE module='iam' AND resource=$1 AND verb=$2 AND NOT per_object AND container_parent IS NULL AND container_relation IS NULL FOR SHARE`, pair.resource, pair.verb).Scan(&live)
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		axes[pair.kind] = e == nil && live
	}
	rows, err := w.tx.Query(ctx, `SELECT rule_fp,'create_binding'::text,''::text FROM kaname.role_create_binding_rule WHERE role_id=$1 UNION ALL SELECT rule_fp,'bind_role',bound_role_id FROM kaname.role_bind_role_rule WHERE role_id=$1 LIMIT 1025`, id)
	if err != nil {
		return err
	}
	actual := map[domain.GrantCapabilityRule]bool{}
	n := 0
	for rows.Next() {
		var c domain.GrantCapabilityRule
		if err = rows.Scan(&c.RuleFP, &c.Kind, &c.BoundRoleID); err != nil {
			rows.Close()
			return err
		}
		actual[c] = true
		n++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if n > domain.MaxCompiledPermissions {
		return kaname.ErrSourceReadLimit
	}
	type edge struct {
		Kind   domain.GrantCapabilityKind
		Target domain.RoleID
	}
	allowed := map[edge]bool{}
	for _, c := range before {
		if actual[c] && axes[c.Kind] && (c.Kind == domain.GrantCapabilityCreateBinding || targets[c.BoundRoleID]) {
			allowed[edge{c.Kind, c.BoundRoleID}] = true
		}
	}
	retained := []domain.GrantCapabilityRule{}
	for _, c := range after {
		if allowed[edge{c.Kind, c.BoundRoleID}] {
			retained = append(retained, c)
		}
	}
	return w.ReplaceGrantCapabilities(ctx, id, retained)
}
