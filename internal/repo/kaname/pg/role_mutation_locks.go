// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"slices"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	ab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
)

// Эти locks не проверяют полномочия. Они переносят физические ожидания actual
// Insert/UpdateCAS, GuardSystemClassReads, Replace*, tuple fold и promotion
// ПЕРЕД finalclock. Проверки ссылок/условий и OLD authority остаются у use-case.
func (s *roleMutationStage) lockMutation(ctx context.Context, w *authorityWriteTx) error {
	r := s.request.Role
	if _, err := w.tx.Exec(ctx, `SELECT 1 FROM kaname.roles WHERE id=$1 FOR UPDATE`, string(r.ID)); err != nil {
		return err
	}
	if err := holdRoleNames(ctx, w.tx, r.HeldNames); err != nil {
		return err
	}
	if r.AccountID != "" {
		if _, err := w.tx.Exec(ctx, `SELECT 1 FROM kaname.accounts WHERE id=$1 FOR SHARE`, string(r.AccountID)); err != nil {
			return err
		}
	}
	if r.ProjectID != "" {
		if _, err := w.tx.Exec(ctx, `SELECT 1 FROM kaname.projects WHERE id=$1 FOR SHARE`, string(r.ProjectID)); err != nil {
			return err
		}
	}
	if s.request.Create || s.request.Rules {
		if err := s.lockProjection(ctx, w); err != nil {
			return err
		}
	}
	store := &reconcileStore{tx: w.tx}
	if err := s.visitBindings(ctx, w.tx, func(id string, _ bool) error { return store.AcquireBindingLock(ctx, domain.AccessBindingID(id)) }); err != nil {
		return err
	}
	if err := s.visitBindings(ctx, w.tx, func(id string, _ bool) error {
		_, err := w.tx.Exec(ctx, `SELECT 1 FROM kaname.access_bindings WHERE id=$1 FOR UPDATE`, id)
		return err
	}); err != nil {
		return err
	}
	if err := s.lockStagedRows(ctx, w); err != nil {
		return err
	}
	if err := s.visitBindings(ctx, w.tx, func(id string, retier bool) error {
		// Включены истёкшие/отозванные OLD строки: решение eligibility делается
		// на finalclock, а census нельзя усечь по более ранним часам snapshot.
		if !retier {
			return nil
		}
		for _, side := range []string{"old", "new"} {
			if err := s.visitTuples(ctx, w.tx, id, side, false, func(page []ab.RelationTuple) error {
				for _, tuple := range page {
					if err := lockRoleTupleFact(ctx, w, tuple); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if s.request.Create && r.AccountID != "" {
		return lockRoleTupleFact(ctx, w, ab.RelationTuple{User: "account:" + string(r.AccountID), Relation: "account", Object: "iam_role:" + string(r.ID)})
	}
	return ctx.Err()
}

func lockRoleTupleFact(ctx context.Context, w *authorityWriteTx, tuple ab.RelationTuple) error {
	typ, id, ok := strings.Cut(tuple.Object, ":")
	if !ok || typ == "" || id == "" {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	subject := tuple.User
	if subject == "user:*" {
		subject = "system_class:authenticated"
		if tuple.Relation == "v_get" {
			subject = "system_class:anonymous"
		}
	}
	_, err := w.tx.Exec(ctx, `SELECT 1 FROM kaname.relation_fact WHERE object_type=$1 AND object_id=$2 AND relation=$3 AND subject=$4 FOR UPDATE`, typ, id, tuple.Relation, subject)
	return err
}

func (s *roleMutationStage) lockProjection(ctx context.Context, w *authorityWriteTx) error {
	r := s.request.Role
	refs := domain.RuleRefsOf(r.Rules)
	// Authoring axes выводятся из той же capability projection, что читает
	// LockGrantAuthoringAxes, даже если форма авторского правила изменится.
	for _, capability := range s.projection.Capabilities {
		switch capability.Kind {
		case domain.GrantCapabilityCreateBinding:
			refs = append(refs, domain.RoleRuleRef{Module: "iam", Resource: "accessBinding", Verb: "create"})
		case domain.GrantCapabilityBindRole:
			refs = append(refs, domain.RoleRuleRef{Module: "iam", Resource: "role", Verb: "bind"})
		}
	}
	modules := []string{}
	if r.OwnerModule != "" {
		modules = append(modules, r.OwnerModule)
	}
	types := lockedCatalogTypesOf(s.projection.Selectors)
	for _, pv := range s.projection.Verbs {
		types = append(types, pv.ObjectType)
	}
	for _, ref := range refs {
		modules = append(modules, ref.Module)
		types = append(types, ref.Module+"."+ref.Resource)
	}
	slices.Sort(modules)
	modules = slices.Compact(modules)
	slices.Sort(types)
	types = slices.Compact(types)
	// Применитель каталога берёт module раньше resource. Такой же порядок
	// удерживается здесь, затем будущие FK/selector locks уже не ждут.
	if _, err := w.tx.Exec(ctx, `SELECT 1 FROM kaname.catalog_module WHERE module=ANY($1::text[]) ORDER BY module FOR KEY SHARE`, modules); err != nil {
		return err
	}
	if _, err := w.tx.Exec(ctx, `SELECT 1 FROM kaname.catalog_resource WHERE dotted=ANY($1::text[]) ORDER BY dotted FOR KEY SHARE`, types); err != nil {
		return err
	}
	slices.SortFunc(refs, func(a, b domain.RoleRuleRef) int {
		if n := strings.Compare(a.Module, b.Module); n != 0 {
			return n
		}
		if n := strings.Compare(a.Resource, b.Resource); n != 0 {
			return n
		}
		return strings.Compare(a.Verb, b.Verb)
	})
	for _, ref := range refs {
		if !ref.IsAnchor() {
			if _, err := w.tx.Exec(ctx, `SELECT 1 FROM kaname.catalog_verb WHERE module=$1 AND resource=$2 AND verb=$3 FOR SHARE`, ref.Module, ref.Resource, ref.Verb); err != nil {
				return err
			}
		}
	}
	var roles []string
	for _, capability := range s.projection.Capabilities {
		if capability.BoundRoleID != "" {
			roles = append(roles, string(capability.BoundRoleID))
		}
	}
	slices.Sort(roles)
	roles = slices.Compact(roles)
	if _, err := w.tx.Exec(ctx, `SELECT 1 FROM kaname.roles WHERE id=ANY($1::text[]) ORDER BY id FOR SHARE`, roles); err != nil {
		return err
	}
	// LockGrantReference позже читает определение и затем его owning scope
	// с FOR SHARE. Предварительный FK KEY SHARE был бы слабее и оставил wait.
	if _, err := w.tx.Exec(ctx, `SELECT 1 FROM kaname.projects p WHERE p.id IN (SELECT r.project_id FROM kaname.roles r WHERE r.id=ANY($1::text[])) ORDER BY p.id FOR SHARE`, roles); err != nil {
		return err
	}
	if _, err := w.tx.Exec(ctx, `SELECT 1 FROM kaname.accounts a WHERE a.id IN (SELECT r.account_id FROM kaname.roles r WHERE r.id=ANY($1::text[])) ORDER BY a.id FOR SHARE`, roles); err != nil {
		return err
	}

	return ctx.Err()
}
