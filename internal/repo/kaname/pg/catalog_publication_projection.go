// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/jackc/pgx/v5"
)

const publicationRolePage = 128

// ReprojectCatalogExtension добавляет к сохранённым проекциям эффекты новых
// типов и действий. Правила автора и проекции выдачи полномочий остаются прежними.
// Каталог и роли защищены одной глобальной транзакцией установки.
func (w catalogPublicationWriter) ReprojectCatalogExtension(ctx context.Context, module string, before, after catalog.Halves) error {
	oldFacts, err := catalog.NewFacts(before)
	if err != nil {
		return err
	}
	newFacts, err := catalog.NewFacts(after)
	if err != nil {
		return err
	}
	moduleRule, err := json.Marshal([]map[string]string{{"module": module}})
	if err != nil {
		return err
	}
	var cursor domain.RoleID
	for {
		roles, err := w.publicationRoles(ctx, moduleRule, cursor)
		if err != nil {
			return err
		}
		for _, role := range roles {
			if err := w.extendRoleProjection(ctx, role, oldFacts, newFacts); err != nil {
				return fmt.Errorf("расширить проекцию роли %s: %w", role.ID, err)
			}
			cursor = role.ID
		}
		if len(roles) < publicationRolePage {
			return nil
		}
	}
}

// Вложенное правило использует модуль своего контейнера. Системные подстановки
// других владельцев учитываются по авторскому правилу, независимо от owner_module.
func (w catalogPublicationWriter) publicationRoles(ctx context.Context, moduleRule []byte, after domain.RoleID) ([]domain.Role, error) {
	rows, err := w.tx.Query(ctx, `
		SELECT id, is_system, coalesce(owner_module, ''), rules,
		       ARRAY(SELECT rule_fp FROM kaname.role_rule_selectors s WHERE s.role_id = r.id LIMIT 4097)
		FROM kaname.roles r
		WHERE id > $1 AND live AND (rules @> $2::jsonb OR rules @> '[{"module":"*"}]'::jsonb)
		ORDER BY id LIMIT $3
		FOR UPDATE OF r
	`, after, moduleRule, publicationRolePage)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	roles := make([]domain.Role, 0, publicationRolePage)
	for rows.Next() {
		var role domain.Role
		var raw []byte
		var stored []string
		if err := rows.Scan(&role.ID, &role.IsSystem, &role.OwnerModule, &raw, &stored); err != nil {
			return nil, err
		}
		if len(stored) > 4096 {
			return nil, fmt.Errorf("предел чтения селекторов роли %s", role.ID)
		}
		rules, err := rulesFromJSON(raw)
		if err != nil {
			return nil, err
		}
		role.Rules = domain.RulesForStoredSelectorLayout(rules, stored)
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

func (w catalogPublicationWriter) extendRoleProjection(ctx context.Context, role domain.Role, before, after *catalog.Facts) error {
	policy := domain.PolicyOfRole(role.IsSystem, role.OwnerModule)
	previous := make(map[string]domain.RuleSelector)
	for _, sel := range before.GrantSelectors(before.MaterializingSelectors(role.Rules), policy) {
		previous[sel.RuleFP] = sel
	}
	added := make(map[domain.RoleVerb]struct{})
	for _, sel := range after.GrantSelectors(after.MaterializingSelectors(role.Rules), policy) {
		old := previous[sel.RuleFP]
		growth := selectorGrowth(old, sel)
		if len(growth.types) == 0 && len(growth.grants) == 0 {
			continue
		}
		grants, err := w.extendStoredSelector(ctx, role.ID, old, sel, growth)
		if err != nil {
			return err
		}
		for typ, verbs := range grants {
			for _, verb := range verbs {
				added[domain.RoleVerb{ObjectType: typ, Verb: verb}] = struct{}{}
			}
		}
	}
	pairs := make([]domain.RoleVerb, 0, len(added))
	for pair := range added {
		pairs = append(pairs, pair)
	}
	slices.SortFunc(pairs, func(a, b domain.RoleVerb) int {
		if order := strings.Compare(a.ObjectType, b.ObjectType); order != 0 {
			return order
		}
		return strings.Compare(a.Verb, b.Verb)
	})
	id := string(role.ID)
	for _, pair := range pairs {
		row := roleVerbProjectionRow{RoleID: &id, ObjectType: &pair.ObjectType, Verb: &pair.Verb}
		if err := writeRoleVerbProjection(ctx, w.tx, id, &row); err != nil {
			return err
		}
	}
	return nil
}

type selectorExtension struct {
	types  []string
	grants map[string][]string
}

func selectorGrowth(before, after domain.RuleSelector) selectorExtension {
	growth := selectorExtension{grants: make(map[string][]string)}
	oldTypes := make(map[string]bool, len(before.ObjectTypes))
	for _, typ := range before.ObjectTypes {
		oldTypes[typ] = true
	}
	for _, typ := range after.ObjectTypes {
		if !oldTypes[typ] {
			growth.types = append(growth.types, typ)
		}
		for _, verb := range after.Grants[typ] {
			if !slices.Contains(before.Grants[typ], verb) {
				growth.grants[typ] = append(growth.grants[typ], verb)
			}
		}
	}
	return growth
}

func (w catalogPublicationWriter) extendStoredSelector(ctx context.Context, id domain.RoleID, old, next domain.RuleSelector, growth selectorExtension) (map[string][]string, error) {
	var types []string
	var encoded []byte
	err := w.tx.QueryRow(ctx, `
		SELECT object_types, verbs_by_type FROM kaname.role_rule_selectors
		WHERE role_id = $1 AND rule_fp = $2 FOR UPDATE
	`, id, next.RuleFP).Scan(&types, &encoded)
	if errors.Is(err, pgx.ErrNoRows) {
		if len(old.ObjectTypes) != 0 {
			// Не восстанавливаем снятый селектор из одних авторских правил.
			return nil, nil
		}
		writer := roleWriter{roleReader{tx: w.tx}}
		if err := writer.upsertRuleSelector(ctx, id, next); err != nil {
			return nil, err
		}
		return growth.grants, nil
	}
	if err != nil {
		return nil, err
	}
	grants := make(map[string][]string)
	if err := json.Unmarshal(encoded, &grants); err != nil {
		return nil, err
	}
	types = append(types, growth.types...)
	slices.Sort(types)
	types = slices.Compact(types)
	for typ, verbs := range growth.grants {
		if _, present := slices.BinarySearch(types, typ); !present {
			delete(growth.grants, typ)
			continue
		}
		values := append(grants[typ], verbs...)
		slices.Sort(values)
		grants[typ] = slices.Compact(values)
	}
	encoded, err = json.Marshal(grants)
	if err != nil {
		return nil, err
	}
	_, err = w.tx.Exec(ctx, `
		UPDATE kaname.role_rule_selectors
		SET object_types = $3, verbs_by_type = $4::jsonb, updated_at = now()
		WHERE role_id = $1 AND rule_fp = $2
		  AND (object_types IS DISTINCT FROM $3 OR verbs_by_type IS DISTINCT FROM $4::jsonb)
	`, id, next.RuleFP, types, encoded)
	return growth.grants, err
}
