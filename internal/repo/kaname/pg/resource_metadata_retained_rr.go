// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Подготовка областей для подписанного входа. Исходное подключение читает
// данные в транзакции Repeatable Read, а проверка прав выполняется после блокировок.
type metadataRetainedRR struct {
	footprint *resourceFootprint
	bindings  map[string]bool
	roles     map[string]bool
	parents   *resourceParentCapture
}

func captureMetadataRetainedRR(ctx context.Context, p *resourceParentCapture, root domain.ResourceRef, projection string) (*metadataRetainedRR, error) {
	if p == nil || p.source == nil || p.source.sealed {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if err := checkMetadataRetainedSourceTables(ctx, p); err != nil {
		return nil, err
	}
	historical, err := p.source.read(ctx, p.tx, resourceSourceKey{
		kind: resourceSourceMetadataHistoricalCarriers, typ: root.Type, id: root.ID, projection: projection,
	})
	if err != nil {
		return nil, err
	}
	c := &metadataRetainedRR{footprint: newResourceFootprint(), bindings: map[string]bool{}, roles: map[string]bool{}, parents: p}
	todo := map[string]bool{}
	for _, row := range historical {
		var v struct {
			ID string `json:"binding_id"`
		}
		if json.Unmarshal(row.value, &v) != nil || !nativeQuestionToken(v.ID) {
			return nil, kaname.ErrSourceUnconfirmed
		}
		todo[v.ID] = true
	}
	catalog, err := p.catalog(ctx, root.Type)
	if err != nil {
		return nil, err
	}
	cat, ok := catalog.selected()
	if !ok || cat.identity.Dotted != root.Type {
		return nil, kaname.ErrSourceUnconfirmed
	}
	rootOutput, err := captureResourceOutput(ctx, p, cat, root.ID)
	if err != nil {
		return nil, err
	}
	if err = rootOutput.addFootprint(ctx, p, c.footprint); err != nil {
		return nil, err
	}
	outputs := []*resourceOutputCapture{rootOutput}
	seenOutputs := map[domain.ResourceRef]bool{}
	for len(todo) > 0 || len(outputs) > 0 {
		// Объекты независимо добавляют все holder bindings, включая ledger-only.
		for _, out := range outputs {
			if seenOutputs[out.object] {
				continue
			}
			seenOutputs[out.object] = true
			if len(seenOutputs) > 4096 {
				return nil, kaname.ErrSourceReadLimit
			}
			if err = chargeNativePolicyBudget(p.source.budget, 1, 0); err != nil {
				return nil, err
			}
			if out.modelType == "cluster" {
				c.footprint.global = true
			}
			if err = c.captureScopeFootprint(ctx, out.modelType, out.object.ID); err != nil {
				return nil, err
			}
			for id := range out.bindings {
				if !c.bindings[id] {
					todo[id] = true
				}
			}
		}
		outputs = nil
		ids := resourceSortedSet(todo)
		todo = map[string]bool{}
		for _, id := range ids {
			if c.bindings[id] {
				continue
			}
			c.bindings[id] = true
			if len(c.bindings) > 4096 {
				return nil, kaname.ErrSourceReadLimit
			}
			if err = chargeNativePolicyBudget(p.source.budget, 1, 0); err != nil {
				return nil, err
			}
			rows, e := p.source.read(ctx, p.tx, resourceSourceKey{kind: resourceSourceBinding, typ: "binding", id: id})
			if e != nil {
				return nil, e
			}
			if len(rows) != 1 {
				return nil, kaname.ErrSourceUnconfirmed
			}
			b, e := resourceCapturedBinding(rows[0].value)
			if e != nil {
				return nil, e
			}
			if string(b.ID) != id {
				return nil, kaname.ErrSourceUnconfirmed
			}
			if e = p.addBindingFootprint(ctx, c.footprint, b); e != nil {
				return nil, e
			}
			// Используем только захват источников, без withdrawal/rewrite ролей.
			raw := &resourceWithdrawalCapture{source: p.source, bindings: map[string][]resourceSourceRow{id: rows}}
			if b.RoleID != "" {
				rid := string(b.RoleID)
				c.roles[rid] = true
				if len(c.roles) > kaname.MaxAuthorityOwnershipRefs {
					return nil, kaname.ErrSourceReadLimit
				}
				roleRows, readErr := p.source.read(ctx, p.tx, resourceSourceKey{kind: resourceSourceRole, typ: "role", id: rid})
				if readErr != nil {
					return nil, readErr
				}
				var roleIdentity struct {
					ID string `json:"id"`
				}
				if len(roleRows) != 1 || json.Unmarshal(roleRows[0].value, &roleIdentity) != nil || roleIdentity.ID != rid {
					return nil, kaname.ErrSourceUnconfirmed
				}
				for _, kind := range []resourceSourceKind{resourceSourceRoleSelectors, resourceSourceRoleVerbs, resourceSourceRoleRuleRefs, resourceSourceRolePendingVerbs} {
					if _, e = p.source.read(ctx, p.tx, resourceSourceKey{kind: kind, typ: "role", id: rid}); e != nil {
						return nil, e
					}
				}
			}
			for _, kind := range []resourceSourceKind{resourceSourceBindingSubjects, resourceSourceBindingMembers, resourceSourceBindingLedger} {
				if _, e = p.source.read(ctx, p.tx, resourceSourceKey{kind: kind, typ: "binding", id: id}); e != nil {
					return nil, e
				}
			}
			next, e := raw.captureOutputs(ctx, p, c.footprint)
			if e != nil {
				return nil, e
			}
			outputs = append(outputs, next...)
		}
	}
	// SQL closure включает и retained account, и текущего владельца прочитанного
	// project. Предпочтение parent_account_id в object projection не скрывает второго.
	projectIDs := map[string]bool{}
	for key := range p.source.entries {
		if key.kind == resourceSourceProject {
			projectIDs[key.id] = true
		}
	}
	for _, projectID := range resourceSortedSet(projectIDs) {
		rows := p.source.entries[resourceSourceKey{kind: resourceSourceProject, typ: "project", id: projectID}]
		if len(rows) > 1 {
			return nil, kaname.ErrSourceUnconfirmed
		}
		for _, row := range rows {
			var project struct {
				ID      string `json:"id"`
				Account string `json:"account_id"`
			}
			if json.Unmarshal(row.value, &project) != nil || project.ID != projectID || !nativeQuestionToken(project.Account) {
				return nil, kaname.ErrSourceUnconfirmed
			}
			if err = p.captureAccount(ctx, project.Account); err != nil {
				return nil, err
			}
			if err = c.footprint.addMutationAccount(domain.AccountID(project.Account)); err != nil {
				return nil, err
			}
		}
	}
	if len(c.footprint.mutation) > kaname.MaxAuthorityFenceAccounts {
		return nil, kaname.ErrSourceReadLimit
	}
	// Live/Retired строки не могут незаметно поменять namespace одной координаты.
	for _, captured := range p.catalogs {
		selected, known := captured.selected()
		if !known {
			return nil, kaname.ErrSourceUnconfirmed
		}
		for _, row := range captured.rows {
			if row.identity.Dotted != selected.identity.Dotted || row.identity.ObjectType != selected.identity.ObjectType {
				return nil, kaname.ErrSourceUnconfirmed
			}
		}
	}
	return c, ctx.Err()
}

// Для подписанного плана собираем аккаунты, найденные на пути к кластеру.
// Затем SQL под блокировками отдельно проверяет полный граф предков.
func (c *metadataRetainedRR) captureScopeFootprint(ctx context.Context, model, id string) error {
	type node struct {
		typ, id string
		depth   int
	}
	queue := []node{{model, id, 0}}
	seen := map[domain.ResourceRef]bool{}
	p := c.parents
	for pos := 0; pos < len(queue); pos++ {
		if len(queue) > 4096 {
			return kaname.ErrSourceReadLimit
		}
		n := queue[pos]
		key := domain.ResourceRef{Type: n.typ, ID: n.id}
		if !nativeQuestionToken(n.typ) || !nativeQuestionToken(n.id) || strings.Contains(n.typ, ".") {
			return kaname.ErrSourceUnconfirmed
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		if err := chargeNativePolicyBudget(p.source.budget, 1, 0); err != nil {
			return err
		}
		if n.typ == "account" {
			if err := p.captureAccount(ctx, n.id); err != nil {
				return err
			}
			if err := c.footprint.addMutationAccount(domain.AccountID(n.id)); err != nil {
				return err
			}
			continue
		}
		if n.typ == "cluster" {
			continue
		}
		// Текущего владельца определяет проекция узла. У внешнего предка
		// аккаунт может храниться только в mirror, а у проекта текущий
		// владелец может отличаться от владельца в старой связи.
		catalog, err := p.catalog(ctx, n.typ)
		if err != nil {
			return err
		}
		current, known := catalog.selected()
		if !known || current.identity.ObjectType != n.typ {
			return kaname.ErrSourceUnconfirmed
		}
		object, present, err := p.captureObjectProjection(ctx, current.identity.Dotted, n.id)
		if err != nil {
			return err
		}
		if present {
			for _, account := range object.ParentAccountIDs {
				if err = p.captureAccount(ctx, account); err != nil {
					return err
				}
				if err = c.footprint.addMutationAccount(domain.AccountID(account)); err != nil {
					return err
				}
			}
		}
		// Проекция читает проект и при явно заданном аккаунте в mirror.
		// Заключительный обход projectIDs добавляет его текущего владельца.
		rows, err := p.source.read(ctx, p.tx, resourceSourceKey{kind: resourceSourceParentEdges, typ: n.typ, id: n.id})
		if err != nil {
			return err
		}
		var parents []node
		for _, r := range rows {
			var e struct {
				Type string `json:"parent_type"`
				ID   string `json:"parent_id"`
			}
			if json.Unmarshal(r.value, &e) != nil {
				return kaname.ErrSourceUnconfirmed
			}
			parents = append(parents, node{e.Type, e.ID, n.depth + 1})
		}
		if len(rows) == 0 {
			switch n.typ {
			case "project":
				rows, err = p.source.read(ctx, p.tx, resourceSourceKey{kind: resourceSourcePointerFacts, typ: n.typ, id: n.id})
				if err != nil {
					return err
				}
				for _, r := range rows {
					var v struct {
						Relation string `json:"relation"`
						Subject  string `json:"subject"`
					}
					if json.Unmarshal(r.value, &v) != nil {
						return kaname.ErrSourceUnconfirmed
					}
					t, i, ok := strings.Cut(v.Subject, ":")
					if v.Relation == t && !strings.Contains(v.Subject, "#") {
						if !ok {
							return kaname.ErrSourceUnconfirmed
						}
						parents = append(parents, node{t, i, n.depth + 1})
					}
				}
			case "iam_user":
				accounts := object.ParentAccountIDs
				if !present {
					accounts, err = p.userMembershipAccounts(ctx, n.id)
					if err != nil {
						return err
					}
				}
				for _, account := range accounts {
					parents = append(parents, node{"account", account, n.depth + 1})
				}
			case "iam_group", "iam_service_account", "iam_role", "iam_access_binding":
				dotted := map[string]string{"iam_group": "iam.group", "iam_service_account": "iam.serviceAccount", "iam_role": "iam.role", "iam_access_binding": "iam.accessBinding"}[n.typ]
				rows, err = p.source.read(ctx, p.tx, resourceSourceKey{kind: resourceSourceIAMObject, typ: dotted, id: n.id})
				if err != nil {
					return err
				}
				if len(rows) > 1 {
					return kaname.ErrSourceUnconfirmed
				}
				for _, r := range rows {
					var v struct {
						Account string `json:"account_id"`
						Project string `json:"project_id"`
						Type    string `json:"resource_type"`
						ID      string `json:"resource_id"`
					}
					if json.Unmarshal(r.value, &v) != nil {
						return kaname.ErrSourceUnconfirmed
					}
					if n.typ == "iam_access_binding" {
						t := strings.ToLower(v.Type)
						if (t == "account" || t == "project" || t == "cluster") && v.ID != "" {
							parents = append(parents, node{t, v.ID, n.depth + 1})
						}
					} else {
						if v.Account != "" {
							parents = append(parents, node{"account", v.Account, n.depth + 1})
						}
						if n.typ == "iam_role" && v.Project != "" {
							parents = append(parents, node{"project", v.Project, n.depth + 1})
						}
					}
				}
			}
		}
		if len(parents) > 4 || (n.depth >= 5 && len(parents) > 0) {
			return kaname.ErrSourceReadLimit
		}
		slices.SortFunc(parents, func(a, b node) int {
			if x := strings.Compare(a.typ, b.typ); x != 0 {
				return x
			}
			return strings.Compare(a.id, b.id)
		})
		queue = append(queue, parents...)
	}
	return ctx.Err()
}

// Выполняется до discoverPolicyPlanWithRows и до его чтения epoch token.
func (c *metadataRetainedRR) extendRequest(in *policyWriteRequest) error {
	if c == nil || in == nil || c.footprint == nil {
		return kaname.ErrSourceUnconfirmed
	}
	for a := range c.footprint.mutation {
		in.additionalAccounts = append(in.additionalAccounts, a)
	}
	slices.Sort(in.additionalAccounts)
	in.additionalAccounts = slices.Compact(in.additionalAccounts)
	if len(in.additionalAccounts) > kaname.MaxAuthorityFenceAccounts {
		return kaname.ErrSourceReadLimit
	}
	in.global = in.global || c.footprint.global
	for _, id := range resourceSortedSet(c.roles) {
		in.readRoles = append(in.readRoles, domain.RoleID(id))
	}
	slices.Sort(in.readRoles)
	in.readRoles = slices.Compact(in.readRoles)
	return nil
}

// Проверяем таблицы, из которых собирается область изменений. Исходное
// подключение выполняет каждый SELECT со своими правами, а проверка формы
// выявляет отсутствующую таблицу или RLS до того, как результат сочтут пустым.
func checkMetadataRetainedSourceTables(ctx context.Context, p *resourceParentCapture) error {
	tables := map[string]bool{
		"kaname.catalog_resource": true,                          // readResourceCatalog
		"kaname.projects":         true, "kaname.accounts": true, // 1,23
		"kaname.resource_mirror": true, "kaname.resource_parent_edge": true, // 2,3
		"kaname.resource_registration_scope": true, "kaname.relation_fact": true, // 4,6
		"kaname.access_bindings": true, "kaname.access_binding_subjects": true, // 8,9
		"kaname.access_binding_target_members": true, "kaname.access_binding_emitted_tuples": true, // 10,11,21,22,35
		"kaname.roles": true, "kaname.role_rule_selectors": true, // 12,13
		"kaname.role_verb": true, "kaname.role_rule_ref": true, // 14,15
		"kaname.resource_registration_pointer": true, "kaname.producer_source_receipt": true, // 25,26
		"kaname.public_read_publication": true, "kaname.resource_registration_retirement": true, // 27,28
		"kaname.memberships": true, "kaname.cluster_admin_grants": true, // 31,36
		"kaname.role_selector_verbs_pending": true, // 37
	}
	for _, spec := range iamDirectScanSpecs {
		tables[spec.table] = true
	}
	return checkMetadataSourceTableShapes(ctx, p, resourceSortedSet(tables))
}

func checkMetadataSourceTableShapes(ctx context.Context, p *resourceParentCapture, names []string) error {
	if err := chargeNativePolicyBudget(p.source.budget, len(names), 1); err != nil {
		return err
	}
	var valid bool
	err := p.tx.QueryRow(ctx, `SELECT current_setting('transaction_isolation')='repeatable read'
  AND current_setting('transaction_read_only')='on' AND current_user=session_user
  AND NOT EXISTS(
   SELECT 1 FROM unnest($1::text[]) expected(name)
   LEFT JOIN pg_catalog.pg_class c ON c.oid=pg_catalog.to_regclass(expected.name)
   WHERE c.oid IS NULL OR c.relkind<>'r' OR c.relpersistence<>'p'
    OR c.relrowsecurity OR c.relforcerowsecurity OR c.relhasrules
    OR c.relispartition OR c.relhassubclass)`, names).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return kaname.ErrSourceUnconfirmed
	}
	return nil
}
