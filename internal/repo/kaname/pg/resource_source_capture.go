// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"maps"
	"slices"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
)

// Это закрытый набор чтений источников родителя. Ключи и SQL не принимает
// вызывающий Resource API; их добавляет RR compiler при каноническом обходе.
// Наличие witness ещё не означает, что RC держит необходимые epoch/row locks.
type resourceSourceKind uint8

const (
	resourceSourceProject resourceSourceKind = iota + 1
	resourceSourceMirror
	resourceSourceParentEdges
	resourceSourceRegistrationScopes
	resourceSourceProjectBinding
	resourceSourcePointerFacts
	resourceSourceDescendantEdges
	resourceSourceBinding
	resourceSourceBindingSubjects
	resourceSourceBindingMembers
	resourceSourceBindingLedger
	resourceSourceRole
	resourceSourceRoleSelectors
	resourceSourceRoleVerbs
	resourceSourceRoleRuleRefs
	resourceSourceRoleCreateRules
	resourceSourceRoleBindRules
	resourceSourceRoleBindings
	resourceSourceBindingsNamingObject
	resourceSourceSelectorsNamingObject
	resourceSourceObjectMembers
	resourceSourceObjectLedger
	resourceSourceAccount
	resourceSourceGrantAxis
	resourceSourceRegistrationPointers
	resourceSourceObjectReceipts
	resourceSourceObjectPublication
	resourceSourceObjectRetirement
	resourceSourceMatchingMirrorBindings
	resourceSourceIAMObject
	resourceSourceUserMemberships
	resourceSourceMatchingIAMBindings
	resourceSourceSelectorObjects
	resourceSourceNestedDescendants
	resourceSourceFactLedgerHolders
	resourceSourceClusterFactHolders
	resourceSourceRolePendingVerbs
	resourceSourceMetadataBindings
	resourceSourceMetadataBindingCoverage
	resourceSourceMetadataAuthoredBindings
	resourceSourceMetadataHistoricalCarriers
	resourceSourceMetadataPolicyReceipt
)

type resourceSourceKey struct {
	kind       resourceSourceKind
	typ, id    string
	projection string
}
type resourceSourceRow struct {
	state string
	value json.RawMessage
}
type resourceSourceCapture struct {
	conn            *pgx.Conn
	stageTX         pgx.Tx
	lifetime        *resourceAttemptLifetime
	budget          *relverdict.AdministrativeReadBudget
	entries         map[resourceSourceKey][]resourceSourceRow
	metadataParents *resourceParentCapture
	sealed          bool
}

func newResourceSourceCapture(tx pgx.Tx, budget *relverdict.AdministrativeReadBudget, lifetime *resourceAttemptLifetime) (*resourceSourceCapture, error) {
	if tx == nil || tx.Conn() == nil || budget == nil || lifetime == nil || lifetime.ended || lifetime.conn != tx.Conn() || lifetime.prepared != nil || lifetime.writer != nil {
		return nil, kaname.ErrSourceUnconfirmed
	}
	return &resourceSourceCapture{stageTX: tx, conn: tx.Conn(), lifetime: lifetime, budget: budget, entries: make(map[resourceSourceKey][]resourceSourceRow)}, nil
}

// Предикаты используют PK, object/binding-префикс либо существующий GIN.
// Для object ledger общий SQL пакет добавляет соответствующий индекс. LIMIT —
// sentinel остатка общего бюджета; порядок задаётся уже после полного чтения
// допустимого набора. SQL не сортирует неограниченный хвост перед LIMIT.
func resourceSourceSQL(k resourceSourceKey, limit int) (string, []any, error) {
	if !nativeQuestionToken(k.id) {
		return "", nil, kaname.ErrSourceUnconfirmed
	}
	var from string
	singleKey := false
	args := []any{k.typ, k.id, limit}
	switch k.kind {
	case resourceSourceMetadataBindings, resourceSourceMetadataBindingCoverage, resourceSourceMetadataAuthoredBindings,
		resourceSourceMetadataHistoricalCarriers:
		return resourceMetadataBindingsSQL(k, limit)
	case resourceSourceSelectorObjects:
		return resourceSelectorObjectsSQL(k, limit)
	case resourceSourceNestedDescendants:
		return resourceNestedDescendantsSQL(k, limit)
	case resourceSourceIAMObject:
		spec, ok := iamDirectScanSpecs[k.typ]
		if !ok {
			return "", nil, kaname.ErrSourceUnconfirmed
		}
		from = spec.table + " r WHERE r.id=$1"
		singleKey = true
	case resourceSourceUserMemberships:
		if k.typ != "iam.user" {
			return "", nil, kaname.ErrSourceUnconfirmed
		}
		from = "kaname.memberships r WHERE r.user_id=$1"
		singleKey = true
	case resourceSourceMatchingIAMBindings:
		spec, ok := iamDirectScanSpecs[k.typ]
		if !ok || k.projection == "" {
			return "", nil, kaname.ErrSourceUnconfirmed
		}
		// Проекция получена тем же RR capture и отдельно сравнивается в RC.
		// Это сохраняет accountsExpr semantics без незамкнутого ARRAY memberships.
		args = append(args, k.projection)
		return `SELECT jsonb_build_array(b.xmin::text,b.ctid::text,to_jsonb(b),
   rrs.xmin::text,rrs.ctid::text,to_jsonb(rrs),o.xmin::text,o.ctid::text,to_jsonb(o))::text,
   jsonb_build_object('binding_id',b.id)::text
   FROM kaname.role_rule_selectors rrs
   JOIN kaname.access_bindings b ON b.role_id=rrs.role_id
   JOIN ` + spec.table + ` o ON o.id=$2
   WHERE b.status='ACTIVE' AND rrs.object_types @> ARRAY[$1::text]
    AND ((rrs.arm='anchor' AND (b.resource_type NOT IN ('account','project')
     OR (b.resource_type='account' AND ($4::jsonb->'accounts') ? b.resource_id)
     OR (b.resource_type='project' AND b.resource_id=$4::jsonb->>'project')))
     OR (rrs.arm='names' AND $2=ANY(rrs.resource_names))
     OR (rrs.arm='labels' AND o.labels @> rrs.match_labels)
     OR (rrs.arm='access_labels' AND o.access_labels @> rrs.match_access_labels)) LIMIT $3`, args, nil
	case resourceSourceMatchingMirrorBindings:
		if !nativeQuestionToken(k.typ) {
			return "", nil, kaname.ErrSourceUnconfirmed
		}
		// Тот же кандидатный predicate, что SelectorBindingsMatchingObject;
		// LIMIT sentinel ограничивает результат, отсутствие ORDER BY не требует
		// полного предварительного sort. Полнота доказывается только при <= cap.
		return `SELECT jsonb_build_array(b.xmin::text,b.ctid::text,to_jsonb(b),
          rrs.xmin::text,rrs.ctid::text,to_jsonb(rrs),m.xmin::text,m.ctid::text,to_jsonb(m),
          pj.xmin::text,pj.ctid::text,to_jsonb(pj))::text,
          jsonb_build_object('binding_id',b.id)::text
         FROM kaname.role_rule_selectors rrs
         JOIN kaname.access_bindings b ON b.role_id=rrs.role_id
         JOIN kaname.resource_mirror m ON m.object_type=$1 AND m.object_id=$2
         LEFT JOIN kaname.projects pj ON pj.id=m.parent_project_id
         WHERE b.status='ACTIVE' AND rrs.object_types @> ARRAY[$1::text]
          AND ((rrs.arm='anchor' AND (b.resource_type='cluster'
           OR (b.resource_type='account' AND b.resource_id=COALESCE(NULLIF(m.parent_account_id,''),pj.account_id))
           OR (b.resource_type='project' AND m.parent_project_id=b.resource_id)))
           OR (rrs.arm='names' AND $2=ANY(rrs.resource_names))
           OR (rrs.arm='labels' AND m.labels @> rrs.match_labels)
           OR (rrs.arm='access_labels' AND m.access_labels @> rrs.match_access_labels)) LIMIT $3`, args, nil
	case resourceSourceAccount:
		if k.typ != "account" {
			return "", nil, kaname.ErrSourceUnconfirmed
		}
		from = "kaname.accounts r WHERE r.id=$1"
		singleKey = true
	case resourceSourceGrantAxis:
		if (k.typ != "accessBinding" || k.id != "create") && (k.typ != "role" || k.id != "bind") {
			return "", nil, kaname.ErrSourceUnconfirmed
		}
		from = "kaname.catalog_verb r WHERE r.module='iam' AND r.resource=$1 AND r.verb=$2 AND NOT r.per_object AND r.container_parent IS NULL AND r.container_relation IS NULL"
	case resourceSourceProject:
		if k.typ != "project" {
			return "", nil, kaname.ErrSourceUnconfirmed
		}
		from = "kaname.projects r WHERE r.id=$1"
		singleKey = true
	case resourceSourceMirror:
		from = "kaname.resource_mirror r WHERE r.object_type=$1 AND r.object_id=$2"
	case resourceSourceParentEdges:
		from = "kaname.resource_parent_edge r WHERE r.object_type=$1 AND r.object_id=$2"
	case resourceSourceRegistrationScopes:
		from = "kaname.resource_registration_scope r WHERE r.object_type=$1 AND r.object_id=$2"
	case resourceSourceProjectBinding:
		from = "kaname.object_project_binding r WHERE r.object_type=$1 AND r.object_id=$2"
	case resourceSourceMetadataPolicyReceipt:
		if (metadataMutation{table: "resource_mirror", kind: k.typ}).catalogType() == "" {
			return "", nil, kaname.ErrSourceUnconfirmed
		}
		// Эпоха зависит только от существования. Нулевой результат тоже
		// сохраняется в RR и сверяется под общей оградой перед решением.
		return `SELECT 'present'::text,'true'::text FROM ONLY kaname.producer_source_receipt
 WHERE catalog_type=$1 AND object_id=$2 LIMIT 1`, []any{k.typ, k.id}, nil
	case resourceSourceObjectReceipts:
		from = "kaname.producer_source_receipt r WHERE r.object_type=$1 AND r.object_id=$2"
	case resourceSourceObjectPublication:
		from = "kaname.public_read_publication r WHERE r.object_type=$1 AND r.object_id=$2"
	case resourceSourceObjectRetirement:
		from = "kaname.resource_registration_retirement r WHERE r.object_type=$1 AND r.object_id=$2"
	case resourceSourceRegistrationPointers:
		from = "kaname.resource_registration_pointer r WHERE r.object_type=$1 AND r.object_id=$2"
	case resourceSourcePointerFacts:
		from = "kaname.relation_fact r WHERE r.object_type=$1 AND r.object_id=$2"
	case resourceSourceDescendantEdges:
		from = "kaname.resource_parent_edge r WHERE r.parent_type=$1 AND r.parent_id=$2"
	case resourceSourceBinding, resourceSourceBindingSubjects, resourceSourceBindingMembers, resourceSourceBindingLedger:
		if k.typ != "binding" {
			return "", nil, kaname.ErrSourceUnconfirmed
		}
		singleKey = true
		switch k.kind {
		case resourceSourceBinding:
			from = "kaname.access_bindings r WHERE r.id=$1"
		case resourceSourceBindingSubjects:
			from = "kaname.access_binding_subjects r WHERE r.binding_id=$1"
		case resourceSourceBindingMembers:
			from = "kaname.access_binding_target_members r WHERE r.binding_id=$1"
		case resourceSourceBindingLedger:
			from = "kaname.access_binding_emitted_tuples r WHERE r.binding_id=$1"
		}
	case resourceSourceRole, resourceSourceRoleSelectors, resourceSourceRoleVerbs, resourceSourceRoleRuleRefs, resourceSourceRoleCreateRules, resourceSourceRoleBindRules, resourceSourceRoleBindings, resourceSourceRolePendingVerbs:
		if k.typ != "role" {
			return "", nil, kaname.ErrSourceUnconfirmed
		}
		singleKey = true
		switch k.kind {
		case resourceSourceRole:
			from = "kaname.roles r WHERE r.id=$1"
		case resourceSourceRoleSelectors:
			from = "kaname.role_rule_selectors r WHERE r.role_id=$1"
		case resourceSourceRoleVerbs:
			from = "kaname.role_verb r WHERE r.role_id=$1"
		case resourceSourceRoleRuleRefs:
			from = "kaname.role_rule_ref r WHERE r.role_id=$1"
		case resourceSourceRoleCreateRules:
			from = "kaname.role_create_binding_rule r WHERE r.role_id=$1"
		case resourceSourceRoleBindRules:
			from = "kaname.role_bind_role_rule r WHERE r.role_id=$1"
		case resourceSourceRolePendingVerbs:
			from = "kaname.role_selector_verbs_pending r WHERE r.role_id=$1"
		case resourceSourceRoleBindings:
			from = "kaname.access_bindings r WHERE r.role_id=$1"
		}
	case resourceSourceBindingsNamingObject:
		from = "kaname.access_bindings r WHERE r.revoked_at IS NULL AND r.target->'resources' @> jsonb_build_array(jsonb_build_object('type',$1::text,'id',$2::text))"
	case resourceSourceSelectorsNamingObject:
		from = "kaname.role_rule_selectors r WHERE r.resource_names @> ARRAY[$2::text] AND r.object_types @> ARRAY[$1::text]"
	case resourceSourceObjectMembers:
		from = "kaname.access_binding_target_members r WHERE r.object_type=$1 AND r.object_id=$2"
	case resourceSourceFactLedgerHolders:
		from = "kaname.access_binding_emitted_tuples r WHERE r.object=$1::text || ':' || $2::text"
	case resourceSourceClusterFactHolders:
		if k.typ != "cluster" {
			return "", nil, kaname.ErrSourceUnconfirmed
		}
		from = "kaname.cluster_admin_grants r WHERE $1::text='cluster' AND r.cluster_id=$2"
	case resourceSourceObjectLedger:
		from = "kaname.access_binding_emitted_tuples r WHERE r.member_object_type=$1 AND r.member_object_id=$2"
	default:
		return "", nil, kaname.ErrSourceUnconfirmed
	}
	if !nativeQuestionToken(k.typ) {
		return "", nil, kaname.ErrSourceUnconfirmed
	}
	suffix := " LIMIT $3"
	if singleKey {
		suffix = " LIMIT $2"
		args = []any{k.id, limit}
	}
	return "SELECT jsonb_build_array(r.xmin::text,r.ctid::text,to_jsonb(r))::text,to_jsonb(r)::text FROM " + from + suffix, args, nil
}

func readResourceSourceRows(ctx context.Context, tx pgx.Tx, k resourceSourceKey, budget *relverdict.AdministrativeReadBudget) ([]resourceSourceRow, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tx == nil || budget == nil {
		return nil, kaname.ErrSourceUnconfirmed
	}
	left := budget.RemainingRows()
	if left == 0 {
		return nil, kaname.ErrSourceReadLimit
	}
	query, args, err := resourceSourceSQL(k, left+1)
	if err != nil {
		return nil, err
	}
	if err = chargeNativePolicyBudget(budget, 0, 1); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []resourceSourceRow
	for rows.Next() {
		var state, value string
		if err = rows.Scan(&state, &value); err != nil {
			return nil, err
		}
		if err = chargeNativePolicyBudget(budget, 1, 0); err != nil {
			return nil, err
		}
		if state == "" || !json.Valid([]byte(value)) {
			return nil, kaname.ErrSourceUnconfirmed
		}
		out = append(out, resourceSourceRow{state: state, value: json.RawMessage(value)})
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	slices.SortFunc(out, func(a, b resourceSourceRow) int {
		if a.state < b.state {
			return -1
		}
		if a.state > b.state {
			return 1
		}
		return 0
	})
	return out, nil
}

func (c *resourceSourceCapture) read(ctx context.Context, tx pgx.Tx, k resourceSourceKey) ([]resourceSourceRow, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c == nil || c.sealed || c.lifetime == nil || c.lifetime.ended || c.lifetime.prepared != nil || tx == nil || tx != c.stageTX || tx.Conn() != c.conn {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if rows, ok := c.entries[k]; ok {
		return rows, nil
	}
	if mirrorMetadataBindingSource(k) {
		if err := c.confirmMetadataMirrorScope(ctx, tx, k.typ, k.id); err != nil {
			return nil, err
		}
	}
	rows, err := readResourceSourceRows(ctx, tx, k, c.budget)
	if err != nil {
		return nil, err
	}
	c.entries[k] = rows
	return rows, nil
}

// После seal нельзя расширить RR witness текущими строками из новой TX.
// Пустой перечень для известного ключа сохраняется как свидетельство отсутствия.
func (c *resourceSourceCapture) seal() error {
	if c == nil || c.sealed || c.lifetime == nil || c.lifetime.ended || c.lifetime.prepared != nil || c.conn == nil || c.budget == nil {
		return kaname.ErrSourceUnconfirmed
	}
	c.sealed = true
	return nil
}

// Runner вызывает это после всех guard/preflight waits и до final clock.
// Повторяется ровно захваченный набор предикатов, включая отсутствие; любые
// новые строки, удаление, move и ABA требуют повторить всю попытку с RR.
func (c *resourceSourceCapture) recheck(ctx context.Context, w *authorityWriteTx) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c == nil || !c.sealed || !c.lifetime.beforeDecision(w) {
		return kaname.ErrSourceUnconfirmed
	}
	tx := w.tx
	if c.metadataParents != nil {
		for _, typ := range slices.Sorted(maps.Keys(c.metadataParents.catalogs)) {
			if err := c.metadataParents.catalogs[typ].recheck(ctx, tx, c.budget); err != nil {
				return err
			}
		}
	}
	keys := make([]resourceSourceKey, 0, len(c.entries))
	for key := range c.entries {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b resourceSourceKey) int {
		if a.kind < b.kind {
			return -1
		}
		if a.kind > b.kind {
			return 1
		}
		if a.typ < b.typ {
			return -1
		}
		if a.typ > b.typ {
			return 1
		}
		if a.id < b.id {
			return -1
		}
		if a.id > b.id {
			return 1
		}
		if a.projection < b.projection {
			return -1
		}
		if a.projection > b.projection {
			return 1
		}
		return 0
	})
	for _, key := range keys {
		current, err := readResourceSourceRows(ctx, tx, key, c.budget)
		if err != nil {
			return err
		}
		expected := c.entries[key]
		if len(current) != len(expected) {
			return kaname.ErrAuthorityClassificationChanged
		}
		for i := range expected {
			if expected[i].state != current[i].state || string(expected[i].value) != string(current[i].value) {
				return kaname.ErrAuthorityClassificationChanged
			}
		}
	}
	return nil
}
