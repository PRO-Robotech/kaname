// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
)

// One canonical projection key holds BOTH independent metadata images, so the
// existing RR capture/RC exact recheck covers them in the same bounded reads.
type resourceMetadataProjection struct {
	Labels       domain.Labels `json:"labels"`
	AccessLabels domain.Labels `json:"access_labels"`
}

type metadataBindingRootSQL struct {
	join, accountMatch, project, historicalProject, witness string
}

func metadataBindingRoot(dotted string) (metadataBindingRootSQL, bool) {
	witness := "o.xmin::text,o.ctid::text,to_jsonb(o)"
	switch dotted {
	case "iam.group":
		// Нативная группа принадлежит аккаунту, без родителя-проекта.
		return metadataBindingRootSQL{
			join: "JOIN ONLY kaname.groups o ON o.id=$2", accountMatch: "b.resource_id=o.account_id",
			project: "false", historicalProject: "false", witness: witness,
		}, true
	case "iam.account", "iam.project", "iam.serviceAccount":
		spec := iamDirectScanSpecs[dotted]
		out := metadataBindingRootSQL{
			join:         "JOIN " + spec.table + " o ON o.id=$2",
			accountMatch: "b.resource_id=" + spec.parentAccountExpr, project: "b.resource_id=" + spec.parentProjectExpr,
			historicalProject: "b.resource_id=o.id", witness: witness,
		}
		if dotted == "iam.account" {
			// Селектор контейнера по меткам аккаунта может действовать только в одном его проекте.
			out.project = "EXISTS (SELECT 1 FROM kaname.projects p WHERE p.id=b.resource_id AND p.account_id=o.id)"
			out.historicalProject = "p.account_id=o.id"
		}
		if dotted == "iam.serviceAccount" {
			out.historicalProject = "false"
		}
		return out, true
	default:
		module, resource, dottedForm := strings.Cut(dotted, ".")
		if !dottedForm || module == "" || module == "iam" || resource == "" ||
			strings.Contains(resource, ".") || !nativeQuestionToken(dotted) {
			return metadataBindingRootSQL{}, false
		}
		const project = "b.resource_id=o.parent_project_id"
		return metadataBindingRootSQL{
			join: `JOIN kaname.resource_mirror o ON o.object_type=$1 AND o.object_id=$2
 LEFT JOIN kaname.projects op ON op.id=o.parent_project_id`,
			accountMatch: "b.resource_id=COALESCE(NULLIF(o.parent_account_id,''),op.account_id)",
			project:      project, historicalProject: project,
			witness: witness + ",op.xmin::text,op.ctid::text,to_jsonb(op)",
		}, true
	}
}

func mirrorMetadataBindingSource(k resourceSourceKey) bool {
	switch k.kind {
	case resourceSourceMetadataBindings, resourceSourceMetadataBindingCoverage,
		resourceSourceMetadataAuthoredBindings, resourceSourceMetadataHistoricalCarriers:
		return domain.FeedSourceForType(k.typ) == domain.FeedMirror
	default:
		return false
	}
}

// До подсчёта привязок фиксируем область зеркала отдельными источниками.
// Даже пустой список должен зависеть от той же версии объекта, проекта и аккаунта.
func (c *resourceSourceCapture) confirmMetadataMirrorScope(ctx context.Context, tx pgx.Tx, typ, id string) error {
	parents, err := c.metadataRegistrationSources(ctx, tx)
	if err != nil {
		return err
	}
	rows, err := c.read(ctx, tx, resourceSourceKey{kind: resourceSourceMirror, typ: typ, id: id})
	if err != nil {
		return err
	}
	type mirrorScope struct {
		Type    string `json:"object_type"`
		ID      string `json:"object_id"`
		Project string `json:"parent_project_id"`
		Account string `json:"parent_account_id"`
	}
	objects, err := resourceDecodeRows[mirrorScope](rows)
	if err != nil || len(objects) != 1 || objects[0].Type != typ || objects[0].ID != id {
		return kaname.ErrSourceUnconfirmed
	}
	root := objects[0]
	accountID := root.Account
	if root.Project != "" {
		project, err := parents.project(ctx, root.Project)
		if err != nil {
			return err
		}
		if !project.Registered || (accountID != "" && accountID != project.AccountID) {
			return kaname.ErrSourceUnconfirmed
		}
		accountID = project.AccountID
	}
	if accountID == "" {
		// Отсутствие записанной области само по себе не подтверждает область кластера.
		return kaname.ErrSourceUnconfirmed
	}
	accounts, err := c.read(ctx, tx, resourceSourceKey{kind: resourceSourceAccount, typ: "account", id: accountID})
	if err != nil {
		return err
	}
	if len(accounts) != 1 {
		return kaname.ErrSourceUnconfirmed
	}
	return parents.confirmMetadataRegistration(ctx, typ, id, root.Project, accountID)
}

// Выбирает привязки, которые могут покрывать изменяемый узел до или после
// правки меток. Вложенный селектор проверяется и по дочернему типу, и по
// контейнеру. Набор не зависит от наличия уже зарегистрированных потомков.
func resourceMetadataBindingsSQL(k resourceSourceKey, limit int) (string, []any, error) {
	if !nativeQuestionToken(k.id) || limit < 1 {
		return "", nil, kaname.ErrSourceUnconfirmed
	}
	root, ok := metadataBindingRoot(k.typ)
	if k.typ == "iam.user" {
		// У пользователя может быть несколько областей. Старое поле
		// users.account_id не подтверждает ни одной из них. Полный набор
		// строк дополнительно удерживается как самостоятельный источник.
		root = metadataBindingRootSQL{
			join: "JOIN ONLY kaname.users o ON o.id=$2",
			accountMatch: `EXISTS (SELECT 1 FROM ONLY kaname.memberships m
 WHERE m.user_id=o.id AND m.account_id=b.resource_id)`,
			project: "false", historicalProject: "false",
			witness: "o.xmin::text,o.ctid::text,to_jsonb(o)",
		}
		ok = true
	}
	if !ok {
		return "", nil, kaname.ErrSourceUnconfirmed
	}
	var next resourceMetadataProjection
	if json.Unmarshal([]byte(k.projection), &next) != nil || next.Labels == nil || next.AccessLabels == nil ||
		next.Labels.Validate() != nil || next.AccessLabels.Validate() != nil {
		return "", nil, kaname.ErrSourceUnconfirmed
	}
	scope := `b.status IN ('ACTIVE','PENDING') AND b.revoked_at IS NULL
   AND (b.resource_type NOT IN ('account','project')
     OR (b.resource_type='account' AND ` + root.accountMatch + `)
     OR (b.resource_type='project' AND ` + root.project + `))`
	args := []any{k.typ, k.id, limit, k.projection}
	const candidates = ` FROM jsonb_array_elements(r.rules) AS rules(rule)
       CROSS JOIN LATERAL jsonb_array_elements(jsonb_build_array(rule) ||
         coalesce(nullif(rule->'children','null'::jsonb),'[]'::jsonb)) AS selectors(candidate)
       WHERE rule->>'module' IN (split_part($1::text,'.',1),'*')
         AND ((candidate->'resources' ? split_part($1::text,'.',2)) OR (candidate->'resources' ? '*'))`
	const authoredChanges = `((o.labels @> (candidate->'match_labels')) IS DISTINCT FROM
           (($4::jsonb->'labels') @> (candidate->'match_labels'))
         OR (o.access_labels @> (candidate->'match_access_labels')) IS DISTINCT FROM
           (($4::jsonb->'access_labels') @> (candidate->'match_access_labels')))`
	if k.kind == resourceSourceMetadataHistoricalCarriers {
		// История выдачи может пережить отзыв привязки и вывод роли из действия.
		// Здесь читаем носителей старых выдач, включая отсутствующую область.
		// Эти строки участвуют в сверке источников и не дают права на выдачу.
		filter := ` FROM jsonb_array_elements(r.rules) AS rules(rule)
     CROSS JOIN LATERAL jsonb_array_elements(jsonb_build_array(rule) ||
       coalesce(nullif(rule->'children','null'::jsonb),'[]'::jsonb)) AS selectors(candidate)
     WHERE rule->>'module'=split_part($1::text,'.',1)
       AND candidate->'resources' ? split_part($1::text,'.',2)
       AND candidate ? 'match_access_labels'
       AND (o.access_labels @> (candidate->'match_access_labels')) IS DISTINCT FROM
           (($4::jsonb->'access_labels') @> (candidate->'match_access_labels'))`
		if k.typ == "iam.user" {
			// В одной команде User могут поменяться обе карты. Даже выведенный
			// из действия носитель обычного селектора способен оставить старый факт.
			filter = candidates + " AND " + authoredChanges
		}
		query := `SELECT jsonb_build_array(b.xmin::text,b.ctid::text,to_jsonb(b),
  r.xmin::text,r.ctid::text,to_jsonb(r),p.xmin::text,p.ctid::text,to_jsonb(p),
  ` + root.witness + `)::text,
  jsonb_build_object('binding_id',b.id,'role_id',b.role_id)::text
 FROM kaname.access_bindings b
 LEFT JOIN kaname.roles r ON r.id=b.role_id
 LEFT JOIN kaname.projects p ON b.resource_type='project' AND p.id=b.resource_id
 ` + root.join + `
 WHERE b.role_id IS NOT NULL
   AND (b.resource_type NOT IN ('account','project')
     OR (b.resource_type='account' AND ` + root.accountMatch + `)
     OR (b.resource_type='project' AND (p.id IS NULL OR ` + root.historicalProject + `)))
   AND CASE WHEN r.id IS NULL OR kaname.access_label_rules_valid_v1(r.rules) IS DISTINCT FROM true THEN true
   ELSE EXISTS (SELECT 1` + filter + `) END
 LIMIT $3`
		return query, args, nil
	}
	if k.kind == resourceSourceMetadataAuthoredBindings {
		// Authored rules also contribute unchanged OLD/NEW coverage when their
		// projection is missing. The changes flag stays independent of coverage.
		authoredCoverage := `((candidate->'resource_names' ? $2::text)
         OR (o.labels @> (candidate->'match_labels'))
         OR (($4::jsonb->'labels') @> (candidate->'match_labels'))
         OR (o.access_labels @> (candidate->'match_access_labels'))
         OR (($4::jsonb->'access_labels') @> (candidate->'match_access_labels'))
         OR (coalesce(candidate->'resource_names','null'::jsonb) IN ('null'::jsonb,'[]'::jsonb)
           AND coalesce(candidate->'match_labels','null'::jsonb)='null'::jsonb
           AND coalesce(candidate->'match_access_labels','null'::jsonb)='null'::jsonb
           AND coalesce(candidate->'created_by_subject','false'::jsonb)!='true'::jsonb))`
		if k.typ == "iam.serviceAccount" {
			// Факт создателя берём из OLD; здесь сохраняем даже неизменное авторское покрытие.
			authoredCoverage = "(" + authoredCoverage + " OR coalesce(candidate->'created_by_subject','false'::jsonb)='true'::jsonb)"
		}

		query := `SELECT jsonb_build_array(b.xmin::text,b.ctid::text,to_jsonb(b),
  r.xmin::text,r.ctid::text,to_jsonb(r),` + root.witness + `)::text,
  jsonb_build_object('binding_id',b.id,'changes',EXISTS (SELECT 1` + candidates + ` AND ` + authoredChanges + `))::text
 FROM kaname.access_bindings b
 JOIN kaname.roles r ON r.id=b.role_id AND r.live
 ` + root.join + `
 WHERE ` + scope + `
   AND EXISTS (SELECT 1` + candidates + ` AND (` + authoredChanges + ` OR ` + authoredCoverage + `))
 LIMIT $3`
		return query, args, nil
	}
	// Неизвестную область оставляем в кандидате: она должна получить отказ
	// на типизированной проверке, а не исчезнуть из свидетельства отсутствия.
	// Каждая строка хранит версии носителя, селектора и самого узла. LIMIT
	// включает sentinel бюджета, без DISTINCT и сортировки до считывания.
	const changes = `((s.object_types @> ARRAY[$1::text] AND s.arm='labels'
     AND (o.labels @> s.match_labels) IS DISTINCT FROM (($4::jsonb->'labels') @> s.match_labels))
   OR (s.object_types @> ARRAY[$1::text] AND s.arm='access_labels'
     AND (o.access_labels @> s.match_access_labels) IS DISTINCT FROM (($4::jsonb->'access_labels') @> s.match_access_labels))
   OR (s.container_type IS NOT DISTINCT FROM $1::text AND s.container_arm='labels'
     AND (o.labels @> s.container_match_labels) IS DISTINCT FROM (($4::jsonb->'labels') @> s.container_match_labels))
   OR (s.container_type IS NOT DISTINCT FROM $1::text AND s.container_arm='access_labels'
     AND (o.access_labels @> s.container_match_access_labels) IS DISTINCT FROM (($4::jsonb->'access_labels') @> s.container_match_access_labels)))`
	match := changes
	if k.kind == resourceSourceMetadataBindingCoverage {
		match = `((s.object_types @> ARRAY[$1::text]
     AND (s.arm='anchor' OR (s.arm='names' AND $2=ANY(s.resource_names))
       OR (s.arm='labels' AND (o.labels @> s.match_labels OR ($4::jsonb->'labels') @> s.match_labels))
       OR (s.arm='access_labels' AND (o.access_labels @> s.match_access_labels
         OR ($4::jsonb->'access_labels') @> s.match_access_labels))))
     OR (s.container_type=$1
     AND (s.container_arm='anchor' OR (s.container_arm='names' AND $2=ANY(s.container_resource_names))
       OR (s.container_arm='labels' AND (o.labels @> s.container_match_labels
         OR ($4::jsonb->'labels') @> s.container_match_labels))
       OR (s.container_arm='access_labels' AND (o.access_labels @> s.container_match_access_labels
         OR ($4::jsonb->'access_labels') @> s.container_match_access_labels)))))`
	}
	query := `SELECT jsonb_build_array(b.xmin::text,b.ctid::text,to_jsonb(b),
  s.xmin::text,s.ctid::text,to_jsonb(s),` + root.witness + `)::text,
  jsonb_build_object('binding_id',b.id,'changes',` + changes + `)::text
 FROM kaname.role_rule_selectors s
 JOIN kaname.access_bindings b ON b.role_id=s.role_id
 ` + root.join + `
 WHERE ` + scope + `
   AND ` + match + `
 LIMIT $3`
	return query, args, nil
}

type metadataGrantCapture struct {
	root               domain.ResourceRef
	mirrorPolicyGlobal bool
	retained           *metadataRetainedRR
	source             *resourceSourceCapture
	accounts           []string
	epoch              string
	before             granteffect.MetadataObject
	after              granteffect.MetadataObject
	bindings           []grantpolicy.MetadataBinding
	roles              []domain.RoleID
	projected          map[domain.RoleID]error
}

func captureMetadataGrant(ctx context.Context, tx pgx.Tx, bundle *granteffect.Bundle, request metadataMutation,
	scope mirrorMetadataScope, rootRows int, oldRow, newLabels, newAccessLabels json.RawMessage,
) (*metadataGrantCapture, error) {
	if request.table != "resource_mirror" && len(newLabels) == 0 && len(newAccessLabels) == 0 {
		return nil, nil
	}
	dotted := request.catalogType()
	user := request.kind == "user" && request.table == "users" && request.typ == "iam_user" &&
		request.mode == metadataMutationAccessLabels
	if user {
		// Открытие транзакции User проверяет собственный контракт. Обычный
		// metadata writer пока не принимает эту таблицу в nativeCatalogType.
		dotted = "iam.user"
	}
	if dotted == "" {
		return nil, kaname.ErrSourceUnconfirmed
	}
	var old struct {
		CreatorType   *domain.SubjectType `json:"created_by_type"`
		CreatorID     *domain.SubjectID   `json:"created_by_id"`
		ID            string              `json:"id"`
		Account       string              `json:"account_id"`
		ObjectType    string              `json:"object_type"`
		ObjectID      string              `json:"object_id"`
		ParentAccount string              `json:"parent_account_id"`
		ParentProject string              `json:"parent_project_id"`
		Labels        json.RawMessage     `json:"labels"`
		AccessLabels  json.RawMessage     `json:"access_labels"`
	}
	if err := json.Unmarshal(oldRow, &old); err != nil {
		return nil, err
	}
	if len(old.Labels) == 0 || len(old.AccessLabels) == 0 {
		return nil, kaname.ErrSourceUnconfirmed
	}
	account := old.Account
	switch request.table {
	case "resource_mirror":
		if old.ObjectType != dotted || old.ObjectID != request.id || old.ParentProject != scope.project ||
			(old.ParentAccount != "" && old.ParentAccount != scope.account) {
			return nil, kaname.ErrSourceUnconfirmed
		}
		account = scope.account
	default:
		if old.ID != request.id {
			return nil, kaname.ErrSourceUnconfirmed
		}
		if request.kind == "account" {
			account = old.ID
		}
	}
	before, err := unmarshalLabels(old.Labels)
	if err != nil {
		return nil, err
	}
	beforeAccess, err := unmarshalLabels(old.AccessLabels)
	if err != nil {
		return nil, err
	}
	// A nil patch preserves its own OLD map; changing one map never clears the other.
	if len(newLabels) == 0 {
		newLabels = old.Labels
	}
	if len(newAccessLabels) == 0 {
		newAccessLabels = old.AccessLabels
	}
	after, err := unmarshalLabels(newLabels)
	if err != nil {
		return nil, err
	}
	afterAccess, err := unmarshalLabels(newAccessLabels)
	if err != nil {
		return nil, err
	}
	unchanged := maps.Equal(before, after) && maps.Equal(beforeAccess, afterAccess)
	if unchanged && request.table != "resource_mirror" {
		return nil, nil
	}
	projection, err := json.Marshal(resourceMetadataProjection{Labels: after, AccessLabels: afterAccess})
	if err != nil {
		return nil, err
	}
	if !user && !nativeQuestionToken(account) {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	lifetime, err := newResourceAttemptLifetime(tx.Conn(), bundle)
	if err != nil {
		return nil, err
	}
	budget := &relverdict.AdministrativeReadBudget{}
	if request.table == "resource_mirror" || user {
		// Повтор может сменить классификацию после нового RR. Бюджет общий для обеих ветвей.
		budget = preparedAdministrativeReadBudget(ctx)
	}
	if err = chargeNativePolicyBudget(budget, rootRows, 0); err != nil {
		return nil, err
	}
	source, err := newResourceSourceCapture(tx, budget, lifetime)
	if err != nil {
		return nil, err
	}
	parents, err := newResourceParentCapture(tx, source)
	if err != nil {
		return nil, err
	}
	accounts := []string{account}
	if user {
		accounts, err = parents.userMembershipAccounts(ctx, request.id)
		if err != nil {
			return nil, err
		}
		// Каждый текущий аккаунт входит в те же RR/RC источники и epoch.
		for _, id := range accounts {
			if err := parents.captureAccount(ctx, id); err != nil {
				return nil, err
			}
		}
	}
	root := domain.ResourceRef{Type: dotted, ID: request.id}
	result := &metadataGrantCapture{
		root:     root,
		source:   source,
		accounts: accounts,
		before:   granteffect.MetadataObject{Type: request.typ, ID: request.id, Labels: before, AccessLabels: beforeAccess},
		after:    granteffect.MetadataObject{Type: request.typ, ID: request.id, Labels: after, AccessLabels: afterAccess},
	}

	if request.kind == "service_account" {
		// NULL/NULL означает доказанное отсутствие legacy creator; частичный факт непригоден.
		if (old.CreatorType == nil) != (old.CreatorID == nil) {
			return nil, kaname.ErrSourceUnconfirmed
		}
		creator := domain.Subject{}
		if old.CreatorType != nil {
			creator = domain.Subject{Type: *old.CreatorType, ID: *old.CreatorID}
			if (creator.Type != domain.SubjectTypeUser && creator.Type != domain.SubjectTypeServiceAccount) ||
				creator.Validate() != nil || !nativeQuestionToken(string(creator.ID)) {
				return nil, kaname.ErrSourceUnconfirmed
			}
		}
		result.before.CreatorKnown, result.after.CreatorKnown = true, true
		result.before.Creator, result.after.Creator = creator, creator
	}
	result.epoch, err = readMetadataBindingEpoch(ctx, tx, budget, accounts)
	if err != nil {
		return nil, err
	}
	if request.table == "resource_mirror" {
		// Наличие receipt определяет режим входа даже для подтверждения no-op.
		rows, err := source.read(ctx, tx, resourceSourceKey{
			kind: resourceSourceMetadataPolicyReceipt, typ: dotted, id: request.id,
		})
		if err != nil {
			return nil, err
		}
		result.mirrorPolicyGlobal = len(rows) != 0
	}
	if unchanged {
		// Даже no-op требует существующего зеркала, владельца и снимка
		// регистрации. Внешний Update проверяет v_update на этой версии.
		if err = source.confirmMetadataMirrorScope(ctx, tx, dotted, request.id); err != nil {
			return nil, err
		}
		if err = source.seal(); err != nil {
			return nil, err
		}
		return result, nil
	}
	if !maps.Equal(beforeAccess, afterAccess) {
		// Перечитывается вместе с остальными RR-источниками после ожиданий.
		// Даже пустой результат фиксирует проверенную область.
		result.retained, err = captureMetadataRetainedRR(ctx, parents, root, string(projection))
		if err != nil {
			return nil, err
		}
	}
	changed, err := source.read(ctx, tx, resourceSourceKey{
		kind: resourceSourceMetadataBindings, typ: dotted, id: request.id, projection: string(projection),
	})
	if err != nil {
		return nil, err
	}
	authored, err := source.read(ctx, tx, resourceSourceKey{
		kind: resourceSourceMetadataAuthoredBindings, typ: dotted, id: request.id, projection: string(projection),
	})
	if err != nil {
		return nil, err
	}
	authoredChanged := false
	for _, row := range authored {
		var coordinate struct {
			BindingID string `json:"binding_id"`
			Changes   *bool  `json:"changes"`
		}
		if json.Unmarshal(row.value, &coordinate) != nil || !nativeQuestionToken(coordinate.BindingID) || coordinate.Changes == nil {
			return nil, kaname.ErrSourceUnconfirmed
		}
		authoredChanged = authoredChanged || *coordinate.Changes
	}
	if len(changed) == 0 && !authoredChanged {
		if err = source.seal(); err != nil {
			return nil, err
		}
		return result, nil
	}
	// Только при смене членства нужны старые покрытия от неизменных привязок.
	// Пустой результат первого прохода также будет проверен в RC.
	coverage, err := source.read(ctx, tx, resourceSourceKey{
		kind: resourceSourceMetadataBindingCoverage, typ: dotted, id: request.id, projection: string(projection),
	})
	if err != nil {
		return nil, err
	}
	ids := make(map[string]bool)
	changes := make(map[string]bool)
	for _, rows := range [][]resourceSourceRow{changed, authored, coverage} {
		for _, row := range rows {
			var coordinate struct {
				BindingID string `json:"binding_id"`
				Changes   *bool  `json:"changes"`
			}
			if json.Unmarshal(row.value, &coordinate) != nil || !nativeQuestionToken(coordinate.BindingID) || coordinate.Changes == nil {
				return nil, kaname.ErrSourceUnconfirmed
			}
			ids[coordinate.BindingID] = true
			changes[coordinate.BindingID] = changes[coordinate.BindingID] || *coordinate.Changes
		}
	}
	out := resourceOutputCapture{bindings: make(map[string]domain.AccessBinding), roles: make(map[string]domain.Role)}
	if err = out.captureBindings(ctx, parents, ids); err != nil {
		return nil, err
	}
	pendingRoles := make(map[domain.RoleID]bool)
	for id, role := range out.roles {
		result.roles = append(result.roles, role.ID)
		pending, err := source.read(ctx, tx, resourceSourceKey{kind: resourceSourceRolePendingVerbs, typ: "role", id: id})
		if err != nil {
			return nil, err
		}
		pendingRoles[role.ID] = len(pending) != 0
	}
	slices.Sort(result.roles)
	for _, id := range resourceSortedSet(ids) {
		binding, exists := out.bindings[id]
		role, known := out.roles[string(binding.RoleID)]
		if !exists || !known || binding.RevokedAt != nil ||
			(binding.Status != domain.AccessBindingStatusActive && binding.Status != domain.AccessBindingStatusPending) {
			return nil, kaname.ErrSourceUnconfirmed
		}
		if role.Lifecycle.State == domain.RoleLifecycleWithdrawn {
			continue
		}
		if pendingRoles[role.ID] {
			if changes[id] {
				return nil, kaname.ErrSourceUnconfirmed
			}
			continue
		}
		record, err := source.read(ctx, tx, resourceSourceKey{kind: resourceSourceBinding, typ: "binding", id: id})
		if err != nil {
			return nil, err
		}
		var carrier struct {
			CapabilityVersion *int `json:"grant_capability_version"`
		}
		if len(record) != 1 || json.Unmarshal(record[0].value, &carrier) != nil ||
			carrier.CapabilityVersion == nil || (*carrier.CapabilityVersion != 0 && *carrier.CapabilityVersion != 1) {
			return nil, kaname.ErrSourceUnconfirmed
		}
		result.bindings = append(result.bindings, grantpolicy.MetadataBinding{
			Binding: granteffect.Binding{SourceID: id, Role: role, Scope: scopeAnchorFor(binding), Target: binding.Target,
				Subjects: binding.Subjects, CapabilityVersion: *carrier.CapabilityVersion},
			Changes: changes[id], Pending: binding.Status == domain.AccessBindingStatusPending, ExpiresAt: binding.ExpiresAt,
		})
	}
	if err = source.seal(); err != nil {
		return nil, err
	}
	return result, nil
}

// Разные dotted могут разрешаться в один модельный тип. Для внешнего
// зеркала проверяем обе координаты и область до использования RR-снимка.
func (s *metadataStage) checkMirrorGrantIdentity() error {
	g := s.grant
	if g == nil || g.source == nil || g.source.lifetime == nil || !g.source.sealed ||
		s.plan == nil || s.plan.nativeBudget == nil || g.source.budget != s.plan.nativeBudget ||
		s.request.catalogType() == "" || g.root != s.request.catalogRef() || s.mirrorAccount == "" || (len(g.accounts) != 1 || g.accounts[0] != s.mirrorAccount) ||
		g.before.Type != s.request.typ || g.after.Type != s.request.typ || g.before.ID != s.request.id || g.after.ID != s.request.id {
		return kaname.ErrSourceUnconfirmed
	}
	return nil
}

func readMetadataBindingEpoch(ctx context.Context, tx pgx.Tx, budget *relverdict.AdministrativeReadBudget, accounts []string) (string, error) {
	if err := chargeNativePolicyBudget(budget, 1+len(accounts), 1); err != nil {
		return "", err
	}
	if accounts == nil {
		// SQL NULL читает сводку всех эпох, а пустой массив — только
		// масштаб поколения и глобальную строку пустой области.
		accounts = []string{}
	}
	var epoch string
	err := tx.QueryRow(ctx, `SELECT kaname.authority_binding_epoch_read($1::text[])::text`, accounts).Scan(&epoch)
	return epoch, err
}

func (c *metadataGrantCapture) recheck(ctx context.Context, w *authorityWriteTx) error {
	if err := c.source.lifetime.prepare(w); err != nil {
		return err
	}
	epoch, err := readMetadataBindingEpoch(ctx, w.tx, c.source.budget, c.accounts)
	if err != nil {
		return err
	}
	if epoch != c.epoch {
		return kaname.ErrAuthorityClassificationChanged
	}
	if c.retained != nil {
		keys := make([]string, 0, len(c.retained.parents.catalogs))
		for key := range c.retained.parents.catalogs {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			if err := c.retained.parents.catalogs[key].recheck(ctx, w.tx, c.source.budget); err != nil {
				return err
			}
		}
	}
	return c.source.recheck(ctx, w)
}

// Чтение полной проекции может ждать DDL. Его выполняют под оградами, но
// до последнего обновления DecisionAt. Статус срока проверяется уже по нему.
func (c *metadataGrantCapture) verifyProjections(ctx context.Context, w *semanticAuthorityWriteTx) error {
	c.projected = make(map[domain.RoleID]error)
	for _, binding := range c.bindings {
		id := binding.Binding.Role.ID
		if _, used := c.projected[id]; used {
			continue
		}
		_, cost, checkErr := w.RoleProjectionCheckpoint(ctx, id)
		if err := w.ChargeSourceRead(cost); err != nil {
			return err
		}
		if checkErr != nil && !errors.Is(checkErr, kaname.ErrSourceUnconfirmed) {
			return checkErr
		}
		c.projected[id] = checkErr
	}
	return ctx.Err()
}

func (c *metadataGrantCapture) authorize(ctx context.Context, w *semanticAuthorityWriteTx, actor domain.Subject) error {
	at := w.AuthorityFence().DecisionAt()
	bindings := make([]grantpolicy.MetadataBinding, 0, len(c.bindings))
	for _, binding := range c.bindings {
		if binding.ExpiresAt != nil && !binding.ExpiresAt.After(at) {
			continue
		}
		err, checked := c.projected[binding.Binding.Role.ID]
		if !checked {
			return kaname.ErrSourceUnconfirmed
		}
		if err != nil {
			if binding.Changes {
				return err
			}
			continue
		}
		bindings = append(bindings, binding)
	}
	return grantpolicy.RequireMetadataGrant(ctx, w, actor, c.before, c.after, bindings)
}
