// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const maxProjectionRows = 4096

// RoleProjectionCheckpoint сравнивает authored inputs с настоящей role-level
// projection и relevant каталогом. Один SQL snapshot читает все их строки.
// Никакой timestamp/boolean Ready не подменяет сравнение. Старые роли без
// доказанной projection остаются ordinary компонентами с obligation.
func (w *semanticAuthorityWriteTx) RoleProjectionCheckpoint(ctx context.Context, id domain.RoleID) (granteffect.ProjectionCheckpoint, kaname.SourceReadCost, error) {
	return w.roleProjectionCheckpoint(ctx, id, nil)
}

func (w *semanticAuthorityWriteTx) roleProjectionCheckpoint(ctx context.Context, id domain.RoleID, source *kaname.RoleProjectionSourceSnapshot) (granteffect.ProjectionCheckpoint, kaname.SourceReadCost, error) {
	budget := w.producerBudget
	if w.nativeRead != nil {
		budget = w.nativeRead.budget
	} else if budget == nil {
		// Вне общей попытки остаётся локальный предел maxProjectionRows.
		budget = &relverdict.AdministrativeReadBudget{}
	}
	return readRoleProjectionCheckpoint(ctx, w.tx, w.bundle, id, budget, source)
}

func readRoleProjectionCheckpoint(ctx context.Context, tx pgx.Tx, bundle *granteffect.Bundle, id domain.RoleID,
	budget *relverdict.AdministrativeReadBudget, source *kaname.RoleProjectionSourceSnapshot,
) (granteffect.ProjectionCheckpoint, kaname.SourceReadCost, error) {
	cost := kaname.SourceReadCost{Reads: 1}
	// Первый input нужен только для определения relevant modules. Полный снимок
	// ниже перечитывает роль и сравнивает authored digest; смена правил закрыта.
	var preliminary domain.Role
	preliminary.ID = id
	var perms, rules []byte
	err := tx.QueryRow(ctx, `SELECT permissions,rules,is_system,coalesce(owner_module,'') FROM kaname.roles WHERE id=$1 AND live`, id).Scan(&perms, &rules, &preliminary.IsSystem, &preliminary.OwnerModule)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			err = kaname.ErrSourceUnconfirmed
		}
		return granteffect.ProjectionCheckpoint{}, cost, err
	}
	cost.Rows++
	if err = scanRolePolicy(&preliminary, perms, rules); err != nil {
		return granteffect.ProjectionCheckpoint{}, cost, err
	}
	expected, err := bundle.Projection(preliminary)
	if err != nil {
		return granteffect.ProjectionCheckpoint{}, cost, kaname.ErrSourceUnconfirmed
	}
	var authored, catalogRaw, selectorRaw, verbRaw, capsRaw []byte
	var pending bool
	var snapshotRows int
	var accessLabelRaw []byte
	var roleXmin, roleCTID string
	var hasProtectedApply bool
	for _, cap := range expected.Capabilities {
		if cap.Kind == domain.GrantCapabilityApplyAccessLabel {
			hasProtectedApply = true
			break
		}
	}
	rowsLeft := maxProjectionRows - cost.Rows
	if hasProtectedApply {
		if budget == nil {
			return granteffect.ProjectionCheckpoint{}, cost, kaname.ErrSourceUnconfirmed
		}
		rowsLeft = min(rowsLeft, budget.RemainingRows()-cost.Rows)
		if budget.RemainingReads() < cost.Reads+4 {
			return granteffect.ProjectionCheckpoint{}, cost, kaname.ErrSourceReadLimit
		}
		if rowsLeft < 3 {
			return granteffect.ProjectionCheckpoint{}, cost, kaname.ErrSourceReadLimit
		}
		// Основной оператор и три вложенных чтения. Этот путь нужен лишь
		// когда правила объявляют apply. Обычные роли стоят прежние два чтения.
		cost.Reads += 4
		err = tx.QueryRow(ctx, roleProjectionWithAccessLabelsSQL, id, expected.Modules, rowsLeft+1, rowsLeft).
			Scan(&authored, &catalogRaw, &selectorRaw, &verbRaw, &capsRaw, &pending, &snapshotRows, &accessLabelRaw)
	} else {
		cost.Reads++
		err = tx.QueryRow(ctx, roleProjectionSnapshotSQL, id, expected.Modules, maxProjectionRows+1).
			Scan(&authored, &catalogRaw, &selectorRaw, &verbRaw, &capsRaw, &pending, &snapshotRows)
	}
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			err = kaname.ErrSourceUnconfirmed
		}
		var rejected *pgconn.PgError
		if hasProtectedApply && errors.As(err, &rejected) && rejected.Code == "54000" {
			// SQL уже мог прочитать строки до сигнала о пределе. Не выдаём
			// предварительное чтение за полную стоимость такого отказа.
			cost.Rows += rowsLeft + 1
			err = kaname.ErrSourceReadLimit
		}
		return granteffect.ProjectionCheckpoint{}, cost, err
	}
	// Учёт уже прочитанного снимка предшествует любому recoverable mismatch.
	// Смена authored inputs не делает catalog/selectors/joins бесплатными.
	cost.Rows += snapshotRows
	if hasProtectedApply {
		var check struct {
			Matches *bool  `json:"matches"`
			Rows    int    `json:"rows"`
			Reads   int    `json:"reads"`
			Limited bool   `json:"limited"`
			RowXmin string `json:"row_xmin"`
			RowCTID string `json:"row_ctid"`
		}
		if err = json.Unmarshal(accessLabelRaw, &check); err != nil {
			return granteffect.ProjectionCheckpoint{}, cost, err
		}
		if check.Limited {
			cost.Reads -= 3
			return granteffect.ProjectionCheckpoint{}, cost, kaname.ErrSourceReadLimit
		}
		if check.Matches == nil || check.Rows < 1 || check.Reads < 1 || check.Reads > 3 {
			return granteffect.ProjectionCheckpoint{}, cost, kaname.ErrSourceUnconfirmed
		}
		cost.Reads -= 3 - check.Reads
		cost.Rows += check.Rows
		if snapshotRows+check.Rows > rowsLeft {
			return granteffect.ProjectionCheckpoint{}, cost, kaname.ErrSourceReadLimit
		}
		if !*check.Matches {
			return granteffect.ProjectionCheckpoint{}, cost, kaname.ErrSourceUnconfirmed
		}
		roleXmin, roleCTID = check.RowXmin, check.RowCTID
		if source != nil && (roleXmin == "" || roleCTID == "") {
			return granteffect.ProjectionCheckpoint{}, cost, kaname.ErrSourceUnconfirmed
		}
	}
	if cost.Rows > maxProjectionRows {
		return granteffect.ProjectionCheckpoint{}, cost, kaname.ErrSourceReadLimit
	}
	var current domain.Role
	current.ID = id
	var record struct {
		Permissions json.RawMessage
		Rules       json.RawMessage
		IsSystem    bool
		OwnerModule string
	}
	if err = json.Unmarshal(authored, &record); err != nil {
		return granteffect.ProjectionCheckpoint{}, cost, err
	}
	current.IsSystem, current.OwnerModule = record.IsSystem, record.OwnerModule
	if err = scanRolePolicy(&current, record.Permissions, record.Rules); err != nil {
		return granteffect.ProjectionCheckpoint{}, cost, err
	}
	now, err := bundle.Projection(current)
	if err != nil || now.Checkpoint != expected.Checkpoint {
		return granteffect.ProjectionCheckpoint{}, cost, kaname.ErrSourceUnconfirmed
	}
	var halves catalog.Halves
	var selectors []domain.RuleSelector
	var verbs []domain.RoleVerb
	var caps []domain.GrantCapabilityRule
	if err = json.Unmarshal(capsRaw, &caps); err != nil {
		return granteffect.ProjectionCheckpoint{}, cost, err
	}
	if err = json.Unmarshal(catalogRaw, &halves); err != nil {
		return granteffect.ProjectionCheckpoint{}, cost, err
	}
	if err = json.Unmarshal(selectorRaw, &selectors); err != nil {
		return granteffect.ProjectionCheckpoint{}, cost, err
	}
	if err = json.Unmarshal(verbRaw, &verbs); err != nil {
		return granteffect.ProjectionCheckpoint{}, cost, err
	}
	gotCatalog, err := catalog.CanonicalJSON(halves)
	if err != nil {
		return granteffect.ProjectionCheckpoint{}, cost, err
	}
	wantCatalog, err := catalog.CanonicalJSON(expected.Catalog)
	if err != nil {
		return granteffect.ProjectionCheckpoint{}, cost, err
	}
	// Закрытая проекция сверена для того же OLD роли. Добавляем вычисленные
	// apply capabilities в общий снимок только после подтверждения равенства.
	if hasProtectedApply {
		for _, cap := range now.Capabilities {
			if cap.Kind == domain.GrantCapabilityApplyAccessLabel {
				caps = append(caps, cap)
			}
		}
	}
	gotProjection, err := granteffect.ProjectionJSON(selectors, verbs, caps)
	if err != nil {
		return granteffect.ProjectionCheckpoint{}, cost, err
	}
	wantProjection, err := granteffect.ProjectionJSON(expected.Selectors, expected.Verbs, expected.Capabilities)
	if err != nil {
		return granteffect.ProjectionCheckpoint{}, cost, err
	}
	if pending || string(gotCatalog) != string(wantCatalog) || string(gotProjection) != string(wantProjection) {
		return granteffect.ProjectionCheckpoint{}, cost, kaname.ErrSourceUnconfirmed
	}
	// Поколения публикуются лишь после ВСЕХ прежних сравнений projection/catalog.
	// Они наблюдались тем же SQL snapshot; новых чтений и row locks здесь нет.
	if source != nil && hasProtectedApply {
		*source = kaname.RoleProjectionSourceSnapshot{RoleID: id, Checkpoint: expected.Checkpoint, RowXmin: roleXmin, RowCTID: roleCTID}
	}
	return expected.Checkpoint, cost, nil
}

// Имена JSON полей совпадают с domain/catalog; константа Arm берётся из Go,
// чтобы SQL не заводил независимый числовой словарь селекторов.
var roleProjectionColumnsSQL = strings.NewReplacer("$ARM_ANCHOR", armNumber(domain.ArmAnchor), "$ARM_NAMES", armNumber(domain.ArmNames), "$ARM_LABELS", armNumber(domain.ArmLabels), "$ARM_ACCESS_LABELS", armNumber(domain.ArmAccessLabels)).Replace(`
WITH module_rows AS (SELECT module,live FROM kaname.catalog_module WHERE module=ANY($2::text[]) LIMIT $3),
 resource_rows AS (SELECT * FROM kaname.catalog_resource WHERE module=ANY($2::text[]) LIMIT $3),
 verb_rows AS (SELECT * FROM kaname.catalog_verb WHERE module=ANY($2::text[]) LIMIT $3),
 selector_rows AS (SELECT * FROM kaname.role_rule_selectors WHERE role_id=$1 LIMIT $3),
 role_verbs AS (SELECT object_type,verb FROM kaname.role_verb WHERE role_id=$1 LIMIT $3),
 create_rows AS (SELECT role_id,rule_fp FROM kaname.role_create_binding_rule WHERE role_id=$1 LIMIT $3),
 bind_rows AS (SELECT role_id,rule_fp,bound_role_id FROM kaname.role_bind_role_rule WHERE role_id=$1 LIMIT $3),
 bind_checks AS (SELECT b.*,t.id AS target_id,t.live AS target_live,
   (r.is_system OR t.is_system OR (coalesce(r.account_id,p.account_id)=coalesce(t.account_id,tp.account_id)
     AND (r.project_id IS NULL OR t.project_id IS NULL OR r.project_id=t.project_id))) AS common_anchor,
   ((t.id IS NOT NULL)::int+(p.id IS NOT NULL)::int+(tp.id IS NOT NULL)::int) AS joined_rows
   FROM bind_rows b JOIN kaname.roles r ON r.id=b.role_id
   LEFT JOIN kaname.roles t ON t.id=b.bound_role_id
   LEFT JOIN kaname.projects p ON p.id=r.project_id LEFT JOIN kaname.projects tp ON tp.id=t.project_id),
 pending_rows AS (SELECT role_id FROM kaname.role_selector_verbs_pending WHERE role_id=$1),
 container_checks AS (SELECT s.container_object_type,c.object_type FROM selector_rows s LEFT JOIN kaname.catalog_resource c ON c.dotted=s.container_type AND c.live WHERE s.container_type IS NOT NULL)
SELECT jsonb_build_object('Permissions',r.permissions,'Rules',r.rules,'IsSystem',r.is_system,'OwnerModule',coalesce(r.owner_module,'')),
jsonb_build_object(
 'Live',jsonb_build_object('Modules',coalesce((SELECT jsonb_agg(module) FROM module_rows WHERE live),'[]'),
 'Resources',coalesce((SELECT jsonb_agg(jsonb_build_object('Module',module,'Resource',resource,'ObjectType',object_type,'ParentTypes',parent_types,'ParentNames',parent_names,'Writes',writes,'PublicReadToChildren',public_read_to_children,'PermanentProject',permanent_project,'ChildRegistration',child_registration)) FROM resource_rows WHERE live),'[]'),
 'Verbs',coalesce((SELECT jsonb_agg(jsonb_build_object('Module',module,'Resource',resource,'Verb',verb,'PerObject',per_object,'ContainerParent',coalesce(container_parent,''),'ContainerRelation',coalesce(container_relation,''))) FROM verb_rows WHERE live),'[]')),
 'Retired',jsonb_build_object('Modules',coalesce((SELECT jsonb_agg(module) FROM module_rows WHERE NOT live),'[]'),
 'Resources',coalesce((SELECT jsonb_agg(jsonb_build_object('Module',module,'Resource',resource,'ObjectType',object_type,'SupersededBy',coalesce(superseded_by,''),'ChildRegistration',child_registration)) FROM resource_rows WHERE NOT live),'[]'),
 'Verbs',coalesce((SELECT jsonb_agg(jsonb_build_object('Module',module,'Resource',resource,'Verb',verb,'PerObject',per_object,'ContainerParent',coalesce(container_parent,''),'ContainerRelation',coalesce(container_relation,''))) FROM verb_rows WHERE NOT live),'[]'))),
coalesce((SELECT jsonb_agg(jsonb_build_object('RuleFP',rule_fp,'Arm',CASE arm WHEN 'names' THEN $ARM_NAMES WHEN 'labels' THEN $ARM_LABELS WHEN 'access_labels' THEN $ARM_ACCESS_LABELS WHEN 'anchor' THEN $ARM_ANCHOR ELSE -1 END,'ObjectTypes',object_types,'ResourceNames',resource_names,'MatchLabels',match_labels,'MatchAccessLabels',match_access_labels,'Grants',verbs_by_type,'CreatedBySubject',created_by_subject,
 'Container',CASE WHEN container_type IS NULL THEN NULL ELSE jsonb_build_object('Type',container_type,'Arm',CASE container_arm WHEN 'names' THEN $ARM_NAMES WHEN 'labels' THEN $ARM_LABELS WHEN 'access_labels' THEN $ARM_ACCESS_LABELS WHEN 'anchor' THEN $ARM_ANCHOR ELSE -1 END,'ResourceNames',container_resource_names,'MatchLabels',container_match_labels,'MatchAccessLabels',container_match_access_labels) END)) FROM selector_rows),'[]'),
coalesce((SELECT jsonb_agg(jsonb_build_object('ObjectType',object_type,'Verb',verb)) FROM role_verbs),'[]'),
coalesce((SELECT jsonb_agg(c) FROM (
 SELECT jsonb_build_object('RuleFP',rule_fp,'Kind','create_binding','BoundRoleID','') AS c FROM create_rows
 UNION ALL SELECT jsonb_build_object('RuleFP',rule_fp,'Kind','bind_role','BoundRoleID',bound_role_id) FROM bind_rows) q),'[]'),
(EXISTS(SELECT 1 FROM pending_rows)
 OR EXISTS(SELECT 1 FROM bind_checks WHERE target_live IS DISTINCT FROM true OR common_anchor IS DISTINCT FROM true)
 OR EXISTS(SELECT 1 FROM container_checks WHERE container_object_type IS DISTINCT FROM object_type)),
 (1+(SELECT count(*) FROM module_rows)+(SELECT count(*) FROM resource_rows)
 +(SELECT count(*) FROM verb_rows)+(SELECT count(*) FROM selector_rows)+(SELECT count(*) FROM role_verbs)
 +(SELECT count(*) FROM pending_rows)+(SELECT count(*) FROM container_checks)
 +(SELECT count(*) FROM create_rows)+(SELECT count(*) FROM bind_rows)
 +(SELECT coalesce(sum(1+joined_rows),0) FROM bind_checks))::int`)

const roleProjectionSourceSQL = `
FROM kaname.roles r WHERE r.id=$1 AND r.live`

var roleProjectionSnapshotSQL = roleProjectionColumnsSQL + roleProjectionSourceSQL

// Обычный запрос сохраняет прежнюю форму. В запросе для apply добавляются
// физические координаты строки и вызов STABLE внутри того же снимка.
var roleProjectionWithAccessLabelsSQL = `WITH snapshot(authored,catalog_data,selectors,verbs,caps,pending,logical_rows,row_xmin,row_ctid) AS MATERIALIZED (` + roleProjectionColumnsSQL + `,r.xmin::text,r.ctid::text` + roleProjectionSourceSQL + `)
SELECT s.authored,s.catalog_data,s.selectors,s.verbs,s.caps,s.pending,s.logical_rows,
 (CASE WHEN s.logical_rows > $4::integer-2 THEN jsonb_build_object('limited',true)
 ELSE kaname.authority_access_label_role_checkpoint_read_v1(
   $1::text,s.row_xmin,s.row_ctid,$4::integer-s.logical_rows) END)
 || jsonb_build_object('row_xmin',s.row_xmin,'row_ctid',s.row_ctid)
FROM snapshot s`

func armNumber(a domain.Arm) string { b, _ := json.Marshal(a); return string(b) }
