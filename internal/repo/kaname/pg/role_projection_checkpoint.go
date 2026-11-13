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
	"github.com/jackc/pgx/v5"
)

const maxProjectionRows = 4096

// RoleProjectionCheckpoint сравнивает authored inputs с настоящей role-level
// projection и relevant каталогом. Один SQL snapshot читает все их строки.
// Никакой timestamp/boolean Ready не подменяет сравнение. Старые роли без
// доказанной projection остаются ordinary компонентами с obligation.
func (w *semanticAuthorityWriteTx) RoleProjectionCheckpoint(ctx context.Context, id domain.RoleID) (granteffect.ProjectionCheckpoint, kaname.SourceReadCost, error) {
	cost := kaname.SourceReadCost{Reads: 1}
	// Первый input нужен только для определения relevant modules. Полный снимок
	// ниже перечитывает роль и сравнивает authored digest; смена правил закрыта.
	var preliminary domain.Role
	preliminary.ID = id
	var perms, rules []byte
	err := w.tx.QueryRow(ctx, `SELECT permissions,rules,is_system,coalesce(owner_module,'') FROM kaname.roles WHERE id=$1 AND live`, id).Scan(&perms, &rules, &preliminary.IsSystem, &preliminary.OwnerModule)
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
	expected, err := w.bundle.Projection(preliminary)
	if err != nil {
		return granteffect.ProjectionCheckpoint{}, cost, kaname.ErrSourceUnconfirmed
	}
	var authored, catalogRaw, selectorRaw, verbRaw []byte
	var pending bool
	var snapshotRows int
	cost.Reads++
	err = w.tx.QueryRow(ctx, roleProjectionSnapshotSQL, id, expected.Modules, maxProjectionRows+1).Scan(&authored, &catalogRaw, &selectorRaw, &verbRaw, &pending, &snapshotRows)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			err = kaname.ErrSourceUnconfirmed
		}
		return granteffect.ProjectionCheckpoint{}, cost, err
	}
	// Учёт уже прочитанного снимка предшествует любому recoverable mismatch.
	// Смена authored inputs не делает catalog/selectors/joins бесплатными.
	cost.Rows += snapshotRows
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
	now, err := w.bundle.Projection(current)
	if err != nil || now.Checkpoint != expected.Checkpoint {
		return granteffect.ProjectionCheckpoint{}, cost, kaname.ErrSourceUnconfirmed
	}
	var halves catalog.Halves
	var selectors []domain.RuleSelector
	var verbs []domain.RoleVerb
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
	gotProjection, err := granteffect.ProjectionJSON(selectors, verbs)
	if err != nil {
		return granteffect.ProjectionCheckpoint{}, cost, err
	}
	wantProjection, err := granteffect.ProjectionJSON(expected.Selectors, expected.Verbs)
	if err != nil {
		return granteffect.ProjectionCheckpoint{}, cost, err
	}
	if pending || string(gotCatalog) != string(wantCatalog) || string(gotProjection) != string(wantProjection) {
		return granteffect.ProjectionCheckpoint{}, cost, kaname.ErrSourceUnconfirmed
	}
	// Meta rule rows имеют отдельного producer. Ordinary/legacy эффекты не
	// удаляются; недоказанный meta checkpoint остаётся явным до его адаптера.
	_, caps, err := domain.SplitGrantCapabilityRules(current.Rules)
	if err != nil || len(caps) > 0 {
		return granteffect.ProjectionCheckpoint{}, cost, kaname.ErrSourceUnconfirmed
	}
	return expected.Checkpoint, cost, nil
}

// Имена JSON полей совпадают с domain/catalog; константа Arm берётся из Go,
// чтобы SQL не заводил независимый числовой словарь селекторов.
var roleProjectionSnapshotSQL = strings.NewReplacer("$ARM_ANCHOR", armNumber(domain.ArmAnchor), "$ARM_NAMES", armNumber(domain.ArmNames), "$ARM_LABELS", armNumber(domain.ArmLabels)).Replace(`
WITH module_rows AS (SELECT module,live FROM kaname.catalog_module WHERE module=ANY($2::text[]) LIMIT $3),
 resource_rows AS (SELECT * FROM kaname.catalog_resource WHERE module=ANY($2::text[]) LIMIT $3),
 verb_rows AS (SELECT * FROM kaname.catalog_verb WHERE module=ANY($2::text[]) LIMIT $3),
 selector_rows AS (SELECT * FROM kaname.role_rule_selectors WHERE role_id=$1 LIMIT $3),
 role_verbs AS (SELECT object_type,verb FROM kaname.role_verb WHERE role_id=$1 LIMIT $3),
 pending_rows AS (SELECT role_id FROM kaname.role_selector_verbs_pending WHERE role_id=$1),
 container_checks AS (SELECT s.container_object_type,c.object_type FROM selector_rows s LEFT JOIN kaname.catalog_resource c ON c.dotted=s.container_type AND c.live WHERE s.container_type IS NOT NULL)
SELECT jsonb_build_object('Permissions',r.permissions,'Rules',r.rules,'IsSystem',r.is_system,'OwnerModule',coalesce(r.owner_module,'')),
jsonb_build_object(
 'Live',jsonb_build_object('Modules',coalesce((SELECT jsonb_agg(module) FROM module_rows WHERE live),'[]'),
 'Resources',coalesce((SELECT jsonb_agg(jsonb_build_object('Module',module,'Resource',resource,'ObjectType',object_type,'ParentTypes',parent_types,'ParentNames',parent_names,'Writes',writes,'PublicReadToChildren',public_read_to_children,'PermanentProject',permanent_project)) FROM resource_rows WHERE live),'[]'),
 'Verbs',coalesce((SELECT jsonb_agg(jsonb_build_object('Module',module,'Resource',resource,'Verb',verb,'PerObject',per_object,'ContainerParent',coalesce(container_parent,''),'ContainerRelation',coalesce(container_relation,''))) FROM verb_rows WHERE live),'[]')),
 'Retired',jsonb_build_object('Modules',coalesce((SELECT jsonb_agg(module) FROM module_rows WHERE NOT live),'[]'),
 'Resources',coalesce((SELECT jsonb_agg(jsonb_build_object('Module',module,'Resource',resource,'ObjectType',object_type,'SupersededBy',coalesce(superseded_by,''))) FROM resource_rows WHERE NOT live),'[]'),
 'Verbs',coalesce((SELECT jsonb_agg(jsonb_build_object('Module',module,'Resource',resource,'Verb',verb,'PerObject',per_object,'ContainerParent',coalesce(container_parent,''),'ContainerRelation',coalesce(container_relation,''))) FROM verb_rows WHERE NOT live),'[]'))),
coalesce((SELECT jsonb_agg(jsonb_build_object('RuleFP',rule_fp,'Arm',CASE arm WHEN 'names' THEN $ARM_NAMES WHEN 'labels' THEN $ARM_LABELS ELSE $ARM_ANCHOR END,'ObjectTypes',object_types,'ResourceNames',resource_names,'MatchLabels',match_labels,'Grants',verbs_by_type,'CreatedBySubject',created_by_subject,
 'Container',CASE WHEN container_type IS NULL THEN NULL ELSE jsonb_build_object('Type',container_type,'Arm',CASE container_arm WHEN 'names' THEN $ARM_NAMES WHEN 'labels' THEN $ARM_LABELS ELSE $ARM_ANCHOR END,'ResourceNames',container_resource_names,'MatchLabels',container_match_labels) END)) FROM selector_rows),'[]'),
coalesce((SELECT jsonb_agg(jsonb_build_object('ObjectType',object_type,'Verb',verb)) FROM role_verbs),'[]'),
(EXISTS(SELECT 1 FROM pending_rows)
 OR EXISTS(SELECT 1 FROM container_checks WHERE container_object_type IS DISTINCT FROM object_type)),
 (1+(SELECT count(*) FROM module_rows)+(SELECT count(*) FROM resource_rows)
 +(SELECT count(*) FROM verb_rows)+(SELECT count(*) FROM selector_rows)+(SELECT count(*) FROM role_verbs)
 +(SELECT count(*) FROM pending_rows)+(SELECT count(*) FROM container_checks))::int
FROM kaname.roles r WHERE r.id=$1 AND r.live`)

func armNumber(a domain.Arm) string { b, _ := json.Marshal(a); return string(b) }
