// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/dto"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// Независимо восстанавливаем обогащение чтения из сохранённых строк в ТОЙ ЖЕ транзакции
// RR. Публичный сценарий/обработчик роли, снимок сервера или DTO REST не читаются.
func rid09PrimaryRoles(t *testing.T, ctx context.Context, tx pgx.Tx, facts *catalog.Facts) []map[string]any {
	t.Helper()
	out := []map[string]any{}
	withdrawn := map[domain.RoleID][]domain.WithdrawnGrant{}
	orphanRows := rid09PrimaryRows(t, ctx, tx, "role_grant_orphan")
	sort.Slice(orphanRows, func(i, j int) bool {
		for _, key := range []string{"role_id", "object_type", "verb", "source", "cause"} {
			a, b := rid09PrimaryValue[string](t, orphanRows[i], key), rid09PrimaryValue[string](t, orphanRows[j], key)
			if a != b {
				return a < b
			}
		}
		return false
	})
	for _, r := range orphanRows {
		g := domain.WithdrawnGrant{ObjectType: rid09PrimaryValue[string](t, r, "object_type"), Verb: rid09PrimaryValue[string](t, r, "verb"), Reason: rid09PrimaryValue[string](t, r, "reason"), WithdrawnAt: rid09PrimaryValue[time.Time](t, r, "orphaned_at").Truncate(time.Second), AppliedBy: rid09PrimaryValue[string](t, r, "applied_by")}
		switch rid09PrimaryValue[string](t, r, "source") {
		case "role_verb":
			g.Source = domain.WithdrawnGrantSourceGrant
		case "rule_ref":
			g.Source = domain.WithdrawnGrantSourceRuleRef
		default:
			t.Fatal("unknown primary withdrawal source")
		}
		switch rid09PrimaryValue[string](t, r, "cause") {
		case "catalog_retired":
			g.Cause = domain.WithdrawnGrantCauseCatalogRetired
		case "role_retired":
			g.Cause = domain.WithdrawnGrantCauseRoleRetired
		default:
			t.Fatal("unknown primary withdrawal cause")
		}
		id := rid09PrimaryValue[domain.RoleID](t, r, "role_id")
		withdrawn[id] = append(withdrawn[id], g)
	}
	pruned := map[domain.RoleID][]domain.PrunedSelectorType{}
	// Хранилище может различаться дайджестом правила, тогда как публичная семантика использует DISTINCT по
	// следующим шести полям (ровно та же проекция, что в документированном контракте чтения).
	rows, err := tx.Query(ctx, `SELECT DISTINCT role_id,object_type,outcome,COALESCE(retired_reason,''),pruned_at,applied_by FROM kaname.role_selector_prune ORDER BY role_id,object_type,outcome`)
	require.NoError(t, err)
	for rows.Next() {
		var id, outcome string
		var p domain.PrunedSelectorType
		require.NoError(t, rows.Scan(&id, &p.ObjectType, &outcome, &p.Reason, &p.PrunedAt, &p.AppliedBy))
		p.PrunedAt = p.PrunedAt.Truncate(time.Second)
		switch outcome {
		case "shortened":
			p.Outcome = domain.SelectorPruneOutcomeShortened
		case "dropped":
			p.Outcome = domain.SelectorPruneOutcomeDropped
		default:
			t.Fatal("unknown primary prune outcome")
		}
		pruned[domain.RoleID(id)] = append(pruned[domain.RoleID(id)], p)
	}
	require.NoError(t, rows.Err())
	rows.Close()
	for _, r := range rid09PrimaryRows(t, ctx, tx, "roles") {
		d := domain.Role{ID: rid09PrimaryValue[domain.RoleID](t, r, "id"), ClusterID: rid09PrimaryValue[domain.ClusterID](t, r, "cluster_id"), AccountID: rid09PrimaryValue[domain.AccountID](t, r, "account_id"), ProjectID: rid09PrimaryValue[domain.ProjectID](t, r, "project_id"), Name: rid09PrimaryValue[domain.RoleName](t, r, "name"), Description: rid09PrimaryValue[domain.Description](t, r, "description"), IsSystem: rid09PrimaryValue[bool](t, r, "is_system"), OwnerModule: rid09PrimaryValue[string](t, r, "owner_module"), CreatedAt: rid09PrimaryValue[time.Time](t, r, "created_at"), UpdatedAt: rid09PrimaryValue[time.Time](t, r, "updated_at"), Labels: rid09PrimaryValue[domain.Labels](t, r, "labels")}
		d.Rules, err = domain.DecodeRules(r["rules"])
		require.NoError(t, err)
		// CreatedByUserID намеренно не является столбцом roles, читаемым roleCols. Его
		// нулевое значение соответствует настоящему чтению из хранилища в домен, а не выдуманному участнику.
		declared := domain.SegmentsOf(d.ID, d.Rules)
		unresolved := []domain.RoleSegment{}
		for _, seg := range declared {
			if _, container := facts.ContainerVerb(seg.ObjectType, seg.Verb); container {
				continue
			}
			var present bool
			require.NoError(t, tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM kaname.role_verb WHERE role_id=$1 AND object_type=$2 AND ($3='' OR verb=$3))`, string(d.ID), seg.ObjectType, seg.Verb).Scan(&present))
			if !present {
				unresolved = append(unresolved, seg)
			}
		}
		d.Integrity = domain.HealthOf(len(declared), len(unresolved))
		d.Withdrawn = withdrawn[d.ID]
		d.PrunedSelectorTypes = pruned[d.ID]
		d.TypeVerbs = facts.RolePreviewLookup()
		d.RuleStates = domain.RuleStatesOf(d.Rules, unresolved, d.Withdrawn)
		d.Lifecycle = domain.RoleLifecycle{State: domain.RoleLifecycleDeclared}
		if !rid09PrimaryValue[bool](t, r, "live") {
			d.Lifecycle.State = domain.RoleLifecycleWithdrawn
		}
		if at := rid09PrimaryValue[*time.Time](t, r, "retired_at"); at != nil {
			d.Lifecycle.RetiredAt = at.Truncate(time.Second)
		}
		d.Lifecycle.RetiredReason = rid09PrimaryValue[string](t, r, "retired_reason")
		d.Lifecycle.RetiredBy = rid09PrimaryValue[string](t, r, "retired_by")
		var pb *iamv1.Role
		require.NoError(t, dto.Transfer(dto.FromTo(d, &pb)))
		out = append(out, rid09PrimaryJSON(t, pb))
	}
	return out
}
