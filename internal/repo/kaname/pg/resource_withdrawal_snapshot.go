// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"encoding/json"
	"slices"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	abrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/resourceeffect"
)

// Преобразование читает исключительно уже захваченные строки. Отсутствующий
// predicate witness отличается от доказанного пустого результата; никаких
// дополнительных SQL-запросов или фильтра по текущему времени здесь нет.
func (c *resourceWithdrawalCapture) snapshot() (resourceeffect.WithdrawalSnapshot, error) {
	var result resourceeffect.WithdrawalSnapshot
	if c == nil || c.source == nil || c.source.lifetime == nil || c.source.lifetime.ended {
		return result, kaname.ErrSourceUnconfirmed
	}
	for _, id := range resourceSortedSet(c.targetBindings) {
		rows, ok := c.bindings[id]
		if !ok || len(rows) != 1 {
			return result, kaname.ErrSourceUnconfirmed
		}
		binding, err := resourceCapturedBinding(rows[0].value)
		if err != nil {
			return result, err
		}
		if string(binding.ID) != id {
			return result, kaname.ErrSourceUnconfirmed
		}
		subjects, ok := c.source.entries[resourceSourceKey{kind: resourceSourceBindingSubjects, typ: "binding", id: id}]
		if !ok {
			return result, kaname.ErrSourceUnconfirmed
		}
		type subjectRow struct {
			BindingID string             `json:"binding_id"`
			Type      domain.SubjectType `json:"subject_type"`
			ID        domain.SubjectID   `json:"subject_id"`
			Ordinal   int                `json:"ordinal"`
		}
		decoded, err := resourceDecodeRows[subjectRow](subjects)
		if err != nil {
			return result, err
		}
		slices.SortFunc(decoded, func(a, b subjectRow) int {
			if a.Ordinal < b.Ordinal {
				return -1
			}
			if a.Ordinal > b.Ordinal {
				return 1
			}
			if a.Type < b.Type {
				return -1
			}
			if a.Type > b.Type {
				return 1
			}
			if a.ID < b.ID {
				return -1
			}
			if a.ID > b.ID {
				return 1
			}
			return 0
		})
		subjectsOut := make([]domain.Subject, 0, len(decoded))
		seen := make(map[domain.Subject]bool, len(decoded))
		for _, s := range decoded {
			subject := domain.Subject{Type: s.Type, ID: s.ID}
			if s.BindingID != id || s.ID == "" || s.Type == "" || seen[subject] {
				return result, kaname.ErrSourceUnconfirmed
			}
			seen[subject] = true
			subjectsOut = append(subjectsOut, subject)
		}
		ledger, ok := c.source.entries[resourceSourceKey{kind: resourceSourceBindingLedger, typ: "binding", id: id}]
		if !ok {
			return result, kaname.ErrSourceUnconfirmed
		}
		type ledgerRow struct {
			BindingID string `json:"binding_id"`
			User      string `json:"fga_user"`
			Relation  string `json:"relation"`
			Object    string `json:"object"`
		}
		emitted, err := resourceDecodeRows[ledgerRow](ledger)
		if err != nil {
			return result, err
		}
		tuples := make([]abrepo.RelationTuple, 0, len(emitted))
		seenTuples := make(map[abrepo.RelationTuple]bool, len(emitted))
		for _, row := range emitted {
			t := abrepo.RelationTuple{User: row.User, Relation: row.Relation, Object: row.Object}
			if row.BindingID != id || row.User == "" || row.Relation == "" || row.Object == "" {
				return result, kaname.ErrSourceUnconfirmed
			}
			// Одинаковый кортеж нескольких materialized members удаляется один раз,
			// как в существующем SelectEmittedTuples с SELECT DISTINCT.
			if !seenTuples[t] {
				seenTuples[t] = true
				tuples = append(tuples, t)
			}
		}
		slices.SortFunc(tuples, func(a, b abrepo.RelationTuple) int {
			if a.Relation < b.Relation {
				return -1
			}
			if a.Relation > b.Relation {
				return 1
			}
			if a.Object < b.Object {
				return -1
			}
			if a.Object > b.Object {
				return 1
			}
			if a.User < b.User {
				return -1
			}
			if a.User > b.User {
				return 1
			}
			return 0
		})
		binding.Subjects = append([]domain.Subject(nil), subjectsOut...)
		result.Bindings = append(result.Bindings, resourceeffect.WithdrawalBinding{Binding: binding, Subjects: subjectsOut, Emitted: tuples})
	}
	for _, id := range resourceSortedSet(c.rewriteRoles) {
		rows, ok := c.roles[id]
		if !ok || len(rows) != 1 {
			return result, kaname.ErrSourceUnconfirmed
		}
		role, err := resourceCapturedRole(rows[0].value)
		if err != nil {
			return result, err
		}
		if string(role.ID) != id {
			return result, kaname.ErrSourceUnconfirmed
		}
		result.Roles = append(result.Roles, role)
	}
	return result, nil
}

func resourceCapturedBinding(raw json.RawMessage) (domain.AccessBinding, error) {
	var row struct {
		ID           domain.AccessBindingID     `json:"id"`
		SubjectType  domain.SubjectType         `json:"subject_type"`
		SubjectID    domain.SubjectID           `json:"subject_id"`
		RoleID       domain.RoleID              `json:"role_id"`
		ResourceType domain.ResourceType        `json:"resource_type"`
		ResourceID   string                     `json:"resource_id"`
		Scope        int                        `json:"scope"`
		Status       domain.AccessBindingStatus `json:"status"`
		ExpiresAt    *time.Time                 `json:"expires_at"`
		RevokedAt    *time.Time                 `json:"revoked_at"`
		RevokedBy    *domain.UserID             `json:"revoked_by_user_id"`
		GrantedBy    domain.UserID              `json:"granted_by_user_id"`
		CreatedAt    time.Time                  `json:"created_at"`
		Protection   bool                       `json:"deletion_protection"`
		Labels       json.RawMessage            `json:"labels"`
		Target       json.RawMessage            `json:"target"`
		Relation     string                     `json:"granted_relation"`
		System       bool                       `json:"is_system"`
		Reason       domain.RevocationReason    `json:"revocation_reason"`
		Delegation   domain.GrantDelegationID   `json:"delegation_id"`
	}
	if err := json.Unmarshal(raw, &row); err != nil {
		return domain.AccessBinding{}, err
	}
	if row.ID == "" || row.Scope < 0 || row.Scope > 3 || len(row.Target) == 0 {
		return domain.AccessBinding{}, kaname.ErrSourceUnconfirmed
	}
	target, err := relverdict.DecodeTarget(row.Target)
	if err != nil {
		return domain.AccessBinding{}, err
	}
	labels, err := unmarshalLabels(row.Labels)
	if err != nil {
		return domain.AccessBinding{}, err
	}
	return domain.AccessBinding{ID: row.ID, SubjectType: row.SubjectType, SubjectID: row.SubjectID, RoleID: row.RoleID,
		ResourceType: row.ResourceType, ResourceID: row.ResourceID, Scope: domain.Scope(row.Scope), Status: row.Status,
		ExpiresAt: row.ExpiresAt, RevokedAt: row.RevokedAt, RevokedByUserID: row.RevokedBy, GrantedByUserID: row.GrantedBy,
		CreatedAt: row.CreatedAt, DeletionProtection: row.Protection, Labels: labels, Target: target, GrantedRelation: row.Relation,
		System: row.System, RevocationReason: row.Reason, DelegationID: row.Delegation}, nil
}

func resourceCapturedRole(raw json.RawMessage) (domain.Role, error) {
	var row struct {
		ID          domain.RoleID      `json:"id"`
		Cluster     domain.ClusterID   `json:"cluster_id"`
		Account     domain.AccountID   `json:"account_id"`
		Project     domain.ProjectID   `json:"project_id"`
		Name        domain.RoleName    `json:"name"`
		Description domain.Description `json:"description"`
		Permissions json.RawMessage    `json:"permissions"`
		Rules       json.RawMessage    `json:"rules"`
		System      bool               `json:"is_system"`
		Module      string             `json:"owner_module"`
		CreatedAt   time.Time          `json:"created_at"`
		UpdatedAt   time.Time          `json:"updated_at"`
		Labels      json.RawMessage    `json:"labels"`
	}
	if err := json.Unmarshal(raw, &row); err != nil {
		return domain.Role{}, err
	}
	if row.ID == "" || len(row.Rules) == 0 || len(row.Permissions) == 0 {
		return domain.Role{}, kaname.ErrSourceUnconfirmed
	}
	role := domain.Role{ID: row.ID, ClusterID: row.Cluster, AccountID: row.Account, ProjectID: row.Project,
		Name: row.Name, Description: row.Description, IsSystem: row.System, OwnerModule: row.Module, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}
	if err := scanRolePolicy(&role, row.Permissions, row.Rules); err != nil {
		return domain.Role{}, err
	}
	var err error
	role.Labels, err = unmarshalLabels(row.Labels)
	return role, err
}
