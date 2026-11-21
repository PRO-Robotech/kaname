// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

const nativeQuestionLimit = 4096

type nativePolicyQuestion struct{ subject, relation, objectType, objectID string }
type nativePolicyQuestions struct {
	roots map[nativePolicyQuestion]struct{}
}

func newNativePolicyQuestions() *nativePolicyQuestions {
	return &nativePolicyQuestions{roots: make(map[nativePolicyQuestion]struct{})}
}
func nativeQuestionToken(s string) bool {
	return s != "" && len(s) <= 16384 && utf8.ValidString(s) && !strings.ContainsAny(s, ":#*\x00") && strings.IndexFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) < 0
}
func (s *nativePolicyQuestions) add(actor domain.Subject, relation, typ, id string) error {
	if s == nil || s.roots == nil || actor.Validate() != nil || actor.ID == "*" ||
		(actor.Type != domain.SubjectTypeUser && actor.Type != domain.SubjectTypeServiceAccount) ||
		!nativeQuestionToken(string(actor.ID)) || !nativeQuestionToken(relation) || !nativeQuestionToken(typ) || !nativeQuestionToken(id) {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	q := nativePolicyQuestion{string(actor.Type) + ":" + string(actor.ID), relation, typ, id}
	if _, ok := s.roots[q]; !ok && len(s.roots) >= nativeQuestionLimit {
		return kaname.ErrSourceReadLimit
	}
	s.roots[q] = struct{}{}
	return nil
}
func (s *nativePolicyQuestions) scopeAdmin(actor domain.Subject, scope domain.ScopeAnchor) error {
	if !domain.IsScopeAnchorKind(scope.Type) || domain.DeriveFromResourceType(scope.Type).ValidateAgainst(scope.Type, scope.ID) != nil {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	if err := s.add(actor, "system_admin", "cluster", domain.ClusterSingletonID); err != nil {
		return err
	}
	return s.add(actor, "admin", scope.Type, scope.ID)
}
func (s *nativePolicyQuestions) binding(actor domain.Subject, scope domain.ScopeAnchor, role domain.RoleID) error {
	if err := s.scopeAdmin(actor, scope); err != nil {
		return err
	}
	for _, kind := range []domain.GrantCapabilityKind{domain.GrantCapabilityCreateBinding, domain.GrantCapabilityBindRole} {
		c := grantcapability.Coordinate{Kind: kind, Anchor: scope}
		if kind == domain.GrantCapabilityBindRole {
			c.RoleID = role
		}
		ref, err := grantcapability.Encode(c)
		if err != nil {
			return err
		}
		if err = s.add(actor, ref.Relation, ref.ObjectType, ref.ObjectID); err != nil {
			return err
		}
	}
	return nil
}

// roleBase включает ВСЕ proposed references, даже system: лишний объявленный
// вопрос не даёт allow, зато discovery не зависит от позднего изменения tier.
// Для Update caller обязан дочитать population и вызвать roleCarrier для каждой
// строки до capture. Этот builder не удостоверяет завершение чужого census.
func (s *nativePolicyQuestions) roleBase(actor domain.Subject, r domain.Role, create bool) error {
	scope := domain.ScopeAnchor{Type: "account", ID: string(r.AccountID)}
	if r.ProjectID != "" {
		scope = domain.ScopeAnchor{Type: "project", ID: string(r.ProjectID)}
	}
	if r.ClusterID != "" {
		scope = domain.ScopeAnchor{Type: "cluster", ID: string(r.ClusterID)}
	}
	if err := s.scopeAdmin(actor, scope); err != nil {
		return err
	}
	relation, typ, id := "v_update", "iam_role", string(r.ID)
	if create {
		relation, typ, id = "editor", scope.Type, scope.ID
	}
	if err := s.add(actor, relation, typ, id); err != nil {
		return err
	}
	_, caps, err := domain.SplitGrantCapabilityRules(r.Rules)
	if err != nil {
		return err
	}
	for _, cap := range caps {
		if cap.Kind == domain.GrantCapabilityBindRole {
			for _, rel := range []string{"viewer", "v_list"} {
				if err = s.add(actor, rel, "iam_role", string(cap.BoundRoleID)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
func (s *nativePolicyQuestions) roleCarrier(actor domain.Subject, b domain.AccessBinding) error {
	return s.scopeAdmin(actor, domain.ScopeAnchor{Type: string(b.ResourceType), ID: b.ResourceID})
}
func (s *nativePolicyQuestions) groupBase(actor domain.Subject, g domain.Group) error {
	if err := s.add(actor, "v_update", "iam_group", string(g.ID)); err != nil {
		return err
	}
	return s.scopeAdmin(actor, domain.ScopeAnchor{Type: "account", ID: string(g.AccountID)})
}
func (s *nativePolicyQuestions) groupCarrier(actor domain.Subject, b domain.AccessBinding) error {
	return s.binding(actor, domain.ScopeAnchor{Type: string(b.ResourceType), ID: b.ResourceID}, b.RoleID)
}
func (s *nativePolicyQuestions) removal(actor domain.Subject, b domain.AccessBinding) error {
	if err := s.add(actor, "v_delete", "iam_access_binding", string(b.ID)); err != nil {
		return err
	}
	return s.scopeAdmin(actor, domain.ScopeAnchor{Type: string(b.ResourceType), ID: b.ResourceID})
}

// D5 issuer задаётся отдельно: actor делегата никогда не подменяет DelegatedBy.
func (s *nativePolicyQuestions) delegationIssuer(issuer domain.Subject, account domain.AccountID) error {
	return s.scopeAdmin(issuer, domain.ScopeAnchor{Type: "account", ID: string(account)})
}
func (s *nativePolicyQuestions) ordered(ctx context.Context) ([]nativePolicyQuestion, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil || len(s.roots) == 0 || len(s.roots) > nativeQuestionLimit {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	out := make([]nativePolicyQuestion, 0, len(s.roots))
	for q := range s.roots {
		out = append(out, q)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.subject != b.subject {
			return a.subject < b.subject
		}
		if a.objectType != b.objectType {
			return a.objectType < b.objectType
		}
		if a.objectID != b.objectID {
			return a.objectID < b.objectID
		}
		return a.relation < b.relation
	})
	return out, ctx.Err()
}

// Полный набор invite-вопросов объявляется до coordinator, а не после allow.
func (s *nativePolicyQuestions) invite(actor domain.Subject, account domain.AccountID, project domain.ProjectID, role domain.RoleID) error {
	if err := s.scopeAdmin(actor, domain.ScopeAnchor{Type: "account", ID: string(account)}); err != nil {
		return err
	}
	for _, relation := range []string{"editor", "owner"} {
		if err := s.add(actor, relation, "account", string(account)); err != nil {
			return err
		}
	}
	if project != "" {
		return s.binding(actor, domain.ScopeAnchor{Type: "project", ID: string(project)}, role)
	}
	return nil
}
