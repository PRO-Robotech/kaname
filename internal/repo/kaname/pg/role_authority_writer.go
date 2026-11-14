// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// GrantPolicyWriters создаётся в закрытом active-mode wiring; конструктор не
// активирует protocol и не позволяет runtime LOGIN менять semantic identity.
type GrantPolicyWriters struct {
	repo             *Repository
	bundle           *granteffect.Bundle
	captureProducers bool
}

func NewGrantPolicyWriters(ctx context.Context, r *Repository, b *granteffect.Bundle) (*GrantPolicyWriters, error) {
	if r == nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	if err := r.ValidateAuthorityRuntime(ctx); err != nil {
		return nil, err
	}
	if err := validatePolicyEpochStorage(ctx, r); err != nil {
		return nil, err
	}
	return &GrantPolicyWriters{repo: r, bundle: b}, nil
}

// Полный source footprint и OLD/NEW scope классифицируются до fences.
// GLOBAL сохраняется для системных и неоднозначных selector/meta источников.
func (p *GrantPolicyWriters) RoleAuthorityWriter(ctx context.Context, r domain.Role, create bool, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	if p == nil || p.repo == nil || actor.Validate() != nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	in := rolePolicyRequest(r, create, actor)
	// Старый lower-level порт допускает Role{ID,Account}: nil Rules не сообщает
	// NEW content. Это заранее GLOBAL compat mode, не пустой complete proof.
	if r.Rules == nil {
		in.global = true
	} else {
		in.roleNative = &roleNativeRequest{role: r, create: create, content: true}
	}
	return p.openPolicyWriter(ctx, in)
}
func (p *GrantPolicyWriters) GroupAdditionAuthorityWriter(ctx context.Context, m domain.GroupMember, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	if p == nil || p.repo == nil || actor.Validate() != nil || m.Validate() != nil || (m.MemberType != domain.SubjectTypeUser && m.MemberType != domain.SubjectTypeServiceAccount) {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	member := domain.Subject{Type: m.MemberType, ID: m.MemberID}
	in := policyWriteRequest{actor: actor, kind: kaname.AuthorityGroup, groupID: m.GroupID, mutationSubjects: []domain.Subject{member, {Type: domain.SubjectTypeGroup, ID: domain.SubjectID(m.GroupID)}}, owners: []kaname.AuthorityOwnerRef{{Kind: "group", ID: string(m.GroupID)}}}
	in.groupNative = &groupAdditionNativeRequest{member: m}
	if m.MemberType == domain.SubjectTypeServiceAccount {
		in.owners = append(in.owners, kaname.AuthorityOwnerRef{Kind: "service_account", ID: string(m.MemberID)})
	}
	return p.openPolicyWriter(ctx, in)
}
func (w *semanticAuthorityWriteTx) PromoteRoleCapabilities(ctx context.Context, id domain.RoleID) error {
	if id == "" {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	_, err := w.tx.Exec(ctx, `UPDATE kaname.access_bindings SET grant_capability_version=1 WHERE role_id=$1 AND status IN ('ACTIVE','PENDING') AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>$2) AND (target->'resources' IS NULL OR target->'resources'='[]'::jsonb)`, string(id), w.fence.decisionAt)
	return err
}

var _ kaname.RoleAuthorityWriterFactory = (*GrantPolicyWriters)(nil)
var _ kaname.GroupAdditionAuthorityWriterFactory = (*GrantPolicyWriters)(nil)
var _ kaname.RoleCapabilityPromoter = (*semanticAuthorityWriteTx)(nil)

// rolePolicyRequest общий для прежнего lower-level входа и подготовленного UC.
func rolePolicyRequest(r domain.Role, create bool, actor domain.Subject) policyWriteRequest {
	in := policyWriteRequest{actor: actor, kind: kaname.AuthorityRole, global: r.IsSystem || r.ClusterID != ""}
	if !create {
		in.roleID = r.ID
		in.owners = append(in.owners, kaname.AuthorityOwnerRef{Kind: "role", ID: string(r.ID)})
	}
	if r.AccountID != "" {
		in.owners = append(in.owners, kaname.AuthorityOwnerRef{Kind: "account", ID: string(r.AccountID)})
	}
	if r.ProjectID != "" {
		in.owners = append(in.owners, kaname.AuthorityOwnerRef{Kind: "project", ID: string(r.ProjectID)})
	}
	for _, rule := range r.Rules {
		if len(rule.ResourceNames) > 0 || len(rule.MatchLabels) > 0 || len(rule.Children) > 0 || rule.CreatedBySubject {
			in.global = true
		}
	}
	return in
}

// WithCapturedProducerSources возвращает отдельную неизменяемую конфигурацию. Она
// не меняет эту фабрику, запуск, активацию или исторические полные сканирования.
func (p *GrantPolicyWriters) WithCapturedProducerSources() (*GrantPolicyWriters, error) {
	if p == nil || p.repo == nil || p.bundle.Validate() != nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	copy := *p
	copy.captureProducers = true
	return &copy, nil
}
