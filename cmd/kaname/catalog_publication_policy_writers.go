// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"log/slog"

	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	ab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// Все порты поколения используют один tagged repository и один semantic bundle.
// Withdrawal строится из того же membership, что обслуживает групповые мутации.
type publishedPolicyParticipants struct {
	membership *kanamepg.GroupMembershipParticipant
	stages     *kanamepg.BindingStageParticipant
	writers    *kanamepg.GrantPolicyWriters
	delegated  *kanamepg.GrantDelegationParticipant
	withdrawal *kanamepg.GrantDelegationRevokeParticipant
}

func newPublishedPolicyParticipants(ctx context.Context, repo *kanamepg.Repository, bundle *granteffect.Bundle) (*publishedPolicyParticipants, error) {
	membership, err := kanamepg.NewGroupMembershipParticipant(ctx, repo, bundle)
	if err != nil {
		return nil, err
	}
	stages, err := membership.NewBindingStageParticipant(ctx, slog.Default())
	if err != nil {
		return nil, err
	}
	writers, err := kanamepg.NewGrantPolicyWriters(ctx, repo, bundle)
	if err != nil {
		return nil, err
	}
	delegated, err := kanamepg.NewGrantDelegationParticipant(ctx, repo, bundle)
	if err != nil {
		return nil, err
	}
	withdrawal, err := kanamepg.NewGrantDelegationRevokeParticipant(ctx, stages)
	if err != nil {
		return nil, err
	}
	return &publishedPolicyParticipants{membership: membership, stages: stages, writers: writers, delegated: delegated, withdrawal: withdrawal}, nil
}

func (r *publishedWriterGenerations) RoleAuthorityWriter(ctx context.Context, role domain.Role, create bool, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return generation.policy.writers.RoleAuthorityWriter(pinned, role, create, actor)
}

func (r *publishedWriterGenerations) RoleMutationWriter(ctx context.Context, request kaname.RoleMutationRequest, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return generation.policy.writers.RoleMutationWriter(pinned, request, actor)
}

func (r *publishedWriterGenerations) GroupAdditionAuthorityWriter(ctx context.Context, member domain.GroupMember, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return generation.policy.writers.GroupAdditionAuthorityWriter(pinned, member, actor)
}

func (r *publishedWriterGenerations) GroupMembershipWriter(ctx context.Context, member domain.GroupMember) (kaname.Writer, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return generation.policy.membership.GroupMembershipWriter(pinned, member)
}

func (r *publishedWriterGenerations) GroupLifecycleWriter(ctx context.Context, mutation kaname.GroupMutation, group domain.Group) (kaname.Writer, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return generation.policy.membership.GroupLifecycleWriter(pinned, mutation, group)
}

// Исполнитель держит исходный pin для open, body и всех полных повторов.
// PG-исполнитель общий для prepared портов и не выбирает фабрику вместо open.
func (r *publishedWriterGenerations) ExecutePreparedWrite(ctx context.Context, open func(context.Context) (kaname.Writer, error), action func(context.Context, kaname.Writer) error) error {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return err
	}
	return generation.policy.writers.ExecutePreparedWrite(pinned, open, action)
}

func (r *publishedWriterGenerations) RunBindingDecision(ctx context.Context, actor domain.Subject, proposed domain.AccessBinding, create bool,
	tuples func(domain.AccessBinding, domain.Role) []ab.RelationTuple,
	apply func(context.Context, kaname.SemanticAuthorityWriter, domain.AccessBinding, domain.Role) error) error {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return err
	}
	return generation.policy.writers.RunBindingDecision(pinned, actor, proposed, create, tuples, apply)
}

func (r *publishedWriterGenerations) RunDelegatedBindingDecision(ctx context.Context, actor domain.Subject, proposed domain.AccessBinding,
	tuples func(domain.AccessBinding, domain.Role) []ab.RelationTuple,
	apply func(context.Context, kaname.SemanticAuthorityWriter, domain.AccessBinding, domain.Role) error) error {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return err
	}
	return generation.policy.writers.RunDelegatedBindingDecision(pinned, actor, proposed, tuples, apply)
}

func (r *publishedWriterGenerations) RunBindingMetadataDecision(ctx context.Context, actor domain.Subject, request kaname.BindingMetadataDecision,
	apply func(context.Context, kaname.SemanticAuthorityWriter, domain.AccessBinding, domain.Role) error) error {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return err
	}
	return generation.policy.writers.RunBindingMetadataDecision(pinned, actor, request, apply)
}

func (r *publishedWriterGenerations) RunBindingAuthorizationDecision(ctx context.Context, actor domain.Subject, proposed domain.AccessBinding, create, delegated bool,
	tuples func(domain.AccessBinding, domain.Role) []ab.RelationTuple,
	apply func(context.Context, kaname.SemanticAuthorityWriter, domain.AccessBinding, domain.Role) error) error {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return err
	}
	return generation.policy.writers.RunBindingAuthorizationDecision(pinned, actor, proposed, create, delegated, tuples, apply)
}

func (r *publishedWriterGenerations) WithdrawBinding(ctx context.Context, id domain.AccessBindingID, kind kaname.BindingWithdrawalKind, actor string,
	before func(context.Context, kaname.Writer, clients.RelationStore, domain.AccessBinding) error,
	after func(context.Context, kaname.Writer, domain.AccessBinding) error) (domain.AccessBinding, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return domain.AccessBinding{}, err
	}
	return generation.policy.stages.WithdrawBinding(pinned, id, kind, actor, before, after)
}

func (r *publishedWriterGenerations) GrantDelegationWriter(ctx context.Context, mutation kaname.GrantDelegationMutation, proposed domain.GrantDelegation) (kaname.Writer, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return generation.policy.delegated.GrantDelegationWriter(pinned, mutation, proposed)
}

func (r *publishedWriterGenerations) GrantDelegationRevokeWriter(ctx context.Context, id domain.GrantDelegationID) (kaname.GrantDelegationRevokeWriter, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return generation.policy.withdrawal.GrantDelegationRevokeWriter(pinned, id)
}

var (
	_ kaname.RoleAuthorityWriterFactory          = (*publishedWriterGenerations)(nil)
	_ kaname.RoleMutationWriterFactory           = (*publishedWriterGenerations)(nil)
	_ kaname.GroupAdditionAuthorityWriterFactory = (*publishedWriterGenerations)(nil)
	_ kaname.GroupMembershipWriterFactory        = (*publishedWriterGenerations)(nil)
	_ kaname.GroupLifecycleWriterFactory         = (*publishedWriterGenerations)(nil)
	_ kaname.PreparedWriteExecutor               = (*publishedWriterGenerations)(nil)
	_ kaname.BindingDecisionRunner               = (*publishedWriterGenerations)(nil)
	_ kaname.DelegatedBindingDecisionRunner      = (*publishedWriterGenerations)(nil)
	_ kaname.BindingMetadataDecisionRunner       = (*publishedWriterGenerations)(nil)
	_ kaname.BindingAuthorizationDecisionRunner  = (*publishedWriterGenerations)(nil)
	_ kaname.BindingWithdrawalRunner             = (*publishedWriterGenerations)(nil)
	_ kaname.GrantDelegationWriterFactory        = (*publishedWriterGenerations)(nil)
	_ kaname.GrantDelegationRevokeWriterFactory  = (*publishedWriterGenerations)(nil)
)
