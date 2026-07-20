// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package toproto

// role.go — Transfer domain.Role → *iamv1.Role.

import (
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/dto"
)

type roleObj struct{}

func (roleObj) toPb(r domain.Role) (*iamv1.Role, error) {
	var createdAt *timestamppb.Timestamp
	if !r.CreatedAt.IsZero() {
		createdAt = timestamppb.New(r.CreatedAt.Truncate(tsTruncate))
	}
	var updatedAt *timestamppb.Timestamp
	if !r.UpdatedAt.IsZero() {
		updatedAt = timestamppb.New(r.UpdatedAt.Truncate(tsTruncate))
	}
	// RBAC rules-model 2026: rules[] is the PUBLIC API surface;
	// permissions[] is the INTERNAL compiled projection and is NOT populated in the
	// public Get/List response (left empty). For a legacy permissions-only role
	// (no rules) rules[] is empty and permissions still stays empty in the public
	// projection — clients render the role from rules[].
	rules := make([]*iamv1.Rule, 0, len(r.Rules))
	for _, rl := range r.Rules {
		rules = append(rules, &iamv1.Rule{
			Module:        rl.Module,
			Resources:     rl.Resources,
			Verbs:         rl.Verbs,
			ResourceNames: rl.ResourceNames,
			MatchLabels:   rl.MatchLabels,
		})
	}
	return &iamv1.Role{
		Id:          string(r.ID),
		AccountId:   string(r.AccountID),
		ProjectId:   string(r.ProjectID),
		ClusterId:   string(r.ClusterID),
		Name:        string(r.Name),
		Description: string(r.Description),
		Rules:       rules,
		// redesign-2026 F4: is_system is DERIVED from the definition tier
		// (tierType==iam.cluster ⇔ cluster_id set), not the stored flag.
		IsSystem: r.IsSystemDerived(),
		// redesign-2026 F4: definitionTier dotted projection over the typed scope
		// columns; the word "scope" is reserved for the AccessBinding anchor.
		DefinitionTier: &iamv1.DefinitionTier{
			TierType: r.DefinitionTierType(),
			TierId:   r.DefinitionTierID(),
		},
		CreatedAt:       createdAt,
		UpdatedAt:       updatedAt,
		CreatedByUserId: string(r.CreatedByUserID),
		Labels:          labelsToStringMap(r.Labels),
		// Permissions intentionally omitted (internal compiled; not on the public
		// API surface — R-7/F5). Read compiled perms via InternalIAMService.GetRoleCompiled.
	}, nil
}

func init() {
	dto.RegTransfer(dto.Fn2Face(roleObj{}.toPb))
}
