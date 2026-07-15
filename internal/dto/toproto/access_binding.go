// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package toproto

// access_binding.go — Transfer domain.AccessBinding → *iamv1.AccessBinding.

import (
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/dto"
)

type abObj struct{}

func (abObj) toPb(b domain.AccessBinding) (*iamv1.AccessBinding, error) {
	var createdAt *timestamppb.Timestamp
	if !b.CreatedAt.IsZero() {
		createdAt = timestamppb.New(b.CreatedAt.Truncate(tsTruncate))
	}
	return &iamv1.AccessBinding{
		Id:           string(b.ID),
		SubjectType:  string(b.SubjectType),
		SubjectId:    string(b.SubjectID),
		RoleId:       string(b.RoleID),
		ResourceType: string(b.ResourceType),
		ResourceId:   b.ResourceID,
		CreatedAt:    createdAt,
		// RBAC v2 — surface the anchor tier on every response.
		Scope: domainScopeToProto(b.Scope),
		// Canonical scope representation derived from the SAME domain row. The
		// RBAC rules-model clean-cut removed the resource-scoped target dimension
		// entirely (the "what object" decision lives on role.rules now), so
		// AccessBinding no longer carries target/target_ref.
		ScopeRef: domainScopeToScopeRef(b.Scope, b.ResourceID),
		// RBAC rules-model: fill the canonical
		// subjects[] AND the legacy single subject_type/subject_id (above) — two
		// views of one model. When the read-side loaded the multi-subject set it
		// is used verbatim; otherwise (a legacy binding, or a read path that did
		// not load the child rows) it falls back to a one-element subjects[] = the
		// legacy single subject, so subjects[] is ALWAYS populated (paritet
		// new←legacy). The legacy single = subjects[0] holds reciprocally.
		Subjects: domainSubjectsToProto(b),
		// RBAC explicit-model — surface deletion_protection on
		// every read so clients can see / clear it before Delete.
		DeletionProtection: b.DeletionProtection,
		// Tenant-facing метки самого ресурса — делают AccessBinding
		// label-selectable наравне с account/project (ARM_LABELS-грант →
		// v_list по `labels @> matchLabels`; List фильтрует viewer ∪ v_list).
		Labels: labelsToStringMap(b.Labels),
	}, nil
}

// domainSubjectsToProto builds the canonical subjects[]. Uses the loaded
// multi-subject set when present; otherwise projects the legacy single subject as
// a one-element list so every response carries subjects[] (legacy clients keep the
// legacy fields; new clients always see subjects[]).
func domainSubjectsToProto(b domain.AccessBinding) []*iamv1.Subject {
	subs := b.Subjects
	if len(subs) == 0 && b.SubjectID != "" {
		subs = []domain.Subject{{Type: b.SubjectType, ID: b.SubjectID}}
	}
	out := make([]*iamv1.Subject, 0, len(subs))
	for _, s := range subs {
		out = append(out, &iamv1.Subject{
			Type: subjectTypeToProtoDTO(s.Type),
			Id:   string(s.ID),
		})
	}
	return out
}

// subjectTypeToProtoDTO maps the domain SubjectType to the proto enum (the DTO
// layer cannot import the use-case package, so the mapping is duplicated here —
// the use-case has its own subjectTypeToProto for ExpandAccess).
func subjectTypeToProtoDTO(t domain.SubjectType) iamv1.SubjectType {
	switch t {
	case domain.SubjectTypeUser:
		return iamv1.SubjectType_SUBJECT_TYPE_USER
	case domain.SubjectTypeServiceAccount:
		return iamv1.SubjectType_SUBJECT_TYPE_SERVICE_ACCOUNT
	case domain.SubjectTypeGroup:
		return iamv1.SubjectType_SUBJECT_TYPE_GROUP
	default:
		return iamv1.SubjectType_SUBJECT_TYPE_UNSPECIFIED
	}
}

// domainScopeToScopeRef builds the canonical ScopeRef{tier, id} from the same
// domain fields the legacy projection uses. The id is the legacy
// resource_id; the tier reuses the enum mapping. An existing binding's row
// supplies these directly — no backfill.
func domainScopeToScopeRef(s domain.Scope, resourceID string) *iamv1.ScopeRef {
	return &iamv1.ScopeRef{
		Tier: domainScopeToProto(s),
		Id:   resourceID,
	}
}

func domainScopeToProto(s domain.Scope) iamv1.AccessBinding_Scope {
	switch s {
	case domain.ScopeCluster:
		return iamv1.AccessBinding_CLUSTER
	case domain.ScopeAccount:
		return iamv1.AccessBinding_ACCOUNT
	case domain.ScopeProject:
		return iamv1.AccessBinding_PROJECT
	default:
		return iamv1.AccessBinding_SCOPE_UNSPECIFIED
	}
}

func init() {
	dto.RegTransfer(dto.Fn2Face(abObj{}.toPb))
}
