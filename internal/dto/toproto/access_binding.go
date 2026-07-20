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
		Id:          string(b.ID),
		SubjectType: string(b.SubjectType),
		SubjectId:   string(b.SubjectID),
		RoleId:      string(b.RoleID),
		// redesign-2026 F7: the scope-anchor is projected as the flattened dotted
		// scopeType/scopeId (the sole scope projection; «resource» freed for
		// target). Within-service storage keeps the bare kind; ScopeTypeToDotted
		// maps it at the API boundary.
		ScopeType: domain.ScopeTypeToDotted(string(b.ResourceType)),
		ScopeId:   b.ResourceID,
		CreatedAt: createdAt,
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

func init() {
	dto.RegTransfer(dto.Fn2Face(abObj{}.toPb))
}
