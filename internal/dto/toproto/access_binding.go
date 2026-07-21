// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package toproto

// access_binding.go — Transfer domain.AccessBinding → *iamv1.AccessBinding.

import (
	"time"

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
		// redesign-2026 F10: the lifecycle projection MUST be surfaced on every read
		// — status (ACTIVE on create, REVOKED after :revoke) + the audit/overlay
		// columns. Previously dropped here → every binding read back as
		// STATUS_UNSPECIFIED and revoke was invisible to clients.
		Status:          abStatusToProto(b.Status),
		ConditionId:     string(b.ConditionID),
		ExpiresAt:       nullableTsTrunc(b.ExpiresAt),
		GrantedByUserId: string(b.GrantedByUserID),
		RevokedAt:       nullableTsTrunc(b.RevokedAt),
		RevokedByUserId: userIDPtrToString(b.RevokedByUserID),
		// RBAC rules-model: fill the canonical
		// subjects[] AND the legacy single subject_type/subject_id (above) — two
		// views of one model. When the read-side loaded the multi-subject set it
		// is used verbatim; otherwise (a legacy binding, or a read path that did
		// not load the child rows) it falls back to a one-element subjects[] = the
		// legacy single subject, so subjects[] is ALWAYS populated (paritet
		// new←legacy). The legacy single = subjects[0] holds reciprocally.
		Subjects: domainSubjectsToProto(b),
		// F8: surface the object-selection under the anchor on every read
		// (allInScope | per-object resources). Legacy / whole-anchor rows project
		// as allInScope.
		Target: domainTargetToProto(b.Target),
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

// domainTargetToProto projects the domain target onto the proto AccessTarget oneof
// (F8). A per-object set → resources; AllInScope OR the empty/legacy whole-anchor
// zero value → allInScope (so every read carries an explicit target arm).
func domainTargetToProto(t domain.AccessTarget) *iamv1.AccessTarget {
	if len(t.Resources) > 0 {
		refs := make([]*iamv1.ResourceRef, 0, len(t.Resources))
		for _, r := range t.Resources {
			refs = append(refs, &iamv1.ResourceRef{Type: r.Type, Id: r.ID})
		}
		return &iamv1.AccessTarget{
			Target: &iamv1.AccessTarget_Resources{
				Resources: &iamv1.AccessTargetResources{Resources: refs},
			},
		}
	}
	return &iamv1.AccessTarget{
		Target: &iamv1.AccessTarget_AllInScope{AllInScope: &iamv1.AccessTargetAllInScope{}},
	}
}

// abStatusToProto maps the domain lifecycle status to the proto enum. An unset /
// unknown status projects as STATUS_UNSPECIFIED (never guessed).
func abStatusToProto(s domain.AccessBindingStatus) iamv1.AccessBinding_Status {
	switch s {
	case domain.AccessBindingStatusPending:
		return iamv1.AccessBinding_PENDING
	case domain.AccessBindingStatusActive:
		return iamv1.AccessBinding_ACTIVE
	case domain.AccessBindingStatusRevoked:
		return iamv1.AccessBinding_REVOKED
	default:
		return iamv1.AccessBinding_STATUS_UNSPECIFIED
	}
}

// nullableTsTrunc projects a nullable timestamp, truncated to the API second
// granularity (parity with created_at); nil stays nil.
func nullableTsTrunc(t *time.Time) *timestamppb.Timestamp {
	if t == nil || t.IsZero() {
		return nil
	}
	return timestamppb.New(t.Truncate(tsTruncate))
}

// userIDPtrToString flattens a nullable UserID to its string ("" when nil).
func userIDPtrToString(u *domain.UserID) string {
	if u == nil {
		return ""
	}
	return string(*u)
}

func init() {
	dto.RegTransfer(dto.Fn2Face(abObj{}.toPb))
}
