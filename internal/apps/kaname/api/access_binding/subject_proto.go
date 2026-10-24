// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// subject_proto.go — RBAC rules-model 2026. Proto ⟷ domain
// mapping for the multi-subject set (transport-adjacent, like delta_input.go).
// The proto SubjectType enum (USER/SERVICE_ACCOUNT/GROUP) maps 1:1 to the domain
// string SubjectType (user/service_account/group).

import (
	"context"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// subjectTypeToDomain maps the proto SubjectType enum to the domain string type.
// SUBJECT_TYPE_UNSPECIFIED maps to "" so the domain validator rejects it.
func subjectTypeToDomain(t iamv1.SubjectType) domain.SubjectType {
	switch t {
	case iamv1.SubjectType_SUBJECT_TYPE_USER:
		return domain.SubjectTypeUser
	case iamv1.SubjectType_SUBJECT_TYPE_SERVICE_ACCOUNT:
		return domain.SubjectTypeServiceAccount
	case iamv1.SubjectType_SUBJECT_TYPE_GROUP:
		return domain.SubjectTypeGroup
	case iamv1.SubjectType_SUBJECT_TYPE_SYSTEM_CLASS:
		return domain.SubjectTypeSystemClass
	default:
		return ""
	}
}

// subjectTypeFromIDPrefix derives the subject type from the resource-id prefix
// (the type is encoded in the 3-char id prefix — usr/sva/grp). Used as a fallback
// when the request carries SUBJECT_TYPE_UNSPECIFIED: protojson DiscardUnknown drops
// a lowercase `"type":"user"` JSON value to the zero enum on the UI flow, so the
// id-prefix is the only remaining signal of the intended subject type. An
// unrecognized prefix (or an id shorter than the prefix) yields "" so the domain
// validator rejects it (no validation weakening).
func subjectTypeFromIDPrefix(id string) domain.SubjectType {
	if len(id) < len(domain.PrefixUser) {
		return ""
	}
	switch id[:len(domain.PrefixUser)] {
	case domain.PrefixUser:
		return domain.SubjectTypeUser
	case domain.PrefixServiceAccount:
		return domain.SubjectTypeServiceAccount
	case domain.PrefixGroup:
		return domain.SubjectTypeGroup
	default:
		return ""
	}
}

// subjectTypeToProto is the inverse mapping (used by the read-projection).
func subjectTypeToProto(t domain.SubjectType) iamv1.SubjectType {
	switch t {
	case domain.SubjectTypeUser:
		return iamv1.SubjectType_SUBJECT_TYPE_USER
	case domain.SubjectTypeServiceAccount:
		return iamv1.SubjectType_SUBJECT_TYPE_SERVICE_ACCOUNT
	case domain.SubjectTypeGroup:
		return iamv1.SubjectType_SUBJECT_TYPE_GROUP
	case domain.SubjectTypeSystemClass:
		return iamv1.SubjectType_SUBJECT_TYPE_SYSTEM_CLASS
	default:
		return iamv1.SubjectType_SUBJECT_TYPE_UNSPECIFIED
	}
}

// projectSubjectsBatch одним запросом читает набор субъектов МНОГИХ выдач и
// ставит каждой её Subjects (проекция чтения E-34 у List/ListByRole), без N+1 по
// строкам. У сохранённой выдачи набор непуст — это держит база
// (`access_bindings_carry_a_subject`, kaname#902).
func projectSubjectsBatch(ctx context.Context, rd Reader, bindings []domain.AccessBinding) error {
	if len(bindings) == 0 {
		return nil
	}
	ids := make([]domain.AccessBindingID, len(bindings))
	for i := range bindings {
		ids[i] = bindings[i].ID
	}
	byID, err := rd.AccessBindings().ListSubjectsForBindings(ctx, ids)
	if err != nil {
		return shared.MapRepoErr(err)
	}
	for i := range bindings {
		bindings[i].Subjects = byID[bindings[i].ID]
	}
	return nil
}

// readBindingsWithSubjects is the shared read skeleton of the binding List
// use-cases (ListByScope / ListBySubject / ListByAccount / ListByRole): open a
// reader-tx, run the binding query, fill the multi-subject projection (E-34), and
// release the (read-only) tx. The per-RPC authz gate runs in the use-case BEFORE
// this call. Repo / projection errors map to gRPC via shared.MapRepoErr.
func readBindingsWithSubjects(ctx context.Context, repo Repo, query func(rd Reader) ([]domain.AccessBinding, string, error)) ([]domain.AccessBinding, string, error) {
	rd, err := repo.Reader(ctx)
	if err != nil {
		return nil, "", shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	out, next, err := query(rd)
	if err != nil {
		return nil, "", shared.MapRepoErr(err)
	}
	if err := projectSubjectsBatch(ctx, rd, out); err != nil {
		return nil, "", err
	}
	if err := projectMaterializedAtBatch(ctx, rd, out); err != nil {
		return nil, "", err
	}
	return out, next, nil
}

// projectMaterializedAtBatch stamps each binding with the instant its per-object
// access last became live (reconciler ledger), in ONE query for the whole page
// (mirrors projectSubjectsBatch — no per-row N+1). A binding with no ACTIVE member
// keeps a zero MaterializedAt, which the API projects as an unset field.
//
// This is the read-only observable for the eventually-consistent materialization
// window; it never gates a write (Operation.done stays durability-only, ban #9).
func projectMaterializedAtBatch(ctx context.Context, rd Reader, bindings []domain.AccessBinding) error {
	if len(bindings) == 0 {
		return nil
	}
	ids := make([]domain.AccessBindingID, len(bindings))
	for i := range bindings {
		ids[i] = bindings[i].ID
	}
	byID, err := rd.AccessBindings().ListMaterializedAtForBindings(ctx, ids)
	if err != nil {
		return shared.MapRepoErr(err)
	}
	for i := range bindings {
		bindings[i].MaterializedAt = byID[bindings[i].ID]
	}
	return nil
}

// subjectsFromProto maps a request's repeated Subject into domain.Subject. nil
// when the request carries no subjects[] (legacy single-subject path).
func subjectsFromProto(in []*iamv1.Subject) []domain.Subject {
	if len(in) == 0 {
		return nil
	}
	out := make([]domain.Subject, 0, len(in))
	for _, s := range in {
		if s == nil {
			continue
		}
		// Explicit enum wins; SUBJECT_TYPE_UNSPECIFIED falls back to the id-prefix
		// derive (UI protojson DiscardUnknown drops a lowercase type to the zero
		// enum). An unrecognized prefix leaves the type "" → validator rejects.
		st := subjectTypeToDomain(s.GetType())
		if st == "" {
			st = subjectTypeFromIDPrefix(s.GetId())
		}
		out = append(out, domain.Subject{
			Type: st,
			ID:   domain.SubjectID(s.GetId()),
		})
	}
	return out
}
