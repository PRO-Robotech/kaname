// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// subject_proto.go — RBAC rules-model 2026. Proto ⟷ domain
// mapping for the multi-subject set (transport-adjacent, like delta_input.go).
// The proto SubjectType enum (USER/SERVICE_ACCOUNT/GROUP) maps 1:1 to the domain
// string SubjectType (user/service_account/group).

import (
	"context"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
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
	default:
		return iamv1.SubjectType_SUBJECT_TYPE_UNSPECIFIED
	}
}

// projectSubjectsBatch loads the multi-subject set of MANY bindings in one query
// and stamps each binding's Subjects (E-34 read-projection on List/ListByRole).
// A binding with no child rows keeps Subjects nil; toPb then falls back to the
// one-element legacy single. Mirrors projectTargetsBatch (no per-row N+1).
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
	return out, next, nil
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
