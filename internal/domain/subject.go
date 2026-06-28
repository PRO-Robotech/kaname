// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

import (
	"fmt"
	"strings"
)

// FGASubjectRef formats the FGA "user" side of a tuple for a subject:
//
//	user            → user:<id>
//	service_account → service_account:<id>
//	group           → group:<id>#member  (computed relation expands group members)
//
// Empty / unknown subject_type defaults to user (defensive). SINGLE source of
// truth shared by the AccessBinding grant-tuple builder (tuples.go /
// scope_grant_tuples.go) and the ARM_LABELS reconciler (reconcile) — the two MUST
// stay byte-symmetric, else a member's grant and revoke would target different FGA
// users and leak standing access.
func FGASubjectRef(subjectType, subjectID string) string {
	switch strings.ToLower(subjectType) {
	case "service_account":
		return "service_account:" + subjectID
	case "group":
		return "group:" + subjectID + "#member"
	default:
		return "user:" + subjectID
	}
}

// Subject — one grantee of an AccessBinding (RBAC rules-model). A binding may
// carry 1..32 subjects; each yields an INDEPENDENT FGA tuple-set + emitted-tuple
// ledger lineage, so per-subject revoke/audit never touches another subject's
// tuples. A GROUP subject grants the role to every member (userset) — resolved to
// concrete principals by ExpandAccess and, for admin/editor-tier roles, requiring
// requireGrantAuthority on the scope (group-amplification guard).
type Subject struct {
	Type SubjectType
	ID   SubjectID
}

// Validate — self-validating subject: closed type + non-empty id.
func (s Subject) Validate() error {
	if err := s.Type.Validate(); err != nil {
		return err
	}
	if s.ID == "" {
		return fmt.Errorf("Illegal argument subject id (must be non-empty)")
	}
	if len(s.ID) > 64 {
		return fmt.Errorf("Illegal argument subject id: length must be <=64")
	}
	return nil
}

// IsGroup reports whether this subject is a GROUP (userset) — the case that
// triggers the group-amplification guard and userset expansion.
func (s Subject) IsGroup() bool { return s.Type == SubjectTypeGroup }

// MaxSubjectsPerBinding — hard upper bound on subjects[]. Anti-DoS
// + tractable per-subject audit/expand. 0 < n ≤ 32 enforced by NormalizeSubjects
// (sync, INVALID_ARGUMENT) and mirrored by the DB.
const MaxSubjectsPerBinding = 32

// NormalizeSubjects resolves the canonical subjects[] set from the request input
// (two-way projection between the new subjects[] and the legacy single
// subject_type/subject_id):
//
//   - subjects[] is the canonical (preferred) input. When it is set, the legacy
//     single pair (if also present) MUST equal subjects[0]; otherwise
//     INVALID_ARGUMENT (a wire client cannot disagree with itself).
//   - When subjects[] is empty, the legacy single pair projects to a one-element
//     subjects[] (legacy clients keep working).
//   - Empty subjects[] AND empty legacy single → INVALID_ARGUMENT
//     ("Illegal argument subjects (must be 1..32)").
//   - More than 32 → INVALID_ARGUMENT (same text).
//   - A duplicate (type,id) → INVALID_ARGUMENT (the DB UNIQUE would also reject;
//     fail sync with a clear message).
//   - Each subject is self-validated (closed type + non-empty id).
//
// Pure domain — no DB / no transport. The use-case maps the returned error to
// the gRPC code (shared.MapValidationErr → INVALID_ARGUMENT).
func NormalizeSubjects(subjects []Subject, legacyType SubjectType, legacyID SubjectID) ([]Subject, error) {
	var out []Subject
	if len(subjects) > 0 {
		out = subjects
		// If a legacy single is ALSO present it must agree with subjects[0]
		// (the two representations may not disagree).
		if legacyID != "" || legacyType != "" {
			if out[0].Type != legacyType || out[0].ID != legacyID {
				return nil, fmt.Errorf(
					"Illegal argument subjects: legacy single subject (%s/%s) disagrees with subjects[0] (%s/%s)",
					legacyType, legacyID, out[0].Type, out[0].ID)
			}
		}
	} else if legacyID != "" {
		// Legacy single → one-element projection.
		out = []Subject{{Type: legacyType, ID: legacyID}}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("Illegal argument subjects (must be 1..32)")
	}
	if len(out) > MaxSubjectsPerBinding {
		return nil, fmt.Errorf("Illegal argument subjects (must be 1..32)")
	}

	seen := make(map[string]struct{}, len(out))
	for _, s := range out {
		if err := s.Validate(); err != nil {
			return nil, err
		}
		key := string(s.Type) + "/" + string(s.ID)
		if _, dup := seen[key]; dup {
			return nil, fmt.Errorf("Illegal argument subjects: duplicate subject %s/%s", s.Type, s.ID)
		}
		seen[key] = struct{}{}
	}
	return out, nil
}
