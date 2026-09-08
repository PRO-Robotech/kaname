// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// list_subject_privileges_existence_test.go — ListSubjectPrivileges must not
// answer "does this subject exist?" to a caller who may not read the subject.
//
// Two answers a caller without authority must NOT be able to tell apart:
//
//	A. the subject exists, in an account the caller has no authority over;
//	B. no such subject exists at all.
//
// If A and B differ in code or in text, the RPC is an existence oracle over
// every user, service account and group in the cluster: the caller enumerates
// ids and reads the answer. Authority is therefore decided BEFORE existence is
// allowed to shape the reply; only a caller who may read the subject (self, an
// admin of its home account, a cluster-admin) is told that it is missing.

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/domain"
	repoab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
)

// answerFor runs one probe and returns the observable pair (code, message).
func answerFor(t *testing.T, uc *ListSubjectPrivilegesUseCase, subjectType domain.SubjectType, id string) (codes.Code, string) {
	t.Helper()
	ctx := userCtxAB(spOtherID) // acc-B; no authority over acc-A, not a cluster-admin
	out, _, err := uc.Execute(ctx, subjectType, domain.SubjectID(id), repoab.PageFilter{})
	if err == nil {
		t.Fatalf("probe of %s %s must not succeed for a caller without authority, got %+v", subjectType, id, out)
	}
	if out != nil {
		t.Fatalf("no privileges may leak on a refused probe, got %+v", out)
	}
	st := status.Convert(err)
	return st.Code(), st.Message()
}

// TestListSubjectPrivileges_ExistingAndAbsentSubjectAreIndistinguishable — the
// oracle probe. For each subject type the caller asks about a real subject in a
// foreign account and about an id that belongs to nobody; both answers must be
// the same bytes.
func TestListSubjectPrivileges_ExistingAndAbsentSubjectAreIndistinguishable(t *testing.T) {
	for _, tc := range []struct {
		name        string
		subjectType domain.SubjectType
		existing    string
		absent      string
	}{
		{"user", domain.SubjectTypeUser, spMemberID, "usr0000000000ghost01"},
		{"service_account", domain.SubjectTypeServiceAccount, spSAID, "sva000000000ghost001"},
		{"group", domain.SubjectTypeGroup, spGroupID, "grp00000000000ghost1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := spRepo()
			repo.seedSubjectPrivileges([]domain.SubjectPrivilege{
				spPriv("acb00000000000bind01", "rol_v", "viewer", "account", spAccA, domain.ScopeAccount),
			})
			uc := NewListSubjectPrivilegesUseCase(repo).WithRelationStore(&denyingFGA{}, nil)

			existsCode, existsMsg := answerFor(t, uc, tc.subjectType, tc.existing)
			absentCode, absentMsg := answerFor(t, uc, tc.subjectType, tc.absent)

			if existsCode != absentCode || existsMsg != absentMsg {
				t.Fatalf("existence oracle: subject that EXISTS answers %s %q, subject that does NOT exist answers %s %q — the caller reads existence off the difference",
					existsCode, existsMsg, absentCode, absentMsg)
			}
			if existsCode != codes.PermissionDenied {
				t.Fatalf("a caller without authority must be refused, got %s %q", existsCode, existsMsg)
			}
		})
	}
}

// TestListSubjectPrivileges_ClusterAdminStillSeesAbsence — the refusal above is
// owed to the caller's lack of authority, not to hiding the truth from everyone:
// a cluster-admin, who may read any subject, still gets NOT_FOUND for an id that
// belongs to nobody.
func TestListSubjectPrivileges_ClusterAdminStillSeesAbsence(t *testing.T) {
	repo := spRepo()
	uc := NewListSubjectPrivilegesUseCase(repo).WithRelationStore(onlyClusterAdmin(), nil)

	ghost := domain.SubjectID("usr0000000000ghost01")
	_, _, err := uc.Execute(clusterAdminCtx("usr00000000000root01"), domain.SubjectTypeUser, ghost, repoab.PageFilter{})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("a cluster-admin may be told the subject does not exist, got %v", err)
	}
}

// TestListSubjectPrivileges_SelfStillSeesAbsence — self-view keeps its own
// answer: a caller asking about itself is authorized without any store lookup,
// so an id that no longer resolves is reported as missing, not refused.
func TestListSubjectPrivileges_SelfStillSeesAbsence(t *testing.T) {
	repo := spRepo()
	uc := NewListSubjectPrivilegesUseCase(repo).WithRelationStore(&denyingFGA{}, nil)

	ghost := "usr0000000000ghost01"
	_, _, err := uc.Execute(userCtxAB(ghost), domain.SubjectTypeUser, domain.SubjectID(ghost), repoab.PageFilter{})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("self-probe of an id that does not resolve must be NotFound, got %v", err)
	}
}
