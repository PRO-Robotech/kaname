// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// list_secl_test.go — SEC-L additions to ProjectService.List authz-filter:
// operator-SA visibility, exact subject-prefix per principal type (the
// pre-SEC-L code hardcoded "user:"+id, breaking the service_account
// operator), and fail-closed UNAVAILABLE on FGA outage (scenario F,
// replacing the pre-SEC-L silent owner-only degrade).
//
// Reuses the in-package list-test fakes from list_authz_test.go
// (newListFakeRepo / seedAccount / seedProject).
package project

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	repoproject "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/project"
)

// seclFGAStub — captures the subject, supports per-type id-sets and an
// injectable error (FGA outage). Embeds RelationQueries so only ListObjects
// needs an impl.
type seclFGAStub struct {
	clients.RelationQueries
	ids         []string
	err         error
	lastSubject string
}

func (s *seclFGAStub) ListObjects(ctx context.Context, subject, relation, objectType string,
	condCtx map[string]any, maxResults int) ([]string, error) {
	s.lastSubject = subject
	if s.err != nil {
		return nil, s.err
	}
	return s.ids, nil
}

func ctxSA(said string) context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{
		Type: "service_account", ID: said,
	})
}

// B — operator SA sees ALL projects; subject reaches FGA as
// service_account:<id>. Pre-SEC-L hardcoded "user:" → operator got 0.
func TestListProjects_SECL_OperatorSeesAll(t *testing.T) {
	repo := newListFakeRepo()
	seedAccount(repo, "acc-1", "usr-u1")
	seedAccount(repo, "acc-2", "usr-u2")
	seedProject(repo, "prj-1", "acc-1")
	seedProject(repo, "prj-2", "acc-2")

	op := "sva-operator"
	fga := &seclFGAStub{ids: []string{"prj-1", "prj-2"}}

	uc := NewListProjectsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxSA(op), repoproject.ListFilter{PageSize: 100})
	require.NoError(t, err)

	ids := make([]string, 0, len(out))
	for _, p := range out {
		ids = append(ids, string(p.ID))
	}
	require.ElementsMatch(t, []string{"prj-1", "prj-2"}, ids,
		"operator system-viewer sees ALL projects (INV-2)")
	require.Equal(t, "service_account:"+op, fga.lastSubject,
		"SA principal must reach FGA as service_account:<id>, not user:<id>")
}

// subject-prefix — exact "user:<id>" for user principal.
func TestListProjects_SECL_SubjectPrefix_User(t *testing.T) {
	repo := newListFakeRepo()
	seedAccount(repo, "acc-1", "usr-u1")
	seedProject(repo, "prj-1", "acc-1")

	fga := &seclFGAStub{ids: []string{"prj-1"}}
	uc := NewListProjectsUseCase(repo).WithRelationStore(fga)

	_, _, err := uc.Execute(ctxAs("usr-u1"), repoproject.ListFilter{PageSize: 100})
	require.NoError(t, err)
	require.Equal(t, "user:usr-u1", fga.lastSubject,
		"user principal must reach FGA as user:<id>")
}

// F — FGA error → UNAVAILABLE fail-closed (INV-7); not a degraded list.
func TestListProjects_SECL_FGAUnavailable_FailClosed(t *testing.T) {
	repo := newListFakeRepo()
	seedAccount(repo, "acc-1", "usr-u1")
	seedAccount(repo, "acc-2", "usr-u2")
	seedProject(repo, "prj-1", "acc-1")
	seedProject(repo, "prj-2", "acc-2")

	fga := &seclFGAStub{err: stderrors.New("openfga listObjects: status 503")}
	uc := NewListProjectsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxAs("usr-u1"), repoproject.ListFilter{PageSize: 100})
	require.Error(t, err, "FGA outage must NOT return a degraded list")
	require.Empty(t, out)
	st, ok := status.FromError(err)
	require.True(t, ok, "want grpc status; got %v", err)
	require.Equal(t, codes.Unavailable, st.Code(),
		"FGA outage → UNAVAILABLE fail-closed (INV-7); no silent owner-only degrade")
}

// F (anon variant) — anon during FGA outage still gets empty/OK (short-circuit
// before FGA — outage must not turn anonymous into UNAVAILABLE).
func TestListProjects_SECL_AnonDuringOutage_StillEmpty(t *testing.T) {
	repo := newListFakeRepo()
	seedAccount(repo, "acc-1", "usr-u1")
	seedProject(repo, "prj-1", "acc-1")

	fga := &seclFGAStub{err: stderrors.New("openfga listObjects: status 503")}
	uc := NewListProjectsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(context.Background(), repoproject.ListFilter{PageSize: 100})
	require.NoError(t, err, "anon path is unaffected by FGA outage (short-circuit before FGA)")
	require.Empty(t, out)
}
