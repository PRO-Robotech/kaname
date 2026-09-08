// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// list_secl_test.go — SEC-L additions to ProjectService.List authz-filter:
// operator-SA visibility, exact subject-prefix per principal type (the
// pre-SEC-L code hardcoded "user:"+id, breaking the service_account
// operator), and fail-closed UNAVAILABLE when the question cannot be answered
// (scenario F, replacing the pre-SEC-L silent owner-only degrade).
//
// The question itself is a DIRECT per-object one about each row of the page
// (internal/authzfilter). It used to be an enumeration of every object of the type
// the subject may see; that door was removed with the external relation engine in
// stage S6, and clients.RelationQueries carries no method that enumerates objects.
// The reason for its removal still holds: the enumeration was capped server-side
// with no continuation token, so past that population a tenant's own row fell
// outside the returned prefix and became permanently invisible while the row and
// the grant both existed.
//
// Reuses the in-package list-test fakes from list_authz_test.go
// (newListFakeRepo / seedAccount / seedProject).
package project

import (
	"context"
	stderrors "errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kaname/internal/authzfilter"
	"github.com/PRO-Robotech/kaname/internal/clients"
	repoproject "github.com/PRO-Robotech/kaname/internal/repo/kaname/project"
)

// seclFGAStub — captures the subject, supports an id-set and an injectable error
// ("the form did not answer"). The port is embedded so that a method these reads do
// not use stays unimplemented rather than getting a lenient stand-in: a stub wider
// than its subject hides the drift it is placed to catch.
type seclFGAStub struct {
	clients.RelationQueries
	mu          sync.Mutex // the per-object Check port is called concurrently
	ids         []string
	err         error
	lastSubject string
}

// CheckWithContext — the DIRECT per-object question the use-case asks
// (internal/authzfilter), answering from the seeded id-set and capturing the
// subject (the SEC-L "subject reaches the model as service_account:<id>"
// assertion).
func (s *seclFGAStub) CheckWithContext(_ context.Context, subject, _, object string,
	_ map[string]any) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastSubject = subject
	if s.err != nil {
		return false, s.err
	}
	id := fgaObjectID(object)
	for _, got := range s.ids {
		if got == id {
			return true, nil
		}
	}
	return false, nil
}

func ctxSA(said string) context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{
		Type: "service_account", ID: said,
	})
}

// B — operator SA sees ALL projects; subject reaches the model as
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
		"SA principal must reach the model as service_account:<id>, not user:<id>")
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
		"user principal must reach the model as user:<id>")
}

// F — a question that could not be answered → UNAVAILABLE fail-closed (INV-7);
// not a degraded list. "Could not ask" and "not allowed" are different worlds.
func TestListProjects_SECL_FGAUnavailable_FailClosed(t *testing.T) {
	repo := newListFakeRepo()
	seedAccount(repo, "acc-1", "usr-u1")
	seedAccount(repo, "acc-2", "usr-u2")
	seedProject(repo, "prj-1", "acc-1")
	seedProject(repo, "prj-2", "acc-2")

	fga := &seclFGAStub{err: stderrors.New("relation form did not answer: connection closed")}
	uc := NewListProjectsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxAs("usr-u1"), repoproject.ListFilter{PageSize: 100})
	require.Error(t, err, "an unanswered question must NOT return a degraded list")
	require.Empty(t, out)
	st, ok := status.FromError(err)
	require.True(t, ok, "want grpc status; got %v", err)
	require.Equal(t, codes.Unavailable, st.Code(),
		"unanswered → UNAVAILABLE fail-closed (INV-7); no silent owner-only degrade")
}

// F (anon variant) — anon during an outage still gets empty/OK (short-circuit
// before asking — an outage must not turn anonymous into UNAVAILABLE).
func TestListProjects_SECL_AnonDuringOutage_StillEmpty(t *testing.T) {
	repo := newListFakeRepo()
	seedAccount(repo, "acc-1", "usr-u1")
	seedProject(repo, "prj-1", "acc-1")

	fga := &seclFGAStub{err: stderrors.New("relation form did not answer: connection closed")}
	uc := NewListProjectsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(context.Background(), repoproject.ListFilter{PageSize: 100})
	require.NoError(t, err, "anon path is unaffected by the outage (short-circuit before asking)")
	require.Empty(t, out)
}

// BatchCheckWithContext — the batched door onto the SAME oracle CheckWithContext
// answers from, so a verdict cannot depend on which door the filter chose.
//
// It is not optional politeness: authzfilter takes its batched path whenever the
// checker offers this method, so a stub that omitted it would leave every test in
// this file exercising a code path production does not take.
//
// The refusal above authzfilter.MaxBatchChecksPerRequest keeps the stub from being
// SLACKER than the declaration it stands behind: that constant is the partition size
// authzfilter itself declares and splits a page against, so a filter that stopped
// honouring its own declaration goes red here instead of quietly changing the shape
// of the request. An error, never a trim — a short answer is indistinguishable from
// a page of denials.
func (s *seclFGAStub) BatchCheckWithContext(ctx context.Context, subject, relation string,
	objects []string, condCtx map[string]any) ([]bool, error) {
	if len(objects) > authzfilter.MaxBatchChecksPerRequest {
		return nil, fmt.Errorf("batch of %d objects exceeds the declared partition size %d",
			len(objects), authzfilter.MaxBatchChecksPerRequest)
	}
	out := make([]bool, len(objects))
	for i, object := range objects {
		allowed, err := s.CheckWithContext(ctx, subject, relation, object, condCtx)
		if err != nil {
			return nil, err
		}
		out[i] = allowed
	}
	return out, nil
}
