// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package listvisibility_test

// pagination_645_integration_test.go — C1, C2, C3 (scenarios 645-02, 645-03,
// 645-19) plus the unwired-port divergence of 645-23.
//
// These are the promises a client actually programs against: a full page is
// full, a token means there is more, and a traversal returns each visible object
// once. Today none of the three holds — a page is "however much of the visible
// happened to fall inside the raw window", and a token is issued for a raw page
// whose next instalment may contain nothing the caller can read.

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	projectapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/project"
	repoproject "github.com/PRO-Robotech/kaname/internal/repo/kaname/project"
)

// seedInterleaved lays down `visible` objects the caller may read, with
// `invisiblePerVisible` unreadable rows before each of them. The interleaving is
// the point: a defect that only shows at the head of the table would be missed
// by a population split into "all foreign, then all mine".
func seedInterleaved(t *testing.T, e *env, visibleCount, invisiblePerVisible int) []string {
	t.Helper()
	out := make([]string, 0, visibleCount)
	n := 0
	for i := 0; i < visibleCount; i++ {
		for j := 0; j < invisiblePerVisible; j++ {
			e.seedProject(t, e.foreignAcc, projectName(n))
			n++
		}
		p := e.seedProject(t, e.callerAcc, projectName(n))
		n++
		e.grantVerb(t, "user", string(e.callerUser), "project", p, "get")
		out = append(out, p)
	}
	return out
}

// TestList645_02_APageOfTheRequestedSizeIsFull — C1.
//
// 120 objects the caller may read, scattered among 360 he may not. He asks for
// 50 and must receive 50 of his own. Today he receives whatever share of the
// first 50 raw rows happens to be his.
//
// The paired negative shares the run: a caller with no grants at all receives an
// empty array and an empty token. Without it, "the page is full" is equally well
// satisfied by a page that stopped being filtered.
func TestList645_02_APageOfTheRequestedSizeIsFull(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	e := newEnv(t)
	visible := seedInterleaved(t, e, 120, 3)

	uc := projectapp.NewListProjectsUseCase(e.repo).WithRelationStore(e.gates)

	got, next, err := uc.Execute(e.ctxUser(e.callerUser), repoproject.ListFilter{PageSize: 50})
	require.NoError(t, err)
	require.Len(t, got, 50,
		"the caller can see %d objects and asked for 50, so the page holds 50 — the length "+
			"of a page is min(visible, page_size), not 'however much of the visible fell "+
			"inside the raw window'", len(visible))
	for _, p := range got {
		require.Contains(t, visible, string(p.ID), "and every row on it is one he may read")
	}
	require.NotEmpty(t, next, "70 visible objects remain, so there is a next page")

	stranger := e.seedUser(t, e.foreignAcc, "stranger")
	gotStranger, nextStranger, err := uc.Execute(e.ctxAs(stranger, "user"), repoproject.ListFilter{PageSize: 50})
	require.NoError(t, err)
	require.Empty(t, gotStranger, "paired control: a caller with no grants gets nothing")
	require.Empty(t, nextStranger, "and is told so, rather than being sent to fetch more nothing")
}

// TestList645_03_TokenMeansThereIsANextPageAndTheTraversalIsExact — C2 and C3.
//
// Every page reached by a non-empty token is itself non-empty; the traversal
// yields each visible object exactly once and no invisible one; and the number of
// pages is ceil(visible / page_size) — no page of padding, no page of nothing.
func TestList645_03_TokenMeansThereIsANextPageAndTheTraversalIsExact(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	e := newEnv(t)
	visible := seedInterleaved(t, e, 120, 3)

	uc := projectapp.NewListProjectsUseCase(e.repo).WithRelationStore(e.gates)
	ctx := e.ctxUser(e.callerUser)

	seen := map[string]int{}
	pages := 0
	token := ""
	for {
		got, next, err := uc.Execute(ctx, repoproject.ListFilter{PageSize: 50, PageToken: token})
		require.NoError(t, err)
		pages++
		require.NotEmpty(t, got,
			"page %d came back empty. It was reached by a token, and a token means the next "+
				"page is NOT empty (C2). The form 'the last page hands out a token and the one "+
				"after it arrives empty' is exactly today's behaviour, and it is why a client "+
				"cannot tell 'nothing further' from 'nothing of yours here'", pages)
		for _, p := range got {
			seen[string(p.ID)]++
		}
		if next == "" {
			break
		}
		token = next
		require.Less(t, pages, 100, "the traversal must terminate")
	}

	require.Equal(t, 3, pages, "120 visible objects at 50 per page is ceil(120/50) = 3 pages")
	for _, id := range visible {
		require.Equal(t, 1, seen[id], "object %s must appear exactly once in the traversal", id)
	}
	require.Len(t, seen, len(visible), "and nothing the caller may not read may appear at all")
}

// TestList645_19_PageSizeOne — the boundary where the defect is loudest.
//
// Three visible objects with invisible ones between them, asked one at a time.
// Three pages, each with exactly one object, the third with an empty token. No
// empty page occurs anywhere in the traversal — today the very first request
// returns an empty array with a non-empty token.
func TestList645_19_PageSizeOne(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	e := newEnv(t)
	visible := seedInterleaved(t, e, 3, 4)

	uc := projectapp.NewListProjectsUseCase(e.repo).WithRelationStore(e.gates)
	ctx := e.ctxUser(e.callerUser)

	var order []string
	token := ""
	for i := 0; ; i++ {
		require.Less(t, i, 50, "the traversal must terminate")
		got, next, err := uc.Execute(ctx, repoproject.ListFilter{PageSize: 1, PageToken: token})
		require.NoError(t, err)
		require.Len(t, got, 1,
			"page %d of a pageSize=1 traversal holds exactly one visible object; got %d", i+1, len(got))
		order = append(order, string(got[0].ID))
		if next == "" {
			break
		}
		token = next
	}

	require.Equal(t, visible, order,
		"three pages, in creation order, each carrying one of the three visible objects — "+
			"and a fourth request never happens because the third page's token is empty")
}

// TestList645_23b_AnUnwiredRelationPortRefusesRatherThanReportingNothing.
//
// The divergence the acceptance names by hand so the implementer does not have to
// find it: six use-cases answer UNAVAILABLE when the relation port is not wired,
// and the access-binding surface answers an EMPTY SET. An empty set is the one
// answer that cannot be distinguished from "no grants exist" — so a deployment
// that forgot to configure the relation store looks, to every tenant, exactly
// like a deployment in which nobody has been granted anything.
//
// This is a change in observable behaviour rather than a threshold, which is why
// it carries its own pair rather than dissolving into the seven of 645-01.
func TestList645_23b_AnUnwiredRelationPortRefusesRatherThanReportingNothing(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	for _, s := range allSurfaces() {
		t.Run(s.name, func(t *testing.T) {
			e := newEnv(t)
			ctx := e.ctxUser(e.callerUser)

			s.seedForeign(t, e, 3)
			own := s.seedOwn(t, e)
			grantOwn(t, e, s, own)

			// Control: wired, the object is there.
			got, _, err := s.list(t, e, ctx, listArgs{pageSize: 1000})
			require.NoError(t, err)
			require.Contains(t, got, own, "%s: control — with the port wired the object is there", s.name)

			// Unwired: no visibility is resolvable at all.
			gotUnwired, _, errUnwired := s.list(t, e, ctx, listArgs{pageSize: 1000, unwired: true})
			require.Error(t, errUnwired,
				"%s: with no relation port there is no way to know what the caller may see, "+
					"so the answer is a refusal. Got %d row(s) and no error — an empty page "+
					"here is indistinguishable from 'you have no grants', which is what makes "+
					"a misconfigured deployment look like a correctly locked-down one",
				s.name, len(gotUnwired))
			require.Equal(t, codes.Unavailable, status.Code(errUnwired),
				"%s: the refusal is UNAVAILABLE", s.name)
		})
	}
}
