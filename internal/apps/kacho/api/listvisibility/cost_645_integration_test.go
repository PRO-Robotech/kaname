// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package listvisibility_test

// cost_645_integration_test.go — group D of the acceptance (645-16, 645-16б,
// 645-17): the price of a request must not follow the population of the cloud.
//
// # Why this file exists at all, and why it is the trap of the whole change
//
// The cheapest way to make a page full is to keep reading the GLOBAL feed until
// `page_size` visible rows have accumulated. Every probe in the other files
// turns green on that repair. The symptom disappears; the class does not — the
// request now reads as many rows as there are strangers' objects ahead of the
// caller's first one, and it comes back under load, where it is hardest to
// diagnose.
//
// §3.4 draws the line not at the presence of a loop or at a ceiling on it, but at
// WHAT the loop walks: a set of candidates the caller's own grants produced (in
// which strangers' objects do not appear at all) versus the global feed (in which
// they are most of the work). So group D asserts a PROPERTY — independence from
// population — and deliberately forbids itself from asserting a mechanism: a probe
// that banned the loop by name, or demanded a hard ceiling, would be red on a
// correct implementation and would break C1 respectively (§2.2).
//
// # What is measured, and what could not be
//
// The acceptance names three quantities (§2.1). Two are observable from outside
// the process, by counting what the request asks of the relation store:
//
//   - requests to the store — messages, each a round-trip;
//   - objects judged — verdicts obtained, which is the count that grows when a
//     loop walks the global feed, because every candidate it reads it must also
//     ask about.
//
// The third — ROWS READ FROM THE DATABASE — has no observer in the tree. The
// acceptance says the counter belongs in the use-case, on the way out of the
// page-filling loop, and no such counter exists yet; the repository takes a
// concrete `*pgxpool.Pool`, so it cannot be wrapped from a test either. Adding
// one is production code and does not belong in a red phase. "Objects judged" is
// the faithful stand-in for now: a loop that reads a row must ask about it, so
// the two move together, and the day the counter lands this file should assert
// the real quantity beside this one rather than instead of it.

import (
	"testing"

	"github.com/stretchr/testify/require"

	projectapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/project"
	repoproject "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/project"
)

// costState is one of the two populations the scenario compares. The difference
// between them is entirely in objects the caller CANNOT see, and entirely BEFORE
// the ones he can.
type costState struct {
	name    string
	foreign int
}

// costMeasurement is what one request cost and what it returned. Both halves
// matter: equal counts on two empty answers would prove only that nothing was
// done twice.
type costMeasurement struct {
	requests int
	objects  int
	subject  int
	returned []string
	want     []string
}

// measureListCost builds one state and runs one request against it, counting
// what that request asked of the relation store.
//
// Position, not quantity, is what makes the two states differ (the acceptance is
// explicit about this): the extra strangers' objects go BEFORE the visible ones.
// If the difference sat after them, a loop walking the global feed would stop at
// the same point in both states, the counts would agree, and the probe would go
// green on precisely the implementation it exists to catch.
func measureListCost(t *testing.T, s costState) costMeasurement {
	t.Helper()
	e := newEnv(t)

	for i := 0; i < s.foreign; i++ {
		e.seedProject(t, e.foreignAcc, projectName(i))
	}
	var visible []string
	for i := 0; i < 10; i++ {
		p := e.seedProject(t, e.callerAcc, projectName(10000+i))
		e.grantVerb(t, "user", string(e.callerUser), "project", p, "get")
		visible = append(visible, p)
	}

	counter := newCountingQueries(e.gates)
	uc := projectapp.NewListProjectsUseCase(e.repo).WithRelationStore(counter)

	got, _, err := uc.Execute(e.ctxUser(e.callerUser), repoproject.ListFilter{PageSize: 10})
	require.NoError(t, err, "%s: the request must succeed", s.name)

	reqs, objs := counter.counts()
	return costMeasurement{
		requests: reqs, objects: objs, subject: counter.subjectQuestions(),
		returned: projectIDs(got), want: visible,
	}
}

// TestList645_16_17_PriceDoesNotFollowThePopulation — 645-16 and 645-17.
//
// Ten times the strangers' objects, same request, same answer, same price.
func TestList645_16_17_PriceDoesNotFollowThePopulation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}

	// Both states are measured in ONE run. Comparing two separate runs would
	// measure the machine.
	a := measureListCost(t, costState{name: "A (100 strangers ahead)", foreign: 100})
	b := measureListCost(t, costState{name: "B (1000 strangers ahead)", foreign: 1000})

	// The answer first. Equal counts over two empty answers would say nothing
	// about cost and everything about the request having done nothing.
	require.ElementsMatch(t, a.want, a.returned,
		"state A: the caller sees exactly his ten objects")
	require.ElementsMatch(t, b.want, b.returned,
		"state B: and the same ten when ten times as many strangers' objects lie ahead "+
			"of them — the answer is a function of his grants, not of the cloud's size")

	require.Equal(t, a.objects, b.objects,
		"objects judged: %d in state A, %d in state B. The two states differ ONLY in "+
			"strangers' objects lying ahead of the caller's; a request whose price follows "+
			"that number is walking the global feed and paying for other tenants. That "+
			"repair makes the symptom disappear and keeps the class — and the class comes "+
			"back under load", a.objects, b.objects)

	require.Equal(t, a.requests, b.requests,
		"requests to the store: %d in state A, %d in state B", a.requests, b.requests)
}

// TestList645_16b_SubjectQuestionsAreAConstant — 645-16б.
//
// Structural tiers are resolved by asking about the CALLER, once. That number may
// not follow the population, and may not follow the page size either: if it does,
// the question is being asked per object, which is enumeration wearing a
// different name.
//
// This probe is only meaningful together with the one in blindspots_645, which
// establishes that the question is asked at all. On its own, "the count is the
// same everywhere" is satisfied by the count being zero everywhere — so the
// assertion below states the pairing rather than leaving it implied.
func TestList645_16b_SubjectQuestionsAreAConstant(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	a := measureListCost(t, costState{name: "A (100 strangers ahead)", foreign: 100})
	b := measureListCost(t, costState{name: "B (1000 strangers ahead)", foreign: 1000})

	require.Equal(t, a.subject, b.subject,
		"subject questions: %d against %d. Asking about the caller is one question per "+
			"request; a count that follows the population means it is being asked per "+
			"object", a.subject, b.subject)
	require.LessOrEqual(t, a.subject, 1,
		"and it is asked at most once per request, not once per relation or per partition; "+
			"got %d. (That it is asked AT ALL is established by "+
			"TestList645_16b_SubjectQuestionFailureIsUnavailableNotANarrowedPage — without "+
			"that pairing this assertion is satisfied by zero)", a.subject)
}
