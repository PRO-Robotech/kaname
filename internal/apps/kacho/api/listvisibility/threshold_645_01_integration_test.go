// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package listvisibility_test

// threshold_645_01_integration_test.go — scenario 645-01, the DEFINING probe of
// the acceptance (§6): "the caller's own object is on the FIRST page even when
// more than `page_size` objects he cannot see lie before it".
//
// Form, verbatim from the acceptance: 60 foreign objects + 1 own, `pageSize=50`,
// ONE call, expected answer — his object. Today the answer is empty.
//
// Both halves of C5 are asserted IN THE SAME RUN: the object is on the page AND
// the same caller reads it by id. Without the second half "he sees his object"
// would also be satisfied by a build that shows everything to everyone; without
// the first, the whole defect is invisible — which is exactly how it survived,
// since Get answered `200` the entire time the list answered empty.
//
// # Why the numbers are computed and not written down
//
// 60-and-50 are the acceptance's working reproduction and they hold on six
// surfaces. They do NOT hold on `role`, and the reason is worth stating because
// it is a finding rather than an inconvenience: the migrations seed a system-role
// catalog that by itself FILLS a default page. Those rows are visible (a code
// floor bypasses the filter for `is_system`), so they are not invisible
// predecessors — but they do occupy the raw window, and a page of exactly
// `page_size` cannot hold the catalog AND the caller's own role. Written as
// constants, this probe would demand of a CORRECT implementation an answer that
// does not fit in the page it asked for, and would then report the product
// broken.
//
// So the two numbers are derived from the surface, keeping the property the
// scenario actually names:
//
//	pageSize ≥ (visible floor) + 1        — the visible set fits the page asked for
//	invisible predecessors > pageSize     — the threshold, strictly
//
// On six surfaces this evaluates to exactly 50 and 60.

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// thresholdPlan is the pair of numbers one surface needs to state the scenario.
type thresholdPlan struct {
	pageSize int32
	foreign  int
	floor    []string
}

func planFor(t *testing.T, e *env, s surface) thresholdPlan {
	t.Helper()
	// РОЛЬ-НОСИТЕЛЬ ВЫДАЧИ ЗАВОДИТСЯ ДО ПЕРЕПИСИ ПОЛА, и это не порядок ради
	// порядка. Право выражено выдачей, выдача несёт роль, а роль — САМА ОБЪЕКТ
	// поверхности `role`, и притом системный: `is_system` минует фильтр, то есть
	// попадает в ответ каждому вызывающему. Заведи её позже — и она окажется в
	// ответе, но не в переписи пола, а проба объявит продукт сломанным на строке,
	// которую сама же и создала.
	e.probeRole(t, s.fgaType, verbOf(s.pageRelation))
	floor := floorOf(t, e, s)
	ps := probePageSize
	if need := int32(len(floor)) + 1; need > ps {
		// Leave headroom so a correct answer is not truncated by the very page
		// size the probe chose.
		ps = need + 10
	}
	return thresholdPlan{pageSize: ps, foreign: int(ps) + thresholdOvershoot, floor: floor}
}

// thresholdOvershoot — how far past one page the caller's object is pushed.
// "More than page_size" is the definition; ten is the acceptance's margin
// (60 against 50), chosen so the result cannot be reached by luck.
const thresholdOvershoot = 10

func TestList645_01_OwnObjectIsOnTheFirstPageBeyondTheThreshold(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	for _, s := range allSurfaces() {
		t.Run(s.name, func(t *testing.T) {
			e := newEnv(t)
			ctx := e.ctxUser(e.callerUser)
			plan := planFor(t, e, s)

			// Given: more than one page of objects the caller cannot see, created
			// FIRST, then his own object.
			foreign := s.seedForeign(t, e, plan.foreign)
			require.Len(t, foreign, plan.foreign)
			own := s.seedOwn(t, e)

			// And: the caller may read his object — the per-object relation the
			// reconciler emits in production. Nothing else is granted.
			grantOwn(t, e, s, own)

			// When: ONE call, no token.
			got, next, err := s.list(t, e, ctx, listArgs{pageSize: plan.pageSize})
			require.NoError(t, err, "%s: a list a caller is entitled to must not fail", s.name)

			// Then: his object is in the answer.
			require.Contains(t, got, own,
				"%s: the caller's own object must be on the FIRST page even though %d objects "+
					"he cannot see were created before it (pageSize=%d); got %d id(s) back. "+
					"An answer without it IS the defect: the page is taken from the database "+
					"first and narrowed by visibility afterwards, so an object past the page "+
					"window never reaches the narrowing at all",
				s.name, plan.foreign, plan.pageSize, len(got))

			// And: nothing he may not see came with it. Without this the assertion
			// above would also pass on a build that stopped filtering.
			for _, id := range foreign {
				require.NotContains(t, got, id,
					"%s: an object the caller holds no relation on must never appear", s.name)
			}

			// And: the answer is exactly the visible set — his object plus whatever
			// this surface's code floors make visible (own user row; system role
			// catalog). Stated as a set, because "contains own" alone would not
			// notice a page padded with rows nobody may read.
			want := append([]string{own}, plan.floor...)
			require.ElementsMatch(t, want, got,
				"%s: the page must be exactly the visible set", s.name)

			// And: the end of the listing is honest — there is nothing visible
			// beyond this page, so the token must be empty (C2). A non-empty token
			// here is today's behaviour and is precisely what makes a client
			// unable to tell "nothing further" from "nothing of yours here".
			require.Empty(t, next,
				"%s: no visible object remains, so nextPageToken must be empty", s.name)

			// And (the other half of C5, same run): the same caller reads the same
			// object by id.
			require.NoError(t, s.get(t, e, ctx, own),
				"%s: the object the list must show is also readable by id — the two "+
					"answers are required to agree", s.name)
		})
	}
}

// floorOf returns the ids this surface shows without any relation tuple.
func floorOf(t *testing.T, e *env, s surface) []string {
	t.Helper()
	if s.floorVisible == nil {
		return nil
	}
	return s.floorVisible(t, e)
}

// TestList645_01_ControlBelowTheThreshold is the positive control that makes the
// probe above an assertion about the THRESHOLD rather than about visibility in
// general.
//
// Same seeding, same grant, same call — only the raw window changes: the page
// asked for is the contract maximum, so the whole population fits inside it and
// today's order of operations still finds the object. This one PASSES on today's
// build. If it ever fails, the probe above is failing for some reason other than
// the window — a broken fixture, a wrong relation, an unreachable store — and
// the whole file is measuring the wrong thing.
func TestList645_01_ControlBelowTheThreshold(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	for _, s := range allSurfaces() {
		t.Run(s.name, func(t *testing.T) {
			e := newEnv(t)
			ctx := e.ctxUser(e.callerUser)

			const belowThreshold = 3
			const wholePopulationFits int32 = 1000 // pkg/validate MaxPageSize

			s.seedForeign(t, e, belowThreshold)
			own := s.seedOwn(t, e)
			grantOwn(t, e, s, own)

			got, _, err := s.list(t, e, ctx, listArgs{pageSize: wholePopulationFits})
			require.NoError(t, err)
			require.Contains(t, got, own,
				"%s: with the whole population inside the raw window, today's order of "+
					"operations still finds the object. If THIS fails, the threshold probe "+
					"is not measuring the threshold", s.name)
		})
	}
}
