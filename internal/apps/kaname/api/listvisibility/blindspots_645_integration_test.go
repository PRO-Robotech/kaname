// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package listvisibility_test

// blindspots_645_integration_test.go — the states the class analysis of #645
// named as places where a repair could look finished and not be.
//
// Each of them shares one property: it CANNOT be reached by asking the product
// nicely. The refill loop's second read, a failure of the one question asked
// about the caller, a page token minted by yesterday's build — none of these
// occur in a run that just calls the RPC, and none of them are visible in a diff.
// They are constructed here on purpose.

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	projectapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/project"
	"github.com/PRO-Robotech/kaname/internal/domain"
	repoproject "github.com/PRO-Robotech/kaname/internal/repo/kaname/project"
)

// ─────────────────────────────────────────────────────────────────────────────
// Blind spot 1 — the refill reads inside ONE request, so a row written between
// two of its reads must not cost a row or duplicate one.
// ─────────────────────────────────────────────────────────────────────────────

// TestList645_04_RefillLosesNothingAndRepeatsNothingWhenARowArrivesMidRequest.
//
// Making the page full requires reading more than once per request. That is
// legitimate (§3.4) — but it means a request now spans several reads, and
// anything another connection writes in between lands between them. Whether the
// implementation takes one snapshot for the whole request or a fresh one per read
// is invisible in the answer of a quiet system and decides the answer of a busy
// one.
//
// The write is placed by HOOKING the first question this request puts to the
// relation store — not by sleeping in a goroutine and hoping to land in the gap.
// A probe built on timing would be an assertion about the scheduler.
//
// What it asserts is deliberately not "the new row appears" (it may or may not,
// and both are defensible): it asserts that the set of rows visible BEFORE the
// traversal began comes back whole, once each, and that nothing else but the new
// row can appear.
//
// # This probe is GREEN today, and that is stated rather than glossed
//
// It is the one probe in this package that cannot be red before the change,
// because the mechanism it guards DOES NOT EXIST YET: today a request performs
// exactly one read, so there is no "between two reads of one request" for a write
// to land in. Today's traversal is complete (it walks every raw page and simply
// hands out empty ones along the way) — the defect is the first page and the
// token, not total loss.
//
// It is written now, before the code it constrains, on purpose: this property is
// invisible in a diff, invisible in a quiet run, and decides the answer of a busy
// one. A probe added after the refill lands would be written to match whatever
// the refill happened to do.
func TestList645_04_RefillLosesNothingAndRepeatsNothingWhenARowArrivesMidRequest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	e := newEnv(t)
	ctx := e.ctxUser(e.callerUser)

	// A population where the visible rows are scattered among invisible ones, and
	// the first visible row is past one page.
	const pageSize int32 = 10
	var visible []string
	for i := 0; i < 60; i++ {
		e.seedProject(t, e.foreignAcc, projectName(i))
	}
	for i := 0; i < 25; i++ {
		p := e.seedProject(t, e.callerAcc, projectName(200+i))
		e.grantVerb(t, "user", string(e.callerUser), "project", p, "get")
		visible = append(visible, p)
		// two invisible rows between every pair of visible ones
		e.seedProject(t, e.foreignAcc, projectName(300+i))
		e.seedProject(t, e.foreignAcc, projectName(400+i))
	}

	// The row that arrives mid-request, timestamped INSIDE the visible sequence
	// so a cursor already past that point would skip it and one taken afresh
	// would not.
	var inserted string
	insertMidRequest := func() {
		inserted = e.seedProjectAt(t, e.callerAcc, "prj-midflight",
			e.timestampOf(t, "projects", visible[3]).Add(500*time.Millisecond))
		e.grantVerb(t, "user", string(e.callerUser), "project", inserted, "get")
	}

	hooked := newHookedQueries(e.gates, 1, insertMidRequest)
	uc := projectapp.NewListProjectsUseCase(e.repo).WithRelationStore(hooked)

	seen := map[string]int{}
	token := ""
	for page := 0; ; page++ {
		require.Less(t, page, 200, "the traversal must terminate")
		got, next, err := uc.Execute(ctx, repoproject.ListFilter{PageSize: pageSize, PageToken: token})
		require.NoError(t, err)
		for _, p := range got {
			seen[string(p.ID)]++
		}
		if next == "" {
			break
		}
		token = next
	}

	require.True(t, hooked.didFire(),
		"the mid-request write never happened — the probe proved nothing. It fires on the "+
			"first question this request puts to the relation store; if no question was "+
			"asked, the filter did not run at all")

	for id, n := range seen {
		require.Equal(t, 1, n, "project %s came back %d times: a traversal must not repeat a row", id, n)
	}
	for _, id := range visible {
		require.Contains(t, seen, id,
			"project %s was visible for the whole traversal and did not come back — the "+
				"refill lost it", id)
	}
	for id := range seen {
		require.True(t, contains(visible, id) || id == inserted,
			"project %s came back although the caller may not read it", id)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Blind spot 2 — the question asked about the CALLER may fail, and its failure
// must not degrade into a narrowed 200.
// ─────────────────────────────────────────────────────────────────────────────

// TestList645_16b_SubjectQuestionFailureIsUnavailableNotANarrowedPage.
//
// Structural tiers (account administrator, cloud administrator) cannot be
// expressed as a condition on iam's tables: a cloud administrator holds no grant
// row on any object. §3.6 resolves them by asking ONE question about the caller.
// A question is a thing that can fail — and this one failing is the dangerous
// case, because the fallback path (per-object questions) still works and returns
// a perfectly well-formed, perfectly wrong `200` with fewer rows.
//
// The injection fails ONLY that question and answers everything else from the
// live store. A whole-store outage would prove nothing: every path fails then.
//
// Two readings of a red here, and both are defects: either the question was never
// asked (a surface resolving tiers some other way, or not at all), or its failure
// was swallowed. The message says both, because the probe cannot tell them apart
// and should not pretend to.
func TestList645_16b_SubjectQuestionFailureIsUnavailableNotANarrowedPage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	for _, s := range allSurfaces() {
		t.Run(s.name, func(t *testing.T) {
			e := newEnv(t)
			plan := planFor(t, e, s)
			// The page asked for is the contract maximum, not the default. A cloud
			// administrator sees EVERY object, so at the default size his own object
			// would legitimately sit on page two and "he cannot see it" would be a
			// statement about pagination rather than about authority.
			const wholePopulationFits int32 = 1000

			admin := e.seedUser(t, e.foreignAcc, "cloudadmin")
			ctx := e.ctxAs(admin, "user")
			// Власть администратора облака СТРУКТУРНА: одна строка на синглтоне
			// кластера, и ни одной пообъектной нигде.
			e.factThroughJournal(t, "cluster", domain.ClusterSingletonID,
				"system_admin", "user:"+admin)

			s.seedForeign(t, e, plan.foreign)
			own := s.seedOwn(t, e)
			// Предпосылка вывода §3.1 — устанавливается фикстурой, а не
			// подразумевается: объект указывает на аккаунт, аккаунт — на кластер.
			// Четыре типа из семи прямого пути к кластеру в модели не имеют вовсе и
			// достают до него только этой цепью; порвись она на первом звене, проба
			// покраснела бы, не сказав ничего о своём предмете.
			//
			// Звено «аккаунт → кластер» здесь БОЛЬШЕ НЕ ПИШЕТСЯ: цепь областей
			// выводит его из схемы (accounts × clusters), потому что аккаунты сеются
			// в том числе миграциями и указателя в журнале у них нет. Проверка
			// предпосылки ниже покрывает и это звено — она спрашивает про аккаунт,
			// а ответ на нём достижим только через кластер.
			require.NotNil(t, s.linkOwnToHierarchy, "%s: every surface must state its parent pointer", s.name)
			s.linkOwnToHierarchy(t, e, own)

			// And the premise is CHECKED, not merely written: the administrator must
			// resolve `admin` on the account before anything is asked about a list.
			// This is the step whose reading misled a round of review of the
			// acceptance itself.
			adminOnAccount, err := e.gates.CheckWithContext(ctx, "user:"+admin, "admin",
				"account:"+string(e.callerAcc), nil)
			require.NoError(t, err)
			require.True(t, adminOnAccount,
				"%s: the derivation cluster#system_admin ⟹ account.super_admin ⟹ account.admin "+
					"does not hold in this fixture, so nothing below would be a statement about "+
					"the product", s.name)

			// Positive half, no injection: the administrator sees the objects.
			got, _, err := s.list(t, e, ctx, listArgs{pageSize: wholePopulationFits})
			require.NoError(t, err, "%s: the administrator's list must not fail", s.name)
			require.Contains(t, got, own,
				"%s: a cloud administrator must see objects of every account — the authority "+
					"is structural and reaches all seven types (the four whose model has no "+
					"direct cluster path reach it through account.admin)", s.name)

			// NOT asserted here, and named so it is not mistaken for an oversight:
			// that the administrator gets a FULL default-sized page. This fixture links
			// only his own object into the hierarchy, so the model can derive his
			// authority over that object and over nothing else; demanding a full page
			// would be demanding something the fixture never set up. Covering it means
			// giving every seeded object its parent pointer — the state production is
			// actually in — and that belongs in the same change as the repair, beside
			// the C1 probes of the other files.

			// Negative half, same run: the subject question is the only thing that
			// fails.
			down := newSubjectQuestionDown(e.gates, e.gates)
			gotDown, _, errDown := s.list(t, e, ctx, listArgs{
				pageSize: wholePopulationFits, queries: down, store: down,
			})
			require.Error(t, errDown,
				"%s: the subject question failed, so the answer must be a refusal. Got %d row(s) "+
					"and no error. Either that question was never asked (asked=%d), or its "+
					"failure was swallowed and the page silently narrowed — both are C6 "+
					"violations, and the second is worse because it looks like an answer",
				s.name, len(gotDown), down.timesAsked())
			require.Equal(t, codes.Unavailable, status.Code(errDown),
				"%s: an unresolvable rights question is UNAVAILABLE, never an empty page", s.name)
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Blind spot 3 — a token minted by the previous build must be refused by the
// FIRST decoder on the path, not by the last one.
// ─────────────────────────────────────────────────────────────────────────────

// TestList645_21_TokenOfThePreviousFormIsRefusedByTheFirstDecoder.
//
// C2 changes what a token MEANS: it stops marking the end of a raw page and
// starts marking the end of a visible one. A traversal begun before the change
// and continued after it must be refused (INVALID_ARGUMENT), never continued
// approximately — an approximate continuation skips rows silently, which is the
// very outcome this whole change exists to remove.
//
// Which decoder refuses matters, and that is what this probe pins. The format of
// the token is written down in THREE places today (task #652), and the one that
// runs first is the app-boundary check, not the repository. Only the first one is
// reached by an ANONYMOUS caller: that path short-circuits to an empty page
// before the repository is touched at all. So an old token presented
// anonymously is a direct question to the first decoder, and nothing else.
//
// # Why the two halves are not contradictory
//
// On today's build the "previous form" IS the current form, so the first
// assertion fails and the second passes — the probe is red, and red for the
// stated reason. After the change the producer emits a distinguishable token: the
// first assertion passes and the second still must, because refusing EVERY token
// is not a fix, it is broken pagination.
func TestList645_21_TokenOfThePreviousFormIsRefusedByTheFirstDecoder(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	e := newEnv(t)

	// A population big enough that a real traversal issues a real token.
	for i := 0; i < 60; i++ {
		p := e.seedProject(t, e.callerAcc, projectName(i))
		e.grantVerb(t, "user", string(e.callerUser), "project", p, "get")
	}

	uc := projectapp.NewListProjectsUseCase(e.repo).WithRelationStore(e.gates)

	// The previous form, verbatim: base64(std) of `<RFC3339Nano>|<id>`, the
	// boundary of a RAW page.
	legacy := base64.StdEncoding.EncodeToString(
		[]byte(time.Now().UTC().Format(time.RFC3339Nano) + "|prj0000000000000000x"))

	t.Run("refused_at_the_first_decoder", func(t *testing.T) {
		// Anonymous: the only caller that never reaches the repository, so only the
		// first decoder can possibly answer.
		_, _, err := uc.Execute(e.ctxAnonymous(),
			repoproject.ListFilter{PageSize: probePageSize, PageToken: legacy})
		require.Error(t, err,
			"a token of the previous form must be refused by the check that runs BEFORE "+
				"the identity short-circuit. An anonymous caller never reaches the "+
				"repository, so a refusal that lives only there is not reached either — "+
				"and the traversal continues with rows silently skipped")
		require.Equal(t, codes.InvalidArgument, status.Code(err),
			"the refusal is INVALID_ARGUMENT with the contract tone, not an approximate "+
				"continuation")
	})

	t.Run("refused_for_an_identified_caller_too", func(t *testing.T) {
		_, _, err := uc.Execute(e.ctxUser(e.callerUser),
			repoproject.ListFilter{PageSize: probePageSize, PageToken: legacy})
		require.Error(t, err, "and for a caller with grants, identically")
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("paired_positive_a_token_this_build_issued_is_accepted", func(t *testing.T) {
		_, next, err := uc.Execute(e.ctxUser(e.callerUser),
			repoproject.ListFilter{PageSize: 10})
		require.NoError(t, err)
		require.NotEmpty(t, next, "with 60 visible rows and a page of 10 there must be a token")

		_, _, err = uc.Execute(e.ctxUser(e.callerUser),
			repoproject.ListFilter{PageSize: 10, PageToken: next})
		require.NoError(t, err,
			"the token this build just issued must be accepted. Without this half the "+
				"probe above is satisfied by a build that refuses EVERY token — that is, "+
				"by pagination being broken outright")
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// C6 — a rights question that cannot be answered is a refusal, on all seven.
// ─────────────────────────────────────────────────────────────────────────────

// TestList645_23_UnresolvableRightsAreUnavailableOnEverySurface.
//
// The acceptance names the divergence rather than leaving it to be discovered:
// six use-cases answer UNAVAILABLE when rights cannot be resolved, and the
// access-binding surface answers an EMPTY SET — which makes an outage
// indistinguishable from "no grants exist". Bringing it to the first form is a
// change in observable behaviour, so it carries its own red→green pair rather
// than dissolving into the seven of 645-01.
func TestList645_23_UnresolvableRightsAreUnavailableOnEverySurface(t *testing.T) {
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

			// Positive half: with the store up, the caller receives his object.
			// (Small population on purpose — this probe is about the outage, not
			// about the threshold, and mixing the two would blur which one failed.)
			got, _, err := s.list(t, e, ctx, listArgs{pageSize: 1000})
			require.NoError(t, err)
			require.Contains(t, got, own, "%s: control — with rights resolvable the object is there", s.name)

			// Negative half: the store answers nothing.
			down := newStoreDown(e.gates, e.gates)
			gotDown, _, errDown := s.list(t, e, ctx, listArgs{pageSize: 1000, queries: down, store: down})
			require.Error(t, errDown,
				"%s: rights could not be resolved, so the answer must be a refusal; got %d row(s) "+
					"and no error. An empty page here is byte-identical to 'you have nothing' — "+
					"the caller cannot tell an outage from a revocation", s.name, len(gotDown))
			require.Equal(t, codes.Unavailable, status.Code(errDown),
				"%s: the refusal is UNAVAILABLE", s.name)
			require.Empty(t, gotDown, "%s: and no partially resolved set is ever handed back", s.name)
		})
	}
}

// contains is a tiny helper kept local: sort.SearchStrings needs a sorted slice
// and the callers here care about membership, not order.
func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
