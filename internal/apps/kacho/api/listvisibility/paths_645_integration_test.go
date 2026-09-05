// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package listvisibility_test

// paths_645_integration_test.go — the paths by which an object becomes visible
// (acceptance §3.2, scenarios 645-05 … 645-10, 645-25), each exercised BEYOND
// the threshold.
//
// The point of running them past the threshold is that the narrowing has to KNOW
// each path in order to select candidates by it. A path the narrowing forgets
// produces an invisibility that shows up only for the caller who travels that
// path, and reads to him as "you have nothing" — the quietest failure this
// change can produce, and the reason the acceptance demands a positive probe per
// path rather than one probe for the class.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	projectapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/project"
	userapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/user"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	repoproject "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/project"
	repouser "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/user"
)

// TestList645_05_AccountOwnerSeesEveryProjectOfHisAccount — path П3.
//
// Ownership is a STRUCTURAL fact held in iam's own tables (accounts.owner_user_id),
// not a grant that has to materialize anywhere. So this probe writes NO relation
// tuple at all.
//
// That is deliberately the state of a stand WHOSE DRAINER IS STOPPED: rows exist,
// nothing has been materialized into the relation store, and the owner must still
// see his own projects. It is therefore also the answer to "is the ownership
// code-path redundant now that the model derives `owner` structurally?" — the
// derivation needs the account's tuples to exist, and here they do not. Reading
// the model text and concluding the code-path can go has already misled one round
// of review; this probe is what settles it, and it must be shown green before any
// removal.
func TestList645_05_AccountOwnerSeesEveryProjectOfHisAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	e := newEnv(t)
	ctx := e.ctxUser(e.callerUser)

	// Given: 60 projects created by someone else, in someone else's account …
	foreign := make([]string, 0, 60)
	for i := 0; i < 60; i++ {
		foreign = append(foreign, e.seedProject(t, e.foreignAcc, projectName(i)))
	}
	// … and one project in the account this caller owns, created after them.
	own := e.seedProject(t, e.callerAcc, "prj-own")

	// When: one call, default page size.
	uc := projectapp.NewListProjectsUseCase(e.repo).WithRelationStore(e.gates)
	got, _, err := uc.Execute(ctx, repoproject.ListFilter{PageSize: probePageSize})
	require.NoError(t, err)

	ids := projectIDs(got)
	require.Contains(t, ids, own,
		"the owner of the parent account must see the project of his own account even "+
			"though %d projects of another account were created before it; got %v",
		len(foreign), ids)
	for _, id := range foreign {
		require.NotContains(t, ids, id,
			"owning one account must not reveal another account's projects")
	}
}

// TestList645_06_DirectGrantBeyondTheThreshold — path П1, on a caller who owns
// nothing at all.
//
// 645-01 already exercises the direct grant, but with a caller who also owns an
// account; this one removes ownership from the picture entirely, so a build that
// resolved candidates by ownership alone cannot pass it.
func TestList645_06_DirectGrantBeyondTheThreshold(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	e := newEnv(t)

	// A principal with no account of his own: he exists in the foreign account
	// and owns nothing.
	grantee := e.seedUser(t, e.foreignAcc, "grantee")
	ctx := e.ctxAs(grantee, "user")

	for i := 0; i < 60; i++ {
		e.seedProject(t, e.foreignAcc, projectName(i))
	}
	granted := e.seedProject(t, e.foreignAcc, "prj-granted")
	// Выдача — ОДНА строка в собственных таблицах iam: её читает и отбор
	// кандидатов сужаемой страницы, и вопрос о доступе. Прежде здесь стояли ДВЕ
	// строки — выдача и её кортеж в чужом хранилище; вторая половина снята вместе
	// с движком, и «две стороны выдачи» перестали быть предметом вовсе.
	e.grantVerb(t, "user", grantee, "project", granted, "get")

	uc := projectapp.NewListProjectsUseCase(e.repo).WithRelationStore(e.gates)
	got, next, err := uc.Execute(ctx, repoproject.ListFilter{PageSize: probePageSize})
	require.NoError(t, err)

	require.Equal(t, []string{granted}, projectIDs(got),
		"a grant on exactly one object must yield exactly that object, wherever in the "+
			"table it happens to sit")
	require.Empty(t, next, "nothing visible remains, so the token must be empty")
}

// TestList645_07_GrantToAGroupTheCallerBelongsTo — path П2.
//
// The grant names a GROUP; the caller is a member of it. Both facts live in
// iam's own tables, and the userset that connects them (`group:<id>#member`) is
// the one the binding emits in production.
//
// The paired control is a second user who is NOT a member: he must see nothing.
// Without him "membership works" is indistinguishable from "the filter is off".
func TestList645_07_GrantToAGroupTheCallerBelongsTo(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	e := newEnv(t)

	member := e.seedUser(t, e.foreignAcc, "member")
	nonMember := e.seedUser(t, e.foreignAcc, "nonmember")
	grp := e.seedGroup(t, e.foreignAcc, "grp-granted")

	for i := 0; i < 60; i++ {
		e.seedProject(t, e.foreignAcc, projectName(i))
	}
	target := e.seedProject(t, e.foreignAcc, "prj-group-granted")

	// Выдача у ГРУППЫ, член — в группе. Обе стороны лежат там, где их держит
	// продукт: строка выдачи и строка членства в собственных таблицах iam.
	//
	// Прежде рядом писались ещё две строки в чужое хранилище — глагольный кортеж
	// на группу-множество и кортеж членства. Их предмет снят вместе с движком:
	// теперь ОДИН источник, и вопрос о доступе разворачивает членство сам, читая
	// `group_members`. Именно поэтому строка членства ниже — не оформление: без
	// неё выдача группе не достигает никого.
	e.grantVerb(t, "group", grp, "project", target, "get")
	e.seedGroupMember(t, grp, "user", member)

	uc := projectapp.NewListProjectsUseCase(e.repo).WithRelationStore(e.gates)

	gotMember, _, err := uc.Execute(e.ctxAs(member, "user"), repoproject.ListFilter{PageSize: probePageSize})
	require.NoError(t, err)
	require.Contains(t, projectIDs(gotMember), target,
		"a grant to a group must reach the group's member — the narrowing has to know "+
			"membership, which lives in iam's own tables, not only direct grants")

	gotNonMember, _, err := uc.Execute(e.ctxAs(nonMember, "user"), repoproject.ListFilter{PageSize: probePageSize})
	require.NoError(t, err)
	require.NotContains(t, projectIDs(gotNonMember), target,
		"paired control: a user outside the group must not receive the group's grant")
}

// TestList645_07b_ServiceAccountPrincipalBeyondTheThreshold — the second axis a
// candidate selection built on "the accounts of a USER" cannot express.
//
// A service account is a first-class principal: it holds grants, it drives
// reconciliation loops, and it never owns an account. If the narrowing resolves
// candidates through a user-shaped question, a machine caller sees an empty list
// while holding a live grant — and an empty list is what a reconciliation loop
// reads as "these are gone".
func TestList645_07b_ServiceAccountPrincipalBeyondTheThreshold(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	e := newEnv(t)

	sa := e.seedServiceAccount(t, e.foreignAcc, "sva-caller")
	ctx := e.ctxAs(sa, "service_account")

	for i := 0; i < 60; i++ {
		e.seedProject(t, e.foreignAcc, projectName(i))
	}
	granted := e.seedProject(t, e.foreignAcc, "prj-sa-granted")
	e.grantVerb(t, "service_account", sa, "project", granted, "get")

	uc := projectapp.NewListProjectsUseCase(e.repo).WithRelationStore(e.gates)
	got, _, err := uc.Execute(ctx, repoproject.ListFilter{PageSize: probePageSize})
	require.NoError(t, err)
	require.Equal(t, []string{granted}, projectIDs(got),
		"a service account holding a grant must see the object it was granted")

	// Paired control, same run: a second machine principal with no grant sees
	// nothing — so the assertion above is about the grant and not about machines
	// being waved through.
	other := e.seedServiceAccount(t, e.foreignAcc, "sva-other")
	gotOther, _, err := uc.Execute(e.ctxAs(other, "service_account"), repoproject.ListFilter{PageSize: probePageSize})
	require.NoError(t, err)
	require.Empty(t, projectIDs(gotOther),
		"paired control: a machine principal without a grant must see nothing")
}

// TestList645_09_FloorsHoldBeyondTheThreshold — path П6, the two code floors.
//
// Both are keyed on a column of the row itself, not on a tuple: the caller's own
// user row, and the system-role catalog. A floor applied AFTER the page is taken
// reproduces the original defect exactly — the row is a floor only if it reached
// the page, and past the threshold it does not.
func TestList645_09_FloorsHoldBeyondTheThreshold(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}

	t.Run("own_user_row", func(t *testing.T) {
		e := newEnv(t)

		// 60 users created in a foreign account, then the caller's own row LAST,
		// so his row sits past the raw window.
		var foreign []string
		for i := 0; i < 60; i++ {
			foreign = append(foreign, e.seedUser(t, e.foreignAcc, "fgn"))
		}
		self := e.seedUser(t, e.foreignAcc, "self")
		ctx := e.ctxAs(self, "user")

		uc := userapp.NewListUsersUseCase(e.repo).WithRelationStore(e.gates)
		got, _, err := uc.Execute(ctx, repouser.ListFilter{PageSize: probePageSize})
		require.NoError(t, err)

		ids := userIDs(got)
		require.Contains(t, ids, self,
			"a user must find his own row in the user list even when %d rows he cannot "+
				"see were created before it; the floor is keyed on his id, so it has to be "+
				"a condition of SELECTING the page, not a filter applied to it", len(foreign))
		require.Equal(t, []string{self}, ids,
			"paired control: the floor must show his row and nobody else's — otherwise "+
				"'the floor works' is indistinguishable from 'the filter is off'")
	})

	t.Run("system_role_catalog", func(t *testing.T) {
		e := newEnv(t)
		system := e.systemRoleIDs(t)
		require.NotEmpty(t, system)

		// Custom roles of a FOREIGN account, placed AHEAD of the catalog in creation
		// order. That is the scenario the acceptance names, and the placement is the
		// whole point: the catalog rows are the oldest in the table by default, so
		// seeding foreign roles after them would leave them inside the raw window and
		// the probe would pass without ever testing the floor.
		ps := int32(len(system) + 10)
		var foreign []string
		for i := 0; i < int(ps)+thresholdOvershoot; i++ {
			foreign = append(foreign, e.seedCustomRoleAt(t, e.foreignAcc, roleName(i), e.before(i)))
		}
		// A caller with no grants whatsoever.
		stranger := e.seedUser(t, e.foreignAcc, "stranger")
		ctx := e.ctxAs(stranger, "user")
		got, _, err := roleSurface().list(t, e, ctx, listArgs{pageSize: ps})
		require.NoError(t, err)

		require.ElementsMatch(t, system, got,
			"the system-role catalog is a floor keyed on is_system: a caller without a "+
				"single grant must receive it whole, and must receive nothing else. "+
				"Foreign custom roles created before the end of the window must not "+
				"displace it (that displacement IS the defect)")
		for _, id := range foreign {
			require.NotContains(t, got, id,
				"paired control: another account's custom role must never appear")
		}
	})
}

// TestList645_10_StrangerSeesNothingAndOwnerSeesHis — the negative line, with its
// positive in the same run.
//
// "Empty" is the ambiguous answer this whole change is about: it means both "you
// have nothing" and "the page never reached the filter". So the probe asserts
// emptiness for the stranger and non-emptiness for the owner AGAINST THE SAME
// population, in one run. Either alone proves nothing.
func TestList645_10_StrangerSeesNothingAndOwnerSeesHis(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	e := newEnv(t)

	for i := 0; i < 60; i++ {
		e.seedProject(t, e.foreignAcc, projectName(i))
	}
	own := e.seedProject(t, e.callerAcc, "prj-own")

	uc := projectapp.NewListProjectsUseCase(e.repo).WithRelationStore(e.gates)

	stranger := e.seedUser(t, e.foreignAcc, "stranger")
	gotStranger, nextStranger, err := uc.Execute(e.ctxAs(stranger, "user"),
		repoproject.ListFilter{PageSize: probePageSize})
	require.NoError(t, err,
		"a caller with no grants gets an empty page, never PERMISSION_DENIED — existence "+
			"is not disclosed")
	require.Empty(t, projectIDs(gotStranger), "a stranger must see nothing")
	require.Empty(t, nextStranger,
		"and must be told the listing ended: a non-empty token here promises a next page "+
			"that will also be empty, which is the ambiguity C2 removes")

	gotOwner, _, err := uc.Execute(e.ctxUser(e.callerUser), repoproject.ListFilter{PageSize: probePageSize})
	require.NoError(t, err)
	require.Contains(t, projectIDs(gotOwner), own,
		"paired positive, same population, same run: the owner sees his project — without "+
			"this, 'the stranger sees nothing' is satisfied by everything being broken")
}

// TestList645_25_AnonymousNeverReachesTheRelationStore — the anonymous caller.
//
// Two assertions, and the second is the one with teeth: not a single question is
// put to the relation store. Otherwise an outage of that store would turn an
// unauthenticated request into UNAVAILABLE, and the answer to "who is asking"
// would depend on a third party being up.
//
// The positive control shares the SAME counter in the SAME run: an identified
// caller does ask. Without it, "zero questions" is satisfied by a build that
// never asks anything — that is, by the filter being gone.
func TestList645_25_AnonymousNeverReachesTheRelationStore(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	e := newEnv(t)

	for i := 0; i < 60; i++ {
		e.seedProject(t, e.foreignAcc, projectName(i))
	}
	own := e.seedProject(t, e.callerAcc, "prj-own")
	e.grantVerb(t, "user", string(e.callerUser), "project", own, "get")

	counter := newCountingQueries(e.gates)
	uc := projectapp.NewListProjectsUseCase(e.repo).WithRelationStore(counter)

	got, next, err := uc.Execute(e.ctxAnonymous(), repoproject.ListFilter{PageSize: probePageSize})
	require.NoError(t, err, "an anonymous list is an empty page, not an error")
	require.Empty(t, projectIDs(got), "anonymous sees nothing")
	require.Empty(t, next, "anonymous is told the listing ended")

	reqs, _ := counter.counts()
	require.Zero(t, reqs,
		"an anonymous request must not reach the relation store at all; it asked %d time(s). "+
			"If it does, an outage of that store makes an unauthenticated request UNAVAILABLE",
		reqs)

	// Paired positive on the same counter, same run.
	gotOwner, _, err := uc.Execute(e.ctxUser(e.callerUser), repoproject.ListFilter{PageSize: probePageSize})
	require.NoError(t, err)
	require.Contains(t, projectIDs(gotOwner), own)
	reqsAfter, _ := counter.counts()
	require.Greater(t, reqsAfter, 0,
		"paired control: an identified caller DOES ask the relation store. Without this, "+
			"'zero questions' would be satisfied by a build that never asks — the filter gone")
}

// TestList645_22_FormatIsJudgedBeforeRights — C7, and it must not regress.
//
// The one answer of these RPCs that does not depend on the caller. Asserted for
// all three kinds of caller in one run, because the defect this guards against is
// precisely that the answer starts to depend on who is asking.
func TestList645_22_FormatIsJudgedBeforeRights(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	e := newEnv(t)
	own := e.seedProject(t, e.callerAcc, "prj-own")
	e.grantVerb(t, "user", string(e.callerUser), "project", own, "get")
	stranger := e.seedUser(t, e.foreignAcc, "stranger")

	uc := projectapp.NewListProjectsUseCase(e.repo).WithRelationStore(e.gates)

	callers := map[string]listCaller{
		"anonymous": {ctx: e.ctxAnonymous()},
		"no_grants": {ctx: e.ctxAs(stranger, "user")},
		"owner":     {ctx: e.ctxUser(e.callerUser)},
	}
	bad := map[string]repoproject.ListFilter{
		"garbage_token":      {PageSize: probePageSize, PageToken: "!!! not a cursor !!!"},
		"page_size_over":     {PageSize: 1001},
		"page_size_negative": {PageSize: -1},
	}

	for cname, c := range callers {
		for bname, f := range bad {
			_, _, err := uc.Execute(c.ctx, f)
			require.Error(t, err, "%s/%s: malformed input must be refused", cname, bname)
			require.Equal(t, codes.InvalidArgument, status.Code(err),
				"%s/%s: the refusal is INVALID_ARGUMENT and does not depend on the caller", cname, bname)
		}
		// Paired positive, same run: a well-formed page goes through for all three.
		_, _, err := uc.Execute(c.ctx, repoproject.ListFilter{PageSize: probePageSize})
		require.NoError(t, err, "%s: a well-formed request must not be refused", cname)
	}
}

// listCaller — one of the three kinds of caller C7 must answer identically.
type listCaller struct{ ctx context.Context }

// projectIDs / userIDs project a page to bare ids.
func projectIDs(rows []domain.Project) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, string(r.ID))
	}
	return out
}

func userIDs(rows []domain.User) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, string(r.ID))
	}
	return out
}
