// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// own_gates_agree_with_edge_integration_test.go — one subject, one object, one
// answer, whoever is asking.
//
// The neighbouring cascade_queue_independence_integration_test.go proves the cascade
// resolves from committed rows on the surface the api-gateway asks (AuthorizeService).
// Its own handoff note records what that leaves open: iam's in-service gates put the
// same question to the relation store directly, so they still waited for delivery, and
// the resulting pair of answers was not merely inconsistent but absurd —
//
//   - the owner of a brand-new account was admitted to DELETE it and told it DOES NOT
//     EXIST when he read it (a read denial is hidden as not-found, so the second answer
//     is not even recognisable as a refusal);
//   - the delegated account administrator was admitted at the edge on a project-scoped
//     grant and refused inside.
//
// These tests assert AGREEMENT rather than two separately-expected outcomes: the edge
// answer and the service answer are both computed and required to be EQUAL, plus the
// edge answer is pinned so the equality cannot be satisfied by both being false. A
// test that only said "the service allows" would go green if the edge ever silently
// started denying too.
//
// THE QUEUE IS PUT IN THE STATE THAT DISTINGUISHES THE TWO DESIGNS, AND THAT STATE IS
// ASSERTED. Rows are committed with SQL and no structural pointer is written; each test
// then requires the store to hold none, so a fixture that started delivering them fails
// as a broken premise instead of quietly making the assertions vacuous.
//
// TestOwnGatesDisagreeWhenTheSecondChanceIsAbsent is the injection in the other
// direction, kept permanently: with the fact source unwired the SAME probes must
// disagree. Without it, nothing in the tree would show that these assertions are
// capable of failing.
//
// Real OpenFGA (canonical fga_model.fga) + real Postgres. Skipped under -short.

package service_test

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"
	accessbindingapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/access_binding"
	accountapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/account"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzcascade"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzfilter"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// agId builds a well-formed id of the canonical length. The in-service read gates
// validate the id BEFORE anything else (shared.ValidateResourceID: prefix + exactly
// domain.ShortIDLen characters), so a short literal would make every probe below fail
// on the format check and never reach the gate under test.
func agId(prefix, tail string) string {
	body := tail
	for len(prefix)+len(body) < domain.ShortIDLen {
		body = "0" + body
	}
	return prefix + body
}

// agreeWorld — the committed iam state, the edge (AuthorizeService, via ciWorld) and
// the in-service gates, all over the SAME database and the SAME relation store.
type agreeWorld struct {
	*ciWorld
	// store — what the composition root hands iam's own gates.
	store *authzcascade.Client
	// accountGet / bindingGet — the two use-cases whose gates cover all three
	// in-service paths: authzguard.AllowsVerb (account read), requireGrantAuthority
	// Path 2 (binding read) and authzfilter.Visible (binding read, D-6 label floor).
	accountGet *accountapp.GetAccountUseCase
	bindingGet *accessbindingapp.GetAccessBindingUseCase
}

// newAgreeWorld wires the gates the way the composition root does: ONE relation value,
// which is the wrapper. withFacts=false reproduces the pre-fix state (no second chance)
// and is used only by the negative-control test.
func newAgreeWorld(t *testing.T, withFacts bool) *agreeWorld {
	t.Helper()
	ci := newCIWorld(t)
	repo := kachopg.New(ci.pool, nil)
	var facts authzcascade.FactSource
	if withFacts {
		// Mirrors the composition root, INCLUDING the batch source: the page filter
		// prefetches through it in production, so an agreement test that left it out would
		// be checking a shape production does not run. The single-object gates below take
		// the per-object path either way, so both are exercised here.
		structuralRepo := kachopg.NewStructuralFactsRepo(ci.pool)
		facts = authzcascade.New(repo).
			WithConditions(kachopg.NewConditionsRepo(ci.pool)).
			WithBatch(authzcascade.BatchSourceFunc(
				func(ctx context.Context) (authzcascade.StructuralSnapshot, error) {
					return structuralRepo.StructuralSnapshot(ctx)
				}))
	}
	store := authzcascade.Wrap(ci.harness.Client, facts)
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &agreeWorld{
		ciWorld:    ci,
		store:      store,
		accountGet: accountapp.NewGetAccountUseCase(repo).WithRelationStore(store),
		bindingGet: accessbindingapp.NewGetAccessBindingUseCase(repo).
			WithRelationStore(store, quiet).
			WithRelationQueries(store),
	}
}

func agUserCtx(id string) context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: id})
}

// requireQueueHasNotDelivered asserts the premise: no STRUCTURAL pointer for these
// objects is in the store. Grants (a delegation tuple whose subject is a user) are left
// alone — those are what the tests deliberately DO deliver.
//
// It is an assertion and not a comment because the alternative is a test that passes
// for the wrong reason: with the pointer delivered, every probe below resolves the
// ordinary way and the fix under test is never exercised.
func (w *agreeWorld) requireQueueHasNotDelivered(t *testing.T, objects ...string) {
	t.Helper()
	structural := map[string]bool{"project": true, "account": true, "cluster": true, "owner": true}
	for _, object := range objects {
		tuples, _, err := w.harness.Client.ReadTuples(context.Background(), "", "", object, 100, "")
		require.NoError(t, err, "premise read for %s", object)
		for _, tp := range tuples {
			require.Falsef(t, structural[tp.Relation],
				"premise broken: the store already holds the structural pointer "+
					"%s#%s@%s, so nothing below distinguishes a request-time cascade "+
					"from a delivered one", tp.Object, tp.Relation, tp.User)
		}
	}
}

// serviceShowsAccount / serviceShowsBinding — the OBSERVABLE in-service answer: did the
// read return the resource, or refuse at all. The refusal's code is deliberately not
// distinguished: not-found and permission-denied are the two masks iam's read gates use
// to hide a denial, and the question this file asks is whether the subject is served,
// not which mask a refusal wore.
func (w *agreeWorld) serviceShowsAccount(t *testing.T, subjectID, accountID string) bool {
	t.Helper()
	_, err := w.accountGet.Execute(agUserCtx(subjectID), domain.AccountID(accountID))
	if err != nil && strings.Contains(err.Error(), "invalid account id") {
		t.Fatalf("fixture id %q is not well-formed, so this probe never reached the gate", accountID)
	}
	return err == nil
}

func (w *agreeWorld) serviceShowsBinding(t *testing.T, subjectID, bindingID string) bool {
	t.Helper()
	_, err := w.bindingGet.Execute(agUserCtx(subjectID), domain.AccessBindingID(bindingID))
	if err != nil && strings.Contains(err.Error(), "invalid access binding id") {
		t.Fatalf("fixture id %q is not well-formed, so this probe never reached the gate", bindingID)
	}
	return err == nil
}

// pageShows runs the page filter — the third in-service path — over the ids of a page
// the caller has already read from iam's own database.
func (w *agreeWorld) pageShows(t *testing.T, subject string, ids []string) map[string]bool {
	t.Helper()
	got, err := authzfilter.VisibleSet(context.Background(), w.store, subject,
		"iam_access_binding", ids)
	require.NoError(t, err, "the page filter must not fail")
	return got
}

// TestAccountOwnerIsShownTheAccountHeIsAdmittedToDelete — the absurd pair, verbatim.
//
// Nothing is in the relation store: the account was created a moment ago. The edge
// resolves the owner's `owner` fact from the committed row and admits him to delete the
// account; the read must not then tell him it does not exist.
func TestAccountOwnerIsShownTheAccountHeIsAdmittedToDelete(t *testing.T) {
	w := newAgreeWorld(t, true)

	var (
		acc      = agId("acc", "agree1")
		owner    = agId("usr", "agreeown1")
		outsider = agId("usr", "agreeout1")
	)
	w.seedAccountWithOwner(t, acc, owner)
	w.seedUser(t, outsider, acc)
	w.requireQueueHasNotDelivered(t, "account:"+acc)

	edgeDelete := w.allowed(t, "user:"+owner, "v_delete", "account:"+acc)
	edgeRead := w.allowed(t, "user:"+owner, "v_get", "account:"+acc)
	require.True(t, edgeDelete, "control: the edge must admit the owner to delete his "+
		"own account with nothing delivered (this is the landed cascade)")
	require.True(t, edgeRead, "control: the edge must admit the owner to read it too")

	require.Equal(t, edgeRead, w.serviceShowsAccount(t, owner, acc),
		"the edge and the in-service read gate must give the account owner the SAME "+
			"answer; a subject admitted to delete a resource cannot be told the "+
			"resource does not exist when he reads it")

	// Narrowing: the second chance supplies the account the row actually names, so a
	// member who is neither owner nor administrator gains nothing.
	require.False(t, w.allowed(t, "user:"+outsider, "v_get", "account:"+acc),
		"control: the edge must refuse a non-owner")
	require.False(t, w.serviceShowsAccount(t, outsider, acc),
		"the in-service read gate must refuse a non-owner too")
}

// TestDelegatedAccountAdminGetsOneAnswerFromEdgeAndService — level 3 over TWO
// undelivered pointers (binding→project, project→account), which is the shape the
// in-service gates were denying while the edge admitted it.
//
// The binding read exercises both remaining paths: requireGrantAuthority Path 2 asks
// `admin` on the binding's scope, and the D-6 label floor asks the page filter about the
// binding object itself.
func TestDelegatedAccountAdminGetsOneAnswerFromEdgeAndService(t *testing.T) {
	w := newAgreeWorld(t, true)

	var (
		acc      = agId("acc", "agree2")
		owner    = agId("usr", "agreeown2")
		accAdmin = agId("usr", "agreeadm2")
		stranger = agId("usr", "agreestr2")
		grantee  = agId("usr", "agreegte2")
		prj      = agId("prj", "agree2")
		role     = agId("rol", "agree2")
		binding  = agId("acb", "agree2")
	)
	w.seedAccountWithOwner(t, acc, owner)
	w.seedUser(t, accAdmin, acc)
	w.seedUser(t, stranger, acc)
	w.seedUser(t, grantee, acc)
	w.seedProject(t, prj, acc)
	w.seedRole(t, role, acc)
	w.seedBinding(t, binding, grantee, role, "project", prj)

	// The ONLY tuple: the administrator's delegation. A grant, not a pointer.
	w.harness.Write(t, "user:"+accAdmin, "admin", "account:"+acc)
	w.requireQueueHasNotDelivered(t, "iam_access_binding:"+binding, "project:"+prj)

	edge := w.allowed(t, "user:"+accAdmin, "v_get", "iam_access_binding:"+binding)
	require.True(t, edge, "control: the edge must admit the delegated administrator to "+
		"a project-scoped binding of his own account over both undelivered pointers")
	require.Equal(t, edge, w.serviceShowsBinding(t, accAdmin, binding),
		"the delegated account administrator must get the SAME answer from the edge and "+
			"from iam's own gates")

	// The page filter is the third path and it is asked separately: a caller can be
	// admitted by the scope-authority gate and still be absent from every list, which is
	// a different observable and was equally broken.
	require.Contains(t, w.pageShows(t, "user:"+accAdmin, []string{binding}), binding,
		"the delegated administrator must SEE the binding on a page he lists, not only "+
			"be allowed to read it by id")

	// Narrowing, on both surfaces: a member of the same account without the delegation
	// is not thereby an administrator.
	require.False(t, w.allowed(t, "user:"+stranger, "v_get", "iam_access_binding:"+binding),
		"control: the edge must refuse a member without the delegation")
	require.False(t, w.serviceShowsBinding(t, stranger, binding),
		"iam's own gates must refuse a member without the delegation too")
	require.NotContains(t, w.pageShows(t, "user:"+stranger, []string{binding}), binding,
		"the page filter must not show the binding to a member without the delegation")

	// The grantee sees his OWN binding through the self floor, which is a different path
	// and must stay working — asserted so the narrowing above is not read as "nobody but
	// the administrator".
	require.True(t, w.serviceShowsBinding(t, grantee, binding),
		"the binding's own subject keeps seeing it through the self floor")
}

// TestOwnGatesDisagreeWhenTheSecondChanceIsAbsent — the injection, in the other
// direction, and the reason the two tests above are not vacuous.
//
// Same fixtures, same probes, fact source unwired: the edge still admits (it resolves
// its own facts) and iam's own gates must REFUSE. If this test ever goes green, the
// probes above have stopped depending on the second chance and prove nothing.
func TestOwnGatesDisagreeWhenTheSecondChanceIsAbsent(t *testing.T) {
	w := newAgreeWorld(t, false)
	require.False(t, w.store.SecondChanceReachable(),
		"premise: this world is deliberately wired without a fact source")

	var (
		acc      = agId("acc", "agree3")
		owner    = agId("usr", "agreeown3")
		accAdmin = agId("usr", "agreeadm3")
		grantee  = agId("usr", "agreegte3")
		prj      = agId("prj", "agree3")
		role     = agId("rol", "agree3")
		binding  = agId("acb", "agree3")
	)
	w.seedAccountWithOwner(t, acc, owner)
	w.seedUser(t, accAdmin, acc)
	w.seedUser(t, grantee, acc)
	w.seedProject(t, prj, acc)
	w.seedRole(t, role, acc)
	w.seedBinding(t, binding, grantee, role, "project", prj)
	w.harness.Write(t, "user:"+accAdmin, "admin", "account:"+acc)
	w.requireQueueHasNotDelivered(t, "account:"+acc, "iam_access_binding:"+binding, "project:"+prj)

	require.True(t, w.allowed(t, "user:"+owner, "v_get", "account:"+acc),
		"the edge resolves its own structural facts regardless of this wiring")
	require.False(t, w.serviceShowsAccount(t, owner, acc),
		"WITHOUT the second chance the in-service read gate refuses the owner — this is "+
			"the defect, reproduced, so the agreement tests above are known to be able "+
			"to fail")
	require.True(t, w.allowed(t, "user:"+accAdmin, "v_get", "iam_access_binding:"+binding),
		"the edge admits the delegated administrator regardless of this wiring")
	require.False(t, w.serviceShowsBinding(t, accAdmin, binding),
		"WITHOUT the second chance iam's own gates refuse the delegated administrator")
	require.NotContains(t, w.pageShows(t, "user:"+accAdmin, []string{binding}), binding,
		"WITHOUT the second chance the page filter hides the binding from him")
}
