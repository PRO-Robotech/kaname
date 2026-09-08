// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// interactive_client_integration_test.go — IAM-INT-1, the invariants that only a
// real database can answer for.
//
// Scenario 02 (name taken) is the reason this file exists. The rule is
// "cluster-unique name", and it is written as a UNIQUE index rather than a
// read-then-write check in Go. That difference is invisible to a unit test and
// decisive under concurrency: a software guard lets two writers both observe
// "free" and both insert. The race case below is the only thing that tells the
// two designs apart.
//
// Scenario 09 (idempotent delete) and the redirect-shape trigger are locked here
// for the same reason: they are the database's word, not the service's.

import (
	"context"
	stderrors "errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

func newInteractiveClient(name string) domain.InteractiveClient {
	return domain.InteractiveClient{
		ID:                     domain.InteractiveClientID(ids.NewHyphenID(ids.PrefixInteractiveClientHyphen)),
		Name:                   domain.InteractiveClientName(name),
		RedirectURIs:           []string{"https://api.example/auth/callback"},
		PostLogoutRedirectURIs: []string{},
		ClientID:               "provider-" + ids.NewHyphenID(ids.PrefixInteractiveClientHyphen),
		Audiences:              []string{"https://api.example"},
		GrantTypes:             []string{"authorization_code", "refresh_token"},
		Status:                 domain.InteractiveClientActive,
	}
}

func newInteractiveClientRepo(t *testing.T) (*kanamepg.InteractiveClientRepo, context.Context) {
	t.Helper()
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return kanamepg.NewInteractiveClientRepo(pool), ctx
}

// TestInteractiveClient_01_InsertGet_RoundTrip — scenario 01's storage half:
// what went in comes back, including the provider-side columns.
func TestInteractiveClient_01_InsertGet_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	repo, ctx := newInteractiveClientRepo(t)

	in := newInteractiveClient("console-roundtrip")
	created, err := repo.Insert(ctx, in)
	require.NoError(t, err)
	require.Equal(t, in.ID, created.ID)
	require.True(t, strings.HasPrefix(string(created.ID), "ic-"), "id must carry the ic- prefix")
	require.Len(t, string(created.ID), 20, "id form is ic- + 17 body chars")
	require.NotEmpty(t, created.ClientID)
	require.Equal(t, []string{"authorization_code", "refresh_token"}, created.GrantTypes)
	require.False(t, created.CreatedAt.IsZero(), "created_at is assigned by the database")

	got, err := repo.Get(ctx, in.ID)
	require.NoError(t, err)
	require.Equal(t, created.Name, got.Name)
	require.Equal(t, created.RedirectURIs, got.RedirectURIs)
}

// TestInteractiveClient_02_Insert_DuplicateName — the sequential half.
func TestInteractiveClient_02_Insert_DuplicateName(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	repo, ctx := newInteractiveClientRepo(t)

	_, err := repo.Insert(ctx, newInteractiveClient("console-dup"))
	require.NoError(t, err)

	_, err = repo.Insert(ctx, newInteractiveClient("console-dup"))
	require.Error(t, err)
	require.True(t, stderrors.Is(err, iamerr.ErrAlreadyExists),
		"a taken name must be ALREADY_EXISTS, got %v", err)
}

// TestInteractiveClient_02_Insert_RaceUnique — scenario 02 under concurrency.
//
// EXACTLY ONE writer may win. Anything else is the defect the UNIQUE index
// exists to prevent, and it is the case a unit test cannot reach: with a
// read-then-write guard in Go every one of these goroutines would observe the
// name as free before any of them inserted.
func TestInteractiveClient_02_Insert_RaceUnique(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	repo, ctx := newInteractiveClientRepo(t)

	const goroutines = 8
	results := make(chan error, goroutines)
	var ready sync.WaitGroup
	ready.Add(goroutines)
	startGate := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func() {
			ready.Done()
			<-startGate
			_, err := repo.Insert(ctx, newInteractiveClient("console-race"))
			results <- err
		}()
	}
	ready.Wait()
	close(startGate)

	successes, dupErrors, otherErrors := 0, 0, 0
	var otherMsg string
	for i := 0; i < goroutines; i++ {
		err := <-results
		switch {
		case err == nil:
			successes++
		case stderrors.Is(err, iamerr.ErrAlreadyExists):
			dupErrors++
		default:
			otherErrors++
			otherMsg = err.Error()
		}
	}
	require.Equal(t, 1, successes, "exactly one concurrent Insert may win the name")
	require.Equal(t, goroutines-1, dupErrors, "every loser must say ALREADY_EXISTS")
	require.Zero(t, otherErrors, "unexpected error from a losing writer: %s", otherMsg)

	// The winner is the only row: the count is the promise, not the error codes.
	page, _, err := repo.List(ctx, 50, "", "console-race")
	require.NoError(t, err)
	require.Len(t, page, 1, "the table must hold exactly one row for the contested name")
}

// TestInteractiveClient_09_Delete_Idempotent — scenario 09.
//
// The first Delete reports that a row was taken; the second reports that none
// was, and neither is an error. The boolean is what lets the use-case be
// idempotent to the caller WITHOUT the repo pretending a second removal happened
// — only a real removal owes a provider-side deregistration.
func TestInteractiveClient_09_Delete_Idempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	repo, ctx := newInteractiveClientRepo(t)

	in := newInteractiveClient("console-del")
	_, err := repo.Insert(ctx, in)
	require.NoError(t, err)

	removed, existed, err := repo.Delete(ctx, in.ID)
	require.NoError(t, err)
	require.True(t, existed, "the first Delete must report that a row was taken")
	require.Equal(t, in.ID, removed.ID)

	_, existed, err = repo.Delete(ctx, in.ID)
	require.NoError(t, err, "a repeated Delete is not an error")
	require.False(t, existed, "the second Delete must report that nothing was taken")

	_, err = repo.Get(ctx, in.ID)
	require.True(t, stderrors.Is(err, iamerr.ErrNotFound))
	require.Contains(t, err.Error(), fmt.Sprintf("InteractiveClient %s not found", in.ID),
		"the not-found tone is part of the contract")
}

// TestInteractiveClient_05_Get_NotFound — a well-formed id with no row is
// NOT_FOUND with the contract tone. (A MALFORMED id never reaches here — the
// use-case refuses it as the first statement — which is precisely why this test
// uses a well-formed one.)
func TestInteractiveClient_05_Get_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	repo, ctx := newInteractiveClientRepo(t)

	_, err := repo.Get(ctx, "ic-00000000000000000")
	require.True(t, stderrors.Is(err, iamerr.ErrNotFound))
	require.Contains(t, err.Error(), "InteractiveClient ic-00000000000000000 not found")
}

// TestInteractiveClient_03_DatabaseRefusesIllFormedTargets — the trigger.
//
// PAIRED on purpose. The rejection half alone would keep passing if the trigger
// refused everything; the acceptance half alone would keep passing if it refused
// nothing. Together they say the rule holds, and they say it about the DATABASE
// — the service's own validation is bypassed entirely on this path.
func TestInteractiveClient_03_DatabaseRefusesIllFormedTargets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	repo, ctx := newInteractiveClientRepo(t)

	// Positive: the legitimate shape is accepted (control for the negatives).
	ok := newInteractiveClient("console-ok")
	_, err := repo.Insert(ctx, ok)
	require.NoError(t, err, "a well-formed https target must be accepted")

	for name, uris := range map[string][]string{
		"plaintext":  {"http://api.example/cb"},
		"fragment":   {"https://api.example/cb#x"},
		"relative":   {"/cb"},
		"empty list": {},
	} {
		t.Run(name, func(t *testing.T) {
			bad := newInteractiveClient("console-bad-" + strings.ReplaceAll(name, " ", "-"))
			bad.RedirectURIs = uris
			_, err := repo.Insert(ctx, bad)
			require.Error(t, err, "the database accepted %v — the rule is not unavoidable", uris)
		})
	}

	// The post-logout list is covered by the same trigger, and it is checked
	// separately: it is OPTIONAL, so "empty is fine, malformed is not" is a
	// different statement than the one above.
	pl := newInteractiveClient("console-postlogout")
	pl.PostLogoutRedirectURIs = []string{"http://api.example/out"}
	_, err = repo.Insert(ctx, pl)
	require.Error(t, err, "a plaintext post-logout target must be refused too")
}
