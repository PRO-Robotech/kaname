// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// list_filter_unknown_rejected_integration_test.go — #445: a List `filter`
// expression the service does not understand must be REFUSED BY NAME, never
// accepted-and-ignored.
//
// The defect this locks: both iam repo-side parsers (`parseNameFilter`,
// `parseFieldFilter`) reported "not my shape" with a bare bool, and the caller's
// `if …; ok` had no else — so an unparseable filter added no WHERE condition and
// List answered with the FULL page. The caller asked to narrow and got everything
// back, which reads as a search result. Per api-conventions.md
// §"Принято-и-проигнорировано — ЗАПРЕЩЕНО" the only legal outcomes are: implement,
// refuse explicitly, or drop from the contract. Silently accepting is not one.
//
// Each negative below is paired with a POSITIVE control on the same table. Without
// the pair, "rejected" would be indistinguishable from "the filter matched nothing"
// — and a repo that refused every filter, valid ones included, would still be green.

import (
	"context"
	stderrors "errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	repoaccount "github.com/PRO-Robotech/kaname/internal/repo/kaname/account"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	repouser "github.com/PRO-Robotech/kaname/internal/repo/kaname/user"
)

// TestAccountList_UnknownFilter_445 — the `name=`-family parser (shared by
// account/group/project/role/service_account).
func TestAccountList_UnknownFilter_445(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "f445a")
	kept := seedAccount(t, ctx, repo, "acc-f445-kept", owner)
	seedAccount(t, ctx, repo, "acc-f445-other", owner)

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	// POSITIVE CONTROL — a well-formed filter still narrows to exactly one row.
	// If this ever goes red, the negatives below prove nothing.
	out, _, err := rd.Accounts().List(ctx, repoaccount.ListFilter{
		PageSize: 100,
		Filter:   fmt.Sprintf(`name=%q`, string(kept.Name)),
	})
	require.NoError(t, err, "well-formed name= filter must be accepted")
	require.Len(t, out, 1, "well-formed name= filter must narrow the page")
	assert.Equal(t, kept.ID, out[0].ID)

	// NEGATIVE — every one of these is an expression the service cannot honour.
	for _, expr := range []string{
		`nam="acc-f445-kept"`, // near-miss field name — the #445 report's own example
		`label="x"`,           // field that exists on the resource but is not filterable
		`acc-f445-kept`,       // bare value, no field and no operator
		`name~"acc"`,          // known field, operator we do not implement
		`name="unclosed`,      // known field, malformed value
	} {
		t.Run(expr, func(t *testing.T) {
			rows, _, ferr := rd.Accounts().List(ctx, repoaccount.ListFilter{
				PageSize: 100,
				Filter:   expr,
			})
			require.Error(t, ferr,
				"unknown filter %q must be refused, got %d rows back instead", expr, len(rows))
			assert.True(t, stderrors.Is(ferr, iamerr.ErrInvalidArg),
				"refusal must be InvalidArgument, got %v", ferr)
		})
	}
}

// TestUserList_UnknownFilter_445 — the multi-field parser (email / external_id /
// invite_status). Same class, second mechanism: here the caller chained three
// `else if`s and fell out of the chain silently.
func TestUserList_UnknownFilter_445(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	mustSeedUser(t, ctx, pool, "f445u1")
	mustSeedUser(t, ctx, pool, "f445u2")

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	// POSITIVE CONTROL — each whitelisted field still works after the fix.
	out, _, err := rd.Users().List(ctx, repouser.ListFilter{
		PageSize: 100,
		Filter:   `email="u-f445u1@example.com"`,
	})
	require.NoError(t, err, "well-formed email= filter must be accepted")
	require.Len(t, out, 1, "well-formed email= filter must narrow the page")

	out, _, err = rd.Users().List(ctx, repouser.ListFilter{
		PageSize: 100,
		Filter:   `invite_status="ACTIVE"`,
	})
	require.NoError(t, err, "well-formed invite_status= filter must be accepted")
	assert.NotEmpty(t, out, "invite_status=ACTIVE must match the seeded users")

	// NEGATIVE.
	for _, expr := range []string{
		`emai="u-f445u1@example.com"`, // near-miss on a whitelisted field
		`name="u-f445u1"`,             // valid field on OTHER resources, not on user
		`email:u-f445u1@example.com`,  // operator we do not implement
		`u-f445u1@example.com`,        // bare value
	} {
		t.Run(expr, func(t *testing.T) {
			rows, _, ferr := rd.Users().List(ctx, repouser.ListFilter{
				PageSize: 100,
				Filter:   expr,
			})
			require.Error(t, ferr,
				"unknown filter %q must be refused, got %d rows back instead", expr, len(rows))
			assert.True(t, stderrors.Is(ferr, iamerr.ErrInvalidArg),
				"refusal must be InvalidArgument, got %v", ferr)
		})
	}
}
