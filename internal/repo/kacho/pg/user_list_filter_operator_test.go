// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// user_list_filter_operator_test.go — #460. `pkg/filter` grammar has two
// operators, `=` and `CONTAINS`, and this reader dispatches on ast.Field while
// taking only ast.Value — so `email CONTAINS "acme"` built `lower(email) =
// lower($1)` and answered the substring question with an equality page under a
// 200. The caller cannot tell that from a genuine one-row result.
//
// Substring search on User is not missing — it is PUBLISHED, as `search="…"`
// (ListUsersRequest.filter), spanning email and id. So the fix is not to widen
// three more fields into LIKE; it is to refuse CONTAINS by name and say where
// substring search actually lives.
//
// The reader is built over a nil tx for the refusals ON PURPOSE (same argument as
// list_page_size_rejected_test.go): the check must run BEFORE any query is
// issued, so reaching the tx at all would panic and fail the test. The positive
// control uses a capturing tx instead, because "= still works" has to be proven
// by the SQL that was actually built, not by the absence of an error.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/user"
)

// errCapturedQuery — sentinel the capturing tx returns instead of rows. The List
// under test only has to get AS FAR AS the query for the positive control to hold;
// scanning rows is the integration suite's job, not this one's.
var errCapturedQuery = errors.New("capturing tx: query captured, no rows served")

// capturingTx implements pgx.Tx and records the SQL and args of the single Query
// the reader issues. Everything else panics: a call this test did not intend must
// be loud, not silently satisfied — a fake more permissive than the real thing
// hides exactly the defect it is standing in for.
type capturingTx struct {
	sql  string
	args []any
}

func (c *capturingTx) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	c.sql, c.args = sql, args
	return nil, errCapturedQuery
}

func (c *capturingTx) Begin(context.Context) (pgx.Tx, error) {
	panic("capturingTx: Begin not expected")
}
func (c *capturingTx) Commit(context.Context) error { panic("capturingTx: Commit not expected") }
func (c *capturingTx) Rollback(context.Context) error {
	panic("capturingTx: Rollback not expected")
}

func (c *capturingTx) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	panic("capturingTx: CopyFrom not expected")
}

func (c *capturingTx) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults {
	panic("capturingTx: SendBatch not expected")
}
func (c *capturingTx) LargeObjects() pgx.LargeObjects {
	panic("capturingTx: LargeObjects not expected")
}
func (c *capturingTx) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	panic("capturingTx: Prepare not expected")
}

func (c *capturingTx) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	panic("capturingTx: Exec not expected")
}
func (c *capturingTx) QueryRow(context.Context, string, ...any) pgx.Row {
	panic("capturingTx: QueryRow not expected")
}
func (c *capturingTx) Conn() *pgx.Conn { panic("capturingTx: Conn not expected") }

// userListFilterFields — the closed whitelist this reader declares, restated here
// so the test walks the same set the production switch does. A field added there
// without a case here leaves the new field unproven, which is the point.
var userListFilterFields = []string{"email", "external_id", "invite_status", "search"}

// TestUserList_460_ContainsRefusedByName — CONTAINS is refused on EVERY whitelisted
// field, including `search`: `search` is already the substring surface and it is
// spelled with `=`, so `search CONTAINS "x"` is a second way to say one thing and
// would have to be kept in step forever.
func TestUserList_460_ContainsRefusedByName(t *testing.T) {
	for _, field := range userListFilterFields {
		t.Run(field+" CONTAINS refused", func(t *testing.T) {
			r := &userReader{} // nil tx: the refusal must precede any query
			_, _, err := r.List(context.Background(), user.ListFilter{
				PageSize: 10,
				Filter:   field + ` CONTAINS "acme"`,
			})

			require.Error(t, err, "CONTAINS on %q must be refused, not answered as equality", field)
			assert.ErrorIs(t, err, iamerr.ErrInvalidArg)
			assert.Contains(t, err.Error(), "CONTAINS",
				"the refusal must name the operator it will not honour")
			assert.Contains(t, err.Error(), field,
				"the refusal must name the field the operator was used on")
			assert.Contains(t, err.Error(), `search="`,
				"the refusal must say where substring search on this resource actually lives")
		})
	}
}

// TestUserList_460_EqualsStillHonoured — the PAIRED positive control, asserted on
// the SQL that was built. Without it the refusal above stays green on a reader that
// rejects every filter, and `search=` — the one substring surface this resource
// publishes — would be dead with nothing to say so.
func TestUserList_460_EqualsStillHonoured(t *testing.T) {
	cases := []struct {
		field   string
		value   string
		wantSQL string
		wantArg any
	}{
		{"email", "a@b.io", "lower(email) = lower($1)", "a@b.io"},
		{"external_id", "ext-7", "external_id = $1", "ext-7"},
		{"invite_status", "PENDING", "invite_status = $1", "PENDING"},
		// The published substring surface: `search` is not a column, it is a term
		// over two of them, and it stays LIKE.
		{"search", "acme", `(lower(email) LIKE $1 ESCAPE '\' OR lower(id) LIKE $1 ESCAPE '\')`, "%acme%"},
	}
	for _, tc := range cases {
		t.Run(tc.field+" = honoured", func(t *testing.T) {
			tx := &capturingTx{}
			r := &userReader{tx: tx}

			_, _, err := r.List(context.Background(), user.ListFilter{
				PageSize: 10,
				Filter:   tc.field + `="` + tc.value + `"`,
			})

			require.ErrorIs(t, err, errCapturedQuery,
				"= must be honoured and reach the query; got %v", err)
			assert.Contains(t, strings.Join(strings.Fields(tx.sql), " "), tc.wantSQL,
				"the predicate built for %s= is not the one this resource promises", tc.field)
			require.NotEmpty(t, tx.args)
			assert.Equal(t, tc.wantArg, tx.args[0])
		})
	}
}
