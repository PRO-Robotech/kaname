// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package listvisibility_test holds the RED-phase probes for
// docs/specs/sub-phase-IAM-645-list-page-is-a-page-of-the-visible-acceptance.md
// (task PRO-Robotech/kacho#645).
//
// # What these probes are about
//
// A list page is a page of what the caller may SEE, not a window over the whole
// table from which the visible is then subtracted. Today every iam list reads a
// page from its own database by cursor and filters it afterwards, so an object
// with more than `page_size` invisible predecessors never reaches the filter at
// all: the caller gets `200` with an empty array while a Get on that same object
// by id answers `200`.
//
// # Why real Postgres AND real OpenFGA
//
// The defect is an ORDER of operations between the database page and the rights
// filter, so neither side may be a lenient double:
//
//   - a fake repository that ignores `PageSize` (the one the package's existing
//     unit tests use) hides the defect BY CONSTRUCTION — it hands the whole
//     population to the filter, which is exactly the state the product never
//     reaches;
//   - a fake relation store that answers from an allow-list would not exercise
//     the batched question path, the store's 50-object partition ceiling, or the
//     model's structural derivations (`owner`, `super_admin`, `group#member`),
//     all of which the acceptance names as visibility paths that the narrowing
//     must know.
//
// So: `kachopg.NewTestPostgres` (testcontainers, migrated) plus `fgatest.New`
// (real openfga/openfga loaded with the canonical `fga_model.fga`). This is the
// harness `readauthz` already uses for the single-object side of the same
// contract; these probes are its list-side counterpart.
//
// # Creation time is an INPUT of these probes, not an accident
//
// The cursor is `(created_at, id) ASC`, and "the threshold" is defined as "more
// than `page_size` objects the caller cannot see lie BEFORE his own by creation
// time". Rows inserted in one test share a timestamp to the microsecond and the
// tie is then broken by a crockford-random id — that is, by chance. Every seed
// helper here therefore SETS `created_at` explicitly, one second apart, in the
// order the scenario needs. Without it the probes would be measuring the
// generator, not the product.
package listvisibility_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/internal/pgtest"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho/services/iam/internal/testsupport/fgatest"
)

// probePageSize — the page size every threshold probe asks for. It is the
// product's own default (`pkg/validate` DefaultPageSize), which is what the live
// stand was running when the defect was observed.
const probePageSize int32 = 50

// env bundles one test's live Postgres, live OpenFGA store and the identities
// every scenario shares.
type env struct {
	pool *pgxpool.Pool
	repo *kachopg.Repository
	fga  *fgatest.Harness

	// base + seq produce the strictly increasing creation timestamps the cursor
	// orders by. base is placed in the FUTURE so that rows seeded by migrations
	// (the system role catalog) sort ahead of everything a probe creates, which
	// keeps their position in the sequence stated rather than assumed.
	base time.Time
	seq  int

	// callerUser is the principal under test; callerAcc is the account it owns.
	callerUser domain.UserID
	callerAcc  domain.AccountID
	// foreignUser owns foreignAcc — everything the caller must NOT see lives there.
	foreignUser domain.UserID
	foreignAcc  domain.AccountID
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()

	pool, err := coredb.NewPool(ctx, kachopg.NewTestPostgres(t))
	require.NoError(t, err)
	// Закрытие С ПРЕДЕЛОМ, а не `t.Cleanup(pool.Close)`: отложенное закрытие ждёт
	// соединение, которое проба, упавшая внутри открытой транзакции, не вернёт
	// никогда, — и уносит с собой вердикт всего пакета. Здесь это не гипотетика:
	// каждый сценарий берёт reader-TX и половина из них намеренно роняет запрос.
	pgtest.ClosePoolAtEnd(t, pool)

	e := &env{
		pool: pool,
		repo: kachopg.New(pool, nil),
		fga:  fgatest.New(t),
		base: time.Now().UTC().Truncate(time.Second).Add(time.Hour),
	}
	t.Cleanup(e.repo.Close)

	e.callerUser, e.callerAcc = e.seedUserWithAccount(t, "caller")
	e.foreignUser, e.foreignAcc = e.seedUserWithAccount(t, "foreign")
	return e
}

// at returns the next creation timestamp in the sequence. Every seeded row takes
// one, so "created before" is a property the test states, not one it hopes for.
func (e *env) at() time.Time {
	e.seq++
	return e.base.Add(time.Duration(e.seq) * time.Second)
}

func (e *env) ctxAs(id string, typ string) context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: typ, ID: id})
}

func (e *env) ctxUser(id domain.UserID) context.Context {
	return e.ctxAs(string(id), "user")
}

// ctxAnonymous mirrors what api-gateway injects for an unauthenticated (or
// un-forwarded) caller.
func (e *env) ctxAnonymous() context.Context {
	return e.ctxAs("anonymous", "system")
}

// ── seeding ──────────────────────────────────────────────────────────────────
//
// All seeding is raw SQL on purpose. The writer path emits outbox rows and audit
// entries that these probes do not exercise, and — decisively — it does not let
// the caller choose `created_at`, which is the very axis under test.

func (e *env) seedUserWithAccount(t *testing.T, suffix string) (domain.UserID, domain.AccountID) {
	t.Helper()
	ctx := context.Background()
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	accID := domain.AccountID(ids.NewID(domain.PrefixAccount))
	uAt, aAt := e.at(), e.at()

	tx, err := e.pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status, created_at)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE', $6)`,
		string(uid), string(accID), "ext-"+suffix+"-"+string(uid),
		"u-"+suffix+"-"+lastSix(string(uid))+"@example.com", "User "+suffix, uAt)
	require.NoError(t, err, "seed user %s", suffix)
	_, err = tx.Exec(ctx, `
		INSERT INTO accounts (id, name, owner_user_id, labels, created_at)
		VALUES ($1, $2, $3, '{}'::jsonb, $4)`,
		string(accID), "acc-"+suffix+"-"+lastSix(string(accID)), string(uid), aAt)
	require.NoError(t, err, "seed account for %s", suffix)
	require.NoError(t, tx.Commit(ctx))
	return uid, accID
}

func (e *env) seedProject(t *testing.T, acc domain.AccountID, name string) string {
	t.Helper()
	id := ids.NewID(domain.PrefixProject)
	_, err := e.pool.Exec(context.Background(), `
		INSERT INTO projects (id, account_id, name, labels, created_at)
		VALUES ($1, $2, $3, '{}'::jsonb, $4)`,
		id, string(acc), name, e.at())
	require.NoError(t, err, "seed project %s", name)
	return id
}

// seedProjectAt is seedProject with the creation time chosen by the caller —
// used where a probe has to place a row INSIDE an existing sequence rather than
// after it.
func (e *env) seedProjectAt(t *testing.T, acc domain.AccountID, name string, at time.Time) string {
	t.Helper()
	id := ids.NewID(domain.PrefixProject)
	_, err := e.pool.Exec(context.Background(), `
		INSERT INTO projects (id, account_id, name, labels, created_at)
		VALUES ($1, $2, $3, '{}'::jsonb, $4)`,
		id, string(acc), name, at)
	require.NoError(t, err, "seed project %s", name)
	return id
}

// timestampOf reads a row's creation time back from the database, so a probe
// that needs to sit between two rows measures where they are instead of assuming.
func (e *env) timestampOf(t *testing.T, table, id string) time.Time {
	t.Helper()
	var at time.Time
	err := e.pool.QueryRow(context.Background(),
		`SELECT created_at FROM `+table+` WHERE id = $1`, id).Scan(&at)
	require.NoError(t, err, "read created_at of %s.%s", table, id)
	return at
}

func (e *env) seedUser(t *testing.T, acc domain.AccountID, suffix string) string {
	t.Helper()
	id := ids.NewID(domain.PrefixUser)
	_, err := e.pool.Exec(context.Background(), `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status, created_at)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE', $6)`,
		id, string(acc), "ext-"+suffix+"-"+id,
		"u-"+suffix+"-"+lastSix(id)+"@example.com", "User "+suffix, e.at())
	require.NoError(t, err, "seed user %s", suffix)
	return id
}

func (e *env) seedGroup(t *testing.T, acc domain.AccountID, name string) string {
	t.Helper()
	id := ids.NewID(domain.PrefixGroup)
	_, err := e.pool.Exec(context.Background(), `
		INSERT INTO groups (id, account_id, name, labels, created_at)
		VALUES ($1, $2, $3, '{}'::jsonb, $4)`,
		id, string(acc), name, e.at())
	require.NoError(t, err, "seed group %s", name)
	return id
}

func (e *env) seedServiceAccount(t *testing.T, acc domain.AccountID, name string) string {
	t.Helper()
	id := ids.NewID(domain.PrefixServiceAccount)
	_, err := e.pool.Exec(context.Background(), `
		INSERT INTO service_accounts (id, account_id, name, enabled, created_at)
		VALUES ($1, $2, $3, true, $4)`,
		id, string(acc), name, e.at())
	require.NoError(t, err, "seed service account %s", name)
	return id
}

// before returns a timestamp strictly EARLIER than anything the migrations
// seeded, so a probe can place rows AHEAD of the system-role catalog. The
// catalog is written when the migrations run, i.e. "now"; base is an hour ahead
// of that, so a year back is unambiguously before it.
func (e *env) before(i int) time.Time {
	return e.base.Add(-365 * 24 * time.Hour).Add(time.Duration(i) * time.Second)
}

func (e *env) seedCustomRole(t *testing.T, acc domain.AccountID, name string) string {
	t.Helper()
	return e.seedCustomRoleAt(t, acc, name, e.at())
}

func (e *env) seedCustomRoleAt(t *testing.T, acc domain.AccountID, name string, at time.Time) string {
	t.Helper()
	id := ids.NewID(domain.PrefixRole)
	// `is_system` is GENERATED (it follows cluster_id), so it is deliberately
	// absent from the column list: an account-scoped role IS a custom role.
	_, err := e.pool.Exec(context.Background(), `
		INSERT INTO roles (id, account_id, name, permissions, created_at)
		VALUES ($1, $2, $3, '["iam.project.*.get"]'::jsonb, $4)`,
		id, string(acc), name, at)
	require.NoError(t, err, "seed custom role %s", name)
	return id
}

// seedAccount creates an account owned by `owner`. Used for the `account`
// surface, where the objects being listed ARE accounts.
func (e *env) seedAccount(t *testing.T, owner domain.UserID, suffix string) string {
	t.Helper()
	id := ids.NewID(domain.PrefixAccount)
	_, err := e.pool.Exec(context.Background(), `
		INSERT INTO accounts (id, name, owner_user_id, labels, created_at)
		VALUES ($1, $2, $3, '{}'::jsonb, $4)`,
		id, "acc-"+suffix+"-"+lastSix(id), string(owner), e.at())
	require.NoError(t, err, "seed account %s", suffix)
	return id
}

// seedAccessBinding writes a grant row. The subject and role must already exist
// — a BEFORE INSERT trigger probes both (migration 0049), so a fixture that
// invented them would be refused, which is the fixture staying no more lenient
// than the product.
func (e *env) seedAccessBinding(t *testing.T, subject domain.UserID, roleID, resourceType, resourceID string) string {
	t.Helper()
	return e.seedAccessBindingFor(t, "user", string(subject), roleID, resourceType, resourceID)
}

// seedAccessBindingFor is seedAccessBinding for ANY subject kind the schema
// admits ('user' / 'service_account' / 'group').
//
// # A grant exists in TWO places, and a fixture writing one of them is blind
//
// In production a grant is a ROW in iam's own database, and the relation tuple
// is its MATERIALIZATION — the row is the authority, the tuple is the copy the
// model answers from. A probe that writes only the tuple therefore describes a
// state the product never reaches, and it does so in the one direction that
// matters here: the candidate selection of a narrowed page reads the ROWS
// (internal/repo/kacho/visibility), so a grant with no row names no candidate,
// and the probe reports "invisible" for a caller whose grant is live.
//
// That is not the probe's subject. 645-06/07/07b are about the PATHS by which an
// object becomes visible; each of them needs its path to exist on both sides, or
// it is measuring the fixture. Hence this helper, and hence seedGroupMember
// below — the membership leg of path П2 lives in `group_members` and nowhere
// else.
func (e *env) seedAccessBindingFor(t *testing.T, subjectType, subjectID, roleID, resourceType, resourceID string) string {
	t.Helper()
	ctx := context.Background()
	id := ids.NewID(domain.PrefixAccessBinding)
	at := e.at()
	tx, err := e.pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO access_bindings
			(id, subject_type, subject_id, role_id, resource_type, resource_id, status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE', $7)`,
		id, subjectType, subjectID, roleID, resourceType, resourceID, at)
	require.NoError(t, err, "seed access binding for %s:%s on %s:%s",
		subjectType, subjectID, resourceType, resourceID)
	_, err = tx.Exec(ctx, `
		INSERT INTO access_binding_subjects (binding_id, subject_type, subject_id, ordinal)
		VALUES ($1, $2, $3, 0)`, id, subjectType, subjectID)
	require.NoError(t, err, "seed access binding subject")
	require.NoError(t, tx.Commit(ctx))
	return id
}

// seedGroupMember writes the membership leg of path П2. `member_type` is
// constrained to 'user' / 'service_account' by the schema, and a BEFORE INSERT
// trigger probes the member's existence — again, no more lenient than the
// product.
func (e *env) seedGroupMember(t *testing.T, groupID, memberType, memberID string) {
	t.Helper()
	_, err := e.pool.Exec(context.Background(), `
		INSERT INTO group_members (group_id, member_type, member_id, added_at)
		VALUES ($1, $2, $3, $4)`, groupID, memberType, memberID, e.at())
	require.NoError(t, err, "seed group member %s:%s in %s", memberType, memberID, groupID)
}

// systemRoleIDs — the catalog rows the migrations seed. They are the `role`
// surface's code floor (`is_system` bypasses the filter entirely), so a probe on
// that surface must expect them in the answer rather than be surprised by them.
func (e *env) systemRoleIDs(t *testing.T) []string {
	t.Helper()
	rows, err := e.pool.Query(context.Background(),
		`SELECT id FROM roles WHERE is_system ORDER BY created_at, id`)
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		out = append(out, id)
	}
	require.NoError(t, rows.Err())
	return out
}

// anySystemRoleID returns one seeded system role — the role a grant fixture can
// point at without inventing one.
func (e *env) anySystemRoleID(t *testing.T) string {
	t.Helper()
	ids := e.systemRoleIDs(t)
	require.NotEmpty(t, ids, "migrations must seed a system role catalog; without it the grant fixtures have no role to reference")
	return ids[0]
}

func lastSix(s string) string {
	if len(s) <= 6 {
		return s
	}
	return s[len(s)-6:]
}

func fgaUser(id domain.UserID) string { return "user:" + string(id) }

func fgaObject(objectType, id string) string { return objectType + ":" + id }

func projectName(i int) string    { return fmt.Sprintf("prj-seed-%04d", i) }
func groupName(i int) string      { return fmt.Sprintf("grp-seed-%04d", i) }
func svcAccountName(i int) string { return fmt.Sprintf("sva-seed-%04d", i) }

// roleName obeys the custom-role name grammar (`^[a-z][a-z0-9_]{0,40}$`), which
// is NOT the grammar of the other names — a dash is refused there.
func roleName(i int) string { return fmt.Sprintf("rol_seed_%04d", i) }
