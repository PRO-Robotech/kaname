// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// page_cost_integration_test.go — what a page costs, measured, not estimated.
//
// The open question when the second chance was localised to one wrapper was cost. A single
// denied object is cheap by construction: one map lookup for a foreign type, and for an own
// type one read-only transaction on the primary with at most three primary-key lookups on
// one snapshot, plus one more relation question. A PAGE of denials multiplies that by the
// page, page size is part of the contract up to 1000, and narrowing the page to fit a
// budget is forbidden — so it had to be measured before the shape was fixed.
//
// WHAT THE MEASUREMENT ESTABLISHED, AND WHAT IT DECIDED
//
// Per-object derivation on a page of 100 denials: 200 primary transactions, 1000
// statements, and twice the relation questions. Ten times that page — which the contract
// allows — is 2000 transactions, and no request budget survives it. So the shape is not
// per-object on a page: the facts of the whole page are read on ONE snapshot, and each
// per-object question then carries the facts it needs instead of asking twice.
//
// Both shapes are still measured here, side by side, because the number that justifies the
// second one is only meaningful next to the first.
//
// WHY COUNTS RATHER THAN SECONDS
//
// Wall time on a local container says little about a deployment where the database is a
// network hop away; the WORK is what carries over. The assertions are therefore on counts,
// which are deterministic, and the time is logged for scale and never asserted — so this
// file cannot become a flaky gate.
//
// Real OpenFGA + real Postgres. Skipped under -short.

package authzcascade

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzfilter"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authztypes"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho/services/iam/internal/testsupport/fgatest"
)

// pageSize — the measured page. The contract's maximum is ten times this; the assertions
// below are about how the cost SCALES, which is what makes the smaller measurement
// sufficient.
const pageSize = 100

// ── instruments ───────────────────────────────────────────────────────────────

// countingRelations counts relation questions, split by whether the question carried
// derived facts. The split is what makes the added cost readable: the total is what the
// store is asked, and the shape of the split says how it was asked.
type countingRelations struct {
	Relations
	plain     atomic.Int64
	withFacts atomic.Int64
}

func (c *countingRelations) Check(ctx context.Context, subject, relation, object string) (bool, error) {
	c.plain.Add(1)
	return c.Relations.Check(ctx, subject, relation, object)
}

func (c *countingRelations) CheckWithContext(
	ctx context.Context, subject, relation, object string, condCtx map[string]any,
) (bool, error) {
	c.plain.Add(1)
	return c.Relations.CheckWithContext(ctx, subject, relation, object, condCtx)
}

func (c *countingRelations) CheckWithContextualTuples(
	ctx context.Context, subject, relation, object string,
	condCtx map[string]any, contextual []authztypes.TupleKey,
) (bool, error) {
	c.withFacts.Add(1)
	return c.Relations.CheckWithContextualTuples(ctx, subject, relation, object, condCtx, contextual)
}

// BatchCheckWithContext / BatchCheckItems — the batched doors, counted in the SAME
// unit as the per-object ones: one QUESTION per item.
//
// The unit has to stay the question, not the request, or the measurement below stops
// measuring the thing it was written for. Its subject is "does a page pay more relation
// questions than it did before the second chance existed", and a batch that carries 50
// questions in one message still asks the store 50 things. Counting requests would show
// the page getting forty times cheaper the day batching landed and would say nothing at
// all about whether the second chance had started doubling them again.
//
// They must also EXIST. A double that omits them is not neutral: authzcascade.Client
// falls back to the per-object path when its Relations cannot carry per-item tuples, so
// a double without these methods quietly measures the fallback and reports it as the
// shipped shape.
func (c *countingRelations) BatchCheckWithContext(
	ctx context.Context, subject, relation string, objects []string, condCtx map[string]any,
) ([]bool, error) {
	c.plain.Add(int64(len(objects)))
	return c.Relations.BatchCheckWithContext(ctx, subject, relation, objects, condCtx)
}

func (c *countingRelations) BatchCheckItems(
	ctx context.Context, subject, relation string,
	items []clients.BatchCheckItem, condCtx map[string]any,
) ([]bool, error) {
	// An item carrying facts is a with-facts question and an item without is a plain
	// one, exactly as the per-object counters classify them — the classification is
	// about what the question carries, not about how it travelled.
	for _, it := range items {
		if len(it.Contextual) > 0 {
			c.withFacts.Add(1)
			continue
		}
		c.plain.Add(1)
	}
	if bc, ok := c.Relations.(interface {
		BatchCheckItems(context.Context, string, string, []clients.BatchCheckItem, map[string]any) ([]bool, error)
	}); ok {
		return bc.BatchCheckItems(ctx, subject, relation, items, condCtx)
	}
	out := make([]bool, len(items))
	for i, it := range items {
		var (
			allowed bool
			err     error
		)
		if len(it.Contextual) > 0 {
			allowed, err = c.Relations.CheckWithContextualTuples(ctx, subject, relation, it.Object, condCtx, it.Contextual)
		} else {
			allowed, err = c.Relations.CheckWithContext(ctx, subject, relation, it.Object, condCtx)
		}
		if err != nil {
			return nil, err
		}
		out[i] = allowed
	}
	return out, nil
}

// countingPrimary counts per-object read transactions on the primary — the unit a network
// hop to the database charges for, independently of how many rows are read inside one.
type countingPrimary struct {
	inner PrimaryReaderSource
	txs   atomic.Int64
}

func (c *countingPrimary) ReaderFromPrimary(ctx context.Context) (kachorepo.Reader, error) {
	c.txs.Add(1)
	return c.inner.ReaderFromPrimary(ctx)
}

// countingBatch counts page snapshots, the batch counterpart of the above.
type countingBatch struct {
	inner     *kachopg.StructuralFactsRepo
	snapshots atomic.Int64
}

func (c *countingBatch) StructuralSnapshot(ctx context.Context) (StructuralSnapshot, error) {
	c.snapshots.Add(1)
	return c.inner.StructuralSnapshot(ctx)
}

// queryTracer counts SQL statements on the pool it is attached to. The resolver gets its
// OWN pool so seeding never lands in the count.
type queryTracer struct{ n atomic.Int64 }

func (q *queryTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	q.n.Add(1)
	return ctx
}

func (q *queryTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// shape — which of the three forms is being measured.
type shape int

const (
	// noSecondChance — the store on its own delivered tuples. The baseline this replaces.
	noSecondChance shape = iota
	// perObjectSecondChance — every denied question derives its own facts. Measured to
	// establish why a page must not use it.
	perObjectSecondChance
	// pagePrefetched — the facts of the page read on one snapshot; each question carries
	// what it needs. The shipped form.
	pagePrefetched
)

// costReading — one measured run.
type costReading struct {
	label      string
	plain      int64
	withFacts  int64
	perObjTx   int64
	snapshots  int64
	statements int64
	elapsed    time.Duration
	visible    int
}

func (r costReading) questions() int64 { return r.plain + r.withFacts }

func (r costReading) String() string {
	return fmt.Sprintf("%-38s questions=%4d (plain %3d / with-facts %3d) per-object-tx=%4d "+
		"page-snapshots=%d sql=%4d visible=%4d wall=%s",
		r.label, r.questions(), r.plain, r.withFacts, r.perObjTx, r.snapshots, r.statements,
		r.visible, r.elapsed.Round(time.Millisecond))
}

// ── fixture ───────────────────────────────────────────────────────────────────

// costWorld — one account, one project, pageSize bindings scoped to that project, and
// NOTHING structural in the relation store.
type costWorld struct {
	harness  *fgatest.Harness
	seedPool *pgxpool.Pool
	dsn      string
	ids      []string
	account  string
	project  string
}

func newCostWorld(t *testing.T) *costWorld {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping real-OpenFGA + real-Postgres measurement in -short mode")
	}
	h := fgatest.New(t)
	dsn := kachopg.NewTestPostgres(t)
	pool, err := pgxpool.New(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	w := &costWorld{
		harness: h, seedPool: pool, dsn: dsn,
		account: costID("acc", "cost1"),
		project: costID("prj", "cost1"),
	}
	ctx := context.Background()
	owner := costID("usr", "costown1")
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO kacho_iam.accounts (id, name, owner_user_id) VALUES ($1, $1, $2)`,
		w.account, owner)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO kacho_iam.users (id, external_id, email, account_id)
	                       VALUES ($1, $1, $1 || '@example.test', $2)`, owner, w.account)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	exec := func(sql string, args ...any) {
		_, eerr := pool.Exec(ctx, sql, args...)
		require.NoError(t, eerr, "seed: %s", sql)
	}
	exec(`INSERT INTO kacho_iam.projects (id, account_id, name) VALUES ($1, $2, $1)`, w.project, w.account)
	role := costID("rol", "cost1")
	exec(`INSERT INTO kacho_iam.roles (id, account_id, name, permissions)
	      VALUES ($1, $2, $3, '["vpc.network.all.get"]'::jsonb)`,
		role, w.account, strings.ReplaceAll(role, "-", "_"))
	// One grantee per binding: an ACTIVE grant is unique on (subject, role, scope), so a
	// page of pageSize bindings on ONE scope needs pageSize distinct subjects. That is also
	// the realistic shape of the page this measures — many people granted inside one project.
	for i := 0; i < pageSize; i++ {
		grantee := costID("usr", fmt.Sprintf("costgte%d", i))
		exec(`INSERT INTO kacho_iam.users (id, external_id, email, account_id)
		      VALUES ($1, $1, $1 || '@example.test', $2)`, grantee, w.account)
		id := costID("acb", fmt.Sprintf("cost%d", i))
		exec(`INSERT INTO kacho_iam.access_bindings
		        (id, subject_type, subject_id, role_id, resource_type, resource_id)
		      VALUES ($1, 'user', $2, $3, 'project', $4)`, id, grantee, role, w.project)
		w.ids = append(w.ids, id)
	}
	return w
}

func costID(prefix, tail string) string {
	body := tail
	for len(prefix)+len(body) < 20 {
		body = "0" + body
	}
	return prefix + body
}

// tracedPool — a pool whose statements are counted.
func (w *costWorld) tracedPool(t *testing.T) (*pgxpool.Pool, *queryTracer) {
	t.Helper()
	tracer := &queryTracer{}
	cfg, err := pgxpool.ParseConfig(w.dsn)
	require.NoError(t, err)
	cfg.ConnConfig.Tracer = tracer
	// NewWithConfig, not New(dsn): the tracer lives on the config, so a pool built from the
	// connection string alone would silently count nothing.
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool, tracer
}

// measure runs the page filter once for `subject` over `ids` and returns the work it cost.
func (w *costWorld) measure(t *testing.T, label, subject string, ids []string, sh shape) costReading {
	t.Helper()
	ctx := context.Background()
	pool, tracer := w.tracedPool(t)

	counting := &countingRelations{Relations: w.harness.Client}
	var store authzfilter.ObjectChecker = counting
	var (
		primary *countingPrimary
		batch   *countingBatch
	)
	if sh != noSecondChance {
		primary = &countingPrimary{inner: kachopg.New(pool, nil)}
		resolver := New(primary)
		if sh == pagePrefetched {
			batch = &countingBatch{inner: kachopg.NewStructuralFactsRepo(pool)}
			resolver = resolver.WithBatch(batch)
		}
		store = Wrap(counting, resolver)
	}

	start := time.Now()
	visible, err := authzfilter.VisibleSet(ctx, store, subject, "iam_access_binding", ids)
	elapsed := time.Since(start)
	require.NoError(t, err, "the page filter must not fail")

	r := costReading{
		label: label, plain: counting.plain.Load(), withFacts: counting.withFacts.Load(),
		statements: tracer.n.Load(), elapsed: elapsed, visible: len(visible),
	}
	if primary != nil {
		r.perObjTx = primary.txs.Load()
	}
	if batch != nil {
		r.snapshots = batch.snapshots.Load()
	}
	t.Log(r.String())
	return r
}

// ── the measurement ───────────────────────────────────────────────────────────

// TestPageCost — the answer to "what does a page of 100 denied items cost", and the gate
// that keeps the answer true.
//
// It pins the SHAPE of the cost rather than a duration: the page must not pay more
// relation questions than it did before the second chance existed, and its database work
// must not grow with the page. A later change that made either grow — a walk that re-read
// an ancestor per row, a prefetch that stopped being reached — fails here instead of in
// production on a full page.
func TestPageCost(t *testing.T) {
	w := newCostWorld(t)
	stranger := "user:" + costID("usr", "coststr1")
	admin := "user:" + costID("usr", "costadm1")
	// The administrator's authority is a GRANT that WAS delivered. The pointers that carry
	// it down to each binding are not.
	w.harness.Write(t, admin, "admin", "account:"+w.account)

	baseDeny := w.measure(t, "denied page, no second chance", stranger, w.ids, noSecondChance)
	objDeny := w.measure(t, "denied page, per-object facts", stranger, w.ids, perObjectSecondChance)
	pageDeny := w.measure(t, "denied page, page-prefetched", stranger, w.ids, pagePrefetched)
	baseAllow := w.measure(t, "tier-allowed page, no second chance", admin, w.ids, noSecondChance)
	pageAllow := w.measure(t, "tier-allowed page, page-prefetched", admin, w.ids, pagePrefetched)

	// The defect in its list-shaped form: without the second chance the delegated
	// administrator's page is EMPTY although his grant is live.
	require.Zero(t, baseAllow.visible,
		"premise: without the second chance the delegated administrator sees none of the "+
			"%d bindings in his own account", pageSize)
	require.Equal(t, pageSize, pageAllow.visible, "with it he must see all of them")
	require.Zero(t, pageDeny.visible, "a subject holding nothing must still see nothing")
	require.Zero(t, objDeny.visible, "and the per-object shape must agree about that")

	// Why the per-object shape is not the shipped one: it doubles the questions AND opens
	// a transaction per question. These are the numbers the choice was made on.
	require.Equal(t, int64(2*pageSize), baseDeny.questions(),
		"premise: the page filter asks two relations per denied object")
	require.Equal(t, 2*baseDeny.questions(), objDeny.questions(),
		"per-object: every denial is asked twice")
	require.Equal(t, int64(2*pageSize), objDeny.perObjTx,
		"per-object: one transaction per denied question")

	// The shipped shape: the SAME number of questions as before the second chance existed,
	// one snapshot, and no per-object transaction at all.
	require.Equal(t, baseDeny.questions(), pageDeny.questions(),
		"the page must not pay more relation questions than it did before")
	require.Equal(t, int64(1), pageDeny.snapshots, "one snapshot for the page")
	require.Zero(t, pageDeny.perObjTx,
		"and no per-object transaction — every fact came from the page read")
	require.Less(t, pageDeny.statements, objDeny.statements/10,
		"the page read must cost an order of magnitude less than deriving per object")

	// A tier-allowed page pays FEWER questions than the baseline, because the first relation
	// already resolves and the filter never asks the second.
	require.Equal(t, int64(pageSize), pageAllow.questions(),
		"an object allowed on the first relation is asked once, not twice")
	require.Equal(t, int64(1), pageAllow.snapshots)

	t.Logf("SUMMARY denied page of %d — questions %d (was %d), page snapshots %d, sql %d, "+
		"wall %s (baseline %s, per-object %s)",
		pageSize, pageDeny.questions(), baseDeny.questions(), pageDeny.snapshots, pageDeny.statements,
		pageDeny.elapsed.Round(time.Millisecond), baseDeny.elapsed.Round(time.Millisecond),
		objDeny.elapsed.Round(time.Millisecond))
	t.Logf("SUMMARY per-object shape, rejected: %d transactions and %d statements for the same page",
		objDeny.perObjTx, objDeny.statements)
	// The cost this file must NOT hide: the question COUNT is unchanged, but a question
	// carrying facts is more work for the relation store than a plain one, because the facts
	// are merged into the tuple set for the duration of it. So the page is not free — it is
	// cheaper than either alternative, which is a different claim, and the number belongs in
	// the log rather than in an argument.
	t.Logf("SUMMARY per-question cost: plain %.3fms, carrying facts %.3fms — same count, "+
		"more work each; the alternative shapes pay this AND a transaction per row",
		float64(baseDeny.elapsed.Microseconds())/float64(baseDeny.questions())/1000,
		float64(pageDeny.elapsed.Microseconds())/float64(pageDeny.questions())/1000)
}

// TestPageReadDoesNotGrowWithThePage — the claim the contract needs, asserted rather than
// argued: page size may be up to 1000 and narrowing it to fit a budget is forbidden, so the
// database work of the page read must be the SAME for a page of 100 and a page of 10.
//
// Statement counts, not seconds: a duration would drift with the machine, while "the same
// number of statements" is exactly the property that makes the page size irrelevant.
func TestPageReadDoesNotGrowWithThePage(t *testing.T) {
	w := newCostWorld(t)
	stranger := "user:" + costID("usr", "coststr2")

	small := w.measure(t, "denied page of 10", stranger, w.ids[:10], pagePrefetched)
	full := w.measure(t, "denied page of 100", stranger, w.ids, pagePrefetched)

	require.Equal(t, small.statements, full.statements,
		"the page read must cost the same for 10 rows and %d — it is one statement per "+
			"level of the hierarchy, not per row", pageSize)
	require.Equal(t, small.snapshots, full.snapshots, "and one snapshot either way")
	require.Equal(t, int64(2*10), small.questions(), "premise: two relations per denied object")
	require.Equal(t, int64(2*pageSize), full.questions())
}

// TestForeignObjectCostsNoRead — the cheap half of the answer, asserted so it stays cheap:
// a question about an object iam does not own must not touch the database at all. Most
// authorization traffic in the cluster is about objects of other services, and if those
// paid a read the wrapper would be unshippable.
func TestForeignObjectCostsNoRead(t *testing.T) {
	w := newCostWorld(t)
	ctx := context.Background()
	pool, tracer := w.tracedPool(t)

	primary := &countingPrimary{inner: kachopg.New(pool, nil)}
	counting := &countingRelations{Relations: w.harness.Client}
	store := Wrap(counting, New(primary).WithBatch(&countingBatch{inner: kachopg.NewStructuralFactsRepo(pool)}))

	allowed, err := store.Check(ctx, "user:"+costID("usr", "coststr1"), "v_get", "vpc_network:net-foreign")
	require.NoError(t, err)
	require.False(t, allowed, "nothing grants it")
	require.Equal(t, int64(1), counting.plain.Load(), "one relation question")
	require.Zero(t, counting.withFacts.Load(), "no second chance for a foreign type")
	require.Zero(t, primary.txs.Load(), "and no transaction")
	require.Zero(t, tracer.n.Load(), "and no statement")

	// The page path must be equally free of it: a prefetch for a type iam does not own must
	// return the context untouched, not open a snapshot to discover there is nothing to read.
	pctx := store.PrefetchStructural(ctx, "vpc_network", []string{"net-foreign"})
	require.Zero(t, tracer.n.Load(), "a prefetch for a foreign type reads nothing")
	require.Nil(t, factMemoFrom(pctx), "and installs no memo")
}

// TestSecondChanceIsFailClosedOnAnUnreadableFact — an unread fact is an UNKNOWN answer, not
// a negative one, and it must reach the caller as such.
//
// This is the coupling the wrapper introduces, stated as a test rather than as a sentence: a
// decision that previously needed only the relation store now also needs iam's primary, on
// the denial path. The direction is safe (no allow is invented) and the caller is told, so a
// read gate answers "unavailable" instead of the not-found it uses to hide a refusal —
// which would be a claim the client acts on.
func TestSecondChanceIsFailClosedOnAnUnreadableFact(t *testing.T) {
	w := newCostWorld(t)
	ctx := context.Background()

	counting := &countingRelations{Relations: w.harness.Client}
	store := Wrap(counting, brokenFacts{})

	_, err := store.Check(ctx, "user:"+costID("usr", "coststr1"), "v_get", "account:"+w.account)
	require.Error(t, err, "an unreadable structural fact must not be reported as a denial")
	require.Contains(t, err.Error(), "structural fact unavailable")

	_, err = store.CheckWithContext(ctx, "user:"+costID("usr", "coststr1"), "viewer",
		"iam_access_binding:"+w.ids[0], nil)
	require.Error(t, err, "the page filter's question must fail the same way")
	require.Zero(t, counting.withFacts.Load(),
		"and the second chance is never asked with facts that could not be read")

	// A page prefetch that CANNOT read is not allowed to turn into a silent denial either:
	// it must leave the context alone so the per-object path produces the error above.
	pctx := store.PrefetchStructural(ctx, "iam_access_binding", w.ids)
	require.Nil(t, factMemoFrom(pctx),
		"a failed prefetch must install no memo — a memo of misses it never established "+
			"would convert an outage into a page of denials")
	_, err = authzfilter.VisibleSet(pctx, store, "user:"+costID("usr", "coststr1"),
		"iam_access_binding", w.ids[:3])
	require.Error(t, err, "the page must fail closed, not come back empty")
}

// brokenFacts — a fact source whose read always fails, on both shapes. It answers Derivable
// truthfully so the failure happens where it matters: after the type check, on the read.
type brokenFacts struct{}

func (brokenFacts) Derivable(objectType string) bool {
	_, ok := DerivableTypes[objectType]
	return ok
}

func (brokenFacts) StructuralFacts(context.Context, string, string) ([]authztypes.TupleKey, error) {
	return nil, fmt.Errorf("structural fact unavailable")
}

func (brokenFacts) BatchReachable() bool { return true }

func (brokenFacts) StructuralFactsBatch(context.Context, string, []string) (map[string][]authztypes.TupleKey, error) {
	return nil, fmt.Errorf("structural fact unavailable")
}

// TestPrefetchAgainstAnUnwiredBatchRecordsNothing — the defect the measurement found in this
// very prefetch, locked so it cannot come back.
//
// A resolver without a batch source still HAS the batch method, and its honest "nothing
// claimed" answer is the same empty result a real read of absent rows gives. Believing it
// recorded every id on the page as having no facts, which made every question ask the store
// plainly — the exact behaviour the second chance exists to replace — while every
// correctness test stayed green because the lazy path was simply never reached.
func TestPrefetchAgainstAnUnwiredBatchRecordsNothing(t *testing.T) {
	w := newCostWorld(t)
	ctx := context.Background()
	pool, tracer := w.tracedPool(t)

	counting := &countingRelations{Relations: w.harness.Client}
	unwired := New(&countingPrimary{inner: kachopg.New(pool, nil)}) // no WithBatch
	require.False(t, unwired.BatchReachable(), "premise: this resolver cannot batch")
	store := Wrap(counting, unwired)

	pctx := store.PrefetchStructural(ctx, "iam_access_binding", w.ids)
	require.Nil(t, factMemoFrom(pctx),
		"a prefetch that could not batch must record NOTHING — a memo of facts it never "+
			"read makes every question on the page behave as if the row had none")
	require.Zero(t, tracer.n.Load(), "and it must not have read anything either")

	// And the page still resolves correctly, the slower way.
	stranger := "user:" + costID("usr", "coststr3")
	visible, err := authzfilter.VisibleSet(pctx, store, stranger, "iam_access_binding", w.ids[:3])
	require.NoError(t, err)
	require.Empty(t, visible, "a subject holding nothing sees nothing")
	require.Positive(t, counting.withFacts.Load(),
		"the per-object second chance must actually have run — that is what the unwired "+
			"prefetch must fall back to")
}

// Compile-time guards: the production transport satisfies the surface the wrapper requires,
// and the production batch repository satisfies the snapshot port. If either stopped doing
// so the composition root would fall back to whatever still compiled, which is how the gates
// came to hold a plain store in the first place.
var (
	_ Relations       = (*clients.OpenFGAHTTPClient)(nil)
	_ BatchFactSource = (*Resolver)(nil)
)
