// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package authzfilter resolves per-object READ-visibility for kaname's own read
// surfaces by asking a DIRECT per-object question — never by enumerating the objects
// a subject may see. The predicate is RelationsFor(objectType): the relation that
// gates a single-object read of that type.
//
// # Why not an enumeration (this was the bug, and the enumeration is now gone)
//
// Every iam read that filtered by visibility USED TO ask the external relations
// engine "enumerate ALL objects of this type the subject may see" and then match
// the resource against that set — read-by-id via membership, List via an
// `id = ANY(...)` push-down.
//
// The engine bounded that enumeration SERVER-side (default 1000) and exposed NO
// continuation token, so it silently returned an arbitrary 1000-id prefix. The
// bound applied to the TYPE IN THE STORE (cluster-wide), not to the tenant: on a
// long-lived store a tenant's own resource fell outside the prefix and became
// PERMANENTLY invisible — Get → 403/404, List → absent — while the DB row existed,
// the grant existed, and mutations (which ask a DIRECT per-object question) kept
// working. Asking for a larger cap did not help: that argument was only a
// CLIENT-side trim of an already-cut response.
//
// Обе стороны этого разбора — история. Движок снят стадией S6 (эпик #747), а его
// перечисление снято с контракта тем же изменением: продолжения у ответа не было
// by construction, и остаток оставался недостижимым при живых правах. Разбор
// оставлен, потому что ФОРМА ВОПРОСА, к которой он привёл, и есть предмет этого
// пакета: спрашивать «видит ли субъект ЭТОТ объект», а не «перечисли вселенную».
//
// The cure is not a bigger cap (it is external, and finite either way) but a
// different SHAPE of question: instead of "enumerate the universe and look for
// me in it", ask "may this subject see THIS object", for the objects on the page
// (List) or for the single object being read (Get). Cost then scales with the
// PAGE, not with the type's population.
//
// # The predicate: the relation that gates the read
//
// Bounding the SHAPE of the question was one change; which question is asked is a
// second, and the two are independent. The enumeration this package replaced asked
// the union `viewer ∪ v_list`, while the gateway gates a single-object `Get` on
// `v_get` — different sets in a model that decouples tiers from verbs, so the page
// and the read disagreed in both directions. A row now belongs on a page exactly
// when its holder may read it by id; see pageRelations for why that loses no granted
// access, and for the one type whose read carries no catalog relation at all.
//
// # Fail-closed
//
// Any Check error aborts the whole resolution with that error; callers map it to
// UNAVAILABLE. A partially-resolved set is never returned: a page filtered by an
// incomplete answer would silently under-report (and, on the deny side, could
// under-report a deny).
package authzfilter

import (
	"context"
	"fmt"
	"sync"
)

// The predicate below. A row belongs on a public List page exactly when the caller may
// read that row by id, so the page predicate IS the relation the gateway's per-RPC
// Check enforces on a single-object read (`<Service>/Get` in the generated permission
// catalog) — `v_get` for every iam type but one.
//
// It used to be the union `viewer ∪ v_list`, and that was not wider access but a
// DIVERGENCE, working in both directions. Tier relations (`viewer`/`editor`/`admin`)
// and verb relations (`v_*`) are deliberately decoupled in the model (Design B,
// fga_model.fga) — neither is derived from the other — so:
//
//   - a subject holding the tier without the verb was handed the row while its own Get
//     refused it: the caller learned of an object it may not read AND received that
//     object's full contents, because List returns the same resource message Get does.
//     "Visible in a selector without contents" is unrealizable on that payload;
//   - conversely, a subject holding `v_get` without any tier did not find its OWN
//     readable object in its OWN list.
//
// Neither state is hypothetical: a partially reconciled role, or a revoked verb grant
// whose back-compat tier tuple outlived it, produces exactly them.
//
// Narrowing loses no granted access. Every iam type unions `or super_admin` into
// `v_get` (and `account` also `or owner`), so all three cascading super-levels and the
// account owner resolve it structurally; the reconciler emits `v_get` for every role
// authoring the `get` verb; and the floors that never go through this package are
// untouched (the caller's own user row, an account owner's projects, the system-role
// catalog).
//
// pageRelations — the page-membership predicate BY OBJECT TYPE, TOTAL by construction:
// the entry under the empty key is the default every type not named here takes, so
// there is no type whose predicate is implicit. That totality is what lets a repo-wide
// gate read this declaration and compare it against the permission catalog
// type-by-type (internal/repohygiene/listreadrelationparity_test.go); a predicate
// hidden in a function body is one no gate can see, which is how the previous sweep
// narrowed four services and left this one.
//
// `iam_role` is the single iam type whose catalog entry for Get declares NO relation
// (`<exempt>`): a custom role's single-object read is enforced IN-SERVICE by the very
// function that filters the page (role.resolveVisibleRoleIDs, shared by ListRoles and
// GetRole). Page and read are therefore the same question by construction and cannot
// diverge — there is nothing here to narrow, and the object-only selector grant
// (`v_list` without a tier) is that surface's declared contract, which its Get honours
// identically. Locked by TestVisibleSet_RoleKeepsTheUnionItsOwnGetEnforces.
var pageRelations = map[string][]string{
	"": {"v_get"}, // default: the relation the catalog gates `<Service>/Get` on

	"account":             {"v_get"},
	"project":             {"v_get"},
	"iam_user":            {"v_get"},
	"iam_group":           {"v_get"},
	"iam_service_account": {"v_get"},
	"iam_access_binding":  {"v_get"},

	"iam_role": {"viewer", "v_list"}, // read has no catalog relation — see above
}

// RelationsFor returns the page-membership predicate for one FGA object type, in the
// order it is asked. Each relation is queried only for the objects the previous one
// denied, so the order is a cost decision and never a correctness one.
//
// A type with no entry takes the default, which is narrow: an omission can never
// silently widen a page.
func RelationsFor(objectType string) []string {
	if rels, ok := pageRelations[objectType]; ok && objectType != "" {
		return rels
	}
	return pageRelations[""]
}

// DefaultParallelism bounds how many per-object Checks VisibleSet keeps in flight
// ON THE FALLBACK PATH — the one taken by a checker that cannot answer in
// batches. Production wiring can (clients.RelationQueries requires the
// capability), so this bound governs in-process fakes and any future checker that
// does not offer the batched door.
//
// # What a page costs on this path, and what this bound does not do
//
// It bounds DEPTH, not COUNT. Каждый вопрос — читающая транзакция к базе службы.
// Со снятием движка (стадия S6) сетевого перехода на этом пути больше нет, и
// прежний довод «клиент в процессе, а хранилище за сетью» истёк вместе с
// хранилищем; цена вопроса от этого не исчезла, а сменила природу — теперь это
// запрос к своей базе. A page pays len(RelationsFor(objectType)) questions for every
// object the first relation does not resolve, so a contract-sized page
// (validate.MaxPageSize = 1000) costs up to 1000 round-trips on the types gated by a
// single relation — and up to 2000 on `iam_role`, the one type that still asks two.
// This bound turns them into sequential waves rather than removing any of them: 63
// waves at one relation, 125 at two. At a 10ms answer that is over half a second of
// wall time on ONE List; at 50ms, over three.
//
// The 200ms budget on a Check belongs to the CALL, not to the page — nothing caps
// the page as a whole — so those waves accumulate without any per-call deadline
// firing. Measured, with the arithmetic spelled out, in
// TestVisibleSet_WorstCasePageCost; the bound itself is locked by
// TestVisibleSet_MaxPageBoundedFanOut.
//
// # Why the bound is nonetheless right
//
// Unbounded is worse, not better: a goroutine per row puts the whole page on the
// client at once. The bound is what keeps a large page from arriving all at once;
// it is not an argument that the page is cheap.
//
// # The count IS smaller now, on the path production takes
//
// This paragraph used to end "Making the COUNT smaller is a different change —
// asking the store about many objects in one request — and it is not done here".
// It is done here now: see MaxBatchChecksPerRequest and visibleSetBatched, which
// resolve the same 2000 tuples in 40 requests. The sentence is kept, corrected,
// rather than deleted, because it was true when written and the next reader of
// DefaultParallelism has to know which path the number above describes.
const DefaultParallelism = 16

// MaxBatchChecksPerRequest — how many objects one question about a page may name.
//
// It USED TO BE the store's ceiling rather than ours, and the distinction decided
// the number: the external relations engine refused an over-cap request outright —
// a `validation_error`, never a trim — so a partition wider than its bound turned
// every page into a refusal instead of a faster page. The bound was read off the
// deployed build rather than assumed: 51 checks were refused by name, 50 were
// answered.
//
// That engine is gone. The verdict is computed by the relational form in iam's own
// database, one statement per partition, and nothing outside refuses a wider one.
// So the number stopped being a foreign boundary and became OUR partition size: the
// unit a page is split into, and the unit BatchParallelism counts in flight. It is
// kept where it stood because the page arithmetic below is asserted against it
// (TestVisibleSet_BatchedWorstCasePageCost) — not because anything still enforces
// it. Moving it is now a cost decision about one statement, and it belongs with a
// fresh measurement, not with this comment.
//
// iam still publishes its own `AuthorizeService.BatchCheck` bounded at 100. That is
// a CONTRACT, not a store limit, and it governs how large a batch a SIBLING service
// may hand to iam — a different number for a different reason.
const MaxBatchChecksPerRequest = 50

// BatchParallelism bounds how many partitions of one page are in flight.
//
// It replaces DefaultParallelism on the batched path and is smaller on purpose:
// each partition already carries MaxBatchChecksPerRequest questions, which the
// store resolves with its own internal concurrency, so in-flight partitions
// multiply against that. Eight partitions is 400 questions the store may be
// resolving at once — comparable to the pressure the per-object path applied at
// sixteen in-flight single questions only because that path spread the same work
// across 125 waves instead of three.
//
// A contract-sized page is 20 partitions per relation, so this bound makes a
// relation round three waves and the whole page at most six — against 125. The
// arithmetic is asserted, with both counts, in
// TestVisibleSet_BatchedWorstCasePageCost.
const BatchParallelism = 8

// BatchObjectChecker — OPTIONAL capability of an ObjectChecker: answer ONE
// relation question about MANY objects in a single request.
//
// Declared here as a narrow port and satisfied by the decision door, so this
// package keeps knowing nothing about where the answer comes from — the same leaf
// discipline as ObjectChecker.
//
// Unlike pagePreparer this capability is NOT best-effort: it decides. An
// implementation must return one verdict per object, in the order the objects
// were given, or an error. It must never return a short slice — a caller cannot
// tell a short answer from a page of denials, and a page of silent denials is
// exactly the permanent-invisibility defect this package exists to prevent.
type BatchObjectChecker interface {
	BatchCheckWithContext(ctx context.Context, subject, relation string, objects []string,
		condCtx map[string]any) (allowed []bool, err error)
}

// ObjectChecker — narrow port: ONE direct per-object relation question.
// Satisfied by clients.RelationQueries (and by the decision door behind it).
//
// The port is declared here rather than imported so this package stays a leaf
// (it must not depend on the adapter that answers) — the same discipline as
// authzguard.RelationChecker.
type ObjectChecker interface {
	CheckWithContext(ctx context.Context, subject, relation, object string, condCtx map[string]any) (allowed bool, err error)
}

// ПОДГОТОВКИ СТРАНИЦЫ ЗДЕСЬ БОЛЬШЕ НЕТ — предмета не осталось.
//
// Порт объявлял НЕОБЯЗАТЕЛЬНУЮ подготовку: пообъектному вопросу мог понадобиться
// факт о месте объекта в иерархии, и его разрешение построчно делало стоимость
// страницы растущей с её размером. Подготовка грела эти факты на всю страницу
// сразу, чтобы стоимость осталась плоской.
//
// Факты грелись ради ВНЕШНЕГО движка, который знал только доехавшее до него
// очередью. Реляционная форма читает те же закоммиченные строки первым же
// вопросом, а страницу отвечает ОДНОЙ читающей транзакцией (`AllowedMany`), —
// то есть стоимость страницы принадлежит запросу by construction, и греть
// нечего.

// Visible reports whether `subject` may read `<objectType>:<id>`, evaluated as a
// direct per-object question over RelationsFor(objectType).
//
// Fail-closed: a nil checker, an empty subject or an empty id yields
// (false, nil); a Check transport error yields (false, err) and the caller MUST
// propagate it (never treat it as a deny — that would turn an FGA outage into a
// silent, permanent 404).
func Visible(ctx context.Context, chk ObjectChecker, subject, objectType, id string) (bool, error) {
	if chk == nil || subject == "" || objectType == "" || id == "" {
		return false, nil
	}
	object := objectType + ":" + id
	for _, relation := range RelationsFor(objectType) {
		allowed, err := chk.CheckWithContext(ctx, subject, relation, object, nil)
		if err != nil {
			return false, err
		}
		if allowed {
			return true, nil
		}
	}
	return false, nil
}

// VisibleSet returns the subset of `ids` visible to `subject`, as a set. It is
// the page-scoped form: callers read a page from their OWN database by cursor
// FIRST (so page_size/page_token validation keeps running before any authz
// short-circuit) and then filter that page with this call.
//
// Duplicate ids are resolved once. The result is always non-nil so callers can
// index it directly. Fail-closed: the FIRST Check error aborts the whole
// resolution and is returned — a partially-resolved set is never handed back.
func VisibleSet(ctx context.Context, chk ObjectChecker, subject, objectType string, ids []string) (map[string]bool, error) {
	out := make(map[string]bool, len(ids))
	if chk == nil || subject == "" || objectType == "" || len(ids) == 0 {
		return out, nil
	}

	// Deduplicate: one page must not pay twice for a repeated id.
	pending := make([]string, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if id == "" {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		pending = append(pending, id)
	}
	if len(pending) == 0 {
		return out, nil
	}

	// One request per partition when the checker can answer that way. This is the
	// whole reduction: the same tuples, asked in ceil(len/cap) messages per
	// relation instead of one message per (object, relation).
	if bc, ok := chk.(BatchObjectChecker); ok {
		return visibleSetBatched(ctx, bc, subject, objectType, pending, out)
	}

	// Bounded fan-out over a fixed worker pool (workers, not goroutine-per-id, so
	// a large page does not spawn a goroutine per row). The first error cancels
	// the remaining work and is the one returned.
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()

	workers := DefaultParallelism
	if len(pending) < workers {
		workers = len(pending)
	}
	queue := make(chan string)

	var (
		mu      sync.Mutex
		firstEr error
		wg      sync.WaitGroup
	)
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for id := range queue {
				allowed, err := Visible(cctx, chk, subject, objectType, id)
				mu.Lock()
				if err != nil {
					if firstEr == nil {
						firstEr = err
						cancel() // stop the rest — the answer is already fail-closed
					}
					mu.Unlock()
					return
				}
				if allowed {
					out[id] = true
				}
				mu.Unlock()
			}
		}()
	}
feed:
	for _, id := range pending {
		select {
		case queue <- id:
		case <-cctx.Done():
			break feed // a worker already failed closed; stop feeding
		}
	}
	close(queue)
	wg.Wait()

	if firstEr != nil {
		return nil, firstEr
	}
	// cancel() is called only after firstEr is set, so a done cctx with no
	// recorded error means the PARENT ctx expired mid-page. Report it instead of
	// handing back the half-resolved set as if it were the answer.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// visibleSetBatched resolves a page by asking the store about many objects per
// request. It evaluates EXACTLY the predicate the per-object path evaluates —
// `viewer` for the whole page, then `v_list` only for what `viewer` denied — and
// differs from it in one respect only: how many messages carry the question.
//
// # Two rounds, not two hundred waves
//
// The relations stay sequential because the second one's input is the first
// one's denials; that data dependency is the same one the per-object path has,
// and it is what keeps the tuple count at "one relation per object until one
// allows" rather than "every relation for every object". What changes is the
// inside of a round: its partitions are issued CONCURRENTLY, so a round is one
// round-trip plus scheduling rather than a queue.
//
// That distinction is the point of the whole change. A budget belongs to the
// REQUEST, and a request may legitimately ask for 1000 rows; twenty partitions
// issued one after another would put the page back on the wrong side of that
// budget while looking, in a request count, as if it had been fixed.
//
// # Fail-closed, and no falling back
//
// The first error aborts the page and is returned; a partially-resolved set is
// never handed back. In particular a refusing batch door is NOT papered over by
// re-asking per object: the two doors reach the same store, so a refusal that is
// real would simply be re-collected 2000 times, and a refusal that is about the
// REQUEST (an over-cap partition, a store that does not serve this endpoint) is a
// configuration fault that must stay loud rather than degrade into a slow path
// nobody notices.
func visibleSetBatched(
	ctx context.Context, bc BatchObjectChecker,
	subject, objectType string, pending []string, out map[string]bool,
) (map[string]bool, error) {
	remaining := pending
	// Предикат членства страницы принадлежит ТИПУ, а не пакету: батчевая дверь
	// обязана спрашивать ровно то, чем гейтится одиночное чтение этого же типа,
	// иначе она восстановит расхождение, снятое на пообъектном пути.
	for _, relation := range RelationsFor(objectType) {
		if len(remaining) == 0 {
			break
		}
		denied, err := batchRelationRound(ctx, bc, subject, objectType, relation, remaining, out)
		if err != nil {
			return nil, err
		}
		remaining = denied
	}
	// Mirrors the per-object path: a done parent context with no recorded error
	// means the REQUEST expired mid-page. Reporting it is the difference between
	// "these rows are not visible" and "we stopped asking".
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// batchRelationRound asks ONE relation about every id in `ids`, in partitions of
// at most MaxBatchChecksPerRequest issued concurrently, records the allowed ids
// in `out`, and returns the denied ids for the next relation.
func batchRelationRound(
	ctx context.Context, bc BatchObjectChecker,
	subject, objectType, relation string, ids []string, out map[string]bool,
) ([]string, error) {
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type partition struct {
		offset int
		ids    []string
	}
	parts := make([]partition, 0, (len(ids)+MaxBatchChecksPerRequest-1)/MaxBatchChecksPerRequest)
	for off := 0; off < len(ids); off += MaxBatchChecksPerRequest {
		end := off + MaxBatchChecksPerRequest
		if end > len(ids) {
			end = len(ids)
		}
		parts = append(parts, partition{offset: off, ids: ids[off:end]})
	}

	// allowed is indexed by position in `ids`, so partitions write disjoint slots
	// and need no lock; the denied list is rebuilt afterwards in input order,
	// which keeps the second relation's partitioning deterministic.
	allowed := make([]bool, len(ids))

	workers := BatchParallelism
	if len(parts) < workers {
		workers = len(parts)
	}
	queue := make(chan partition)

	var (
		mu      sync.Mutex
		firstEr error
		wg      sync.WaitGroup
	)
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for p := range queue {
				objects := make([]string, len(p.ids))
				for i, id := range p.ids {
					objects[i] = objectType + ":" + id
				}
				verdicts, err := bc.BatchCheckWithContext(cctx, subject, relation, objects, nil)
				if err == nil && len(verdicts) != len(objects) {
					// A short or long answer cannot be aligned with the objects it
					// was asked about, and a page filtered by a misaligned answer is
					// wrong in a way no caller can detect. Refuse it as an error.
					err = fmt.Errorf(
						"authzfilter: relation store answered %d of %d checks for relation %q",
						len(verdicts), len(objects), relation)
				}
				mu.Lock()
				if err != nil {
					if firstEr == nil {
						firstEr = err
						cancel() // stop the rest — the answer is already fail-closed
					}
					mu.Unlock()
					return
				}
				mu.Unlock()
				for i, ok := range verdicts {
					allowed[p.offset+i] = ok
				}
			}
		}()
	}
feed:
	for _, p := range parts {
		select {
		case queue <- p:
		case <-cctx.Done():
			break feed // a worker already failed closed; stop feeding
		}
	}
	close(queue)
	wg.Wait()

	if firstEr != nil {
		return nil, firstEr
	}

	denied := make([]string, 0, len(ids))
	for i, id := range ids {
		if allowed[i] {
			out[id] = true
			continue
		}
		denied = append(denied, id)
	}
	return denied, nil
}
