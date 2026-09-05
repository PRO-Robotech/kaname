// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package shared

// postcommit.go — run a post-commit materialization pass OFF the Operation.done path.
//
// WHY THIS EXISTS. `Operation.done` means one thing: the subject of the mutation is
// DURABLE — the writer-tx committed. It must NEVER mean "the eventually-consistent
// downstream side-effect is visible" (api-conventions.md, ban #9): the FGA owner /
// grant tuples, the mirror, the outbox drain. A mutation whose worker-fn performs the
// materialization inline gates `done` on exactly that side-effect, and the gate is
// unbounded: the passes are O(objects-in-scope × verbs-per-object), so a broad role
// bound at account scope walks the whole account. Measured on the stand, an `admin`
// (verbs `*`) account-scoped binding reported done after 29.06s while its `view`
// sibling on the SAME scope, created 0.4s earlier, took 4.3s — the client's poll
// budget expired on the first and not the second, though both rows were durable in
// milliseconds.
//
// WHAT IT DOES. Runs fn on a context DETACHED from the caller's cancellation
// (context.WithoutCancel) so the pass survives the request/worker return, while
// PRESERVING its observability baggage (trace / request-id / slog handler), under a
// bounded timeout so a wedged pass cannot leak the goroutine forever. Panics are
// recovered and logged: the goroutine outlives its request, so an unrecovered panic
// would take down a process that sits on the critical path of every
// InternalIAMService.Check.
//
// WHY IT IS SAFE TO DETACH. The pass is an accelerator, never the source of truth.
// Everything it materializes is ALSO durable in the caller's writer-tx — the
// fga_outbox rows and the resource_reconcile_outbox event are co-committed (ban #10) —
// so a skipped, failed, or killed pass converges through the async drainer, the
// reconciler-worker and the periodic sweep exactly as it did before. Detaching moves
// WHEN the work is observed, never WHETHER it happens.
//
// This mirrors the detach the sa-key secret redaction already performs for the same
// structural reason (the work must outlive the worker-fn that scheduled it).

import (
	"context"
	"log/slog"
	"time"
)

// PostCommitTimeout bounds a detached post-commit materialization pass. Generous
// relative to a healthy pass (milliseconds to low seconds) but finite, so a pass
// wedged on a lock or an unresponsive peer cannot pin a goroutine for the process
// lifetime. Exceeding it is not data loss — the durable outbox/event backstop
// re-converges the object.
const PostCommitTimeout = 2 * time.Minute

// GoPostCommit runs fn asynchronously, detached from callerCtx's cancellation and
// deadline but carrying its values, under PostCommitTimeout. `what` names the pass in
// the panic log. A nil fn is a no-op.
//
// The caller MUST NOT rely on fn having completed when GoPostCommit returns — that is
// the entire point. Use it only for work whose durable record is already committed.
func GoPostCommit(callerCtx context.Context, logger *slog.Logger, what string, fn func(context.Context)) {
	if fn == nil {
		return
	}
	// G118 is suppressed deliberately: the pass must outlive the operation worker-fn
	// that schedules it, because binding it to that ctx is precisely the gate this
	// helper exists to remove. The goroutine is bounded (PostCommitTimeout) and
	// panic-guarded below.
	go func() { //nolint:contextcheck // deliberate lifetime detach; baggage kept via WithoutCancel.
		defer func() {
			if r := recover(); r != nil && logger != nil {
				logger.Error("post-commit materialization pass panicked; the durable outbox/sweep backstop will re-converge",
					slog.String("pass", what), slog.Any("panic", r))
			}
		}()
		ctx, cancel := context.WithTimeout(context.WithoutCancel(callerCtx), PostCommitTimeout)
		defer cancel()
		fn(ctx)
	}()
}
