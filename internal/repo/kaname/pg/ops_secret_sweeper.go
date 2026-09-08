// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ops_secret_sweeper.go — the durable half of the one-shot-credential clean-up.
//
// WHY IT EXISTS. Issuing a machine key or a personal token stages the private half
// in the operation response deliberately: the client polls the operation to collect
// it, and it is handed over exactly once. Clearing it afterwards was the job of a
// goroutine detached from the request, holding a grace window so the poller wins the
// race. That goroutine belongs to no shutdown group and outlives no process — and
// the default termination grace is SHORTER than the credential grace window, so an
// ordinary rollout strands every credential issued in the preceding window. No OOM
// kill or eviction is required; the routine case is enough.
//
// What made the strand permanent rather than momentary: the operation is done=true,
// and the orphan reconciler claims `done = false`, so it can never see one of these
// rows by construction. Nothing else ages operations out. The plaintext therefore
// persisted for the life of the cluster — in every dump, backup and read replica —
// and every branch that logs "key material may remain" runs inside the goroutine
// that no longer exists, so nothing said a word.
//
// WHAT THIS DOES. Reads only the response types that carry credentials, only those
// settled longer than the grace window, only within a bounded recent window, and
// clears the named fields. Re-running is a no-op — clearing an already-clear field
// writes nothing — which is also what makes the "how many did I have to clear"
// count meaningful: a non-zero count means the fast path did not run.
package pg

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// SecretSweepTarget — one credential-bearing response type and the fields on it
// that must not outlive the grace window.
type SecretSweepTarget struct {
	// ResponseType — the Any type URL exactly as operations.response_type stores it.
	ResponseType string
	// Fields — proto field names to clear. A field the type does not carry is
	// skipped, so one target may name the union of spellings.
	Fields []string
}

// SecretSweepSpec — the bounds of one sweep.
type SecretSweepSpec struct {
	Targets []SecretSweepTarget
	// Settled — how long a response must have been final before it is swept. It
	// MUST exceed the credential grace window, or the backstop races the client
	// still collecting a key that cannot be reissued.
	Settled time.Duration
	// Window — how far back to look. The backstop covers a process restart, which
	// is minutes; a bounded window keeps the cost of a sweep independent of the size
	// of the operations table. Anything older was cleared or reported long ago.
	Window time.Duration
	// Limit — rows per target per sweep.
	Limit int
}

// SecretSweepResult — what the sweep read, and what it had to change.
type SecretSweepResult struct {
	// Scanned — candidate rows read.
	Scanned int
	// Redacted — rows that still carried a credential and were cleared. Non-zero
	// means the in-process clean-up did not run for those rows.
	Redacted int
}

// SweepStrandedSecrets clears credential fields left in settled operation
// responses.
//
// Safe to run concurrently with itself and with the in-process clean-up: every
// write is an idempotent single-statement UPDATE of one row, and two processes
// clearing the same field produce identical bytes. Deliberately NOT serialised
// behind a claim or an advisory lock — the duplicated work is one no-op UPDATE,
// while a lock would add a way for the backstop itself to get stuck, which is the
// failure mode it exists to cover.
func (r *OpsResponseRedactor) SweepStrandedSecrets(ctx context.Context, spec SecretSweepSpec) (SecretSweepResult, error) {
	var out SecretSweepResult
	if r.pool == nil {
		return out, fmt.Errorf("ops secret sweep: nil pool")
	}
	if spec.Limit <= 0 || spec.Settled <= 0 || spec.Window <= 0 {
		return out, fmt.Errorf("ops secret sweep: settled, window and limit must all be positive")
	}

	table := pgx.Identifier{r.schema, "operations"}.Sanitize()
	listSQL := fmt.Sprintf(`
		SELECT id
		FROM %s
		WHERE done = true
		  AND response_type = $1
		  AND response_data IS NOT NULL
		  AND modified_at < now() - $2::interval
		  AND modified_at > now() - $3::interval
		ORDER BY modified_at ASC
		LIMIT $4`, table)

	for _, target := range spec.Targets {
		if target.ResponseType == "" || len(target.Fields) == 0 {
			continue
		}
		ids, err := r.listSweepCandidates(ctx, listSQL, target, spec)
		if err != nil {
			return out, err
		}
		for _, id := range ids {
			out.Scanned++
			cleared, rerr := r.RedactResponseFields(ctx, id, target.Fields)
			if rerr != nil {
				return out, fmt.Errorf("ops secret sweep: redact %s: %w", id, rerr)
			}
			if cleared {
				out.Redacted++
			}
		}
	}
	return out, nil
}

func (r *OpsResponseRedactor) listSweepCandidates(
	ctx context.Context, listSQL string, target SecretSweepTarget, spec SecretSweepSpec,
) ([]string, error) {
	rows, err := r.pool.Query(ctx, listSQL,
		target.ResponseType, spec.Settled.String(), spec.Window.String(), spec.Limit)
	if err != nil {
		return nil, fmt.Errorf("ops secret sweep: list %s: %w", target.ResponseType, err)
	}
	defer rows.Close()

	ids := make([]string, 0, spec.Limit)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("ops secret sweep: scan: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ops secret sweep: iterate: %w", err)
	}
	return ids, nil
}
