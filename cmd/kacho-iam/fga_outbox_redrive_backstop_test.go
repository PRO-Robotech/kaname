// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package main

// Что здесь утверждается — и почему именно это.
//
// Возврат отравленных строк в работу обязан удовлетворять ДВУМ требованиям
// одновременно, и они тянут в разные стороны:
//
//	не потерять право   — строка, отравленная временной причиной, обязана
//	                      вернуться в очередь БЕЗ вмешательства руками;
//	не долбить впустую  — отказ владельца прав постоянный, поэтому повтор
//	                      идентичного запроса не может пройти, и делать его
//	                      по таймеру значит платить за заведомый отказ.
//
// Примиряет их привязка к СОБЫТИЮ: проход делается тогда и только тогда, когда
// наблюдалась смена версии модели прав — единственное, что способно превратить
// постоянный отказ в проходящую запись.
//
// Ключевое утверждение — о ЧИСЛЕ проходов, а не о факте вызова. «Возврат
// вызывается» остаётся зелёным и на реализации, которая зовёт его каждый тик;
// именно её здесь и надо отличить.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/outbox/reconciler"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// redriveSpy counts passes so the assertions can be about HOW MANY, not whether.
type redriveSpy struct {
	calls int
	err   error
}

func (s *redriveSpy) run(context.Context) (int, error) {
	s.calls++
	return 0, s.err
}

// TestRedrive_UnchangedModel_DoesNotTouchTheQueue — the "производительность" half.
//
// While the model id is what it was, nothing has happened that could change the
// outcome of a refused write, so the pass is not made at all. A ticker-driven
// redrive would issue the identical refused request every period, forever, and
// charge OpenFGA, an attempt bump and a log line for each — the "таймер вслепую"
// the design rejects.
func TestRedrive_UnchangedModel_DoesNotTouchTheQueue(t *testing.T) {
	t.Parallel()

	spy := &redriveSpy{}
	r := &redriveOnModelChange{
		redrive: spy.run,
		probe:   func(context.Context) (string, error) { return "model-A", nil },
		log:     quietLogger(),
	}

	require.True(t, r.Tick(t.Context()), "the first observation is itself an event: a restart is how a pinned model changes")
	for i := 0; i < 20; i++ {
		require.Falsef(t, r.Tick(t.Context()), "tick %d: the model did not change; there is nothing to re-drive", i)
	}
	require.Equal(t, 1, spy.calls,
		"twenty ticks on an unchanged model must cost exactly ONE pass — the one at first observation")
}

// TestRedrive_ModelChanged_ReturnsRowsToTheQueue — the "безопасность" half: the
// event that CAN change the outcome does produce a pass. Without this the test
// above would pass on a redrive that never runs at all.
func TestRedrive_ModelChanged_ReturnsRowsToTheQueue(t *testing.T) {
	t.Parallel()

	ids := []string{"model-A", "model-A", "model-B", "model-B", "model-C"}
	i := 0
	spy := &redriveSpy{}
	r := &redriveOnModelChange{
		redrive: spy.run,
		probe: func(context.Context) (string, error) {
			id := ids[i]
			i++
			return id, nil
		},
		log: quietLogger(),
	}

	got := make([]bool, 0, len(ids))
	for range ids {
		got = append(got, r.Tick(t.Context()))
	}
	require.Equal(t, []bool{true, false, true, false, true}, got,
		"a pass on first observation and on every CHANGE; silence in between")
	require.Equal(t, 3, spy.calls)
}

// TestRedrive_ProbeFailure_IsNotAnObservation — an unreachable OpenFGA means
// "the event was not observed", never "there was no event". Recording a failed
// probe as a seen revision would eat the change: the model could land during the
// outage and the next tick, seeing the same id it now believes it handled, would
// never re-drive.
func TestRedrive_ProbeFailure_IsNotAnObservation(t *testing.T) {
	t.Parallel()

	spy := &redriveSpy{}
	fail := true
	r := &redriveOnModelChange{
		redrive: spy.run,
		probe: func(context.Context) (string, error) {
			if fail {
				return "", errors.New("connection refused")
			}
			return "model-A", nil
		},
		log: quietLogger(),
	}

	require.False(t, r.Tick(t.Context()), "a failed probe observes nothing")
	require.False(t, r.Tick(t.Context()))
	require.Equal(t, 0, spy.calls, "a failed probe must not run the pass")

	fail = false
	require.True(t, r.Tick(t.Context()), "once the probe answers, the observation is made and the pass runs")
	require.Equal(t, 1, spy.calls)
}

// TestRedrive_EmptyModelId_IsNotAChange — a store with no model yet is a cluster
// still coming up, not an event. Treating "" as a revision would burn the first
// observation on nothing and then read the arrival of the REAL model as a change
// — which happens to be harmless here, and is asserted anyway so the meaning of
// the empty value stays written down.
func TestRedrive_EmptyModelId_IsNotAChange(t *testing.T) {
	t.Parallel()

	spy := &redriveSpy{}
	id := ""
	r := &redriveOnModelChange{
		redrive: spy.run,
		probe:   func(context.Context) (string, error) { return id, nil },
		log:     quietLogger(),
	}

	require.False(t, r.Tick(t.Context()))
	require.Equal(t, 0, spy.calls, "no model yet is not an event")

	id = "model-A"
	require.True(t, r.Tick(t.Context()))
	require.Equal(t, 1, spy.calls)
}

// TestRedrive_FailedPass_DoesNotConsumeTheEvent — if the pass itself fails
// (database unavailable mid-tick), the revision must NOT be recorded as handled.
// Otherwise one transient failure swallows the whole event and the poisoned rows
// wait for the NEXT model change — which may never come.
func TestRedrive_FailedPass_DoesNotConsumeTheEvent(t *testing.T) {
	t.Parallel()

	spy := &redriveSpy{err: errors.New("pool closed")}
	r := &redriveOnModelChange{
		redrive: spy.run,
		probe:   func(context.Context) (string, error) { return "model-A", nil },
		log:     quietLogger(),
	}

	require.False(t, r.Tick(t.Context()), "a failed pass is not a pass")
	require.Equal(t, 1, spy.calls)

	spy.err = nil
	require.True(t, r.Tick(t.Context()),
		"the same revision must still be treated as unhandled after a failed pass")
	require.Equal(t, 2, spy.calls)

	require.False(t, r.Tick(t.Context()), "…and only until it succeeds once")
	require.Equal(t, 2, spy.calls)
}

// TestRedriveAndDrainerAgreeOnTheOrderingKey — the two halves of ONE rule.
//
// The claim refuses to take a row ahead of a DELIVERABLE same-partition
// predecessor; the revival refuses to raise a row past a DELIVERED same-partition
// successor. On two different keys each half guards a partition the other does
// not, and the visible consequence is concrete: a poisoned grant raised past its
// own delivered revocation puts revoked access back.
//
// Both values are read from the SAME configuration the process runs with, so this
// cannot pass by two literals agreeing today and drifting tomorrow. It needs no
// server — which is why it is here and not in an e2e.
func TestRedriveAndDrainerAgreeOnTheOrderingKey(t *testing.T) {
	t.Parallel()

	cfg := fgaOutboxDrainerConfig()
	require.Equal(t, fgaOutboxTupleKeyColumn, cfg.PartitionColumn,
		"precondition: the drainer orders kacho_iam.fga_outbox by the tuple key")
	require.NotEqual(t, reconciler.RegisterOutboxPartition, cfg.PartitionColumn,
		"precondition that keeps this test honest: this queue is NOT a register-outbox, "+
			"so the corelib default would have been wrong for it — that is the defect being closed")

	// The revive-only reconciler is built from exactly these two values (see
	// startFGAOutboxRedrive). Constructing it here proves the pair is acceptable
	// to corelib as well — an unset or malformed key refuses to build.
	_, err := reconciler.NewRedriveOnly(nil, reconciler.Config{
		Table:           fgaOutboxTable,
		Channel:         fgaOutboxChannel,
		MaxAttempts:     cfg.MaxAttempts,
		PartitionColumn: cfg.PartitionColumn,
	}, quietLogger())
	// nil pool is refused last, AFTER the config checks — so reaching the pool
	// complaint is itself the proof that the key and table were accepted.
	require.ErrorContains(t, err, "pool is nil",
		"the table/key pair must be acceptable; only the nil pool may be refused: %v", err)
}
