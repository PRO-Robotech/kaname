// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

// Проверяем настоящую обёртку, зарегистрированную serve, а не воспроизведение её
// предиката ошибки. Смешанная ошибка не доказывает, что вся неудачная работа была лишь
// прервана, даже если контекст завершения с тех пор закончился.
func TestSuperviseStartupTaskPreservesFailureSemantics(t *testing.T) {
	fatal := errors.New("independent completed startup failure")
	wrappedCancel := fmt.Errorf("interrupted startup: %w", context.Canceled)
	joinedFatal := errors.Join(fatal, context.Canceled)
	nestedFatal := fmt.Errorf("startup aggregate: %w", errors.Join(context.Canceled, fatal))
	bothEnds := errors.Join(context.Canceled, context.DeadlineExceeded)
	for _, tc := range []struct {
		name, contextState string
		result             error
		graceful           bool
	}{
		{"successful-active", "active", nil, true},
		{"successful-after-cancellation", "cancelled", nil, true},
		{"own-cancellation", "cancelled", context.Canceled, true},
		{"wrapped-own-cancellation", "cancelled", wrappedCancel, true},
		{"only-cancellation-aggregate", "cancelled", errors.Join(context.Canceled, wrappedCancel), true},
		{"foreign-cancellation-active-context", "active", context.Canceled, false},
		{"deadline-error-active-context", "active", context.DeadlineExceeded, false},
		{"own-deadline-is-not-signal-shutdown", "deadline", context.DeadlineExceeded, false},
		{"completed-fatal-concurrent-cancellation", "cancelled", fatal, false},
		{"joined-fatal-and-cancellation", "cancelled", joinedFatal, false},
		{"nested-joined-fatal-and-cancellation", "cancelled", nestedFatal, false},
		{"deadline-joined-with-cancellation", "cancelled", bothEnds, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.contextState == "deadline" {
				var stop context.CancelFunc
				ctx, stop = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				defer stop()
			}
			calls, triggers := 0, 0
			got := superviseStartupTask(ctx, func() { triggers++ }, func(actual context.Context) error {
				calls++
				require.Equal(t, ctx, actual, "actual work receives its original task context")
				// Отмена происходит после получения результата телом. Это
				// гонка, которую общая проверка ctx.Err классифицировала бы неверно.
				result := tc.result
				if tc.contextState == "cancelled" {
					cancel()
				}
				return result
			})
			require.Equal(t, 1, calls)
			if tc.graceful {
				require.NoError(t, got)
				require.Zero(t, triggers)
			} else {
				require.True(t, got == tc.result, "preserve the exact genuine failure object, including all joined causes")
				require.Equal(t, 1, triggers, "a genuine failure must invoke the shared shutdown trigger exactly once")
			}
		})
	}
}

// Те же производственные rootShutdown и простой errgroup, что использует serve, должны завершиться
// после фатального результата запуска БЕЗ внешнего сигнала. Скопированный обратный вызов,
// самостоятельно вызывающий Trigger, вовсе не проверил бы связи надзора.
func TestSuperviseStartupTaskDrainsActualRootWithoutSignal(t *testing.T) {
	for _, tc := range []struct {
		name               string
		joined, lateCancel bool
	}{
		{"plain-fatal", false, false},
		{"fatal-containing-cancellation", true, false},
		{"completed-fatal-during-signal", false, true},
		{"joined-fatal-during-signal", true, true},
	} {
		name := tc.name
		t.Run(name, func(t *testing.T) {
			signal, cancelSignal := context.WithCancel(context.Background())
			defer cancelSignal()
			var teardown, triggerCalls atomic.Int64
			root := newRootShutdown(signal, func() { teardown.Add(1) })
			defer root.Stop()
			workerReady := make(chan struct{})
			workerDrained := make(chan struct{})
			fatal := errors.New("independent structural startup refusal")
			var expected error = fatal
			if tc.joined {
				expected = errors.Join(fatal, context.Canceled)
			}
			var group errgroup.Group
			group.Go(func() error { close(workerReady); <-root.Context().Done(); close(workerDrained); return nil })
			group.Go(func() error { root.Await(); return nil })
			group.Go(func() error {
				<-workerReady
				return superviseStartupTask(root.Context(), func() { triggerCalls.Add(1); root.Trigger() }, func(context.Context) error {
					if tc.lateCancel {
						cancelSignal()
					}
					return expected
				})
			})
			done := make(chan error, 1)
			drained := make(chan struct{})
			go func() { done <- group.Wait(); close(drained) }()
			defer func() {
				cancelSignal()
				select {
				case <-drained:
				case <-time.After(5 * time.Second):
					t.Error("root goroutines did not clean up")
				}
			}()
			select {
			case got := <-done:
				require.True(t, got == expected, "errgroup must retain the startup failure object")
			case <-time.After(5 * time.Second):
				t.Fatal("fatal startup did not stop the real root without an external signal")
			}
			if tc.lateCancel {
				require.ErrorIs(t, signal.Err(), context.Canceled)
			} else {
				require.NoError(t, signal.Err(), "no external signal or parent cancellation caused this drain")
			}
			select {
			case <-workerDrained:
			default:
				t.Fatal("background worker was not drained")
			}
			require.EqualValues(t, 1, triggerCalls.Load())
			require.EqualValues(t, 1, teardown.Load())
			root.Trigger()
			require.EqualValues(t, 1, teardown.Load(), "root teardown remains idempotent")
		})
	}
}

func TestSuperviseStartupTaskSuccessLeavesActualRootRunning(t *testing.T) {
	signal, cancel := context.WithCancel(context.Background())
	defer cancel()
	var teardown atomic.Int64
	root := newRootShutdown(signal, func() { teardown.Add(1) })
	defer root.Stop()
	require.NoError(t, superviseStartupTask(root.Context(), root.Trigger, func(context.Context) error { return nil }))
	require.NoError(t, root.Context().Err())
	require.Zero(t, teardown.Load(), "successful startup must not shut down a healthy app")
	root.Trigger()
	require.EqualValues(t, 1, teardown.Load())
	require.ErrorIs(t, root.Context().Err(), context.Canceled)
}

func TestSuperviseStartupTaskOwnCancellationDrainsActualRoot(t *testing.T) {
	signal, cancelSignal := context.WithCancel(context.Background())
	defer cancelSignal()
	var teardown, wrapperTriggers atomic.Int64
	root := newRootShutdown(signal, func() { teardown.Add(1) })
	defer root.Stop()
	bodyEntered := make(chan struct{})
	var group errgroup.Group
	group.Go(func() error { root.Await(); return nil })
	group.Go(func() error {
		return superviseStartupTask(root.Context(), func() { wrapperTriggers.Add(1); root.Trigger() }, func(ctx context.Context) error {
			close(bodyEntered)
			<-ctx.Done()
			return ctx.Err()
		})
	})
	select {
	case <-bodyEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("startup body did not enter the cancellation barrier")
	}
	cancelSignal()
	done := make(chan error, 1)
	go func() { done <- group.Wait() }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("own cancellation did not drain startup/root tasks")
	}
	require.Zero(t, wrapperTriggers.Load(), "normal signal cancellation is not a fatal startup trigger")
	require.EqualValues(t, 1, teardown.Load(), "the actual root still performs normal signal teardown")
}
