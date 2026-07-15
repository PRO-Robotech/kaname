// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package seed

// reconcile_worker_notify_test.go — unit-тест NOTIFY-driven дренажа reconcile-
// очереди. Подтверждает, что worker делает drain по NOTIFY-wakeup (а не только по
// poll-тику): DrainInterval/SweepInterval выставлены заведомо длинными, поэтому
// единственный путь к дренажу в окне теста — сигнал от NotifyWatcher.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/reconcile_outbox"
)

// fakeNotifyEngine — фиксирует вызовы ReconcileObject и сигналит о первом.
type fakeNotifyEngine struct {
	mu      sync.Mutex
	objects []string
	called  chan struct{}
}

func (f *fakeNotifyEngine) ReconcileObject(_ context.Context, objectType, objectID string) error {
	f.mu.Lock()
	f.objects = append(f.objects, objectType+":"+objectID)
	f.mu.Unlock()
	select {
	case f.called <- struct{}{}:
	default:
	}
	return nil
}
func (f *fakeNotifyEngine) ReconcileBinding(context.Context, domain.AccessBindingID) error {
	return nil
}
func (f *fakeNotifyEngine) ExpireBinding(context.Context, domain.AccessBindingID) error { return nil }

// fakeNotifyQueue — отдает ровно одно событие на первом claim, затем пусто.
type fakeNotifyQueue struct {
	mu      sync.Mutex
	claimed bool
	marked  []int64
}

func (q *fakeNotifyQueue) ClaimReconcileEvents(context.Context, int) ([]reconcile_outbox.Event, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.claimed {
		return nil, nil
	}
	q.claimed = true
	return []reconcile_outbox.Event{{
		ID: 7, ObjectType: "compute.instance", ObjectID: "cinst-notify",
		EventType: reconcile_outbox.EventUpsert,
	}}, nil
}
func (q *fakeNotifyQueue) MarkReconcileEventSent(_ context.Context, id int64) error {
	q.mu.Lock()
	q.marked = append(q.marked, id)
	q.mu.Unlock()
	return nil
}
func (q *fakeNotifyQueue) ListSelectorBindingIDs(context.Context) ([]domain.AccessBindingID, error) {
	return nil, nil
}
func (q *fakeNotifyQueue) ListExpiredBindingIDs(context.Context) ([]domain.AccessBindingID, error) {
	return nil, nil
}

// fakeNotifyWatcher — имитирует доставленный NOTIFY: один раз сигналит wakeup,
// затем блокируется до отмены ctx (как реальный LISTEN-loop).
type fakeNotifyWatcher struct{}

func (fakeNotifyWatcher) Watch(ctx context.Context, wakeup chan<- struct{}) {
	select {
	case wakeup <- struct{}{}:
	default:
	}
	<-ctx.Done()
}

func TestReconcileWorker_DrainsOnNotify_NotOnlyPoll(t *testing.T) {
	engine := &fakeNotifyEngine{called: make(chan struct{}, 1)}
	queue := &fakeNotifyQueue{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Длинные интервалы: poll-тик не сработает в окне теста, поэтому единственный
	// путь к дренажу — NOTIFY-wakeup от watcher'а.
	w := NewReconcileWorker(engine, queue, ReconcileWorkerConfig{
		DrainInterval: time.Hour,
		SweepInterval: time.Hour,
		Notify:        fakeNotifyWatcher{},
	})

	done := make(chan struct{})
	go func() { _ = w.Run(ctx); close(done) }()

	select {
	case <-engine.called:
		// drain произошел по NOTIFY-wakeup, а не по poll-тику.
	case <-time.After(2 * time.Second):
		t.Fatal("worker не сделал drain по NOTIFY в пределах 2s (poll-тик отключен длинным интервалом)")
	}

	cancel()
	<-done

	engine.mu.Lock()
	defer engine.mu.Unlock()
	if len(engine.objects) == 0 || engine.objects[0] != "compute.instance:cinst-notify" {
		t.Fatalf("ожидали ReconcileObject(compute.instance, cinst-notify), got %v", engine.objects)
	}

	queue.mu.Lock()
	defer queue.mu.Unlock()
	if len(queue.marked) != 1 || queue.marked[0] != 7 {
		t.Fatalf("ожидали MarkReconcileEventSent(7) после успешного reconcile, got %v", queue.marked)
	}
}
