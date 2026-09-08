// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed

// reconcile_drain_poison_test.go — отказ сверки УЧИТЫВАЕТСЯ, а не только
// логируется (#2050).
//
// ПРЕДМЕТ. Отказ `ReconcileObject` оставлял строку неотправленной и повторялся
// ВЕЧНО: ни `attempt_count`, ни `last_error` не писал никто, хотя схема оба
// столбца объявляет. Постоянно падающее событие повторялось без видимости и без
// отсечки, а объявленные и никем не записываемые столбцы создавали ВИД учёта
// попыток — читатель схемы заключал, что отсечка есть.
//
// ЧТО УТВЕРЖДАЕТСЯ. Дренаж, получив отказ, зовёт учёт ровно один раз на строку
// и передаёт ПРИЧИНУ. Без причины «отравлено» не отличить от «отравлено чем»;
// без учёта отсечка недостижима by construction.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/reconcile_outbox"
)

// failingEngine — сверка, отказывающая всегда одной и той же названной причиной.
type failingEngine struct {
	mu     sync.Mutex
	calls  int
	called chan struct{}
}

var errReconcileRefused = errors.New("сосед отверг регистрацию: отношение вне закрытого набора")

func (f *failingEngine) ReconcileObject(context.Context, string, string) error {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	select {
	case f.called <- struct{}{}:
	default:
	}
	return errReconcileRefused
}
func (f *failingEngine) ReconcileBinding(context.Context, domain.AccessBindingID) error { return nil }
func (f *failingEngine) ExpireBinding(context.Context, domain.AccessBindingID) error    { return nil }

// poisonQueue — очередь, отдающая одно и то же событие, пока его не учли.
// Учёт записывается сюда же — так дублёр повторяет договор настоящей таблицы:
// счётчик растёт, причина сохраняется, отправленной строка не становится.
type poisonQueue struct {
	mu       sync.Mutex
	attempts int
	causes   []string
	marked   []int64
}

func (q *poisonQueue) ClaimReconcileEvents(context.Context, int) ([]reconcile_outbox.Event, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.attempts >= reconcile_outbox.MaxAttempts {
		// Отсечка: настоящий клейм исключает отравленную строку предикатом
		// `attempt_count < MaxAttempts`. Дублёр обязан вести себя так же —
		// иначе проба зеленела бы на клейме, отсечки не знающем.
		return nil, nil
	}
	return []reconcile_outbox.Event{{
		ID: 42, ObjectType: "compute.instance", ObjectID: "cinst-poison",
		EventType: reconcile_outbox.EventUpsert,
	}}, nil
}

func (q *poisonQueue) MarkReconcileEventSent(_ context.Context, id int64) error {
	q.mu.Lock()
	q.marked = append(q.marked, id)
	q.mu.Unlock()
	return nil
}

func (q *poisonQueue) RecordReconcileEventFailure(_ context.Context, _ int64, cause string) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.attempts++
	q.causes = append(q.causes, cause)
	return q.attempts, nil
}

func (q *poisonQueue) ListSelectorBindingIDs(context.Context) ([]domain.AccessBindingID, error) {
	return nil, nil
}
func (q *poisonQueue) ListExpiredBindingIDs(context.Context) ([]domain.AccessBindingID, error) {
	return nil, nil
}

func (q *poisonQueue) snapshot() (int, []string, []int64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.attempts, append([]string(nil), q.causes...), append([]int64(nil), q.marked...)
}

// TestReconcileDrain_FailureIsCountedAndCarriesItsCause — отказ учитывается, а
// не только логируется, и учёт несёт причину.
func TestReconcileDrain_FailureIsCountedAndCarriesItsCause(t *testing.T) {
	engine := &failingEngine{called: make(chan struct{}, 1)}
	queue := &poisonQueue{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Короткий тик дренажа: предмет — повторяемость отказа, а не расписание.
	w := NewReconcileWorker(engine, queue, ReconcileWorkerConfig{
		DrainInterval: 5 * time.Millisecond,
		SweepInterval: time.Hour,
	})
	done := make(chan struct{})
	go func() { _ = w.Run(ctx); close(done) }()

	// Ждём, пока строка перестанет клеймиться, — то есть пока её не отсечёт
	// порог. Ожидание условия, а не паузы.
	deadline := time.After(5 * time.Second)
	for {
		attempts, _, _ := queue.snapshot()
		if attempts >= reconcile_outbox.MaxAttempts {
			break
		}
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatalf("учёт попыток не дошёл до порога: попыток %d из %d — отказ не учитывается",
				attempts, reconcile_outbox.MaxAttempts)
		case <-time.After(2 * time.Millisecond):
		}
	}
	cancel()
	<-done

	attempts, causes, marked := queue.snapshot()
	if attempts != reconcile_outbox.MaxAttempts {
		t.Fatalf("попыток учтено %d, порог %d — счёт разошёлся с отсечкой",
			attempts, reconcile_outbox.MaxAttempts)
	}
	if len(causes) != reconcile_outbox.MaxAttempts {
		t.Fatalf("причин записано %d при %d попытках", len(causes), attempts)
	}
	for i, c := range causes {
		if !strings.Contains(c, errReconcileRefused.Error()) {
			t.Fatalf("причина %d не называет отказ соседа: %q", i+1, c)
		}
	}
	if len(marked) != 0 {
		t.Fatalf("отравленная строка помечена отправленной %d раз — отказ зачтён в успех", len(marked))
	}
	t.Logf("перепись: попыток учтено %d · причин записано %d · помечено отправленными %d · порог отсечки %d",
		attempts, len(causes), len(marked), reconcile_outbox.MaxAttempts)
}

// TestReconcileDrain_SuccessIsNotCounted — положительный контроль в паре с
// отрицанием выше. Без него «отказ учитывается» зеленело бы на дренаже,
// учитывающем попытку по КАЖДОМУ событию, включая применённое: тогда исправная
// очередь травила бы себя сама.
func TestReconcileDrain_SuccessIsNotCounted(t *testing.T) {
	engine := &fakeNotifyEngine{called: make(chan struct{}, 1)}
	queue := &countingOKQueue{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := NewReconcileWorker(engine, queue, ReconcileWorkerConfig{
		DrainInterval: 5 * time.Millisecond,
		SweepInterval: time.Hour,
	})
	done := make(chan struct{})
	go func() { _ = w.Run(ctx); close(done) }()

	select {
	case <-engine.called:
	case <-time.After(2 * time.Second):
		cancel()
		<-done
		t.Fatal("дренаж не дошёл до сверки")
	}
	cancel()
	<-done

	failures, marked := queue.snapshot()
	if failures != 0 {
		t.Fatalf("успешная сверка учтена отказом %d раз — исправная очередь травит себя", failures)
	}
	if marked == 0 {
		t.Fatal("применённая строка не помечена отправленной")
	}
	t.Logf("перепись: событий применено %d · отказов учтено %d", marked, failures)
}

// countingOKQueue — очередь с одним событием, сверка которого проходит.
type countingOKQueue struct {
	mu       sync.Mutex
	claimed  bool
	failures int
	marked   int
}

func (q *countingOKQueue) ClaimReconcileEvents(context.Context, int) ([]reconcile_outbox.Event, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.claimed {
		return nil, nil
	}
	q.claimed = true
	return []reconcile_outbox.Event{{
		ID: 1, ObjectType: "compute.instance", ObjectID: "cinst-ok",
		EventType: reconcile_outbox.EventUpsert,
	}}, nil
}
func (q *countingOKQueue) MarkReconcileEventSent(context.Context, int64) error {
	q.mu.Lock()
	q.marked++
	q.mu.Unlock()
	return nil
}
func (q *countingOKQueue) RecordReconcileEventFailure(context.Context, int64, string) (int, error) {
	q.mu.Lock()
	q.failures++
	q.mu.Unlock()
	return q.failures, nil
}
func (q *countingOKQueue) ListSelectorBindingIDs(context.Context) ([]domain.AccessBindingID, error) {
	return nil, nil
}
func (q *countingOKQueue) ListExpiredBindingIDs(context.Context) ([]domain.AccessBindingID, error) {
	return nil, nil
}
func (q *countingOKQueue) snapshot() (int, int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.failures, q.marked
}
