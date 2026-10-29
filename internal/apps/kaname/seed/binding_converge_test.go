// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed

// binding_converge_test.go — сводящий проход по выдачам: единственный путь,
// которым у выдачи одному субъекту снимается лишний кортеж после смены
// вычисления (kaname#1006). Пробы держат два свойства, без которых этот путь
// отзыва останавливается молча.
//
// # Отказ одной выдачи не останавливает проход (находка M2 / SD-1006-C1)
//
// Прежде `RunOnce` выходил на первой ошибке `ConvergeBinding`, и все выдачи с
// большим id сохраняли лишнее право до следующего старта, а при
// детерминированной ошибке — навсегда. Утверждается: проход доходит до конца,
// отказавшая выдача повторяется в том же проходе, у каждого вызова свой срок,
// исход по каждой выдаче сообщён наблюдателю, перепись печатается и на отказе.
//
// # Сведение повторяется без перезапуска процесса (находка M1 / I1)
//
// Реплика прежней версии, живая во время перекрытия выкатки, снова пишет
// лишний кортеж уже после разового прохода при старте; прежний держатель
// замка-одиночки заставляет новую реплику пропустить проход целиком.
// Утверждается: проход повторяется по такту, и такт после пропущенного либо
// отказавшего прохода сводит выдачу.

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// convergeStore — перечень выдач с постраничным чтением по ключу и
// замком-одиночкой, который может держать «другая реплика».
type convergeStore struct {
	mu       sync.Mutex
	ids      []domain.AccessBindingID
	held     []bool // held[i] — замок занят на i-м такте; дальше — свободен
	attempts int
	lists    int
}

func (s *convergeStore) TryAcquireSingletonBackfillLock(context.Context) (bool, func(context.Context), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.attempts
	s.attempts++
	if i < len(s.held) && s.held[i] {
		return false, func(context.Context) {}, nil
	}
	return true, func(context.Context) {}, nil
}

func (s *convergeStore) ListActiveBindingIDsChunk(_ context.Context, afterID string, limit int) ([]domain.AccessBindingID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lists++
	var out []domain.AccessBindingID
	for _, id := range s.ids {
		if string(id) > afterID && len(out) < limit {
			out = append(out, id)
		}
	}
	return out, nil
}

// convergeEngine — сводящая сверка; fail решает исход вызова по выдаче и
// номеру попытки (с единицы) в границах всей пробы.
type convergeEngine struct {
	mu          sync.Mutex
	calls       map[domain.AccessBindingID]int
	noDeadline  int
	fail        func(ctx context.Context, id domain.AccessBindingID, attempt int) error
	maxDeadline time.Duration
}

func (e *convergeEngine) ConvergeBinding(ctx context.Context, id domain.AccessBindingID) error {
	e.mu.Lock()
	if e.calls == nil {
		e.calls = map[domain.AccessBindingID]int{}
	}
	e.calls[id]++
	attempt := e.calls[id]
	if dl, ok := ctx.Deadline(); !ok {
		e.noDeadline++
	} else if left := time.Until(dl); left > e.maxDeadline {
		e.maxDeadline = left
	}
	fail := e.fail
	e.mu.Unlock()
	if fail == nil {
		return nil
	}
	return fail(ctx, id, attempt)
}

func (e *convergeEngine) callsOf(id domain.AccessBindingID) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls[id]
}

// countingObserver — исходы по выдаче.
type countingObserver struct {
	mu  sync.Mutex
	got map[string]int
}

func (o *countingObserver) IncBindingConverge(outcome string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.got == nil {
		o.got = map[string]int{}
	}
	o.got[outcome]++
}

func fiveBindings() []domain.AccessBindingID {
	return []domain.AccessBindingID{"acb1", "acb2", "acb3", "acb4", "acb5"}
}

// errCoverageDesync — детерминированный отказ выдачи, дословно из applyDiff.
var errCoverageDesync = errors.New("membership tuple inconsistent (role coverage desync)")

// Законный близнец: все выдачи сходятся — ни повтора, ни ошибки, каждая
// выдача сведена ровно один раз.
func TestConvergeSweep_AllBindingsConverge_NoRetryNoError(t *testing.T) {
	store := &convergeStore{ids: fiveBindings()}
	engine := &convergeEngine{}
	r := NewBackfillRunner(engine, store, BackfillConfig{ChunkSize: 2})

	res, err := r.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("сходящийся проход вернул ошибку: %v", err)
	}
	if !res.Executed || res.BindingsReconciled != 5 || res.BindingsFailed != 0 {
		t.Fatalf("перепись = %+v, ожидалось Executed, сведено 5, отказало 0", res)
	}
	for _, id := range store.ids {
		if n := engine.callsOf(id); n != 1 {
			t.Fatalf("выдача %s сведена %d раз, ожидался ровно один (повтор без отказа — лишняя работа)", id, n)
		}
	}
}

// M2: детерминированный отказ выдачи acb2 не останавливает проход — выдачи
// acb3..acb5 (и через границу страницы) сводятся, отказ назван в ошибке и в
// переписи.
func TestConvergeSweep_FailedBindingDoesNotStopTheSweep(t *testing.T) {
	store := &convergeStore{ids: fiveBindings()}
	engine := &convergeEngine{fail: func(_ context.Context, id domain.AccessBindingID, _ int) error {
		if id == "acb2" {
			return errCoverageDesync
		}
		return nil
	}}
	r := NewBackfillRunner(engine, store, BackfillConfig{ChunkSize: 2})

	res, err := r.RunOnce(context.Background())
	for _, id := range []domain.AccessBindingID{"acb3", "acb4", "acb5"} {
		if engine.callsOf(id) == 0 {
			t.Errorf("выдача %s не сведена: отказ acb2 остановил проход, и её лишний кортеж "+
				"переживает выкатку", id)
		}
	}
	if res.BindingsReconciled != 4 || res.BindingsFailed != 1 ||
		!slices.Equal(res.FailedBindings, []domain.AccessBindingID{"acb2"}) {
		t.Errorf("перепись = %+v, ожидалось сведено 4, отказало 1 (acb2)", res)
	}
	if !errors.Is(err, errCoverageDesync) || err == nil || !strings.Contains(err.Error(), "acb2") {
		t.Errorf("ошибка прохода = %v, ожидалась несущая причину отказа и id acb2", err)
	}
}

// M2: транзиентный отказ (первая попытка) повторяется в ТОМ ЖЕ проходе.
func TestConvergeSweep_TransientFailureIsRetriedWithinThePass(t *testing.T) {
	store := &convergeStore{ids: fiveBindings()}
	engine := &convergeEngine{fail: func(_ context.Context, id domain.AccessBindingID, attempt int) error {
		if id == "acb2" && attempt == 1 {
			return errors.New("deadlock detected (SQLSTATE 40P01)")
		}
		return nil
	}}
	r := NewBackfillRunner(engine, store, BackfillConfig{ChunkSize: 2})

	res, err := r.RunOnce(context.Background())
	if err != nil {
		t.Errorf("транзиентный отказ не повторён в проходе: %v", err)
	}
	if res.BindingsReconciled != 5 || res.BindingsFailed != 0 {
		t.Errorf("перепись = %+v, ожидалось сведено 5, отказало 0", res)
	}
	if n := engine.callsOf("acb2"); n != 2 {
		t.Errorf("acb2 сведена %d раз, ожидалось 2 (отказ и повтор)", n)
	}
}

// M2: у каждого вызова свой срок — зависшее ожидание замка выдачи не держит
// замок-одиночку прохода и не останавливает остальные выдачи.
func TestConvergeSweep_EachBindingHasItsOwnDeadline(t *testing.T) {
	store := &convergeStore{ids: fiveBindings()}
	engine := &convergeEngine{fail: func(ctx context.Context, id domain.AccessBindingID, _ int) error {
		if id == "acb1" {
			<-ctx.Done() // ждёт замка выдачи, который не отпускают
			return ctx.Err()
		}
		return nil
	}}
	const perBinding = 20 * time.Millisecond
	r := NewBackfillRunner(engine, store, BackfillConfig{ChunkSize: 2, BindingTimeout: perBinding})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := r.RunOnce(ctx)

	if engine.noDeadline != 0 {
		t.Errorf("%d вызовов ConvergeBinding без собственного срока", engine.noDeadline)
	}
	if engine.maxDeadline > perBinding {
		t.Errorf("срок вызова %v шире объявленного %v", engine.maxDeadline, perBinding)
	}
	if engine.callsOf("acb5") == 0 {
		t.Errorf("зависшая acb1 остановила проход: acb5 не сведена")
	}
	if res.BindingsFailed != 1 || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("перепись = %+v, ошибка = %v; ожидалась одна отказавшая по сроку", res, err)
	}
}

// M2: исход по каждой выдаче сообщается наблюдателю — счётчик читаем снаружи,
// а успехи считаются наравне с отказами.
func TestConvergeSweep_OutcomePerBindingReachesTheObserver(t *testing.T) {
	store := &convergeStore{ids: fiveBindings()}
	engine := &convergeEngine{fail: func(_ context.Context, id domain.AccessBindingID, _ int) error {
		if id == "acb4" {
			return errCoverageDesync
		}
		return nil
	}}
	obs := &countingObserver{}
	r := NewBackfillRunner(engine, store, BackfillConfig{ChunkSize: 2, Observer: obs})

	_, _ = r.RunOnce(context.Background())
	if obs.got[BindingConvergeOutcomeConverged] != 4 || obs.got[BindingConvergeOutcomeFailed] != 1 {
		t.Errorf("наблюдатель получил %v, ожидалось converged=4 failed=1", obs.got)
	}
}

// M2: перепись печатается и на отказе — «ноль сведённых» отличим от «ноль
// прочитанных», а отказавшие выдачи названы.
func TestConvergeSweep_CensusIsLoggedOnFailureToo(t *testing.T) {
	store := &convergeStore{ids: fiveBindings()}
	engine := &convergeEngine{fail: func(_ context.Context, id domain.AccessBindingID, _ int) error {
		if id == "acb3" {
			return errCoverageDesync
		}
		return nil
	}}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	r := NewBackfillRunner(engine, store, BackfillConfig{ChunkSize: 2, Logger: logger})

	_, _ = r.RunOnce(context.Background())
	out := buf.String()
	for _, want := range []string{"bindings_examined=5", "bindings_reconciled=4", "bindings_failed=1", "acb3"} {
		if !strings.Contains(out, want) {
			t.Errorf("перепись отказавшего прохода не несёт %q; журнал:\n%s", want, out)
		}
	}
}

// M1: проход повторяется по такту без перезапуска процесса. Первый такт —
// замок-одиночку держит реплика прежней версии (проход пропущен), второй — acb2
// отказывает, третий — сводит её. Каждая выдача сведена на каждом исполненном
// такте.
func TestConvergeLoop_RepeatsThePassWithoutRestart(t *testing.T) {
	store := &convergeStore{ids: fiveBindings(), held: []bool{true}}
	engine := &convergeEngine{fail: func(_ context.Context, id domain.AccessBindingID, attempt int) error {
		if id == "acb2" && attempt <= 2 { // отказ и повтор в том же проходе
			return errCoverageDesync
		}
		return nil
	}}
	r := NewBackfillRunner(engine, store, BackfillConfig{ChunkSize: 2})

	ticks := make(chan time.Time)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.convergeOn(ctx, ticks)
	}()
	for range 3 {
		select {
		case ticks <- time.Now():
		case <-time.After(3 * time.Second):
			t.Fatal("цикл сведения не принял такт: повтор прохода не провязан")
		}
	}
	// Небуферизованная отправка четвёртого такта гарантирует, что третий проход
	// закончен; после неё цикл снимается.
	select {
	case ticks <- time.Now():
	case <-time.After(3 * time.Second):
		t.Fatal("третий проход не завершился")
	}
	cancel()
	<-done

	if engine.callsOf("acb1") < 2 {
		t.Errorf("acb1 сведена %d раз: проход после пропущенного такта не повторился", engine.callsOf("acb1"))
	}
	if engine.callsOf("acb2") < 3 {
		t.Errorf("acb2 сведена %d раз: отказавшая выдача не повторена следующим тактом", engine.callsOf("acb2"))
	}
}
