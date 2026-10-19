// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// processor_gate_context_test.go — ожидание места вычисления прерывается
// контекстом вызывающего (kaname#892).
//
// Вызов, кончившийся в очереди (отменён либо вышел срок), не ждёт места до
// конца и не вычисляет: он возвращает ошибку контекста, места не занимает, а
// ёмкость, взятую до очереди, отдаёт. Иначе отменённая операция стоит в
// очереди, вычисляет и держит ёмкость, а порт сверки секрета клиента отвечает
// позже своего срока — на всё время очереди. Близнец — ждущий без отмены —
// получает место, как только оно освобождается.
//
// Проба внутренняя: занять места вычисления снаружи нечем, а предмет — сам
// затвор. Время и блокировки — пузырём `synctest`: «ждущий стоит на затворе»
// и «срок вышел» наступают детерминированно, без сна по настоящим часам.
package passwordverify

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// acquired — исход одного ожидания места.
type acquired struct {
	release func()
	err     error
}

// waitInQueue заводит ждущего в горутине и возвращает канал его исхода.
func waitInQueue(ctx context.Context, g *processorGate) <-chan acquired {
	out := make(chan acquired, 1)
	go func() {
		release, err := g.acquire(ctx)
		out <- acquired{release: release, err: err}
	}()
	return out
}

// TestProcessorGate_CallEndedInTheQueueLeavesItWithTheContextError — место
// занято; ждущий с отменяемым контекстом и ждущий со сроком стоят в очереди;
// отмена и истечение срока возвращают каждому ошибку его контекста, мест они
// не занимают. Близнец без отмены получает освободившееся место.
func TestProcessorGate_CallEndedInTheQueueLeavesItWithTheContextError(t *testing.T) {
	cases := []struct {
		name string
		end  func(t *testing.T) (context.Context, func())
		want error
	}{
		{
			name: "отменён",
			end: func(t *testing.T) (context.Context, func()) {
				ctx, cancel := context.WithCancel(t.Context())
				return ctx, cancel
			},
			want: context.Canceled,
		},
		{
			name: "срок вышел",
			end: func(t *testing.T) (context.Context, func()) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				return ctx, func() { time.Sleep(2 * time.Second); cancel() }
			},
			want: context.DeadlineExceeded,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newProcessorGate(1)
				holder, err := g.acquire(t.Context())
				if err != nil {
					t.Fatalf("предпосылка: свободное место не занято: %v", err)
				}

				ctx, end := c.end(t)
				ended := waitInQueue(ctx, g)
				synctest.Wait()
				twin := waitInQueue(t.Context(), g)
				synctest.Wait()
				select {
				case got := <-ended:
					t.Fatalf("предпосылка: ждущий вышел из очереди до конца вызова (ошибка %v)", got.err)
				default:
				}

				end()
				synctest.Wait()
				select {
				case got := <-ended:
					if !errors.Is(got.err, c.want) {
						t.Errorf("ждущий, чей вызов кончился (%s), вернул ошибку %v, ожидалась ошибка контекста %v",
							c.name, got.err, c.want)
					}
					if got.release != nil {
						t.Errorf("ждущий, чей вызов кончился (%s), получил освобождение места", c.name)
						got.release()
					}
				default:
					holder()
					synctest.Wait()
					leaked := <-ended
					if leaked.release != nil {
						leaked.release()
					}
					if tw := <-twin; tw.release != nil {
						tw.release()
					}
					t.Fatalf("вызов кончился (%s), а ждущий остался в очереди за занятым местом; "+
						"по освобождении он занял место (ошибка %v): отменённая операция вычисляет и держит ёмкость",
						c.name, leaked.err)
				}
				if n := len(g.slots); n != 1 {
					t.Errorf("после выхода ждущего из очереди занято мест %d, ожидалось одно — держателя", n)
				}

				holder()
				synctest.Wait()
				select {
				case tw := <-twin:
					if tw.err != nil {
						t.Fatalf("близнец без отмены не получил места: %v", tw.err)
					}
					tw.release()
				default:
					t.Fatal("близнец без отмены не получил освободившегося места")
				}
			})
		})
	}
}

// TestProcessorGate_EndedCallNeverTakesAFreeSlot — вызов, кончившийся ДО
// ожидания, места не берёт и при свободном: выбор между свободным местом и
// концом вызова не отдаётся случаю. Близнец — живой вызов — место берёт.
func TestProcessorGate_EndedCallNeverTakesAFreeSlot(t *testing.T) {
	g := newProcessorGate(1)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for i := range 64 {
		release, err := g.acquire(ctx)
		if !errors.Is(err, context.Canceled) {
			if release != nil {
				release()
			}
			t.Fatalf("попытка %d: кончившийся вызов при свободном месте вернул %v, ожидалась ошибка контекста", i, err)
		}
	}
	release, err := g.acquire(t.Context())
	if err != nil {
		t.Fatalf("близнец: живой вызов при свободном месте не получил его: %v", err)
	}
	release()
}

// countingObserver — приёмник исходов пробы.
type countingObserver struct {
	mu    sync.Mutex
	cells map[Outcome]int
}

func (o *countingObserver) VerificationObserved(outcome Outcome) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.cells == nil {
		o.cells = map[Outcome]int{}
	}
	o.cells[outcome]++
}

func (o *countingObserver) total() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := 0
	for _, c := range o.cells {
		n += c
	}
	return n
}

// TestVerify_CallEndedInTheQueueReturnsTheContextErrorAndFreesTheCapacity —
// все места вычисления заняты; проверка, чей вызов кончается в очереди,
// возвращает ошибку контекста, исхода не получает (ни одного события
// приёмнику) и ёмкость, взятую до очереди, отдаёт. Те же три свойства — у
// кандидата набора и у прогона калибровки. Близнец — проверка без отмены —
// проходит, как только место освобождается.
func TestVerify_CallEndedInTheQueueReturnsTheContextErrorAndFreesTheCapacity(t *testing.T) {
	paths := []struct {
		name string
		run  func(ctx context.Context, v *Verifier) error
	}{
		{"проверка", func(ctx context.Context, v *Verifier) error {
			_, err := v.Verify(ctx, domain.LoginVerifier{}, "x")
			return err
		}},
		{"кандидат набора", func(ctx context.Context, v *Verifier) error {
			_, err := v.SetCandidate(ctx, domain.LoginVerifier{}, "x")
			return err
		}},
		{"калибровка", func(ctx context.Context, v *Verifier) error {
			_, err := v.compute(ctx, domain.LoginVerifier{}, "x")
			return err
		}},
	}
	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				obs := &countingObserver{}
				v, err := New(4, obs)
				if err != nil {
					t.Fatalf("фикстура НЕ ПОСТРОЕНА: %v", err)
				}
				var holders []func()
				for range cap(v.processor.slots) {
					h, herr := v.processor.acquire(t.Context())
					if herr != nil {
						t.Fatalf("предпосылка: место вычисления не занято: %v", herr)
					}
					holders = append(holders, h)
				}
				releaseAll := func() {
					for _, h := range holders {
						h()
					}
					holders = nil
				}

				ctx, cancel := context.WithCancel(t.Context())
				done := make(chan error, 1)
				go func() { done <- p.run(ctx, v) }()
				synctest.Wait()
				cancel()
				synctest.Wait()

				select {
				case err := <-done:
					if !errors.Is(err, context.Canceled) {
						t.Errorf("%s, чей вызов кончился в очереди, вернула %v, ожидалась ошибка контекста", p.name, err)
					}
				default:
					releaseAll()
					err := <-done
					t.Fatalf("%s: вызов кончился, а она осталась в очереди за занятыми местами и по освобождении "+
						"дошла до вычисления (ошибка %v)", p.name, err)
				}
				if n := obs.total(); n != 0 {
					t.Errorf("%s, не состоявшаяся по концу вызова, отдала приёмнику %d исходов, ожидалось ни одного", p.name, n)
				}
				if n := len(v.capacity.slots); n != 0 {
					t.Errorf("%s, не состоявшаяся по концу вызова, держит мест ёмкости %d, ожидалось ни одного", p.name, n)
				}

				releaseAll()
				if err := p.run(t.Context(), v); err != nil {
					t.Fatalf("близнец: %s без отмены при свободных местах не состоялась: %v", p.name, err)
				}
			})
		})
	}
}
