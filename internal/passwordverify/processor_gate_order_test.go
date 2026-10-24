// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// processor_gate_order_test.go — место вычисления достаётся ждущим В ПОРЯДКЕ
// ПРИХОДА (kaname#882).
//
// На этом порядке держится оценка ожидания одной проверки, из которой
// считается срок операции церемонии (`ceremonyOperationDeadline`): ждущих не
// больше ёмкости, и при порядке прихода каждый ждёт около ёмкость × стоимость
// одной проверки (оценка, а не предел: чеканка хеша идёт мимо мест, а предел —
// контекст вызывающего, kaname#892). При «последний пришедший — первым» ранний ждущий под
// непрерывным потоком проверок обгоняется каждым новым, и его ожидание
// предела не имеет. Пробы окончаний (`processor_gate_test.go`) этого не
// различают: шесть разом пришедших кончаются по одной при любом порядке.
//
// Проба внутренняя: предмет — порядок выдачи места самим затвором, а через
// Verify порядок прихода не задаётся детерминированно. Приход упорядочен
// `synctest.Wait`: следующий ждущий заводится, лишь когда предыдущий стоит на
// затворе.
package passwordverify

import (
	"context"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
)

// TestProcessorGate_WaitersTakeTheSlotInArrivalOrder — единственное место
// занято; восемь ждущих приходят по одному; место освобождается — ждущие
// получают его в порядке прихода. Близнец — порядок «последний первым» —
// обратная перестановка, и она здесь — находка.
func TestProcessorGate_WaitersTakeTheSlotInArrivalOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := newProcessorGate(1)
		if got := cap(g.slots); got != 1 {
			t.Fatalf("предпосылка: мест вычисления %d, ожидалось одно", got)
		}
		holder, err := g.acquire(context.Background())
		if err != nil {
			t.Fatalf("предпосылка: свободное место не занято: %v", err)
		}

		const waiters = 8
		var (
			mu  sync.Mutex
			got []int
		)
		for i := range waiters {
			go func() {
				release, err := g.acquire(context.Background())
				if err != nil {
					t.Errorf("ждущий %d без отмены не получил места: %v", i, err)
					return
				}
				mu.Lock()
				got = append(got, i)
				mu.Unlock()
				release()
			}()
			// Ждущий i стоит на затворе прежде, чем приходит i+1.
			synctest.Wait()
		}
		mu.Lock()
		early := len(got)
		mu.Unlock()
		if early != 0 {
			t.Fatalf("предпосылка: при занятом месте %d ждущих уже получили его", early)
		}

		holder()
		synctest.Wait()

		want := make([]int, waiters)
		for i := range want {
			want[i] = i
		}
		if !slices.Equal(got, want) {
			t.Fatalf("место вычисления досталось ждущим в порядке %v, а пришли они в порядке %v: "+
				"без порядка прихода ожидание одной проверки не ограничено ёмкость × стоимость", got, want)
		}
	})
}
