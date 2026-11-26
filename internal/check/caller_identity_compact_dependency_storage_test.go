// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"fmt"
	"slices"
	"testing"
	"unsafe"
)

// Проверяем физически отдельный backing, а не уменьшенный slice-header над
// прежним массивом. Ни records, ни ответы, ни work counters не внедряются.
func TestCallerIdentityCompactDependencyPrefixOwnsStorage(t *testing.T) {
	for _, count := range []int{0, 1, 63, 64} {
		t.Run(fmt.Sprintf("count_%d", count), func(t *testing.T) {
			live := make([]callerTraceDependency, 64)
			for i := range live {
				live[i] = callerTraceDependency{source: callerObjectSourceID(i + 1), want: uint64(i % 2)}
			}
			want := slices.Clone(live[:count])
			prefix := callerTraceDependencyPrefix(live, count)
			if len(prefix) != count || cap(prefix) != count || !slices.Equal(prefix, want) {
				t.Fatal("compact prefix lost exact predicates, order or physical capacity")
			}
			if count > 0 && &prefix[0] == &live[0] {
				t.Fatal("compact prefix still retains the live backing")
			}
			clear(live)
			if !slices.Equal(prefix, want) {
				t.Fatal("retained prefix aliases its released live storage")
			}
			if count > 0 {
				prefix[0].want ^= 1
				if live[0] != (callerTraceDependency{}) {
					t.Fatal("prefix write changed the separately owned live backing")
				}
			}
			// sizeof включает slice header; оба allocation одновременно живы.
			physical := int((unsafe.Sizeof(callerTraceRecord{})+7)/8) + int((unsafe.Sizeof(callerTraceGuard{})+7)/8) + (cap(live)+cap(prefix))*int((unsafe.Sizeof(callerTraceDependency{})+7)/8)
			reserved := callerTraceLiveRecordUnits + callerTraceGuardUnits + count*callerTraceDependencyUnits
			// Guard сохраняет прежнюю reservation24; sizeof может быть меньше.
			// Этот явно учтённый запас не маскирует header/backing новой записи.
			guardPadding := 24 - int((unsafe.Sizeof(callerTraceGuard{})+7)/8)
			if guardPadding < 0 || reserved != physical+guardPadding {
				t.Fatal("live-plus-prefix peak reservation differs from storage plus the unchanged guard reservation")
			}
		})
	}
}
