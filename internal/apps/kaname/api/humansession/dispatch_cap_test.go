// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

// dispatch_cap_test.go — условие аудита поверхности к приёмке
// `access-beyond-login-needs-a-verified-address.md` (kaname#456): работа вне
// пути ответа ограничена числом одновременных работ, и работа сверх предела не
// принимается и СЧИТАЕТСЯ. Близнец — работа в пределах принимается.

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
)

func TestGoDispatcherRefusesWorkBeyondItsCapAndCountsIt(t *testing.T) {
	var dropped atomic.Int64
	d := humansession.NewGoDispatcher(0).WithCap(2, func() { dropped.Add(1) })
	release := make(chan struct{})
	var started sync.WaitGroup
	started.Add(2)
	var ran atomic.Int64
	for i := 0; i < 2; i++ {
		d.Dispatch(context.Background(), func(context.Context) {
			ran.Add(1)
			started.Done()
			<-release
		})
	}
	started.Wait()
	// Предел занят: третья работа не принимается и считается.
	d.Dispatch(context.Background(), func(context.Context) { ran.Add(1) })
	if got := dropped.Load(); got != 1 {
		t.Fatalf("работа сверх предела: отвергнуто %d, ожидалась 1", got)
	}
	close(release)
	d.Wait()
	if got := ran.Load(); got != 2 {
		t.Fatalf("исполнено %d работ, ожидалось 2 (в пределах)", got)
	}
}
