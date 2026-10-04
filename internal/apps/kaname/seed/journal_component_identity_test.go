// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed

// journal_component_identity_test.go — фоновые пути службы, пишущие ресурсный
// журнал, приходят к пишущей транзакции с личностью СВОЕГО компонента (NTF-3,
// Р2): строка журнала без инициатора базой не принимается, а открывающий
// берёт инициатора только у принципала контекста.
//
// Судится контекст, который путь отдаёт порту записи: у сверщика — снятие
// истёкшей выдачи (`ExpireBinding`), у уборщика — перепись осиротевших
// областей, после которой он открывает пишущую транзакцию.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/auth"
	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func initiatorOf(ctx context.Context) string {
	p, ok := operations.PrincipalFromContextOK(ctx)
	if !ok {
		return ""
	}
	i, err := auth.InitiatorOf(p)
	if err != nil {
		return ""
	}
	return i.String()
}

// initiatorEngine — сверщик, записывающий инициатора контекста снятия.
type initiatorEngine struct {
	exEngine
	mu   sync.Mutex
	seen []string
}

func (e *initiatorEngine) ExpireBinding(ctx context.Context, id domain.AccessBindingID) error {
	e.mu.Lock()
	e.seen = append(e.seen, initiatorOf(ctx))
	e.mu.Unlock()
	return e.exEngine.ExpireBinding(ctx, id)
}

func TestReconcileWorkerExpiresUnderTheReconcilerIdentity(t *testing.T) {
	eng := &initiatorEngine{}
	q := &exQueue{expired: []domain.AccessBindingID{"abn-expired"}}
	w := NewReconcileWorker(eng, q, ReconcileWorkerConfig{
		SweepInterval: time.Hour, DrainInterval: time.Hour, Logger: discardLogger(),
	})
	stop := runWorker(t, w)
	waitForExpiries(t, &eng.exEngine, 1, 3*time.Second, "проход снятия истёкших выдач не исполнился")
	stop()

	eng.mu.Lock()
	defer eng.mu.Unlock()
	if len(eng.seen) == 0 {
		t.Fatal("снятие не исполнилось — судить нечего")
	}
	for _, got := range eng.seen {
		if got != "system:kaname-reconciler" {
			t.Fatalf("снятие истёкшей выдачи идёт с инициатором %q, ожидался system:kaname-reconciler", got)
		}
	}
}

// initiatorScopeStore — перепись уборщика, записывающая инициатора контекста.
type initiatorScopeStore struct{ seen string }

func (s *initiatorScopeStore) TryAcquireSingletonOrphanScopeLock(ctx context.Context) (bool, func(context.Context), error) {
	s.seen = initiatorOf(ctx)
	return true, func(context.Context) {}, nil
}

func (s *initiatorScopeStore) ListOrphanBindingScopes(context.Context, int) ([]OrphanScope, error) {
	return nil, nil
}

func TestOrphanScopeSweepRunsUnderTheSweeperIdentity(t *testing.T) {
	store := &initiatorScopeStore{}
	s := NewOrphanScopeSweeper(nil, store, OrphanScopeConfig{Logger: discardLogger()})
	if _, err := s.RunOnce(context.Background()); err != nil {
		t.Fatalf("уборка отказала: %v", err)
	}
	if store.seen != "system:kaname-sweeper" {
		t.Fatalf("уборка идёт с инициатором %q, ожидался system:kaname-sweeper", store.seen)
	}
}
