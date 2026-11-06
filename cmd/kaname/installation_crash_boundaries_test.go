// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"google.golang.org/protobuf/types/known/anypb"
)

// ЗАКРЫТАЯ основа дочернего драйвера. Граница лишь сообщает о достижении и ждёт через
// принадлежащий ей канал IPC; она не может вернуть вымышленный результат БД или выдать себя за C.
// Принадлежащая фикстуре дочерняя точка входа обеспечивает настоящую производственную аутентификацию;
// родитель наблюдает сохранение и завершает точный процесс в выбранной точке.
type rid02Boundary func(context.Context, string, string) error

type rid02ObservedOperation struct {
	mu       sync.Mutex
	id       string
	attempts []rid02TerminalAttempt
}

func (s *rid02ObservedOperation) set(id string) { s.mu.Lock(); defer s.mu.Unlock(); s.id = id }
func (s *rid02ObservedOperation) get() string   { s.mu.Lock(); defer s.mu.Unlock(); return s.id }

// Это наблюдения вокруг НАСТОЯЩЕГО CAS репозитория, а не подменные записи.
type rid02TerminalAttempt struct {
	Started, Finished                   time.Time
	ContextLiveBefore, ContextLiveAfter bool
	ReadBeforeOK, ReadAfterOK           bool
	AlreadyDone                         bool
	Before, After                       json.RawMessage
}

func (s *rid02ObservedOperation) record(a rid02TerminalAttempt) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts = append(s.attempts, a)
}
func (s *rid02ObservedOperation) terminalAttempts() []rid02TerminalAttempt {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]rid02TerminalAttempt(nil), s.attempts...)
}

type rid02CrashRepo struct {
	kanamerepo.Repository
	operation *rid02ObservedOperation
	boundary  rid02Boundary
}

func (r *rid02CrashRepo) Writer(ctx context.Context) (kanamerepo.Writer, error) {
	id := r.operation.get()
	if id == "" {
		return nil, fmt.Errorf("crash fixture has no ordinary persisted Operation")
	}
	if err := r.boundary(ctx, "before-writer", id); err != nil {
		return nil, err
	}
	w, err := r.Repository.Writer(ctx)
	if err != nil {
		return nil, err
	}
	cap, ok := w.(installationTransactionControl)
	if !ok {
		_ = w.Rollback(ctx)
		return nil, fmt.Errorf("actual writer lacks installation transaction capability")
	}
	return &rid02CrashWriter{Writer: w, installation: cap, operation: id, boundary: r.boundary}, nil
}

// Также передаём первичный порт. Одно встраивание репозитория незаметно
// потеряло бы его и превратило тестовый шов в другую реализацию восстановления.
func (r *rid02CrashRepo) ReaderFromPrimary(ctx context.Context) (kanamerepo.Reader, error) {
	primary, ok := r.Repository.(interface {
		ReaderFromPrimary(context.Context) (kanamerepo.Reader, error)
	})
	if !ok {
		return nil, fmt.Errorf("actual repository lacks primary reader")
	}
	return primary.ReaderFromPrimary(ctx)
}

type rid02CrashWriter struct {
	kanamerepo.Writer
	installation installationTransactionControl
	operation    string
	boundary     rid02Boundary
}

func (w *rid02CrashWriter) LockPendingInstallationOperation(ctx context.Context, id, account, proposed string) error {
	return w.installation.LockPendingInstallationOperation(ctx, id, account, proposed)
}
func (w *rid02CrashWriter) RequireInstallationAuthority(ctx context.Context, plans *authzmodel.Plans) error {
	return w.installation.RequireInstallationAuthority(ctx, plans)
}
func (w *rid02CrashWriter) BindInstallationOperation(ctx context.Context, id string, metadata *anypb.Any, winner string) error {
	return w.installation.BindInstallationOperation(ctx, id, metadata, winner)
}
func (w *rid02CrashWriter) Commit(ctx context.Context) error {
	if err := w.boundary(ctx, "before-commit", w.operation); err != nil {
		return err
	}
	if err := w.Writer.Commit(ctx); err != nil {
		return err
	}
	// Здесь нет открытой SQL-транзакции. Принадлежащая фикстуре пауза IPC предшествует возврату
	// из функции операции, поэтому operations.Run ЕЩЁ НЕ создал
	// свежий контекст конечной попытки. Исходный срок исполнителя не изменяется.
	return w.boundary(ctx, "after-commit-before-terminal", w.operation)
}

type rid02CrashOperations struct {
	operations.Repo
	observed *rid02ObservedOperation
}

func (r *rid02CrashOperations) Create(ctx context.Context, op operations.Operation) error {
	if err := r.Repo.Create(ctx, op); err != nil {
		return err
	}
	r.observed.set(op.ID)
	return nil
}

// Этот метод намеренно сохранён: удаление необязательного для исполнителя
// executionClaimer убрало бы из теста штатную защиту конечного состояния.
func (r *rid02CrashOperations) ClaimForExecution(ctx context.Context, id string) (bool, error) {
	actual, ok := r.Repo.(interface {
		ClaimForExecution(context.Context, string) (bool, error)
	})
	if !ok {
		return false, fmt.Errorf("normal Operations repository lacks execution claim")
	}
	return actual.ClaimForExecution(ctx, id)
}
func (r *rid02CrashOperations) MarkDone(ctx context.Context, id string, response *anypb.Any) error {
	a := rid02TerminalAttempt{}
	before, err := r.Repo.Get(ctx, id)
	a.ReadBeforeOK = err == nil
	if err == nil {
		a.Before, err = json.Marshal(before)
		a.ReadBeforeOK = err == nil
	}
	a.Started = time.Now()
	a.ContextLiveBefore = ctx.Err() == nil
	// Не заменяем, не обновляем и не отделяем этот контекст: он должен прийти из настоящего Run.
	err = r.Repo.MarkDone(ctx, id, response)
	a.Finished = time.Now()
	a.ContextLiveAfter = ctx.Err() == nil
	a.AlreadyDone = errors.Is(err, operations.ErrAlreadyDone)
	after, readErr := r.Repo.Get(ctx, id)
	a.ReadAfterOK = readErr == nil
	if readErr == nil {
		a.After, readErr = json.Marshal(after)
		a.ReadAfterOK = readErr == nil
	}
	r.observed.record(a)
	return err
}
