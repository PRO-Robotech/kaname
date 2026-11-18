// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package humansession

import (
	"context"
	"errors"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// Callback включает только записи одной транзакции; её фиксацией владеет хранилище.
type PreparedVerificationStore interface {
	RunVerificationWrite(context.Context, domain.UserID, func(context.Context, VerificationWriter) error) error
}
type PreparedEmailChangeStore interface {
	RunEmailChangeWrite(context.Context, domain.UserID, func(context.Context, EmailChangeWriter) error) error
}
type PreparedRecoveryCompletionStore interface {
	RunRecoveryCompletionWrite(context.Context, domain.UserID, func(context.Context, RecoveryCompletionWriter) error) error
}

type admissionTransaction interface {
	Commit(context.Context) error
	Rollback(context.Context) error
}

// Старые stores сохраняют ровно одну попытку. Повторы принадлежат только PG.
func runAdmissionOnce[T admissionTransaction](ctx context.Context, open func(context.Context) (T, error), body func(context.Context, T) error) (err error) {
	w, err := open(ctx)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = w.Rollback(cleanup)
	}()
	if err = body(ctx, w); err != nil {
		return err
	}
	return w.Commit(ctx)
}

func runVerificationWrite(ctx context.Context, store VerificationStore, id domain.UserID, body func(context.Context, VerificationWriter) error) error {
	if prepared, ok := store.(PreparedVerificationStore); ok {
		return prepared.RunVerificationWrite(ctx, id, body)
	}
	return runAdmissionOnce(ctx, func(ctx context.Context) (VerificationWriter, error) { return store.VerificationWriter(ctx, id) }, body)
}
func runEmailChangeWrite(ctx context.Context, store EmailChangeStore, id domain.UserID, body func(context.Context, EmailChangeWriter) error) error {
	if prepared, ok := store.(PreparedEmailChangeStore); ok {
		return prepared.RunEmailChangeWrite(ctx, id, body)
	}
	return runAdmissionOnce(ctx, func(ctx context.Context) (EmailChangeWriter, error) { return store.EmailChangeWriter(ctx, id) }, body)
}
func runRecoveryCompletionWrite(ctx context.Context, store RecoveryCompletionStore, id domain.UserID, body func(context.Context, RecoveryCompletionWriter) error) error {
	if prepared, ok := store.(PreparedRecoveryCompletionStore); ok {
		return prepared.RunRecoveryCompletionWrite(ctx, id, body)
	}
	return runAdmissionOnce(ctx, func(ctx context.Context) (RecoveryCompletionWriter, error) {
		return store.RecoveryCompletionWriter(ctx, id)
	}, body)
}

// AdmissionWriteFailure сохраняет публичный класс исчерпанного конфликта,
// но не исходную диагностику хранилища. Отмена и отказ уборки терминальны.
func AdmissionWriteFailure(err error) error {
	var cleanup interface{ PreparedCleanupFailed() bool }
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		(errors.As(err, &cleanup) && cleanup.PreparedCleanupFailed()) {
		return ErrStoreUnavailable
	}
	var exhausted interface{ PreparedAttemptsExhausted() bool }
	if errors.Is(err, iamerr.ErrAborted) && errors.As(err, &exhausted) && exhausted.PreparedAttemptsExhausted() {
		return iamerr.Wrapf(iamerr.ErrAborted, "%s", iamerr.SerializationConflictSyncText)
	}
	return ErrStoreUnavailable
}
