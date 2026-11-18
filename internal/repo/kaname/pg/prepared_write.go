// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"errors"
	"reflect"
	"time"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type preparedSingleEntryKey struct{}
type preparedReadBudgetKey struct{}

func preparedAdministrativeReadBudget(ctx context.Context) *relverdict.AdministrativeReadBudget {
	if budget, ok := ctx.Value(preparedReadBudgetKey{}).(*relverdict.AdministrativeReadBudget); ok {
		return budget
	}
	return &relverdict.AdministrativeReadBudget{}
}
func preparedSingleEntry(ctx context.Context) bool {
	return ctx.Value(preparedSingleEntryKey{}) == true
}
func authorityEntryLimit(ctx context.Context) int {
	if preparedSingleEntry(ctx) {
		return 1
	}
	return authorityEntryAttempts
}

type preparedTransaction interface {
	Commit(context.Context) error
	Rollback(context.Context) error
}
type preparedCleanupFailure struct{ cause, cleanup error }

func (e *preparedCleanupFailure) Error() string             { return "prepared transaction cleanup failed" }
func (e *preparedCleanupFailure) Unwrap() []error           { return []error{e.cause, e.cleanup} }
func (*preparedCleanupFailure) PreparedCleanupFailed() bool { return true }

// Общий структурный маркер также распознаёт cleanup отказ authorityprotocol.
func preparedEntryFailure(cause, cleanup error) error {
	if cleanup == nil || cleanup == pgx.ErrTxClosed {
		return cause
	}
	return &preparedCleanupFailure{cause, cleanup}
}
func preparedRetryable(err error, commitStarted bool) bool {
	var cleanup interface{ PreparedCleanupFailed() bool }
	if errors.As(err, &cleanup) && cleanup.PreparedCleanupFailed() {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	for _, refusal := range []error{iamerr.ErrPermissionDenied, iamerr.ErrUnauthenticated, iamerr.ErrInvalidArg, iamerr.ErrFailedPrecondition, iamerr.ErrNotFound, iamerr.ErrAlreadyExists, iamerr.ErrUnavailable, kaname.ErrSourceUnconfirmed, kaname.ErrSourceReadLimit} {
		if errors.Is(err, refusal) {
			return false
		}
	}
	var pe *pgconn.PgError
	knownAbort := errors.Is(err, iamerr.ErrAborted) || errors.Is(err, pgx.ErrTxCommitRollback) ||
		(errors.As(err, &pe) && (pe.Code == "40001" || pe.Code == "40P01" || pe.Code == "P1034"))
	if commitStarted {
		return knownAbort
	}
	return knownAbort || errors.Is(err, kaname.ErrAuthorityClassificationChanged)
}

type preparedConflict struct{ cause error }

func (e preparedConflict) Error() string { return iamerr.SerializationConflictSyncText }
func (e preparedConflict) Unwrap() error { return e.cause }
func preparedNil[T preparedTransaction](tx T) bool {
	v := reflect.ValueOf(tx)
	if !v.IsValid() {
		return true
	}
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		return v.IsNil()
	}
	return false
}

// Один budget включает open/stage, body и Commit. Неизвестный исход Commit не
// становится abort только потому, что следующая Rollback вернула ErrTxClosed.
func executePreparedAttempts[T preparedTransaction](ctx context.Context, open func(context.Context) (T, error), action func(context.Context, T) error) error {
	if open == nil || action == nil || preparedSingleEntry(ctx) {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	attemptCtx := context.WithValue(ctx, preparedSingleEntryKey{}, true)
	attemptCtx = context.WithValue(attemptCtx, preparedReadBudgetKey{}, &relverdict.AdministrativeReadBudget{})
	var last error
	for attempt := 0; attempt < authorityEntryAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		commitStarted := false
		last = func() (err error) {
			tx, err := open(attemptCtx)
			if err != nil {
				// По контракту open уже очистил неудачный вход. Если он всё же
				// вернул TX с ошибкой, исполнитель не оставляет её открытой.
				if !preparedNil(tx) {
					cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
					defer cancel()
					return preparedEntryFailure(err, tx.Rollback(cleanup))
				}
				return err
			}
			if preparedNil(tx) {
				return kaname.ErrInvalidAuthorityFencePlan
			}
			committed := false
			defer func() {
				if committed {
					return
				}
				cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
				defer cancel()
				err = preparedEntryFailure(err, tx.Rollback(cleanup))
			}()
			if err = ctx.Err(); err != nil {
				return err
			}
			if err = action(attemptCtx, tx); err != nil {
				return err
			}
			if err = ctx.Err(); err != nil {
				return err
			}
			commitStarted = true
			if err = tx.Commit(attemptCtx); err != nil {
				return err
			}
			committed = true
			return nil
		}()
		if last == nil {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return errors.Join(err, last)
		}
		if !preparedRetryable(last, commitStarted) {
			return last
		}
	}
	return iamerr.Wrapf(iamerr.ErrAborted, "%w", preparedConflict{last})
}

func (p *MetadataMutationWriters) ExecutePreparedWrite(ctx context.Context, open func(context.Context) (kaname.Writer, error), action func(context.Context, kaname.Writer) error) error {
	if p == nil {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	return executePreparedAttempts(ctx, open, action)
}

var _ kaname.PreparedWriteExecutor = (*MetadataMutationWriters)(nil)

func (p *ServiceAccountStateWriters) ExecutePreparedWrite(ctx context.Context, open func(context.Context) (kaname.Writer, error), action func(context.Context, kaname.Writer) error) error {
	if p == nil {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	return executePreparedAttempts(ctx, open, action)
}

var _ kaname.PreparedWriteExecutor = (*ServiceAccountStateWriters)(nil)

func (p *CRUDWriters) ExecutePreparedWrite(ctx context.Context, open func(context.Context) (kaname.Writer, error), action func(context.Context, kaname.Writer) error) error {
	if p == nil {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	return executePreparedAttempts(ctx, open, action)
}

var _ kaname.PreparedWriteExecutor = (*CRUDWriters)(nil)

func (p *GroupMembershipParticipant) ExecutePreparedWrite(ctx context.Context, open func(context.Context) (kaname.Writer, error), action func(context.Context, kaname.Writer) error) error {
	if p == nil {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	return executePreparedAttempts(ctx, open, action)
}

var _ kaname.PreparedWriteExecutor = (*GroupMembershipParticipant)(nil)

func (p *HumanAdmissionParticipant) ExecutePreparedWrite(ctx context.Context, open func(context.Context) (kaname.Writer, error), action func(context.Context, kaname.Writer) error) error {
	if p == nil {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	return executePreparedAttempts(ctx, open, action)
}

var _ kaname.PreparedWriteExecutor = (*HumanAdmissionParticipant)(nil)

func (p *GrantPolicyWriters) ExecutePreparedWrite(ctx context.Context, open func(context.Context) (kaname.Writer, error), action func(context.Context, kaname.Writer) error) error {
	if p == nil {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	return executePreparedAttempts(ctx, open, action)
}

var _ kaname.PreparedWriteExecutor = (*GrantPolicyWriters)(nil)
