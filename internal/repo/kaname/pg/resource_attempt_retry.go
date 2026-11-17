// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Этот маркер создаётся владельцем попытки лишь после bounded cleanup. Ошибка
// SQL сама по себе не разрешает запуск следующей TX с ещё занятой lease.
type resourceAttemptError struct {
	cause   error
	cleanup error
	retry   bool
}

func (e *resourceAttemptError) Error() string   { return "resource decision attempt failed" }
func (e *resourceAttemptError) Unwrap() []error { return []error{e.cause, e.cleanup} }

func resourceRetryableSQL(err error) bool {
	if errors.Is(err, kaname.ErrAuthorityClassificationChanged) || errors.Is(err, iamerr.ErrAborted) {
		return true
	}
	var pgerr *pgconn.PgError
	return errors.As(err, &pgerr) && (pgerr.Code == "40001" || pgerr.Code == "40P01" || pgerr.Code == "P1034" || pgerr.Code == "55P03")
}

// После Commit ErrTxClosed при Rollback не доказывает отсутствия commit.
// Повтор разрешён только для известного abort, включая сохранённый mapErr
// ErrAborted. Сетевая/неизвестная ошибка не повторяется вслепую.
func resourceFailedAttempt(cause, cleanup error, commitStarted bool) error {
	if cause == nil {
		return cleanup
	}
	if errors.Is(cleanup, pgx.ErrTxClosed) {
		cleanup = nil
	}
	retry := cleanup == nil && resourceRetryableSQL(cause)
	if commitStarted {
		var pgerr *pgconn.PgError
		knownAbort := errors.Is(cause, iamerr.ErrAborted) || errors.Is(cause, pgx.ErrTxCommitRollback) ||
			(errors.As(cause, &pgerr) && (pgerr.Code == "40001" || pgerr.Code == "40P01" || pgerr.Code == "P1034" || pgerr.Code == "55P03"))
		retry = cleanup == nil && knownAbort && (resourceRetryableSQL(cause) || errors.Is(cause, pgx.ErrTxCommitRollback))
	}
	return &resourceAttemptError{cause: cause, cleanup: cleanup, retry: retry}
}

// Один внешний budget включает stage, body и Commit. Callback private и
// принадлежит runner; API не получает его, открытый writer или retry-флаг.
func runResourceAttempts(ctx context.Context, once func() (kaname.ResourceDecisionResult, error)) (kaname.ResourceDecisionResult, error) {
	if once == nil {
		return kaname.ResourceDecisionResult{}, kaname.ErrInvalidAuthorityFencePlan
	}
	var last error
	for attempt := 0; attempt < authorityEntryAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return kaname.ResourceDecisionResult{}, err
		}
		result, err := once()
		if err == nil {
			return result, nil
		}
		last = err
		var failed *resourceAttemptError
		if cancel := ctx.Err(); cancel != nil {
			if errors.As(err, &failed) && failed.cleanup != nil {
				return kaname.ResourceDecisionResult{}, errors.Join(cancel, err)
			}
			return kaname.ResourceDecisionResult{}, cancel
		}
		if !errors.As(err, &failed) || !failed.retry {
			return kaname.ResourceDecisionResult{}, err
		}
	}
	return kaname.ResourceDecisionResult{}, errors.Join(iamerr.ErrAborted, last)
}
