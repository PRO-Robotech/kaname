// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// nil сохраняет прежнее поведение вызывающего/умолчаний моста. Ограниченный бюджетом
// наблюдатель проверяет настоящий срок вместе с отменой, включая задержку таймера.
func ridNewmanBudgetCheck(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	if ctx.Err() != nil {
		return errors.New("Newman observation budget expired")
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return errors.New("Newman observation budget expired")
	}
	return nil
}

type ridNewmanBudgetWriter interface {
	Write([]byte) (int, error)
	SetWriteDeadline(time.Time) error
}

// written равен true ТОЛЬКО после успеха настоящего Encode, даже если следующая
// проверка срока отклоняет приём. Очистка тогда не должна посылать второе разрешение.
func ridNewmanBudgetWrite(ctx context.Context, out ridNewmanBudgetWriter, action string, cap time.Duration) (written bool, err error) {
	if err = ridNewmanBudgetCheck(ctx); err != nil {
		return false, err
	}
	deadline := time.Now().Add(cap)
	if ctx != nil {
		if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
			deadline = parent
		}
	}
	if err = out.SetWriteDeadline(deadline); err != nil {
		return false, err
	}
	if err = ridNewmanBudgetCheck(ctx); err != nil {
		return false, err
	}
	if err = json.NewEncoder(out).Encode(action); err != nil {
		return false, err
	}
	return true, ridNewmanBudgetCheck(ctx)
}

type rid06CriticalActions struct {
	Await, Pending, Revoke, Boundary func(context.Context) error
	Release                          func(context.Context) (bool, error)
}

// Это настоящий контроллер необязательного наблюдателя, общий для всех четырёх миров.
// Неудачная проверка не продвигает к следующей стадии; очисткой/ожиданием владеет внешний код.
func rid06RunCritical(ctx context.Context, actions rid06CriticalActions) (bool, error) {
	for _, stage := range []func(context.Context) error{actions.Await, actions.Pending, actions.Revoke, actions.Boundary} {
		if err := ridNewmanBudgetCheck(ctx); err != nil {
			return false, err
		}
		if err := stage(ctx); err != nil {
			return false, err
		}
		if err := ridNewmanBudgetCheck(ctx); err != nil {
			return false, err
		}
	}
	if err := ridNewmanBudgetCheck(ctx); err != nil {
		return false, err
	}
	written, err := actions.Release(ctx)
	if err != nil {
		return written, err
	}
	return written, ridNewmanBudgetCheck(ctx)
}
