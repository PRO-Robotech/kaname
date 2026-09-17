// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// sf_status.go — СОСТОЯНИЕ второго фактора (`GET /iam/v1/auth/second-factor`,
// Ф12 Р4 матрица, Ф12-01, Ф12-02, Ф12-26, Ф12-27): заведён ли, срок ожидающего
// заведения, остаток запасных кодов — только числа и моменты, ни секрета, ни
// кода. Свежести чтение не требует.

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

// StatusInput — сессия.
type StatusInput struct {
	Bearer domain.SessionBearer
}

// BackupCodesView — остаток набора: величина ответа (Р6). При нуле — число,
// не молчание.
type BackupCodesView struct {
	Remaining int
	Total     int
}

// StatusOutput — состояние строки `totp` и набора.
type StatusOutput struct {
	TOTPEnrolled bool
	// PendingUntil — срок ожидающего заведения; нулевой — заведения нет либо
	// оно подтверждено.
	PendingUntil time.Time
	// ConfirmedAt — момент подтверждения у `active`.
	ConfirmedAt time.Time
	// BackupCodes — есть только у заведённого фактора.
	BackupCodes *BackupCodesView
}

// SecondFactorStatusUseCase — чтение состояния.
type SecondFactorStatusUseCase struct {
	deps SecondFactorDeps
}

// NewSecondFactorStatusUseCase — построение с проверкой зависимостей.
func NewSecondFactorStatusUseCase(d SecondFactorDeps) (*SecondFactorStatusUseCase, error) {
	d, err := d.validate("second factor status")
	if err != nil {
		return nil, err
	}
	return &SecondFactorStatusUseCase{deps: d}, nil
}

// Execute — состояние по матрице Р4: нет · `pending` · `active`.
func (uc *SecondFactorStatusUseCase) Execute(ctx context.Context, in StatusInput) (StatusOutput, error) {
	now := uc.deps.Now().UTC()
	resolved, err := resolveLiveSession(ctx, uc.deps, in.Bearer, now)
	if err != nil {
		return StatusOutput{}, err
	}
	row, found, err := factorState(ctx, uc.deps.Methods, resolved.User.ID)
	if err != nil {
		return StatusOutput{}, ErrStoreUnavailable
	}
	switch {
	case !found:
		return StatusOutput{}, nil
	case !row.Enrolled():
		// Истёкшее заведение показывается сроком в прошлом, не скрывается:
		// ответ не зависит от расписания уборки (Ф12-04).
		return StatusOutput{PendingUntil: row.CreatedAt.Add(uc.deps.Freshness)}, nil
	}
	out := StatusOutput{TOTPEnrolled: true, ConfirmedAt: row.CreatedAt, BackupCodes: &BackupCodesView{Total: passwordverify.BackupCodeCount}}
	set, err := uc.deps.Methods.Get(ctx, resolved.User.ID, domain.LoginMethodLookupSecret)
	switch {
	case err == nil:
		if n, ok := uc.deps.Sets.SetSize(set.Verifier); ok {
			out.BackupCodes.Remaining = n
		} else {
			uc.deps.Logger.Error("second factor status: backup code set unreadable — our data, not the caller's input",
				"user_id", string(resolved.User.ID))
		}
	case isNotFound(err):
		uc.deps.Logger.Error("second factor status: active factor without a backup code set — our data",
			"user_id", string(resolved.User.ID))
	default:
		return StatusOutput{}, ErrStoreUnavailable
	}
	return out, nil
}
