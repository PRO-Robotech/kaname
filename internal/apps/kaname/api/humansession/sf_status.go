// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// sf_status.go — СОСТОЯНИЕ второго фактора (`GET /iam/v1/auth/second-factor`,
// Ф12 Р4 матрица, Ф12-01, Ф12-02, Ф12-26, Ф12-27): заведён ли, срок ожидающего
// заведения, остаток запасных кодов — только числа и моменты, ни секрета, ни
// кода. Свежести чтение не требует.

import (
	"context"
	"sort"
	"time"

	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

// StatusInput — сессия.
type StatusInput struct {
	Bearer domain.SessionBearer
}

// BackupCodeSetView — состояние набора запасных кодов (kaname#297 Р2): остаток,
// размер, момент выпуска и момент последней траты; кодов и материала нет.
// Строится только о ПРОЧИТАННОМ наборе — значений-заглушек нет.
type BackupCodeSetView struct {
	Remaining int
	Total     int
	// IssuedAt — момент выпуска набора (kaname#827, SUA Р6): момент строки
	// набора; перевыпуск его сдвигает.
	IssuedAt time.Time
	// LastUsedAt — момент последней траты запасного кода; LastUsed=false —
	// после выпуска набора не тратили, и ключа в ответе нет.
	LastUsedAt time.Time
	LastUsed   bool
}

// StatusOutput — состояние строки `totp` и набора, способы повышения и
// доступность ключей (kaname#827, SUA Р6).
type StatusOutput struct {
	TOTPEnrolled bool
	// PendingUntil — срок ожидающего заведения; нулевой — заведения нет либо
	// оно подтверждено.
	PendingUntil time.Time
	// ConfirmedAt — момент подтверждения у `active`.
	ConfirmedAt time.Time
	// TOTPLastUsedAt — момент последнего принятого кода; TOTPLastUsed=false —
	// после подтверждения код не предъявляли, и ключа в ответе нет.
	TOTPLastUsedAt time.Time
	TOTPLastUsed   bool
	// BackupCodeSet — есть только у заведённого фактора.
	BackupCodeSet *BackupCodeSetView
	// AccessKeysAvailable — ключи доступа на установке включены.
	AccessKeysAvailable bool
	// StepUpMethods — способы, которыми человек может повысить уровень этой
	// сессии: набор, отсортированный по имени; пусто — пустой набор.
	StepUpMethods []string
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
func (uc *SecondFactorStatusUseCase) Execute(ctx context.Context, in StatusInput) (_ StatusOutput, err error) {
	// Клетка сбоя хранилища (kaname#691) — единственная точка на выходе
	// глагола, а не каждый возврат по отдельности.
	defer func() { err = observeStoreFailure(uc.deps.Observer, StoreFailureSecondFactorStatus, err) }()
	now := uc.deps.Now().UTC()
	resolved, err := resolveLiveSession(ctx, uc.deps, in.Bearer, now)
	if err != nil {
		return StatusOutput{}, err
	}
	row, found, err := factorState(ctx, uc.deps.Methods, resolved.User.ID)
	if err != nil {
		return StatusOutput{}, ErrStoreUnavailable
	}
	methods, err := uc.stepUpMethods(ctx, resolved.User.ID)
	if err != nil {
		return StatusOutput{}, ErrStoreUnavailable
	}
	out := StatusOutput{AccessKeysAvailable: !uc.deps.Keys.Binding.Disabled(), StepUpMethods: methods}
	switch {
	case !found:
		return out, nil
	case !row.Enrolled():
		// Истёкшее заведение показывается сроком в прошлом, не скрывается:
		// ответ не зависит от расписания уборки (Ф12-04).
		out.PendingUntil = row.CreatedAt.Add(uc.deps.Freshness)
		return out, nil
	}
	out.TOTPEnrolled, out.ConfirmedAt = true, row.CreatedAt
	out.TOTPLastUsedAt, out.TOTPLastUsed = row.LastUsedAt, row.LastUsed
	out.BackupCodeSet = &BackupCodeSetView{Total: passwordverify.BackupCodeCount}
	set, err := uc.deps.Methods.Get(ctx, resolved.User.ID, domain.LoginMethodLookupSecret)
	switch {
	case err == nil:
		out.BackupCodeSet.IssuedAt = set.CreatedAt
		out.BackupCodeSet.LastUsedAt, out.BackupCodeSet.LastUsed = set.LastUsedAt, set.LastUsed
		if n, ok := uc.deps.Sets.SetSize(set.Verifier); ok {
			out.BackupCodeSet.Remaining = n
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

// stepUpMethods — способы, которыми человек может повысить уровень сессии
// (SUA Р6): код по времени — при заведённом факторе, запасной код — при
// непустом остатке набора, ключ — при включённых ключах и хотя бы одной
// строке ключа. Пароль способом ПОВЫШЕНИЯ не считается: «2» он не даёт.
func (uc *SecondFactorStatusUseCase) stepUpMethods(ctx context.Context, userID domain.UserID) ([]string, error) {
	presentable, err := presentableMethods(ctx, uc.deps, userID)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, m := range presentable {
		switch m {
		case assurance.MethodTOTP, assurance.MethodWebAuthn:
			out = append(out, m.String())
		case assurance.MethodLookupSecret:
			has, err := uc.setHasCodes(ctx, userID)
			if err != nil {
				return nil, err
			}
			if has {
				out = append(out, m.String())
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// setHasCodes — у набора остался хоть один код. Набора нет либо он не
// читается — способом не называется: предъявить его нечем (о нечитаемом
// набору уже сказал журнал чтения состояния). Отказ хранилища — отказ.
func (uc *SecondFactorStatusUseCase) setHasCodes(ctx context.Context, userID domain.UserID) (bool, error) {
	set, err := uc.deps.Methods.Get(ctx, userID, domain.LoginMethodLookupSecret)
	switch {
	case isNotFound(err):
		return false, nil
	case err != nil:
		return false, err
	}
	n, ok := uc.deps.Sets.SetSize(set.Verifier)
	return ok && n > 0, nil
}
