// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// sf_backup_codes.go — ПЕРЕЧЕКАНКА набора запасных кодов (Ф12 Р6; Ф12-25):
// подтверждается кодом — это предъявление, свежесть отдельно не проверяется;
// новый набор из десяти заменяет прежний ЦЕЛИКОМ, показывается один раз; одним
// исходом с событием аудита. Перечеканка без кода отвергнута решением: иначе
// набор перечеканивал бы всякий держатель сессии «1».

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

// RegenerateBackupCodesInput — перечеканка с подтверждением кодом.
type RegenerateBackupCodesInput struct {
	Bearer domain.SessionBearer
	Factor SecondFactorPresentation
	Source string
}

// RegenerateBackupCodesOutput — новый набор, ответ как у церемонии.
type RegenerateBackupCodesOutput struct {
	View        SessionView
	Bearer      domain.SessionBearer
	BackupCodes []string
	Assurance   AssuranceView
}

// RegenerateBackupCodesUseCase — перечеканка.
type RegenerateBackupCodesUseCase struct {
	deps SecondFactorDeps
	gate attemptGate
}

// NewRegenerateBackupCodesUseCase — построение с проверкой зависимостей.
func NewRegenerateBackupCodesUseCase(d SecondFactorDeps) (*RegenerateBackupCodesUseCase, error) {
	d, err := d.validate("backup codes regenerate")
	if err != nil {
		return nil, err
	}
	return &RegenerateBackupCodesUseCase{deps: d, gate: d.gate()}, nil
}

// Execute — порядок: форма → сессия → частота → состояние → сверка → набор
// целиком и событие одним исходом.
func (uc *RegenerateBackupCodesUseCase) Execute(ctx context.Context, in RegenerateBackupCodesInput) (RegenerateBackupCodesOutput, error) {
	if err := JudgeCodeForm("code", in.Factor); err != nil {
		return RegenerateBackupCodesOutput{}, err
	}
	now := uc.deps.Now().UTC()
	resolved, err := resolveLiveSession(ctx, uc.deps, in.Bearer, now)
	if err != nil {
		return RegenerateBackupCodesOutput{}, err
	}
	user := resolved.User
	addressKey := AddressKey(string(user.Email))
	if hit, err := uc.gate.check(ctx, addressKey, in.Source); err != nil {
		return RegenerateBackupCodesOutput{}, ErrStoreUnavailable
	} else if hit != nil {
		uc.deps.Observer.RateLimitObserved(hit.Scope)
		return RegenerateBackupCodesOutput{}, hit
	}

	p := presenter{deps: uc.deps}
	pr, err := p.prepare(ctx, user.ID, in.Factor)
	if err != nil {
		return RegenerateBackupCodesOutput{}, ErrStoreUnavailable
	}
	if pr.verdict != verdictMatched {
		st, _ := p.settle(ctx, nil, pr, false)
		p.observe(pr, st)
		return RegenerateBackupCodesOutput{}, uc.refuse(ctx, pr.verdict, addressKey, in.Source, now)
	}
	codes, err := passwordverify.NewBackupCodes()
	if err != nil {
		uc.deps.Logger.Error("backup codes regenerate: codes not minted", "err", err.Error())
		return RegenerateBackupCodesOutput{}, ErrStoreUnavailable
	}
	set, err := uc.deps.SetHasher.HashSet(codes)
	if err != nil {
		uc.deps.Logger.Error("backup codes regenerate: set not hashed", "err", err.Error())
		return RegenerateBackupCodesOutput{}, ErrStoreUnavailable
	}
	bearer, err := domain.NewSessionBearer()
	if err != nil {
		return RegenerateBackupCodesOutput{}, ErrStoreUnavailable
	}
	methods := withMethod(resolved.Session.PresentedMethods, in.Factor.Method)
	level, err := levelOf(methods)
	if err != nil {
		uc.deps.Logger.Error("backup codes regenerate: level not derived", "err", err.Error())
		return RegenerateBackupCodesOutput{}, ErrStoreUnavailable
	}

	w, err := uc.deps.Store.Writer(ctx)
	if err != nil {
		return RegenerateBackupCodesOutput{}, ErrStoreUnavailable
	}
	defer func() { _ = w.Rollback(ctx) }()
	// Сверка под замком набора: предъявленный запасной код сравнивается с
	// ПРЕЖНИМ набором и потребляется из него — набор тут же заменяется, но
	// «код потреблён» остаётся правдой о попытке.
	st, err := p.settle(ctx, w, pr, true)
	if err != nil {
		return RegenerateBackupCodesOutput{}, ErrStoreUnavailable
	}
	if st.verdict != verdictMatched {
		_ = w.Rollback(ctx)
		p.observe(pr, st)
		return RegenerateBackupCodesOutput{}, uc.refuse(ctx, st.verdict, addressKey, in.Source, now)
	}
	if err := w.ReplaceLookupSet(ctx, domain.LoginMethod{
		UserID: user.ID, Kind: domain.LoginMethodLookupSecret, Verifier: set,
		State: domain.LoginMethodStateActive, CreatedAt: now,
	}); err != nil {
		return RegenerateBackupCodesOutput{}, ErrStoreUnavailable
	}
	if err := w.PresentInSession(ctx, resolved.Session.ID, methods, level, bearer.Digest(), now); err != nil {
		return RegenerateBackupCodesOutput{}, ErrStoreUnavailable
	}
	if err := w.ResetFailures(ctx, FailureByAddress, addressKey); err != nil {
		return RegenerateBackupCodesOutput{}, ErrStoreUnavailable
	}
	if err := emitSecondFactorAudit(ctx, w, AuditBackupCodesRegenerated, user, resolved.Session.ID, in.Factor.Method); err != nil {
		return RegenerateBackupCodesOutput{}, ErrStoreUnavailable
	}
	if err := emitStepUpJournal(ctx, w, user, resolved.Session, in.Factor.Method, level); err != nil {
		return RegenerateBackupCodesOutput{}, ErrStoreUnavailable
	}
	if err := w.Commit(ctx); err != nil {
		return RegenerateBackupCodesOutput{}, ErrStoreUnavailable
	}
	p.observe(pr, st)
	uc.deps.Observer.SecondFactorEventObserved(SecondFactorBackupCodesMinted)

	s := resolved.Session
	s.PresentedMethods, s.AssuranceLevel, s.LastPresentedAt = methods, level, now
	return RegenerateBackupCodesOutput{
		View:        SessionView{User: user, Session: s, EmailVerified: resolved.EmailVerified},
		Bearer:      bearer,
		BackupCodes: codes,
		Assurance:   assuranceAfter(ctx, uc.deps, user.ID, methods),
	}, nil
}

func (uc *RegenerateBackupCodesUseCase) refuse(ctx context.Context, v presentVerdict, addressKey, source string, at time.Time) error {
	if countsAsAttempt(v) {
		if werr := recordFailureTx(ctx, uc.deps.Store, addressKey, source, at); werr != nil {
			uc.deps.Logger.Error("backup codes regenerate: failed attempt not recorded", "err", werr.Error())
		}
	}
	return refusalOf(v)
}
