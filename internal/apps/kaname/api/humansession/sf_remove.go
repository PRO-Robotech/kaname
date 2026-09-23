// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// sf_remove.go — СНЯТИЕ второго фактора самим человеком (Ф12 Р9; Ф12-28, Ф12-29):
// подтверждается кодом (по времени либо запасным) — это предъявление (Ф11 Р5),
// поэтому свежесть отдельно не проверяется и ответ несёт НОВЫЙ носитель
// текущей сессии с уровнем «2». Одним исходом одной транзакции: строки `totp` и
// `lookup_secret` сняты; записи ВСЕХ прочих сессий сняты (устройство, которым
// повышались чужие сессии, могло быть тем, ради чего снимают); событие аудита.
// Текущая сессия уровня не теряет (Ф11 §7 инв. 5).
//
// Последний фактор снять МОЖНО — отступление от одной строки F4d-51 (Д5):
// иначе смена телефона при ключе «один totp на человека» невыразима вовсе.

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// RemoveSecondFactorInput — снятие с подтверждением кодом.
type RemoveSecondFactorInput struct {
	Bearer domain.SessionBearer
	Factor SecondFactorPresentation
	Source string
}

// RemoveSecondFactorOutput — ответ как у церемонии.
type RemoveSecondFactorOutput struct {
	View      SessionView
	Bearer    domain.SessionBearer
	Assurance AssuranceView
	// BackupCodesRemaining — всегда `0` (Р4 ред. 10, kaname#275): снятие любым
	// годным кодом убирает фактор, набора запасных кодов больше нет; согласовано
	// с `GET` того же человека («не заведён»). Стоит на выдаче всегда, а не
	// только у ответа, потребившего запасной код.
	BackupCodesRemaining *int
}

// RemoveSecondFactorUseCase — снятие.
type RemoveSecondFactorUseCase struct {
	deps SecondFactorDeps
	gate attemptGate
}

// NewRemoveSecondFactorUseCase — построение с проверкой зависимостей.
func NewRemoveSecondFactorUseCase(d SecondFactorDeps) (*RemoveSecondFactorUseCase, error) {
	d, err := d.validate("second factor remove")
	if err != nil {
		return nil, err
	}
	return &RemoveSecondFactorUseCase{deps: d, gate: d.gate()}, nil
}

// Execute — порядок: форма → сессия → частота → состояние → сверка → снятие
// одним исходом.
func (uc *RemoveSecondFactorUseCase) Execute(ctx context.Context, in RemoveSecondFactorInput) (RemoveSecondFactorOutput, error) {
	if err := JudgeCodeForm("code", in.Factor); err != nil {
		return RemoveSecondFactorOutput{}, err
	}
	now := uc.deps.Now().UTC()
	resolved, err := resolveLiveSession(ctx, uc.deps, in.Bearer, now)
	if err != nil {
		return RemoveSecondFactorOutput{}, err
	}
	user := resolved.User
	addressKey := AddressKey(string(user.Email))
	if hit, err := uc.gate.check(ctx, addressKey, in.Source); err != nil {
		return RemoveSecondFactorOutput{}, ErrStoreUnavailable
	} else if hit != nil {
		uc.deps.Observer.RateLimitObserved(hit.Scope)
		return RemoveSecondFactorOutput{}, hit
	}

	p := presenter{deps: uc.deps}
	pr, err := p.prepare(ctx, user.ID, in.Factor)
	if err != nil {
		return RemoveSecondFactorOutput{}, ErrStoreUnavailable
	}
	if pr.verdict != verdictMatched {
		st, _ := p.settle(ctx, nil, pr, false)
		p.observe(pr, st)
		return RemoveSecondFactorOutput{}, uc.refuse(ctx, pr.verdict, addressKey, in.Source, now)
	}
	bearer, err := domain.NewSessionBearer()
	if err != nil {
		return RemoveSecondFactorOutput{}, ErrStoreUnavailable
	}
	methods := withMethod(resolved.Session.PresentedMethods, in.Factor.Method)
	level, err := levelOf(methods)
	if err != nil {
		uc.deps.Logger.Error("second factor remove: level not derived", "err", err.Error())
		return RemoveSecondFactorOutput{}, ErrStoreUnavailable
	}

	// Заведённое читается ДО открытия транзакции: оба адаптера делят один пул,
	// и чтение изнутри открытой транзакции дало бы вложенный захват соединения.
	enrolled, enrolledKnown := enrollmentBeforeWrite(ctx, uc.deps.Methods, uc.deps.Logger, user.ID)
	w, err := uc.deps.Store.Writer(ctx)
	if err != nil {
		return RemoveSecondFactorOutput{}, ErrStoreUnavailable
	}
	defer func() { _ = w.Rollback(ctx) }()
	st, err := p.settle(ctx, w, pr, true)
	if err != nil {
		return RemoveSecondFactorOutput{}, ErrStoreUnavailable
	}
	if st.verdict != verdictMatched {
		_ = w.Rollback(ctx)
		p.observe(pr, st)
		return RemoveSecondFactorOutput{}, uc.refuse(ctx, st.verdict, addressKey, in.Source, now)
	}
	removed, err := w.RemoveSecondFactor(ctx, user.ID)
	if err != nil {
		return RemoveSecondFactorOutput{}, ErrStoreUnavailable
	}
	if !removed {
		// Сверка прошла, а строки `active` нет: гонка со сбросом распорядителем.
		_ = w.Rollback(ctx)
		uc.deps.Observer.SecondFactorRefusalObserved(RefusalNotEnrolled)
		return RemoveSecondFactorOutput{}, ErrSecondFactorNotEnrolled
	}
	if _, err := w.EndOtherSessions(ctx, user.ID, resolved.Session.ID, now, domain.RevokeReasonSecondFactorRemoved); err != nil {
		return RemoveSecondFactorOutput{}, ErrStoreUnavailable
	}
	if err := w.PresentInSession(ctx, resolved.Session.ID, methods, level, bearer.Digest(), now); err != nil {
		return RemoveSecondFactorOutput{}, ErrStoreUnavailable
	}
	// Счёт по адресу обнуляет вход, ЗАВЕРШЁННЫЙ до уровня всех заведённых у
	// личности факторов (Ф12 Р7 ред. 11, Ф3 Р10 ред. 11). Сюда путь лежит
	// только через совпавший КОД, доводящий сессию до «2», — но решает это
	// единственный писатель, а не эта полоса.
	if err := resetFailuresOnCompletedLogin(ctx, w, completedLogin{
		Enrolled: enrolled, EnrolledKnown: enrolledKnown,
		AddressKey: addressKey, Presented: methods,
	}); err != nil {
		return RemoveSecondFactorOutput{}, ErrStoreUnavailable
	}
	if err := emitSecondFactorAudit(ctx, w, AuditSecondFactorRemoved, user, resolved.Session.ID, in.Factor.Method); err != nil {
		return RemoveSecondFactorOutput{}, ErrStoreUnavailable
	}
	if err := emitStepUpJournal(ctx, w, user, resolved.Session, in.Factor.Method, level); err != nil {
		return RemoveSecondFactorOutput{}, ErrStoreUnavailable
	}
	if err := w.Commit(ctx); err != nil {
		return RemoveSecondFactorOutput{}, ErrStoreUnavailable
	}
	p.observe(pr, st)
	uc.deps.Observer.SecondFactorEventObserved(SecondFactorRemoved)

	s := resolved.Session
	s.PresentedMethods, s.AssuranceLevel, s.LastPresentedAt = methods, level, now
	out := RemoveSecondFactorOutput{
		View:      SessionView{User: user, Session: s, EmailVerified: resolved.EmailVerified},
		Bearer:    bearer,
		Assurance: assuranceAfter(ctx, uc.deps, user.ID, methods),
	}
	// Снятие убирает фактор целиком: набора запасных кодов больше нет, поэтому
	// ответ несёт `backupCodesRemaining: 0` ВСЕГДА — и при снятии запасным кодом,
	// и при снятии кодом по времени (Р4 ред. 10, Ф12-28, Ф12-45 «а», kaname#275).
	// Остаток `st.remaining` потреблённого набора наружу не выходит: он был бы
	// остатком уже снятого набора и расходился бы с `GET` («не заведён»).
	zero := 0
	out.BackupCodesRemaining = &zero
	return out, nil
}

func (uc *RemoveSecondFactorUseCase) refuse(ctx context.Context, v presentVerdict, addressKey, source string, at time.Time) error {
	if countsAsAttempt(v) {
		if werr := recordFailureTx(ctx, uc.deps.Store, addressKey, source, at); werr != nil {
			uc.deps.Logger.Error("second factor remove: failed attempt not recorded", "err", werr.Error())
		}
	}
	return refusalOf(v)
}
