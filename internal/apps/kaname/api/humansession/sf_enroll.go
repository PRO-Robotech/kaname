// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// sf_enroll.go — ЗАВЕДЕНИЕ второго фактора: начать (`enroll`) и подтвердить
// первым кодом (`confirm`) — Ф12 Р1, Р2, Р5, Р6, Р8; Ф12-01…05, Ф12-07, Ф12-09,
// Ф12-10.
//
// Оба глагола — правка своих данных (Ф1 §4.1): требуют, чтобы с момента
// последнего предъявления прошло не больше окна свежести (Р8); иначе — отказ
// `SESSION_NOT_FRESH`, называющий следующий шаг (церемонию). Срок
// неподтверждённого заведения — то же окно от момента `enroll`.
//
// `enroll` — ОДИН оператор под ключом «человек, вид»: при `active` — 409, при
// `pending` — замена секрета (человек, потерявший экран, не ждёт истечения),
// при отсутствии — вставка. Секрет показывается ОДИН раз — этим ответом.
//
// `confirm` — ЧЕТЫРЕ записи одним исходом: строка `totp` → `active` с принятым
// шагом (CAS по моменту заведения — из двух одновременных проходит ровно один,
// проигравший получает «уже заведён», как и опоздавший), набор запасных кодов,
// предъявление внутри сессии (множество, уровень, носитель, момент), событие
// аудита и запись журнала повышения.

import (
	"context"
	"fmt"
	"time"

	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	"github.com/PRO-Robotech/kaname/internal/totpverify"
)

// EnrollInput — начать заведение: только сессия (форму судит транспорт).
type EnrollInput struct {
	Bearer domain.SessionBearer
}

// EnrollOutput — секрет и адрес показываются ОДИН раз (Ф12-27).
type EnrollOutput struct {
	Secret     totpverify.Secret
	OtpauthURI string
	// ExpiresAt — момент enroll плюс окно свежести (Р8).
	ExpiresAt time.Time
}

// EnrollSecondFactorUseCase — начать заведение.
type EnrollSecondFactorUseCase struct {
	deps SecondFactorDeps
}

// NewEnrollSecondFactorUseCase — построение с проверкой зависимостей.
func NewEnrollSecondFactorUseCase(d SecondFactorDeps) (*EnrollSecondFactorUseCase, error) {
	d, err := d.validate("second factor enroll")
	if err != nil {
		return nil, err
	}
	return &EnrollSecondFactorUseCase{deps: d}, nil
}

// resolveLiveSession — сессия по носителю (Р16: отсечку читает край до нас);
// «сессии нет» — тот же отказ, что у смены пароля.
func resolveLiveSession(ctx context.Context, d SecondFactorDeps, bearer domain.SessionBearer, now time.Time) (Resolved, error) {
	if bearer.IsZero() {
		return Resolved{}, ErrAuthenticationFailed
	}
	resolved, reason, err := d.Store.Resolve(ctx, bearer.Digest(), now)
	if err != nil {
		return Resolved{}, ErrStoreUnavailable
	}
	if reason != SessionFound {
		d.Observer.NoSessionObserved(reason)
		return Resolved{}, ErrAuthenticationFailed
	}
	return resolved, nil
}

// requireFresh — окно свежести правки своих данных от момента последнего
// предъявления (Ф11 Р6, Р8).
func requireFresh(d SecondFactorDeps, s domain.HumanSession, now time.Time) error {
	if now.Sub(s.LastPresentedAt) > d.Freshness {
		d.Observer.SecondFactorRefusalObserved(RefusalSessionNotFresh)
		return ErrSessionNotFresh
	}
	return nil
}

// Execute — заведение.
func (uc *EnrollSecondFactorUseCase) Execute(ctx context.Context, in EnrollInput) (EnrollOutput, error) {
	now := uc.deps.Now().UTC()
	resolved, err := resolveLiveSession(ctx, uc.deps, in.Bearer, now)
	if err != nil {
		return EnrollOutput{}, err
	}
	if err := requireFresh(uc.deps, resolved.Session, now); err != nil {
		return EnrollOutput{}, err
	}
	// Состояние строки судится оператором заведения (матрица Р4): проверки
	// перед вставкой нет — `active` даёт ноль строк.
	secret, err := totpverify.NewSecret()
	if err != nil {
		uc.deps.Logger.Error("second factor enroll: secret not minted", "err", err.Error())
		return EnrollOutput{}, ErrStoreUnavailable
	}
	wrapped, err := uc.deps.TOTP.Wrap(secret)
	if err != nil {
		uc.deps.Logger.Error("second factor enroll: secret not wrapped", "err", err.Error())
		return EnrollOutput{}, ErrStoreUnavailable
	}
	w, err := uc.deps.Store.Writer(ctx)
	if err != nil {
		return EnrollOutput{}, ErrStoreUnavailable
	}
	defer func() { _ = w.Rollback(ctx) }()
	accepted, err := w.UpsertPendingTOTP(ctx, domain.LoginMethod{
		UserID: resolved.User.ID, Kind: domain.LoginMethodTOTP, Verifier: wrapped,
		State: domain.LoginMethodStatePending, CreatedAt: now,
	})
	if err != nil {
		return EnrollOutput{}, ErrStoreUnavailable
	}
	if !accepted {
		uc.deps.Observer.SecondFactorRefusalObserved(RefusalAlreadyEnrolled)
		return EnrollOutput{}, ErrSecondFactorAlreadyEnrolled
	}
	if err := w.Commit(ctx); err != nil {
		return EnrollOutput{}, ErrStoreUnavailable
	}
	uc.deps.Observer.SecondFactorEventObserved(SecondFactorEnrollmentStarted)
	return EnrollOutput{
		Secret:     secret,
		OtpauthURI: totpverify.OtpauthURI(uc.deps.Domain, string(resolved.User.Email), secret),
		ExpiresAt:  now.Add(uc.deps.Freshness),
	}, nil
}

// ConfirmInput — подтвердить заведение первым кодом.
type ConfirmInput struct {
	Bearer domain.SessionBearer
	Code   string
	Source string
}

// ConfirmOutput — коды показываются ОДИН раз; ответ — как у церемонии.
type ConfirmOutput struct {
	View        SessionView
	Bearer      domain.SessionBearer
	BackupCodes []string
	Assurance   AssuranceView
}

// ConfirmSecondFactorUseCase — подтвердить заведение.
type ConfirmSecondFactorUseCase struct {
	deps SecondFactorDeps
	gate attemptGate
}

// NewConfirmSecondFactorUseCase — построение с проверкой зависимостей.
func NewConfirmSecondFactorUseCase(d SecondFactorDeps) (*ConfirmSecondFactorUseCase, error) {
	d, err := d.validate("second factor confirm")
	if err != nil {
		return nil, err
	}
	return &ConfirmSecondFactorUseCase{deps: d, gate: d.gate()}, nil
}

// Execute — подтверждение. Порядок: сессия → свежесть → частота → состояние
// (матрица) → срок → сверка → четыре записи одним исходом.
func (uc *ConfirmSecondFactorUseCase) Execute(ctx context.Context, in ConfirmInput) (ConfirmOutput, error) {
	if in.Code == "" {
		return ConfirmOutput{}, FieldRequired("code")
	}
	if !totpverify.IsWellFormedCode(in.Code) {
		return ConfirmOutput{}, &FieldError{Field: "code", Rule: fmt.Sprintf("must be %d digits", totpverify.Digits)}
	}
	now := uc.deps.Now().UTC()
	resolved, err := resolveLiveSession(ctx, uc.deps, in.Bearer, now)
	if err != nil {
		return ConfirmOutput{}, err
	}
	if err := requireFresh(uc.deps, resolved.Session, now); err != nil {
		return ConfirmOutput{}, err
	}
	user := resolved.User
	addressKey := AddressKey(string(user.Email))
	if hit, err := uc.gate.check(ctx, addressKey, in.Source); err != nil {
		return ConfirmOutput{}, ErrStoreUnavailable
	} else if hit != nil {
		uc.deps.Observer.RateLimitObserved(hit.Scope)
		return ConfirmOutput{}, hit
	}

	// Состояние и срок — раньше кода; код при них не сверяется (Р4, Р7).
	row, found, err := factorState(ctx, uc.deps.Methods, user.ID)
	if err != nil {
		return ConfirmOutput{}, ErrStoreUnavailable
	}
	switch {
	case found && row.Enrolled():
		uc.deps.Observer.SecondFactorRefusalObserved(RefusalAlreadyEnrolled)
		return ConfirmOutput{}, ErrSecondFactorAlreadyEnrolled
	case !found, now.Sub(row.CreatedAt) > uc.deps.Freshness:
		// Не начато, истекло, снято уборкой — снаружи неразличимы (Ф12-04).
		uc.deps.Observer.SecondFactorRefusalObserved(RefusalEnrollmentNotPending)
		return ConfirmOutput{}, ErrEnrollmentNotPending
	}

	res := uc.deps.TOTP.Verify(row.Verifier, totpverify.NoAcceptedStep(), in.Code, now)
	switch res.Outcome {
	case totpverify.OutcomeMatched:
	case totpverify.OutcomeMaterialUnreadable:
		uc.deps.Observer.SecondFactorPresentationObserved(assurance.MethodTOTP, PresentationMaterialUnreadable)
		uc.deps.Observer.SecondFactorRefusalObserved(RefusalUnavailable)
		return ConfirmOutput{}, ErrSecondFactorUnavailable
	default:
		uc.deps.Observer.SecondFactorPresentationObserved(assurance.MethodTOTP, PresentationMismatched)
		if werr := uc.recordFailure(ctx, addressKey, in.Source, now); werr != nil {
			uc.deps.Logger.Error("second factor confirm: failed attempt not recorded", "err", werr.Error())
		}
		return ConfirmOutput{}, ErrAuthenticationFailed
	}

	codes, err := passwordverify.NewBackupCodes()
	if err != nil {
		uc.deps.Logger.Error("second factor confirm: backup codes not minted", "err", err.Error())
		return ConfirmOutput{}, ErrStoreUnavailable
	}
	set, err := uc.deps.SetHasher.HashSet(codes)
	if err != nil {
		uc.deps.Logger.Error("second factor confirm: backup code set not hashed", "err", err.Error())
		return ConfirmOutput{}, ErrStoreUnavailable
	}
	bearer, err := domain.NewSessionBearer()
	if err != nil {
		return ConfirmOutput{}, ErrStoreUnavailable
	}
	methods := withMethod(resolved.Session.PresentedMethods, assurance.MethodTOTP)
	level, err := levelOf(methods)
	if err != nil {
		uc.deps.Logger.Error("second factor confirm: level not derived", "err", err.Error())
		return ConfirmOutput{}, ErrStoreUnavailable
	}

	w, err := uc.deps.Store.Writer(ctx)
	if err != nil {
		return ConfirmOutput{}, ErrStoreUnavailable
	}
	defer func() { _ = w.Rollback(ctx) }()
	activated, err := w.ActivateTOTP(ctx, user.ID, row.CreatedAt, res.Step, now)
	if err != nil {
		return ConfirmOutput{}, ErrStoreUnavailable
	}
	if !activated {
		// Проигравший гонку: заведение того момента уже подтверждено (либо
		// заменено новым). Отвечаем по СОСТОЯНИЮ, как опоздавшему (Ф12-07).
		_ = w.Rollback(ctx)
		cur, found, rerr := factorState(ctx, uc.deps.Methods, user.ID)
		if rerr != nil {
			return ConfirmOutput{}, ErrStoreUnavailable
		}
		if found && cur.Enrolled() {
			uc.deps.Observer.SecondFactorRefusalObserved(RefusalAlreadyEnrolled)
			return ConfirmOutput{}, ErrSecondFactorAlreadyEnrolled
		}
		uc.deps.Observer.SecondFactorRefusalObserved(RefusalEnrollmentNotPending)
		return ConfirmOutput{}, ErrEnrollmentNotPending
	}
	if err := w.ReplaceLookupSet(ctx, domain.LoginMethod{
		UserID: user.ID, Kind: domain.LoginMethodLookupSecret, Verifier: set,
		State: domain.LoginMethodStateActive, CreatedAt: now,
	}); err != nil {
		return ConfirmOutput{}, ErrStoreUnavailable
	}
	if err := w.PresentInSession(ctx, resolved.Session.ID, methods, level, bearer.Digest(), now); err != nil {
		return ConfirmOutput{}, ErrStoreUnavailable
	}
	if err := w.ResetFailures(ctx, FailureByAddress, addressKey); err != nil {
		return ConfirmOutput{}, ErrStoreUnavailable
	}
	if err := emitSecondFactorAudit(ctx, w, AuditSecondFactorEnrolled, user, resolved.Session.ID, assurance.MethodTOTP); err != nil {
		return ConfirmOutput{}, ErrStoreUnavailable
	}
	if err := emitStepUpJournal(ctx, w, user, resolved.Session, assurance.MethodTOTP, level); err != nil {
		return ConfirmOutput{}, ErrStoreUnavailable
	}
	if err := w.Commit(ctx); err != nil {
		return ConfirmOutput{}, ErrStoreUnavailable
	}
	uc.deps.Observer.SecondFactorPresentationObserved(assurance.MethodTOTP, PresentationMatched)
	uc.deps.Observer.SecondFactorEventObserved(SecondFactorEnrollmentConfirmed)

	s := resolved.Session
	s.PresentedMethods, s.AssuranceLevel, s.LastPresentedAt = methods, level, now
	return ConfirmOutput{
		View:        SessionView{User: user, Session: s, EmailVerified: resolved.EmailVerified},
		Bearer:      bearer,
		BackupCodes: codes,
		Assurance:   assuranceAfter(ctx, uc.deps, user.ID, methods),
	}, nil
}

// assuranceAfter — вид `assurance` после зафиксированного предъявления:
// заведённые способы читаются заново. Отказ чтения — журнал и вид без пути к
// «2»: ответ уже выдан, лгать о достижимости нельзя, честнее назвать неизвестное.
func assuranceAfter(ctx context.Context, d SecondFactorDeps, userID domain.UserID, presented []string) AssuranceView {
	enrolled, err := enrolledMethods(ctx, d.Methods, userID)
	if err != nil {
		d.Logger.Error("second factor: enrolled methods unreadable after commit", "err", err.Error())
	}
	return assuranceViewOf(presented, enrolled)
}

func (uc *ConfirmSecondFactorUseCase) recordFailure(ctx context.Context, addressKey, source string, at time.Time) error {
	return recordFailureTx(ctx, uc.deps.Store, addressKey, source, at)
}

// recordFailureTx — след неверного предъявления своей транзакцией.
func recordFailureTx(ctx context.Context, store Store, addressKey, source string, at time.Time) error {
	w, err := store.Writer(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = w.Rollback(ctx) }()
	if err := recordFailure(ctx, w, addressKey, source, at); err != nil {
		return err
	}
	return w.Commit(ctx)
}

// emitSecondFactorAudit — событие второго фактора той же транзакцией (Р11):
// субъект, сессия, способ; ни адреса, ни имени, ни секрета, ни кодов.
func emitSecondFactorAudit(ctx context.Context, w Writer, eventType string, user domain.User, session domain.HumanSessionID, method assurance.Method) error {
	return w.EmitAudit(ctx, outboxtypes.AuditEvent{
		EventType:       eventType,
		TenantAccountID: string(user.AccountID),
		Payload: map[string]any{
			"user_id":    string(user.ID),
			"session_id": string(session),
			"method":     method.String(),
		},
	})
}

// stepUpOutcome — исход предъявления в записи журнала повышения (Ф11-14):
// поле `outcome` записи ОДНОГО вида `iam.session.step_up`, закрытый перечень
// из двух значений. Второго вида события на отказ не заводится: потребитель
// журнала читал бы два вида об одном предмете.
type stepUpOutcome string

const (
	// stepUpAccepted — предъявление принято и записано вместе с записью журнала.
	stepUpAccepted stepUpOutcome = "accepted"
	// stepUpRefused — суждённое предъявление отклонено; уровень не менялся.
	stepUpRefused stepUpOutcome = "refused"
)

// emitStepUpJournal — запись журнала повышения о ПРИНЯТОМ предъявлении
// (Ф11-14): способ, уровень до и после, исход `accepted` — той же
// транзакцией, что предъявление.
func emitStepUpJournal(ctx context.Context, w Writer, user domain.User, before domain.HumanSession, method assurance.Method, after string) error {
	return emitStepUpRecord(ctx, w, user, before, method, after, stepUpAccepted)
}

// emitStepUpRefusal — запись журнала повышения об ОТКЛОНЁННОМ суждённом
// предъявлении (Ф11-14): отказ сессию не понижает и не повышает (Ф11-13,
// Ф11-30), поэтому уровень до и после — уровень сессии; исход `refused`.
func emitStepUpRefusal(ctx context.Context, w Writer, user domain.User, session domain.HumanSession, method assurance.Method) error {
	return emitStepUpRecord(ctx, w, user, session, method, session.AssuranceLevel, stepUpRefused)
}

// emitStepUpRecord — одна форма записи журнала повышения на оба исхода:
// субъект, сессия, способ из словаря Р8, уровень до и после, исход. Ни
// секрета предъявления, ни значения носителя, ни его дайджеста.
func emitStepUpRecord(ctx context.Context, w Writer, user domain.User, before domain.HumanSession, method assurance.Method, after string, outcome stepUpOutcome) error {
	return w.EmitAudit(ctx, outboxtypes.AuditEvent{
		EventType:       AuditSessionStepUp,
		TenantAccountID: string(user.AccountID),
		Payload: map[string]any{
			"user_id":      string(user.ID),
			"session_id":   string(before.ID),
			"method":       method.String(),
			"level_before": before.AssuranceLevel,
			"level_after":  after,
			"outcome":      string(outcome),
		},
	})
}
