// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// login.go — ВХОД ПАРОЛЕМ (Ф3-01…05, Ф3-24, Ф3-28…30, Ф3-43; Р2, Р10, Р13).
//
// # Порядок внутри входа — несущий
//
//	частота (обе оси) → строка адреса → ПРОВЕРКА ПАРОЛЯ (всегда, даже когда
//	адреса нет: полоса «адреса нет» занимает ту же ёмкость проверяющего —
//	PWV-15.4) → блокировка → выдача одним исходом → переписывание материала
//	отдельной записью (не смена пароля — ID-PW-1 Р5)
//
// Отказ — ОДИН на все причины (Ф1 Р3): «адреса нет», «пароль не тот»,
// «заблокирована», исходы проверяющего — наружу уходит один и тот же
// ErrAuthenticationFailed; причина различима только приёмником (Ф3-48).
//
// # Второй фактор во входе (Ф12 Р5, Ф12-11…14, Ф12-13)
//
// Поле `secondFactor` необязательно: без него вход даёт «1». С ним код
// сверяется ВСЕГДА после пароля — тем же путём и при несошедшемся пароле, и
// у личности без фактора (холостая сверка), — а исход поля различим только
// после совпавшего пароля: «не заведён» отвечает 400 лишь тому, кто пароль
// знает; всё прочее — тот же один отказ. Запись (принятый шаг, потреблённый
// код) — только при ПОЛНОМ успехе, в транзакции выдачи сессии.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/loginmethod"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

// UserDirectory — чтение человека по адресу (порт над репозиторием зеркала).
type UserDirectory interface {
	// UserByEmail — NOT_FOUND, если адреса нет.
	UserByEmail(ctx context.Context, email domain.Email) (domain.User, error)
}

// Verifier — проверяющий пароля Ф2 (порт по существующему типу).
type Verifier interface {
	Verify(stored domain.LoginVerifier, presented string) passwordverify.Result
	MeetsDeclared(stored domain.LoginVerifier, declared passwordverify.Declared) (bool, error)
}

// Hasher — хешер вновь заводимых значений.
type Hasher interface {
	Hash(password string) (domain.LoginVerifier, error)
	Declared() passwordverify.Declared
}

// LoginInput — форма входа. Форму (поля, лишние поля) судит транспорт; сюда
// приходят значения.
type LoginInput struct {
	Email    string
	Password string
	// Source — адрес источника, как его прислал допущенный вызывающий (Р10).
	Source string
	// SecondFactor — предъявление кода второго фактора (Ф12 Р5); nil — без
	// него, сессия уровня «1».
	SecondFactor *SecondFactorPresentation
}

// SessionView — то, что глагол отдаёт транспорту для ответа (Ф3-01).
type SessionView struct {
	User          domain.User
	Session       domain.HumanSession
	EmailVerified bool
}

// LoginOutput — исход успешного входа: состав ответа и носитель.
type LoginOutput struct {
	View   SessionView
	Bearer domain.SessionBearer
}

// LoginUseCase — вход паролем.
type LoginUseCase struct {
	store     Store
	users     UserDirectory
	methods   loginmethod.Store
	verifier  Verifier
	hasher    Hasher
	limits    Limits
	ttl       time.Duration
	observer  Observer
	now       func() time.Time
	logger    *slog.Logger
	gate      attemptGate
	rewriteOn bool
	// factor — сверка кода второго фактора теми же портами, что глаголы Ф12.
	factor presenter
}

// LoginDeps — зависимости входа; все обязательны, кроме наблюдателя и журнала.
type LoginDeps struct {
	Store    Store
	Users    UserDirectory
	Methods  loginmethod.Store
	Verifier Verifier
	Hasher   Hasher
	Limits   Limits
	TTL      time.Duration
	Observer Observer
	Now      func() time.Time
	Logger   *slog.Logger
	// TOTP и Sets — проверяющие второго фактора (Ф12 Р5, Р6): поле
	// `secondFactor` без них не судится, поэтому оба обязательны.
	TOTP TOTPVerifier
	Sets SetVerifier
}

// NewLoginUseCase — построение с проверкой зависимостей: полоса без любой из
// них не собирается, а не деградирует молча.
func NewLoginUseCase(d LoginDeps) (*LoginUseCase, error) {
	switch {
	case d.Store == nil:
		return nil, fmt.Errorf("login: session store required")
	case d.Users == nil:
		return nil, fmt.Errorf("login: user directory required")
	case d.Methods == nil:
		return nil, fmt.Errorf("login: login method store required")
	case d.Verifier == nil:
		return nil, fmt.Errorf("login: password verifier required")
	case d.Hasher == nil:
		return nil, fmt.Errorf("login: password hasher required")
	case d.TTL <= 0:
		return nil, fmt.Errorf("login: session ttl must be positive")
	case d.TOTP == nil:
		return nil, fmt.Errorf("login: totp verifier required")
	case d.Sets == nil:
		return nil, fmt.Errorf("login: backup code set verifier required")
	}
	if err := d.Limits.Validate(); err != nil {
		return nil, err
	}
	if d.Observer == nil {
		d.Observer = NopObserver{}
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	return &LoginUseCase{
		store: d.Store, users: d.Users, methods: d.Methods, verifier: d.Verifier, hasher: d.Hasher,
		limits: d.Limits, ttl: d.TTL, observer: d.Observer, now: d.Now, logger: d.Logger,
		gate: attemptGate{store: d.Store, limits: d.Limits, now: d.Now, observer: d.Observer}, rewriteOn: true,
		factor: presenter{deps: SecondFactorDeps{
			Store: d.Store, Methods: d.Methods, TOTP: d.TOTP, Sets: d.Sets, Observer: d.Observer, Now: d.Now, Logger: d.Logger,
		}},
	}, nil
}

// Execute — вход.
func (uc *LoginUseCase) Execute(ctx context.Context, in LoginInput) (LoginOutput, error) {
	addressKey := AddressKey(in.Email)
	if addressKey == "" {
		return LoginOutput{}, FieldRequired("email")
	}
	if in.Password == "" {
		return LoginOutput{}, FieldRequired("password")
	}

	// (1) Частота — до всего: отказ по частоте не занимает проверяющего и не
	// считается попыткой.
	if hit, err := uc.gate.check(ctx, addressKey, in.Source); err != nil {
		uc.observer.LoginObserved(LoginOutcomeStoreFailed)
		return LoginOutput{}, ErrStoreUnavailable
	} else if hit != nil {
		uc.observer.LoginObserved(LoginOutcomeRateLimited)
		uc.observer.RateLimitObserved(hit.Scope)
		return LoginOutput{}, hit
	}

	// (2) Строка адреса и материал. Отсутствие того или другого — нулевой
	// материал, который проверяющий сверит с занятой ёмкостью (PWV-15.4).
	user, found, err := uc.lookup(ctx, addressKey)
	if err != nil {
		uc.observer.LoginObserved(LoginOutcomeStoreFailed)
		return LoginOutput{}, ErrStoreUnavailable
	}
	var stored domain.LoginVerifier
	if found {
		m, merr := uc.methods.Get(ctx, user.ID, domain.LoginMethodPassword)
		switch {
		case merr == nil:
			stored = m.Verifier
		case errors.Is(merr, iamerr.ErrNotFound):
			// материала нет — законное состояние, проверяющий ответит своим исходом
		default:
			uc.observer.LoginObserved(LoginOutcomeStoreFailed)
			return LoginOutput{}, ErrStoreUnavailable
		}
	}

	// (3) Проверка — всегда.
	res := uc.verifier.Verify(stored, in.Password)
	now := uc.now().UTC()

	// (3а) Второй фактор — тоже всегда, тем же путём (Ф12-13 «б», «ж»; Ф12-33):
	// у отсутствующей личности и у личности без фактора сверка холостая.
	var factor *preparedPresentation
	if in.SecondFactor != nil {
		pr, perr := uc.factor.prepare(ctx, user.ID, *in.SecondFactor)
		if perr != nil {
			var fe *FieldError
			if errors.As(perr, &fe) {
				return LoginOutput{}, perr
			}
			uc.observer.LoginObserved(LoginOutcomeStoreFailed)
			return LoginOutput{}, ErrStoreUnavailable
		}
		factor = &pr
	}

	switch res.Outcome {
	case passwordverify.OutcomeMatched:
		// проходим дальше
	case passwordverify.OutcomeCapacityExhausted:
		// Преходящий исход: попыткой не считается (PWV-15.3), наружу — тот же
		// отказ.
		uc.observer.LoginObserved(LoginOutcomeCapacity)
		return LoginOutput{}, ErrAuthenticationFailed
	default:
		return LoginOutput{}, uc.refuse(ctx, res.Outcome, found, addressKey, in.Source, now, factor)
	}

	// (4) Блокировка — после проверки, чтобы полоса «заблокирована» стоила то
	// же, что «пароль не тот» (Ф1-05, Ф1-48).
	if !found || user.InviteStatus != domain.InviteStatusActive {
		outcome := LoginOutcomeNoRow
		if found {
			outcome = LoginOutcomeBlocked
		}
		return LoginOutput{}, uc.refuseWith(ctx, outcome, addressKey, in.Source, now, factor)
	}

	// (4а) Пароль сошёлся — исход поля `secondFactor` теперь различим (Р5):
	// состояние и недоступность — своим отказом и не попыткой; несовпадение
	// — тот же один отказ и попытка; совпадение решается ПОД транзакцией выдачи.
	if factor != nil && factor.verdict != verdictMatched {
		return LoginOutput{}, uc.refuseSecondFactor(ctx, *factor, settledPresentation{verdict: factor.verdict, outcome: factor.outcome}, addressKey, in.Source, now)
	}

	// (5) Выдача — одним исходом: запись, память, сброс счёта, событие.
	out, settled, err := uc.issue(ctx, user, now, factor)
	if err != nil {
		uc.observer.LoginObserved(LoginOutcomeStoreFailed)
		return LoginOutput{}, ErrStoreUnavailable
	}
	if factor != nil && settled.verdict != verdictMatched {
		// Второй из двух одновременных (повтор) либо набор не открылся под замком.
		return LoginOutput{}, uc.refuseSecondFactor(ctx, *factor, settled, addressKey, in.Source, now)
	}
	if factor != nil {
		uc.factor.observe(*factor, settled)
	}
	uc.observer.LoginObserved(LoginOutcomeIssued)

	// (6) Переписывание материала при успешной проверке (Ф3-43) — ОТДЕЛЬНОЙ
	// записью после «совпал»: отказ записи входа не пересматривает.
	uc.rewriteIfNeeded(ctx, user, stored, res, in.Password)
	return out, nil
}

func (uc *LoginUseCase) lookup(ctx context.Context, addressKey string) (domain.User, bool, error) {
	user, err := uc.users.UserByEmail(ctx, domain.Email(addressKey))
	if errors.Is(err, iamerr.ErrNotFound) {
		return domain.User{}, false, nil
	}
	if err != nil {
		return domain.User{}, false, err
	}
	return user, true, nil
}

// refuse — отказ по исходу проверяющего: попытка считается на всех исходах,
// кроме преходящего.
func (uc *LoginUseCase) refuse(ctx context.Context, outcome passwordverify.Outcome, found bool, addressKey, source string, now time.Time, factor *preparedPresentation) error {
	observed := LoginOutcomeMismatched
	switch {
	case outcome == passwordverify.OutcomeMaterialMissing && !found:
		observed = LoginOutcomeNoRow
	case outcome == passwordverify.OutcomeMaterialMissing:
		observed = LoginOutcomeMaterialNone
	case outcome.IsOurError():
		observed = LoginOutcomeVerifierIssue
		uc.logger.Error("login: stored password material could not be checked — our data, not the caller's input",
			"outcome", string(outcome))
	}
	return uc.refuseWith(ctx, observed, addressKey, source, now, factor)
}

// refuseWith — отказ с записью попытки. Предъявленный код при несошедшемся
// пароле проходит вторую половину сверки БЕЗ записи (Ф12-13 «б», «ж»): исход
// наружу не выходит и в клетки предъявления не идёт — пароль его не открыл.
func (uc *LoginUseCase) refuseWith(ctx context.Context, observed LoginOutcome, addressKey, source string, now time.Time, factor *preparedPresentation) error {
	uc.observer.LoginObserved(observed)
	w, err := uc.store.Writer(ctx)
	if err != nil {
		uc.observer.LoginObserved(LoginOutcomeStoreFailed)
		return ErrAuthenticationFailed
	}
	defer func() { _ = w.Rollback(ctx) }()
	if factor != nil {
		if _, serr := uc.factor.settle(ctx, w, *factor, false); serr != nil {
			uc.observer.LoginObserved(LoginOutcomeStoreFailed)
			return ErrAuthenticationFailed
		}
	}
	if err := recordFailure(ctx, w, addressKey, source, now); err != nil {
		uc.observer.LoginObserved(LoginOutcomeStoreFailed)
		return ErrAuthenticationFailed
	}
	if err := w.Commit(ctx); err != nil {
		uc.observer.LoginObserved(LoginOutcomeStoreFailed)
	}
	return ErrAuthenticationFailed
}

// refuseSecondFactor — отказ по полю `secondFactor` после совпавшего пароля
// (Р5, Р7): «не сошёлся» и «повторён» — попытка и тот же один отказ; «не
// заведён», «недоступен», «ёмкость» — своим исходом, без попытки.
func (uc *LoginUseCase) refuseSecondFactor(ctx context.Context, pr preparedPresentation, st settledPresentation, addressKey, source string, now time.Time) error {
	uc.factor.observe(pr, st)
	if !countsAsAttempt(st.verdict) {
		uc.observer.LoginObserved(LoginOutcomeSecondFactorRefused)
		return refusalOf(st.verdict)
	}
	return uc.refuseWith(ctx, LoginOutcomeSecondFactorRefused, addressKey, source, now, nil)
}

// issue — выдача одним исходом; с кодом второго фактора — его запись (Р5:
// принятый шаг, потреблённый элемент) в той же транзакции, ДО выдачи, и
// проигравший гонку повтор выдачи не получает.
func (uc *LoginUseCase) issue(ctx context.Context, user domain.User, now time.Time, factor *preparedPresentation) (LoginOutput, settledPresentation, error) {
	var settled settledPresentation
	w, err := uc.store.Writer(ctx)
	if err != nil {
		return LoginOutput{}, settled, err
	}
	defer func() { _ = w.Rollback(ctx) }()
	presented := []assurance.Presentation{assurance.PasswordPresented()}
	if factor != nil {
		settled, err = uc.factor.settle(ctx, w, *factor, true)
		if err != nil {
			return LoginOutput{}, settled, err
		}
		if settled.verdict != verdictMatched {
			return LoginOutput{}, settled, nil
		}
		presented = presentationsOf(withMethod([]string{assurance.MethodPassword.String()}, factor.method))
	}
	s, bearer, err := IssueSession(ctx, w, IssueInput{
		User:      user,
		Presented: presented,
		At:        now,
		TTL:       uc.ttl,
		EmitAudit: true,
	})
	if err != nil {
		return LoginOutput{}, settled, err
	}
	if err := w.ResetFailures(ctx, FailureByAddress, AddressKey(string(user.Email))); err != nil {
		return LoginOutput{}, settled, err
	}
	if err := w.Commit(ctx); err != nil {
		return LoginOutput{}, settled, err
	}
	_, verified, err := uc.methods.EmailVerification(ctx, user.ID)
	if err != nil {
		// Сессия уже выдана; подтверждённость — поле ответа, и его источник не
		// ответил: честнее сказать «не подтверждён», чем не ответить вовсе.
		uc.logger.Error("login: e-mail verification state unreadable after issue", "err", err.Error())
		verified = false
	}
	return LoginOutput{View: SessionView{User: user, Session: s, EmailVerified: verified}, Bearer: bearer}, settled, nil
}

// rewriteIfNeeded — Ф3-43 / ID-PW-1 PWV-08…11, 18, 19. Не смена пароля:
// следствий Ф1 Р4 не вызывает (прочие сессии не трогает, отсечки не пишет).
func (uc *LoginUseCase) rewriteIfNeeded(ctx context.Context, user domain.User, stored domain.LoginVerifier, res passwordverify.Result, password string) {
	if !uc.rewriteOn || stored.IsZero() {
		return
	}
	meets, err := uc.verifier.MeetsDeclared(stored, uc.hasher.Declared())
	if err != nil {
		uc.observer.RewriteObserved(RewriteSkippedUnjudgeable)
		return
	}
	if meets {
		uc.observer.RewriteObserved(RewriteNotNeeded)
		return
	}
	// Границы PWV-19: значение формата A сверяет ТОЛЬКО первые 72 байта и
	// обрывается на нулевом байте; переписанное новым форматом сузило бы
	// множество паролей, которые входили. Пароль в 72 байта (наибольшая длина,
	// которую строит библиотека) и пароль с нулевым байтом не переписываются, и
	// каждое непереписывание сосчитано по причине.
	if res.Format == domain.PasswordHashFormatBcrypt {
		if len(password) >= 72 {
			uc.observer.RewriteObserved(RewriteSkippedLong72)
			return
		}
		if strings.ContainsRune(password, 0) {
			uc.observer.RewriteObserved(RewriteSkippedNulByte)
			return
		}
	}
	fresh, err := uc.hasher.Hash(password)
	if err != nil {
		uc.observer.RewriteObserved(RewriteWriteFailed)
		uc.logger.Error("login: rewrite of the stored material did not happen — hasher refused", "err", err.Error())
		return
	}
	w, err := uc.store.Writer(ctx)
	if err != nil {
		uc.observer.RewriteObserved(RewriteWriteFailed)
		return
	}
	defer func() { _ = w.Rollback(ctx) }()
	replaced, err := w.ReplaceLoginVerifier(ctx, domain.LoginMethod{UserID: user.ID, Kind: domain.LoginMethodPassword, Verifier: fresh, State: domain.LoginMethodStateActive})
	if err != nil || !replaced {
		uc.observer.RewriteObserved(RewriteWriteFailed)
		if err != nil {
			uc.logger.Error("login: rewrite of the stored material did not happen — store refused; next login retries", "err", err.Error())
		}
		return
	}
	if err := w.Commit(ctx); err != nil {
		uc.observer.RewriteObserved(RewriteWriteFailed)
		return
	}
	uc.observer.RewriteObserved(RewriteDone)
}
