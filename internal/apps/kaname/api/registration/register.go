// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package registration

// register.go — РЕГИСТРАЦИЯ ПАРОЛЕМ: четыре следствия одним исходом (Ф4-01…05, Р8),
// единый отказ (Ф4-11…13), приглашённый той же полосой (Ф4-23, Ф4-24).
//
// # Порядок внутри глагола — несущий
//
//	форма (поля) → правило пароля (Ф1-32, ДО транзакции) → ХЕШ (всегда до
//	транзакции: занятый и свободный адрес стоят одинаково — Р7) → ОДНА
//	транзакция: зеркало → строка адреса → строка сессии → фиксация (потолок
//	темпа решается триггером на фиксации — Р5) → пост-коммитная материализация
//
// Занятость адреса судит ключ базы внутри транзакции, а не проверка перед ней
// (ban #10): две одновременные регистрации дают ровно одно `ACTIVE` (Ф1-62).
//
// # Отказ — ОДИН (Р3)
//
// «Адрес занят», «приглашение уже активировано», «приглашение истекло»,
// «потолок темпа исчерпан» — наружу уходит один `ErrRefused`; причина
// различима только клеткой счётчика. Отказ хранилища — `ErrStoreUnavailable`:
// глагол не выполнен, состояние не изменено.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

// actorSelfService — актор аудита: человек заводит себя сам, субъекта у него
// до записи нет; то же значение пишет провизион-хук без принципала.
const actorSelfService = "system"

// Input — форма регистрации. Форму (поля, лишние поля) судит транспорт; сюда
// приходят значения.
type Input struct {
	Email    string
	Password string
	// Source — адрес источника, как его прислал допущенный вызывающий.
	Source string
}

// Output — исход успешной регистрации: состав ответа, носитель, лёг ли способ
// входа на строку приглашения (kaname#456, Р11 п. 1: приглашение регистрация
// не активирует — его активирует подтверждение адреса).
type Output struct {
	View    humansession.SessionView
	Bearer  domain.SessionBearer
	Invited bool
}

// Deps — зависимости глагола; все обязательны, кроме наблюдателя, журнала и
// материализации.
type Deps struct {
	Store      Store
	Rule       PasswordJudge
	Hasher     humansession.Hasher
	Lane       Lane
	TTL        time.Duration
	Observer   Observer
	Reconciler OwnerBindingReconciler
	// Letter — пять величин подтверждения адреса (kaname#456, Р7, Р9): письмо
	// подтверждения ставится той же транзакцией, что заводит человека.
	Letter humansession.VerificationPace
	// Sources / SourcePace — окно регистраций одного источника: списывается ДО
	// транзакции одним оператором; сверх окна — единый отказ, ни строки
	// человека, ни письма.
	Sources    humansession.SourcePacer
	SourcePace humansession.SourcePace
	Now        func() time.Time
	Logger     *slog.Logger
}

// RegisterUseCase — регистрация паролем.
type RegisterUseCase struct {
	store      Store
	rule       PasswordJudge
	hasher     humansession.Hasher
	lane       Lane
	ttl        time.Duration
	observer   Observer
	reconciler OwnerBindingReconciler
	letter     humansession.VerificationPace
	sources    humansession.SourcePacer
	sourcePace humansession.SourcePace
	now        func() time.Time
	logger     *slog.Logger
}

// NewRegisterUseCase — построение с проверкой зависимостей и ПОЛОСЫ: глагол
// собирается только для полосы, объявившей все три следствия (Р4). Полоса без
// выдачи сессии не собирается — и гейт дерева называет её раньше, в CI.
func NewRegisterUseCase(d Deps) (*RegisterUseCase, error) {
	switch {
	case d.Store == nil:
		return nil, fmt.Errorf("registration: store required")
	case d.Rule == nil:
		return nil, fmt.Errorf("registration: password rule required")
	case d.Hasher == nil:
		return nil, fmt.Errorf("registration: password hasher required")
	case d.TTL <= 0:
		return nil, fmt.Errorf("registration: session ttl must be positive")
	case d.Lane.Name == "":
		return nil, fmt.Errorf("registration: lane must be named")
	case d.Sources == nil:
		return nil, fmt.Errorf("registration: source pacer required — registration sends a letter, and its pace per source is not optional")
	}
	if err := d.Letter.Validate(); err != nil {
		return nil, fmt.Errorf("registration: %w", err)
	}
	if err := d.SourcePace.Validate(); err != nil {
		return nil, fmt.Errorf("registration: %w", err)
	}
	for _, c := range Consequences() {
		if !d.Lane.Produces(c) {
			return nil, fmt.Errorf("registration: lane %q does not declare consequence %q — every lane "+
				"ends the same way (Ф1-24); declare it in registration.Lanes", d.Lane.Name, c)
		}
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
	return &RegisterUseCase{
		store: d.Store, rule: d.Rule, hasher: d.Hasher, lane: d.Lane, ttl: d.TTL,
		observer: d.Observer, reconciler: d.Reconciler, letter: d.Letter, sources: d.Sources,
		sourcePace: d.SourcePace, now: d.Now, logger: d.Logger,
	}, nil
}

// Execute — регистрация.
func (uc *RegisterUseCase) Execute(ctx context.Context, in Input) (Output, error) {
	addressKey := humansession.AddressKey(in.Email)
	if addressKey == "" {
		return Output{}, humansession.FieldRequired("email")
	}
	if in.Password == "" {
		return Output{}, humansession.FieldRequired("password")
	}
	email := domain.Email(addressKey)
	if err := email.Validate(); err != nil {
		return Output{}, &humansession.FieldError{Field: "email", Rule: "invalid format"}
	}
	// (1) Правило пароля — одно на три полосы, ДО транзакции и до хеша: отказ
	// называет поле и правило (Ф1-32) и состояния не меняет.
	if err := uc.rule.Judge(ctx, addressKey, in.Password); err != nil {
		uc.observer.RegistrationObserved(uc.lane.Name, OutcomeRefusedPassword)
		return Output{}, namedByThisForm(err)
	}
	// (2) Хеш — ВСЕГДА до транзакции: занятый адрес и свободный стоят одинаково
	// (Р7). Отказ хешера — наш, не вызывающего.
	verifier, err := uc.hasher.Hash(in.Password)
	if err != nil {
		uc.logger.Error("registration: password material could not be produced — our hasher, not the caller's input",
			"err", err.Error())
		uc.observer.RegistrationObserved(uc.lane.Name, OutcomeStoreFailed)
		return Output{}, humansession.ErrStoreUnavailable
	}
	now := uc.now().UTC()

	// (2а) Окно регистраций источника — ДО транзакции, одним оператором
	// (kaname#456): регистрация ставит письмо на адрес, который назвал
	// вызывающий без удостоверения, и число таких писем с одного источника
	// ограничено. Сверх окна — тот же единый отказ, без строки человека и без
	// письма. Источник не назван — ось не спрашивается: на живом проводе адрес
	// ставит край всегда (форма оси источника полосы входа).
	if src := strings.TrimSpace(in.Source); src != "" {
		admitted, perr := uc.sources.ChargeSource(ctx, humansession.SourceLaneRegistration, src, now, uc.sourcePace)
		if perr != nil {
			uc.logger.Error("registration: source window not charged — store refused", "err", perr.Error())
			uc.observer.RegistrationObserved(uc.lane.Name, OutcomeStoreFailed)
			return Output{}, humansession.ErrStoreUnavailable
		}
		if !admitted {
			uc.observer.RegistrationObserved(uc.lane.Name, OutcomeRefusedSource)
			return Output{}, ErrRefused
		}
	}

	// (3) Одна транзакция трёх следствий — в объявленном порядке полосы.
	w, err := uc.store.Writer(ctx)
	if err != nil {
		uc.observer.RegistrationObserved(uc.lane.Name, OutcomeStoreFailed)
		return Output{}, humansession.ErrStoreUnavailable
	}
	defer func() { _ = w.Rollback(ctx) }()

	var (
		mirror  MirrorResult
		session domain.HumanSession
		bearer  domain.SessionBearer
	)
	for _, c := range Consequences() {
		if !uc.lane.Produces(c) {
			continue
		}
		switch c {
		case ConsequenceMirror:
			mirror, err = w.Mirror(ctx, MirrorInput{
				Email: email, ExternalID: domain.NewOwnLaneSubject(),
				CandidateUserID: domain.UserID(ids.NewID(domain.PrefixUser)), Actor: actorSelfService,
			})
		case ConsequenceAddress:
			err = w.InsertLoginMethod(ctx, domain.LoginMethod{
				UserID: mirror.User.ID, Kind: domain.LoginMethodPassword, Verifier: verifier,
				State: domain.LoginMethodStateActive,
			})
		case ConsequenceSession:
			session, bearer, err = humansession.IssueSession(ctx, w, humansession.IssueInput{
				User:      mirror.User,
				Presented: []assurance.Presentation{assurance.PasswordPresented()},
				At:        now,
				TTL:       uc.ttl,
				// Своё событие — ниже; выдача его не дублирует (Ф3-47).
				EmitAudit: false,
			})
			if err == nil {
				err = w.EmitAudit(ctx, outboxtypes.AuditEvent{
					EventType:       AuditUserRegistered,
					TenantAccountID: string(mirror.User.AccountID),
					// Без адреса и без имени (гейт `audit_payload_pii`): субъект
					// назван неизменяемым идентификатором.
					Payload: map[string]any{
						"user_id":    string(mirror.User.ID),
						"session_id": string(session.ID),
						"lane":       uc.lane.Name,
						"invited":    mirror.Invited,
					},
				})
			}
			// Письмо подтверждения — ТОЙ ЖЕ транзакцией, что заводит человека
			// (kaname#456, Р9): зарегистрирован ⟹ письмо поставлено. Письмо
			// регистрации идёт в счёт предела писем.
			if err == nil {
				var refusal humansession.LetterRefusal
				refusal, err = humansession.EnqueueVerificationLetter(ctx, w, mirror.User, now, uc.letter)
				if err == nil && refusal.Refused {
					err = fmt.Errorf("registration: verification letter refused by its pace for a person just registered")
				}
			}
		}
		if err != nil {
			return Output{}, uc.refuse(err)
		}
	}
	// (4) Фиксация: потолок темпа заведения решается триггером ЗДЕСЬ — одним
	// оператором базы, отложенным до фиксации (Р5).
	if err := w.Commit(ctx); err != nil {
		return Output{}, uc.refuse(err)
	}

	// (5) Пост-коммитная материализация — не гейтит исход (Р2, ban #9):
	// намерения уже лежат в очереди той же транзакцией, уборка доберёт.
	if uc.reconciler != nil && mirror.OwnerBindingID != "" {
		if rerr := uc.reconciler.ReconcileBinding(ctx, mirror.OwnerBindingID); rerr != nil {
			uc.logger.Error("registration: owner-binding reconcile failed (sweep will retry)",
				"account_id", string(mirror.AccountID), "binding_id", string(mirror.OwnerBindingID), "err", rerr.Error())
		}
	}
	outcome := OutcomeIssued
	if mirror.Invited {
		outcome = OutcomeIssuedInvited
	}
	uc.observer.RegistrationObserved(uc.lane.Name, outcome)
	return Output{
		// Адрес только что заведён и подтверждён быть не может (Ф1-20).
		View:    humansession.SessionView{User: mirror.User, Session: session, EmailVerified: false},
		Bearer:  bearer,
		Invited: mirror.Invited,
	}, nil
}

// registrationPasswordField — имя поля пароля в форме регистрации. Правило одно
// на три полосы и называет поле формы смены пароля; отказ обязан называть поле
// ТОЙ формы, которую заполнял вызывающий (Ф1-32), поэтому имя переводится
// здесь, а второе правило не заводится.
const registrationPasswordField = "password"

func namedByThisForm(err error) error {
	var fe *humansession.FieldError
	if errors.As(err, &fe) && fe.Field == "newPassword" {
		return &humansession.FieldError{Field: registrationPasswordField, Rule: fe.Rule}
	}
	return err
}

// refuse — отказ по сентинелу адаптера: единый отказ регистрации (Р3) либо
// недоступность. Причина — только в клетке счётчика.
//
// Классификация идёт ПО МЕСТУ, а не по одному сентинелу: нарушение уникальности
// из записи ЛИЧНОГО аккаунта (`ErrPersonalAccountNameUnavailable`, вложено в
// `ErrAlreadyExists`) — НЕВЫПОЛНЕНИЕ, а не занятость адреса, поэтому проверяется
// ПЕРВЫМ, до общего `ErrAlreadyExists`. Иначе тот же 23505 из системно-выбранного
// имени ушёл бы в единый отказ занятости (400) и солгал бы о свободном адресе (Р9,
// Р3).
func (uc *RegisterUseCase) refuse(err error) error {
	switch {
	case errors.Is(err, iamerr.ErrPersonalAccountNameUnavailable):
		uc.logger.Error("registration: not performed — personal account name could not be allocated; state unchanged",
			"err", err.Error())
		uc.observer.RegistrationObserved(uc.lane.Name, OutcomeStoreFailed)
		return humansession.ErrStoreUnavailable
	case errors.Is(err, iamerr.ErrAlreadyExists):
		uc.observer.RegistrationObserved(uc.lane.Name, OutcomeRefusedOccupied)
		return ErrRefused
	case errors.Is(err, iamerr.ErrInviteExpired):
		uc.observer.RegistrationObserved(uc.lane.Name, OutcomeRefusedInviteExpired)
		return ErrRefused
	case errors.Is(err, iamerr.ErrQuotaRateExceeded):
		uc.observer.RegistrationObserved(uc.lane.Name, OutcomeRefusedRate)
		return ErrRefused
	default:
		uc.logger.Error("registration: not performed — store refused; state unchanged", "err", err.Error())
		uc.observer.RegistrationObserved(uc.lane.Name, OutcomeStoreFailed)
		return humansession.ErrStoreUnavailable
	}
}
