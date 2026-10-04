// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// verification.go — ПОДТВЕРЖДЕНИЕ АДРЕСА: запрос письма и предъявление кода под
// сессией человека (задача PRO-Robotech/kaname#456; приёмка
// `docs/engineering/acceptance/access-beyond-login-needs-a-verified-address.md`,
// решения Р6–Р10, Р15).
//
// # Два обращения, оба под сессией, адреса в теле нет (Р6)
//
// Подтверждает тот, кто И предъявил пароль, И владеет ящиком: код без сессии
// этого человека не подтверждает ничего. Адрес берётся из строки человека,
// которому принадлежит сессия, а не из формы.
//
// # Порядок суждения предъявления — несущий (Р6)
//
//	сессия · подтверждён ли уже адрес · форма (`code: required`) · код ·
//	приглашение
//
// Суждение о приглашении получает только тот, у кого есть и сессия, и
// подошедший код; отказ по приглашению попытку кода не тратит — исход
// откатывается целиком.
//
// # Исход подтверждения — одна транзакция (Р10)
//
// Отметка — момент этого подтверждения; новый носитель той же сессии; прочие
// сессии человека сняты причиной `email-verified`; событие
// `iam.user.email_verified` без адреса; активация приглашения, если строка
// человека — приглашение. Транзакция открыта замком писателя нескольких сессий
// на строке человека, и этим же замком сериализованы запросы письма одного
// человека: решение о пределе писем и запись строки кода — один условный
// оператор под этим замком (Р9, ban #10).

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/admission"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

// Тексты и признаки отказов глагола подтверждения (Р3, Р6, Р11, Р15) —
// контракт полосы.
const (
	// TextEmailNotVerified — отказ положения подтверждения: одно значение на
	// полосе формы и на обоих слушателях (Р3).
	TextEmailNotVerified = admission.TextNotVerified
	// ReasonEmailNotVerified — машинный признак отказа положения.
	ReasonEmailNotVerified = admission.ReasonNotVerified
	// TextEmailAlreadyVerified — глагол подтверждения у подтверждённого (Р15).
	TextEmailAlreadyVerified = "email address is already verified"
	// ReasonEmailAlreadyVerified — машинный признак того же отказа.
	ReasonEmailAlreadyVerified = "EMAIL_ALREADY_VERIFIED"
	// TextInviteNotValid — код подошёл, приглашение приглашённого негодно
	// (Р11 п. 4).
	TextInviteNotValid = "invite is no longer valid; ask an account administrator to invite again"
	// ReasonInviteNotValid — машинный признак того же отказа.
	ReasonInviteNotValid = "INVITE_NOT_VALID"
)

// AuditEmailVerified — событие исхода подтверждения (Р10 п. 4): нагрузка
// `{user_id, session_id}`, адреса нет.
const AuditEmailVerified = "iam.user.email_verified"

// verificationCodeIDPrefix — приставка идентификатора строки кода. Наружу не
// адресуется; в платформенный каталог приставок не входит.
const verificationCodeIDPrefix = "evc"

var (
	// ErrEmailNotVerified — отказ положения подтверждения (Р3).
	ErrEmailNotVerified = errors.New(TextEmailNotVerified)
	// ErrEmailAlreadyVerified — глагол подтверждения у подтверждённого (Р15).
	ErrEmailAlreadyVerified = errors.New(TextEmailAlreadyVerified)
	// ErrInviteNotValid — приглашение приглашённого истекло либо снято (Р11 п. 4).
	ErrInviteNotValid = errors.New(TextInviteNotValid)
)

// VerificationPace — пять величин Р7 и Р9. Незаданная — отказ построения: страж
// старта отказывает раньше, здесь — чтобы глагол, собранный мимо него, не
// поднялся.
type VerificationPace struct {
	// CodeTTL — срок кода от выдачи письма.
	CodeTTL time.Duration
	// Attempts — неподошедших предъявлений на код; столько тратит код.
	Attempts int
	// Interval — наименьший промежуток между двумя письмами одного человека.
	Interval time.Duration
	// Limit — писем одному человеку за окно, письмо регистрации в счёт.
	Limit int
	// Window — скользящее окно числа писем.
	Window time.Duration
}

// Validate — все пять положительны, промежуток короче окна.
func (p VerificationPace) Validate() error {
	switch {
	case p.CodeTTL <= 0:
		return fmt.Errorf("verification: code ttl must be positive")
	case p.Attempts <= 0:
		return fmt.Errorf("verification: attempts per code must be positive")
	case p.Interval <= 0:
		return fmt.Errorf("verification: resend interval must be positive")
	case p.Limit <= 0:
		return fmt.Errorf("verification: resend limit must be positive")
	case p.Window <= 0:
		return fmt.Errorf("verification: resend window must be positive")
	case p.Interval >= p.Window:
		return fmt.Errorf("verification: resend interval must be shorter than the resend window")
	}
	return nil
}

// VerificationMailIntent — намерение отправить письмо подтверждения: пишется той
// же транзакцией, что строка кода (Р8). Код уходит в письмо своей формой для
// человека — единственным своим выходом к нему.
type VerificationMailIntent struct {
	UserID    domain.UserID
	AccountID domain.AccountID
	To        string
	Code      domain.VerificationCodeValue
	// ValidFor — срок кода, как его назовёт письмо.
	ValidFor time.Duration
}

// LetterRefusal — почему письмо не поставлено пределом Р9; RetryAfter — до
// ближайшего разрешённого момента. Нулевое значение — письмо поставлено.
type LetterRefusal struct {
	Refused    bool
	RetryAfter time.Duration
}

// VerificationLetterWriter — операторы строки кода и письма подтверждения на
// транзакции вызывающего. Их зовут двое: регистрация (письмо той же
// транзакцией, что заводит человека, — Р9) и запрос письма.
type VerificationLetterWriter interface {
	// SupersedeVerificationCodes — неприменённые живые коды человека
	// вытеснены: живой код у человека один (Р7).
	SupersedeVerificationCodes(ctx context.Context, userID domain.UserID, at time.Time) (int, error)
	// InsertVerificationCodePaced — строка кода, ЕСЛИ предел писем Р9 это
	// позволяет: решение и запись — один условный оператор. Отказ предела —
	// LetterRefusal.Refused, строки нет.
	InsertVerificationCodePaced(ctx context.Context, c domain.VerificationCode, pace VerificationPace) (LetterRefusal, error)
	// EmitVerificationMail — намерение письма той же транзакцией (Р8).
	EmitVerificationMail(ctx context.Context, in VerificationMailIntent) error
}

// PresentedCode — исход предъявления кода одним оператором.
type PresentedCode int

const (
	// CodeNotFound — живого кода у человека нет, он истёк, вытеснен, применён,
	// истрачен пределом попыток либо выдан другому значению адреса.
	CodeNotFound PresentedCode = iota
	// CodeMismatched — живой код есть, значение не то; попытка засчитана.
	CodeMismatched
	// CodeExhausted — значение не то, и эта попытка истратила код пределом:
	// дальше он не подходит и верным значением.
	CodeExhausted
	// CodeMatched — значение подошло; строка получила отметку применения.
	CodeMatched
)

// VerificationWriter — транзакция исхода подтверждения. Открывается замком
// писателя нескольких сессий на строке человека.
type VerificationWriter interface {
	Writer
	VerificationLetterWriter
	// PresentVerificationCode — ОДИН оператор: счёт попытки и сверка свёртки не
	// разнесены чтением и записью (Р7); код ищется по человеку сессии, а не по
	// свёртке глобально. Адрес, на который выдан код, возвращается при
	// совпадении.
	PresentVerificationCode(ctx context.Context, userID domain.UserID, digest domain.CodeDigest, now time.Time, attempts int) (PresentedCode, domain.Email, error)
	// MarkEmailVerified — отметка на подтверждённое значение адреса: сверка
	// адреса и запись — один оператор. marked=false — адрес строки уже не тот.
	MarkEmailVerified(ctx context.Context, userID domain.UserID, email domain.Email, at time.Time) (marked bool, err error)
	// ActivateInviteOnVerification — активация приглашения, личность и личные
	// ресурсы тем же исходом (Р11 п. 2). ErrInviteNotValid — приглашение
	// истекло либо снято.
	ActivateInviteOnVerification(ctx context.Context, pending domain.User) (InviteActivation, error)
}

// InviteActivation — исход активации приглашения в исходе подтверждения.
type InviteActivation struct {
	User domain.User
	// OwnerBindingID — собственническая выдача личного аккаунта: её
	// материализует пост-коммитный согласователь.
	OwnerBindingID domain.AccessBindingID
}

// VerificationStore — хранилище глагола подтверждения.
type VerificationStore interface {
	// Resolve — запись сессии по дайджесту носителя (тот же вопрос, что у
	// ответа краю).
	Resolve(ctx context.Context, digest domain.BearerDigest, now time.Time) (Resolved, NoSessionReason, error)
	// VerificationWriter — транзакция, ПЕРВЫМ оператором которой взята строка
	// человека замком писателя нескольких сессий.
	VerificationWriter(ctx context.Context, userID domain.UserID) (VerificationWriter, error)
}

// VerificationOutcome — исход глаголов подтверждения и отказов положения.
// Перечень ЗАКРЫТ: клетки заводятся нулём до первого события.
type VerificationOutcome string

const (
	VerificationLetterQueued        VerificationOutcome = "letter-queued"
	VerificationLetterPaced         VerificationOutcome = "letter-paced"
	VerificationAlreadyVerified     VerificationOutcome = "already-verified"
	VerificationNoSession           VerificationOutcome = "no-session"
	VerificationConfirmed           VerificationOutcome = "confirmed"
	VerificationCodeMismatched      VerificationOutcome = "code-mismatched"
	VerificationCodeNotFound        VerificationOutcome = "code-not-found"
	VerificationCodeExhausted       VerificationOutcome = "code-exhausted"
	VerificationInviteNotValid      VerificationOutcome = "invite-not-valid"
	VerificationStoreFailed         VerificationOutcome = "store-failed"
	VerificationPositionRefusedLane VerificationOutcome = "position-refused-lane"
	// VerificationPositionRefusedListener — отказ положения на слушателях gRPC
	// службы (рубеж Р4б, Р4в).
	VerificationPositionRefusedListener VerificationOutcome = "position-refused-listener"
)

// VerificationOutcomes — закрытый перечень.
func VerificationOutcomes() []VerificationOutcome {
	return []VerificationOutcome{
		VerificationLetterQueued, VerificationLetterPaced, VerificationAlreadyVerified, VerificationNoSession,
		VerificationConfirmed, VerificationCodeMismatched, VerificationCodeNotFound, VerificationCodeExhausted,
		VerificationInviteNotValid,
		VerificationStoreFailed, VerificationPositionRefusedLane, VerificationPositionRefusedListener,
	}
}

// AddressVerificationObserver — приёмник исходов подтверждения. Дёшев и ничего не
// возвращает; адреса и кода не получает по построению.
type AddressVerificationObserver interface {
	AddressVerificationObserved(VerificationOutcome)
}

// AddressVerificationObserved — см. порт.
func (NopObserver) AddressVerificationObserved(VerificationOutcome) {}

// OwnerBindingReconciler — пост-коммитная материализация собственнической
// выдачи личного аккаунта, заведённого активацией. nil — материализует уборка
// по намерениям, лежащим в очереди той же транзакцией.
type OwnerBindingReconciler interface {
	ReconcileBinding(ctx context.Context, id domain.AccessBindingID) error
}

// EnqueueVerificationLetter — ЕДИНСТВЕННЫЙ производитель письма подтверждения:
// вытеснить прежние коды, записать новый под пределом Р9, положить намерение
// письма — на транзакции вызывающего. Зовут регистрация и запрос письма.
func EnqueueVerificationLetter(ctx context.Context, w VerificationLetterWriter, user domain.User, at time.Time, pace VerificationPace) (LetterRefusal, error) {
	value, err := domain.NewVerificationCodeValue()
	if err != nil {
		return LetterRefusal{}, fmt.Errorf("verification letter: code not minted: %w", err)
	}
	code := domain.VerificationCode{
		ID:     domain.VerificationCodeID(ids.NewHyphenID(verificationCodeIDPrefix)),
		UserID: user.ID, Email: domain.Email(AddressKey(string(user.Email))), Digest: value.Digest(),
		IssuedAt: at, ExpiresAt: at.Add(pace.CodeTTL),
	}
	if _, err := w.SupersedeVerificationCodes(ctx, user.ID, at); err != nil {
		return LetterRefusal{}, err
	}
	refusal, err := w.InsertVerificationCodePaced(ctx, code, pace)
	if err != nil || refusal.Refused {
		return refusal, err
	}
	if err := w.EmitVerificationMail(ctx, VerificationMailIntent{
		UserID: user.ID, AccountID: user.AccountID, To: string(user.Email), Code: value, ValidFor: pace.CodeTTL,
	}); err != nil {
		return LetterRefusal{}, err
	}
	return LetterRefusal{}, nil
}

// VerificationDeps — зависимости глаголов подтверждения.
type VerificationDeps struct {
	Store      VerificationStore
	Pace       VerificationPace
	Observer   AddressVerificationObserver
	Reconciler OwnerBindingReconciler
	Now        func() time.Time
	Logger     *slog.Logger
}

func (d VerificationDeps) complete() (VerificationDeps, error) {
	if d.Store == nil {
		return d, fmt.Errorf("verification: store required")
	}
	if err := d.Pace.Validate(); err != nil {
		return d, err
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
	return d, nil
}

// resolveForVerification — первая ступень порядка суждения: сессия и её
// отметка. Сессии нет — ErrAuthenticationFailed; адрес подтверждён —
// ErrEmailAlreadyVerified.
func resolveForVerification(ctx context.Context, d VerificationDeps, bearer domain.SessionBearer, now time.Time) (Resolved, error) {
	if bearer.IsZero() {
		d.Observer.AddressVerificationObserved(VerificationNoSession)
		return Resolved{}, ErrAuthenticationFailed
	}
	resolved, reason, err := d.Store.Resolve(ctx, bearer.Digest(), now)
	if err != nil {
		d.Observer.AddressVerificationObserved(VerificationStoreFailed)
		return Resolved{}, ErrStoreUnavailable
	}
	if reason != SessionFound {
		d.Observer.AddressVerificationObserved(VerificationNoSession)
		return Resolved{}, ErrAuthenticationFailed
	}
	if resolved.EmailVerified {
		d.Observer.AddressVerificationObserved(VerificationAlreadyVerified)
		return Resolved{}, ErrEmailAlreadyVerified
	}
	return resolved, nil
}

// RequestVerificationUseCase — запрос письма подтверждения (Р6, Р9).
type RequestVerificationUseCase struct{ d VerificationDeps }

// NewRequestVerificationUseCase — построение с проверкой зависимостей.
func NewRequestVerificationUseCase(d VerificationDeps) (*RequestVerificationUseCase, error) {
	d, err := d.complete()
	if err != nil {
		return nil, err
	}
	return &RequestVerificationUseCase{d: d}, nil
}

// RequestVerificationOutput — исход поставленного письма: промежуток до
// следующего разрешённого письма (консоль ведёт отсчёт по нему).
type RequestVerificationOutput struct {
	NextAllowedIn time.Duration
}

// Execute — запрос письма.
func (uc *RequestVerificationUseCase) Execute(ctx context.Context, bearer domain.SessionBearer) (RequestVerificationOutput, error) {
	now := uc.d.Now().UTC()
	resolved, err := resolveForVerification(ctx, uc.d, bearer, now)
	if err != nil {
		return RequestVerificationOutput{}, err
	}
	w, err := uc.d.Store.VerificationWriter(ctx, resolved.User.ID)
	if err != nil {
		uc.d.Observer.AddressVerificationObserved(VerificationStoreFailed)
		return RequestVerificationOutput{}, ErrStoreUnavailable
	}
	defer func() { _ = w.Rollback(ctx) }()
	refusal, err := EnqueueVerificationLetter(ctx, w, resolved.User, now, uc.d.Pace)
	if err != nil {
		uc.d.Observer.AddressVerificationObserved(VerificationStoreFailed)
		uc.d.Logger.Error("verification request: letter not recorded", "err", err.Error(), "user_id", string(resolved.User.ID))
		return RequestVerificationOutput{}, ErrStoreUnavailable
	}
	if refusal.Refused {
		uc.d.Observer.AddressVerificationObserved(VerificationLetterPaced)
		return RequestVerificationOutput{}, &TooManyAttemptsError{Scope: FailureByAddress, RetryAfter: refusal.RetryAfter}
	}
	if err := w.Commit(ctx); err != nil {
		uc.d.Observer.AddressVerificationObserved(VerificationStoreFailed)
		return RequestVerificationOutput{}, ErrStoreUnavailable
	}
	uc.d.Observer.AddressVerificationObserved(VerificationLetterQueued)
	return RequestVerificationOutput{NextAllowedIn: uc.d.Pace.Interval}, nil
}

// ConfirmVerificationInput — предъявление кода.
type ConfirmVerificationInput struct {
	Bearer domain.SessionBearer
	Code   string
}

// ConfirmVerificationOutput — исход подтверждения: состав ответа и новый
// носитель той же сессии.
type ConfirmVerificationOutput struct {
	View   SessionView
	Bearer domain.SessionBearer
}

// ConfirmVerificationUseCase — предъявление кода (Р6, Р7, Р10, Р11).
type ConfirmVerificationUseCase struct{ d VerificationDeps }

// NewConfirmVerificationUseCase — построение с проверкой зависимостей.
func NewConfirmVerificationUseCase(d VerificationDeps) (*ConfirmVerificationUseCase, error) {
	d, err := d.complete()
	if err != nil {
		return nil, err
	}
	return &ConfirmVerificationUseCase{d: d}, nil
}

// Execute — предъявление кода.
func (uc *ConfirmVerificationUseCase) Execute(ctx context.Context, in ConfirmVerificationInput) (ConfirmVerificationOutput, error) {
	now := uc.d.Now().UTC()
	resolved, err := resolveForVerification(ctx, uc.d, in.Bearer, now)
	if err != nil {
		return ConfirmVerificationOutput{}, err
	}
	presented := domain.PresentedVerificationCode(in.Code)
	if presented.IsZero() {
		return ConfirmVerificationOutput{}, FieldRequired("code")
	}
	bearer, err := domain.NewSessionBearer()
	if err != nil {
		return ConfirmVerificationOutput{}, ErrStoreUnavailable
	}
	user := resolved.User

	// Транзакция исхода пишет строку человека — отметку и активацию
	// приглашения, — а значит и ресурсный журнал, чья строка без инициатора
	// базой не принимается (NTF-3, Р2). Изменение начинает человек, чья
	// сессия, удостоверенная носителем выше, предъявила код: он и инициатор.
	// Принципал ставится только на открытие транзакции — прочие операторы
	// идут на контексте вызова.
	w, err := uc.d.Store.VerificationWriter(
		operations.WithPrincipal(ctx, operations.Principal{Type: domain.PrincipalTypeUser, ID: string(user.ID)}), user.ID)
	if err != nil {
		uc.d.Observer.AddressVerificationObserved(VerificationStoreFailed)
		return ConfirmVerificationOutput{}, ErrStoreUnavailable
	}
	defer func() { _ = w.Rollback(ctx) }()

	outcome, email, err := w.PresentVerificationCode(ctx, user.ID, presented.Digest(), now, uc.d.Pace.Attempts)
	if err != nil {
		uc.d.Observer.AddressVerificationObserved(VerificationStoreFailed)
		return ConfirmVerificationOutput{}, ErrStoreUnavailable
	}
	switch outcome {
	case CodeMismatched, CodeExhausted:
		// Попытка засчитана оператором предъявления и фиксируется: предел
		// попыток — свойство кода, а не запроса.
		if err := w.Commit(ctx); err != nil {
			uc.d.Observer.AddressVerificationObserved(VerificationStoreFailed)
			return ConfirmVerificationOutput{}, ErrStoreUnavailable
		}
		cell := VerificationCodeMismatched
		if outcome == CodeExhausted {
			cell = VerificationCodeExhausted
		}
		uc.d.Observer.AddressVerificationObserved(cell)
		return ConfirmVerificationOutput{}, ErrAuthenticationFailed
	case CodeMatched:
	default:
		uc.d.Observer.AddressVerificationObserved(VerificationCodeNotFound)
		return ConfirmVerificationOutput{}, ErrAuthenticationFailed
	}

	// (1) Отметка — момент этого подтверждения, на значение адреса, на которое
	// выдан код.
	marked, err := w.MarkEmailVerified(ctx, user.ID, email, now)
	if err != nil {
		uc.d.Observer.AddressVerificationObserved(VerificationStoreFailed)
		return ConfirmVerificationOutput{}, ErrStoreUnavailable
	}
	if !marked {
		// Адрес строки сменился после выдачи кода: код не подходит (Р7).
		uc.d.Observer.AddressVerificationObserved(VerificationCodeNotFound)
		return ConfirmVerificationOutput{}, ErrAuthenticationFailed
	}
	// (2) Новый носитель той же сессии.
	if err := w.RotateBearer(ctx, resolved.Session.ID, bearer.Digest(), now); err != nil {
		uc.d.Observer.AddressVerificationObserved(VerificationStoreFailed)
		return ConfirmVerificationOutput{}, ErrStoreUnavailable
	}
	// (3) Прочие сессии человека сняты: обычное положение получает только та
	// сессия, в которой код предъявлен.
	if _, err := w.EndOtherSessions(ctx, user.ID, resolved.Session.ID, now, domain.RevokeReasonEmailVerified); err != nil {
		uc.d.Observer.AddressVerificationObserved(VerificationStoreFailed)
		return ConfirmVerificationOutput{}, ErrStoreUnavailable
	}
	// (4) Событие — без адреса.
	if err := w.EmitAudit(ctx, outboxtypes.AuditEvent{
		EventType:       AuditEmailVerified,
		TenantAccountID: string(user.AccountID),
		Payload: map[string]any{
			"user_id":    string(user.ID),
			"session_id": string(resolved.Session.ID),
		},
	}); err != nil {
		uc.d.Observer.AddressVerificationObserved(VerificationStoreFailed)
		return ConfirmVerificationOutput{}, ErrStoreUnavailable
	}
	// (5) Приглашение активируется подтверждением — и только живое.
	var ownerBinding domain.AccessBindingID
	if user.InviteStatus == domain.InviteStatusPending {
		act, aerr := w.ActivateInviteOnVerification(ctx, user)
		switch {
		case errors.Is(aerr, ErrInviteNotValid):
			uc.d.Observer.AddressVerificationObserved(VerificationInviteNotValid)
			return ConfirmVerificationOutput{}, ErrInviteNotValid
		case aerr != nil:
			uc.d.Logger.Error("verification confirm: invite not activated — store refused; outcome rolled back",
				"err", aerr.Error(), "user_id", string(user.ID))
			uc.d.Observer.AddressVerificationObserved(VerificationStoreFailed)
			return ConfirmVerificationOutput{}, ErrStoreUnavailable
		}
		user = act.User
		ownerBinding = act.OwnerBindingID
	}
	if err := w.Commit(ctx); err != nil {
		uc.d.Observer.AddressVerificationObserved(VerificationStoreFailed)
		return ConfirmVerificationOutput{}, ErrStoreUnavailable
	}
	if uc.d.Reconciler != nil && ownerBinding != "" {
		if rerr := uc.d.Reconciler.ReconcileBinding(ctx, ownerBinding); rerr != nil {
			uc.d.Logger.Error("verification confirm: owner-binding reconcile failed (sweep will retry)",
				"user_id", string(user.ID), "binding_id", string(ownerBinding), "err", rerr.Error())
		}
	}
	uc.d.Observer.AddressVerificationObserved(VerificationConfirmed)
	s := resolved.Session
	s.LastPresentedAt = now
	return ConfirmVerificationOutput{
		View:   SessionView{User: user, Session: s, EmailVerified: true},
		Bearer: bearer,
	}, nil
}

// Position — положение сессии, выведенное из ТЕКУЩЕЙ отметки (Р1). Нулевое
// значение — сессии нет: судить нечего, отказ сессии выносит глагол.
type Position int

const (
	PositionNoSession Position = iota
	// PositionVerification — положение подтверждения: сессия действует только
	// для перечня Р2.
	PositionVerification
	// PositionNormal — обычное положение.
	PositionNormal
)

// PositionUseCase — положение сессии по носителю на КАЖДОМ запросе. Кэша нет
// намеренно: снятие отметки и подтверждение действуют на следующем запросе.
type PositionUseCase struct {
	store Store
	now   func() time.Time
}

// NewPositionUseCase — построение.
func NewPositionUseCase(store Store, now func() time.Time) (*PositionUseCase, error) {
	if store == nil {
		return nil, fmt.Errorf("position: session store required")
	}
	if now == nil {
		now = time.Now
	}
	return &PositionUseCase{store: store, now: now}, nil
}

// Execute — положение сессии носителя. Ошибка — хранилище не ответило: это не
// «обычное положение».
func (uc *PositionUseCase) Execute(ctx context.Context, bearer domain.SessionBearer) (Position, error) {
	if bearer.IsZero() {
		return PositionNoSession, nil
	}
	resolved, reason, err := uc.store.Resolve(ctx, bearer.Digest(), uc.now().UTC())
	if err != nil {
		return PositionNoSession, ErrStoreUnavailable
	}
	if reason != SessionFound {
		return PositionNoSession, nil
	}
	if !resolved.EmailVerified {
		return PositionVerification, nil
	}
	return PositionNormal, nil
}

// SourceLane — обращение без удостоверения, чей темп считается по источнику
// (kaname#456): регистрация и запрос восстановления. Словарь ЗАКРЫТ —
// ограничение схемы `source_request_windows_lane_check`.
type SourceLane string

const (
	SourceLaneRegistration    SourceLane = "registration"
	SourceLaneRecoveryRequest SourceLane = "recovery-request"
)

// SourcePace — предел обращений одного источника за окно.
type SourcePace struct {
	Limit  int
	Window time.Duration
}

// Validate — обе величины положительны: значения «без предела» нет.
func (p SourcePace) Validate() error {
	if p.Limit <= 0 || p.Window <= 0 {
		return fmt.Errorf("source pace: limit and window must be positive (got %d per %s)", p.Limit, p.Window)
	}
	return nil
}

// SourcePacer — окно обращений по источнику: списание и переход окна — ОДИН
// оператор (ban #10). admitted=false — окно полно, обращение не выполняется.
type SourcePacer interface {
	ChargeSource(ctx context.Context, lane SourceLane, source string, at time.Time, pace SourcePace) (admitted bool, err error)
}

// ErrLetterWindowFull — окно писем адресата полно: письмо не ставится, ответ
// вызывающему не меняется (оракула нет). Отличим от отказа хранилища.
var ErrLetterWindowFull = errors.New("letter window of the recipient is full")
