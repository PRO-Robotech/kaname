// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// email_change.go — СМЕНА АДРЕСА ПОЧТЫ с подтверждением с нового адреса:
// запрос смены и предъявление кода под сессией человека (задача
// PRO-Robotech/kaname#635; приёмка
// `docs/engineering/acceptance/email-change-is-confirmed-from-the-new-address.md`,
// решения Р1–Р10).
//
// # Два глагола полосы формы; адрес меняет только второй (Р1)
//
// Запрос записывает отложенную смену и ставит письмо с кодом на НОВЫЙ адрес.
// До предъявления действует прежний адрес: им входят, на него идёт
// восстановление, его видят чтения. Предъявление кода под живой сессией того
// же человека меняет адрес одним исходом.
//
// # Порядок суждения запроса — несущий
//
//	сессия · положение (адрес подтверждён) · свежесть · форма адреса ·
//	«отличен от текущего» · темп человека · окно адресата · запись
//
// Ни одна ступень до записи не ставит письма и не расходует темп (Р3). Отказ
// темпа откатывает транзакцию целиком: запрос не записан, прежний код не
// вытеснен (Р6).
//
// # Занятый адрес на запросе неотличим от свободного (Р4)
//
// Запрос на адрес, занятый любой строкой человека, записывается так же, как на
// свободный, расходует темп человека и окно адресата одинаково и вытесняет
// прежний код так же; отличие одно и наружу не выходит — письма с кодом нет, и
// запись кода не несёт. Окончательную уникальность решает ключ базы в
// операторе исхода (`users_identity_email_uniq`), а не проверка перед ним:
// чтение занятости на запросе решает только, ставить ли письмо.
//
// # Исход смены — одна транзакция (Р8)
//
// Транзакция открыта замком писателя нескольких сессий на строке человека —
// тем же, что у подтверждения адреса, — и им же сериализованы запросы одного
// человека: решение о темпе и запись строки — один условный оператор под этим
// замком (ban #10). Адрес · отметка существующим оператором · новый носитель ·
// прочие сессии сняты · коды восстановления сняты · уведомление на прежний
// адрес · событие аудита · строка очереди смены субъекта — один исход; отказ
// любого шага откатывает всё.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

// Тексты и признаки отказов глаголов смены (Р3, Р4) — контракт полосы.
const (
	// TextEmailInUse — новый адрес заняли между запросом и предъявлением
	// (Р4): этот отказ видит только владелец кода.
	TextEmailInUse = "email address is already in use"
	// ReasonEmailInUse — машинный признак того же отказа.
	ReasonEmailInUse = "EMAIL_IN_USE"
	// RuleMustDiffer — правило поля нового адреса, совпавшего с текущим.
	RuleMustDiffer = "must differ from the current address"
	// fieldNewEmail — имя поля формы запроса.
	fieldNewEmail = "newEmail"
)

// AuditEmailChanged — событие исхода смены (Р8 п. 7): нагрузка
// `{user_id, session_id}`, адресов нет.
const AuditEmailChanged = "iam.user.email_changed"

// SubjectChangeUserEmail — вид события очереди смены субъекта исхода смены
// (Р8 п. 8): `op` = `event_type`.
const SubjectChangeUserEmail = "user_email_change"

// emailChangeCodeIDPrefix — приставка идентификатора строки отложенной смены.
// Наружу не адресуется; в платформенный каталог приставок не входит.
const emailChangeCodeIDPrefix = "ecc"

// ErrEmailInUse — новый адрес занят на исходе смены (Р4).
var ErrEmailInUse = errors.New(TextEmailInUse)

// EmailChangeMailIntent — намерение письма с кодом на НОВЫЙ адрес (Р7): пишется
// той же транзакцией, что строка отложенной смены.
type EmailChangeMailIntent struct {
	UserID    domain.UserID
	AccountID domain.AccountID
	To        domain.Email
	Code      domain.VerificationCodeValue
	// ValidFor — срок кода, как его назовёт письмо.
	ValidFor time.Duration
}

// EmailChangedMailIntent — намерение уведомления на ПРЕЖНИЙ адрес (Р7):
// момент смены — и ничего сверх; нового адреса, кода и ссылки нет.
type EmailChangedMailIntent struct {
	UserID    domain.UserID
	AccountID domain.AccountID
	To        domain.Email
	ChangedAt time.Time
}

// SubjectChange — строка очереди смены субъекта о человеке (Р8 п. 8).
type SubjectChange struct {
	SubjectID   string
	SubjectType string
	Op          string
}

// EmailChangeWriter — транзакция глаголов смены. Открывается замком писателя
// нескольких сессий на строке человека.
type EmailChangeWriter interface {
	Writer
	// AddressTaken — адрес занят любой строкой человека (зарегистрированной,
	// приглашённой, в том числе с истёкшим приглашением), прочитанный ЭТОЙ
	// транзакцией. Решает только, ставить ли письмо (Р4).
	AddressTaken(ctx context.Context, email domain.Email) (bool, error)
	// SupersedeEmailChangeCodes — живая отложенная смена человека вытеснена
	// (Р5); строка остаётся — по строкам считается темп.
	SupersedeEmailChangeCodes(ctx context.Context, userID domain.UserID, at time.Time) (int, error)
	// InsertEmailChangeCodePaced — строка принятого запроса, ЕСЛИ темп человека
	// это позволяет: решение и запись — один условный оператор (Р6).
	InsertEmailChangeCodePaced(ctx context.Context, c domain.EmailChangeCode, pace VerificationPace) (LetterRefusal, error)
	// ChargeEmailChangeWindow — списание окна писем пары «email-change, адрес»
	// одним оператором (Р6); окно полно — LetterRefusal.Refused со сроком.
	ChargeEmailChangeWindow(ctx context.Context, to domain.Email, limit outboxtypes.InviteMailRateLimit) (LetterRefusal, error)
	// EmitEmailChangeMail — письмо с кодом той же транзакцией (Р7).
	EmitEmailChangeMail(ctx context.Context, in EmailChangeMailIntent) error
	// PresentEmailChangeCode — ОДИН оператор предъявления (Р5): счёт попытки и
	// сверка свёртки не разнесены; при совпадении — новый адрес, на который
	// выдан код.
	PresentEmailChangeCode(ctx context.Context, userID domain.UserID, digest domain.CodeDigest, now time.Time, attempts int) (PresentedCode, domain.Email, error)
	// ChangeEmail — ЕДИНСТВЕННЫЙ законный писатель адреса в существующую строку
	// человека (Р8 п. 1, Р9): отвечает прежним адресом. Занятость решает ключ
	// базы — ErrEmailInUse.
	ChangeEmail(ctx context.Context, userID domain.UserID, newEmail domain.Email) (previous domain.Email, err error)
	// EmitEmailChangedMail — уведомление на прежний адрес той же транзакцией
	// (Р7, Р8 п. 6).
	EmitEmailChangedMail(ctx context.Context, in EmailChangedMailIntent) error
	// EmitSubjectChangeEvent — строка очереди смены субъекта тем же методом,
	// которым пишут выдачи и членства (Р8 п. 8).
	EmitSubjectChangeEvent(ctx context.Context, c SubjectChange) error
}

// EmailChangeStore — хранилище глаголов смены.
type EmailChangeStore interface {
	// Resolve — запись сессии по дайджесту носителя.
	Resolve(ctx context.Context, digest domain.BearerDigest, now time.Time) (Resolved, NoSessionReason, error)
	// EmailChangeWriter — транзакция, ПЕРВЫМ оператором которой взята строка
	// человека замком писателя нескольких сессий.
	EmailChangeWriter(ctx context.Context, userID domain.UserID) (EmailChangeWriter, error)
}

// EmailChangeOutcome — исход глаголов смены. Перечень ЗАКРЫТ: клетки заводятся
// нулём до первого события.
type EmailChangeOutcome string

const (
	EmailChangeLetterQueued     EmailChangeOutcome = "letter-queued"
	EmailChangeAddressTaken     EmailChangeOutcome = "address-taken"
	EmailChangePersonPaced      EmailChangeOutcome = "person-paced"
	EmailChangeRecipientPaced   EmailChangeOutcome = "recipient-paced"
	EmailChangeNoSession        EmailChangeOutcome = "no-session"
	EmailChangeNotVerified      EmailChangeOutcome = "not-verified"
	EmailChangeNotFresh         EmailChangeOutcome = "not-fresh"
	EmailChangeFieldRefused     EmailChangeOutcome = "field-refused"
	EmailChangeConfirmed        EmailChangeOutcome = "confirmed"
	EmailChangeCodeMismatched   EmailChangeOutcome = "code-mismatched"
	EmailChangeCodeNotFound     EmailChangeOutcome = "code-not-found"
	EmailChangeCodeExhausted    EmailChangeOutcome = "code-exhausted"
	EmailChangeInUse            EmailChangeOutcome = "address-in-use"
	EmailChangeStoreFailed      EmailChangeOutcome = "store-failed"
	EmailChangeMarkNotReapplied EmailChangeOutcome = "mark-not-reapplied"
)

// EmailChangeOutcomes — закрытый перечень.
func EmailChangeOutcomes() []EmailChangeOutcome {
	return []EmailChangeOutcome{
		EmailChangeLetterQueued, EmailChangeAddressTaken, EmailChangePersonPaced, EmailChangeRecipientPaced,
		EmailChangeNoSession, EmailChangeNotVerified, EmailChangeNotFresh, EmailChangeFieldRefused,
		EmailChangeConfirmed, EmailChangeCodeMismatched, EmailChangeCodeNotFound, EmailChangeCodeExhausted,
		EmailChangeInUse, EmailChangeStoreFailed, EmailChangeMarkNotReapplied,
	}
}

// EmailChangeObserver — приёмник исходов смены. Адреса и кода не получает по
// построению.
type EmailChangeObserver interface {
	EmailChangeObserved(EmailChangeOutcome)
}

// EmailChangeObserved — см. порт.
func (NopObserver) EmailChangeObserved(EmailChangeOutcome) {}

// EmailChangeDeps — зависимости глаголов смены.
type EmailChangeDeps struct {
	Store EmailChangeStore
	// Pace — значения пяти ручек F6b Р9 (Р5, Р6): срок кода, попытки,
	// интервал, предел и окно. Своих ручек у смены нет.
	Pace VerificationPace
	// Freshness — окно свежести правки своих данных (Ф1 §4.1, Р2).
	Freshness time.Duration
	// MailLimit — окно писем адресата под ограничением нашего отправителя
	// (ID-MAIL-1 Р22, Р6).
	MailLimit outboxtypes.InviteMailRateLimit
	Observer  EmailChangeObserver
	Now       func() time.Time
	Logger    *slog.Logger
}

func (d EmailChangeDeps) complete() (EmailChangeDeps, error) {
	switch {
	case d.Store == nil:
		return d, fmt.Errorf("email change: store required")
	case d.Freshness <= 0:
		return d, fmt.Errorf("email change: freshness window must be positive")
	case d.MailLimit.MaxPerWindow <= 0 || d.MailLimit.Window <= 0:
		return d, fmt.Errorf("email change: recipient letter window must be positive (got %d per %s)",
			d.MailLimit.MaxPerWindow, d.MailLimit.Window)
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

// resolveForEmailChange — первая ступень обоих глаголов: живая сессия и
// подтверждённое положение. Положение судит и слушатель (путь объявлен отказом
// в положении подтверждения, Р2); глагол судит его сам, чтобы собранный мимо
// слушателя не стал обходом.
func resolveForEmailChange(ctx context.Context, d EmailChangeDeps, bearer domain.SessionBearer, now time.Time) (Resolved, error) {
	if bearer.IsZero() {
		d.Observer.EmailChangeObserved(EmailChangeNoSession)
		return Resolved{}, ErrAuthenticationFailed
	}
	resolved, reason, err := d.Store.Resolve(ctx, bearer.Digest(), now)
	if err != nil {
		d.Observer.EmailChangeObserved(EmailChangeStoreFailed)
		return Resolved{}, ErrStoreUnavailable
	}
	if reason != SessionFound {
		d.Observer.EmailChangeObserved(EmailChangeNoSession)
		return Resolved{}, ErrAuthenticationFailed
	}
	if !resolved.EmailVerified {
		d.Observer.EmailChangeObserved(EmailChangeNotVerified)
		return Resolved{}, ErrEmailNotVerified
	}
	return resolved, nil
}

// sessionIsFresh — окно свежести правки своих данных от момента последнего
// предъявления (Ф1 §4.1, Ф11 Р6). Граница включена: ровно окно — ещё свежая.
// Одно правило на все правки своих данных: его зовут и второй фактор
// (`requireFresh`), и смена адреса.
func sessionIsFresh(s domain.HumanSession, now time.Time, window time.Duration) bool {
	return now.Sub(s.LastPresentedAt) <= window
}

// RequestEmailChangeInput — запрос смены.
type RequestEmailChangeInput struct {
	Bearer   domain.SessionBearer
	NewEmail string
}

// RequestEmailChangeOutput — исход принятого запроса: промежуток до
// следующего разрешённого запроса (экран ведёт отсчёт по нему).
type RequestEmailChangeOutput struct {
	NextAllowedIn time.Duration
}

// RequestEmailChangeUseCase — запрос смены адреса (Р2–Р7).
type RequestEmailChangeUseCase struct{ d EmailChangeDeps }

// NewRequestEmailChangeUseCase — построение с проверкой зависимостей.
func NewRequestEmailChangeUseCase(d EmailChangeDeps) (*RequestEmailChangeUseCase, error) {
	d, err := d.complete()
	if err != nil {
		return nil, err
	}
	return &RequestEmailChangeUseCase{d: d}, nil
}

// Execute — запрос смены (порядок суждения — шапка файла).
func (uc *RequestEmailChangeUseCase) Execute(ctx context.Context, in RequestEmailChangeInput) (RequestEmailChangeOutput, error) {
	now := uc.d.Now().UTC()
	resolved, err := resolveForEmailChange(ctx, uc.d, in.Bearer, now)
	if err != nil {
		return RequestEmailChangeOutput{}, err
	}
	if !sessionIsFresh(resolved.Session, now, uc.d.Freshness) {
		uc.d.Observer.EmailChangeObserved(EmailChangeNotFresh)
		return RequestEmailChangeOutput{}, ErrSessionNotFresh
	}
	newEmail, err := judgeNewEmail(in.NewEmail, resolved.User.Email)
	if err != nil {
		uc.d.Observer.EmailChangeObserved(EmailChangeFieldRefused)
		return RequestEmailChangeOutput{}, err
	}
	user := resolved.User

	w, err := uc.d.Store.EmailChangeWriter(ctx, user.ID)
	if err != nil {
		uc.d.Observer.EmailChangeObserved(EmailChangeStoreFailed)
		return RequestEmailChangeOutput{}, ErrStoreUnavailable
	}
	defer func() { _ = w.Rollback(ctx) }()

	taken, err := w.AddressTaken(ctx, newEmail)
	if err != nil {
		return RequestEmailChangeOutput{}, uc.storeFailed("address occupancy not read", user.ID, err)
	}
	code := domain.EmailChangeCode{
		ID:       domain.EmailChangeCodeID(ids.NewHyphenID(emailChangeCodeIDPrefix)),
		UserID:   user.ID,
		NewEmail: newEmail,
		IssuedAt: now,
		// Срок — ручка кода подтверждения (Р5): тот же предмет «код в ящик под
		// сессией».
		ExpiresAt: now.Add(uc.d.Pace.CodeTTL),
	}
	var value domain.VerificationCodeValue
	if !taken {
		value, err = domain.NewVerificationCodeValue()
		if err != nil {
			return RequestEmailChangeOutput{}, uc.storeFailed("code not minted", user.ID, err)
		}
		code.Digest = value.Digest()
	}
	// Вытеснение прежней отложенной смены и запись принятого запроса — в одной
	// транзакции: отказ темпа ниже откатывает и вытеснение (Р6).
	if _, err := w.SupersedeEmailChangeCodes(ctx, user.ID, now); err != nil {
		return RequestEmailChangeOutput{}, uc.storeFailed("earlier change not superseded", user.ID, err)
	}
	refusal, err := w.InsertEmailChangeCodePaced(ctx, code, uc.d.Pace)
	if err != nil {
		return RequestEmailChangeOutput{}, uc.storeFailed("request not recorded", user.ID, err)
	}
	if refusal.Refused {
		uc.d.Observer.EmailChangeObserved(EmailChangePersonPaced)
		return RequestEmailChangeOutput{}, &TooManyAttemptsError{Scope: FailureByAddress, RetryAfter: refusal.RetryAfter}
	}
	// Окно адресата списывается и на занятый адрес: иначе разница темпа была бы
	// ответом на вопрос «занят ли адрес» (Р6).
	refusal, err = w.ChargeEmailChangeWindow(ctx, newEmail, uc.d.MailLimit)
	if err != nil {
		return RequestEmailChangeOutput{}, uc.storeFailed("recipient window not charged", user.ID, err)
	}
	if refusal.Refused {
		uc.d.Observer.EmailChangeObserved(EmailChangeRecipientPaced)
		return RequestEmailChangeOutput{}, &TooManyAttemptsError{Scope: FailureByAddress, RetryAfter: refusal.RetryAfter}
	}
	if !taken {
		if err := w.EmitEmailChangeMail(ctx, EmailChangeMailIntent{
			UserID: user.ID, AccountID: user.AccountID, To: newEmail, Code: value, ValidFor: uc.d.Pace.CodeTTL,
		}); err != nil {
			return RequestEmailChangeOutput{}, uc.storeFailed("letter not queued", user.ID, err)
		}
	}
	if err := w.Commit(ctx); err != nil {
		return RequestEmailChangeOutput{}, uc.storeFailed("request not committed", user.ID, err)
	}
	if taken {
		uc.d.Observer.EmailChangeObserved(EmailChangeAddressTaken)
	} else {
		uc.d.Observer.EmailChangeObserved(EmailChangeLetterQueued)
	}
	return RequestEmailChangeOutput{NextAllowedIn: uc.d.Pace.Interval}, nil
}

func (uc *RequestEmailChangeUseCase) storeFailed(what string, user domain.UserID, err error) error {
	uc.d.Observer.EmailChangeObserved(EmailChangeStoreFailed)
	uc.d.Logger.Error("email change request: "+what, "err", err.Error(), "user_id", string(user))
	return ErrStoreUnavailable
}

// judgeNewEmail — форма нового адреса (Р3): то же приведение и та же проверка
// формы, что у регистрации; совпавший после приведения с текущим — отказ поля.
func judgeNewEmail(raw string, current domain.Email) (domain.Email, error) {
	key := AddressKey(raw)
	if key == "" {
		return "", FieldRequired(fieldNewEmail)
	}
	email := domain.Email(key)
	if err := email.Validate(); err != nil {
		return "", &FieldError{Field: fieldNewEmail, Rule: "invalid format"}
	}
	if key == AddressKey(string(current)) {
		return "", &FieldError{Field: fieldNewEmail, Rule: RuleMustDiffer}
	}
	return email, nil
}

// ConfirmEmailChangeInput — предъявление кода смены.
type ConfirmEmailChangeInput struct {
	Bearer domain.SessionBearer
	Code   string
}

// ConfirmEmailChangeOutput — исход смены: состав ответа и новый носитель той
// же сессии.
type ConfirmEmailChangeOutput struct {
	View   SessionView
	Bearer domain.SessionBearer
}

// ConfirmEmailChangeUseCase — предъявление кода смены (Р2, Р5, Р8).
type ConfirmEmailChangeUseCase struct{ d EmailChangeDeps }

// NewConfirmEmailChangeUseCase — построение с проверкой зависимостей.
func NewConfirmEmailChangeUseCase(d EmailChangeDeps) (*ConfirmEmailChangeUseCase, error) {
	d, err := d.complete()
	if err != nil {
		return nil, err
	}
	return &ConfirmEmailChangeUseCase{d: d}, nil
}

// Execute — предъявление кода: сессия · положение · форма (`code: required`)
// · код · исход одной транзакцией. Свежести предъявление не требует (Р2):
// решение принято на запросе, владение ящиком доказывает код.
func (uc *ConfirmEmailChangeUseCase) Execute(ctx context.Context, in ConfirmEmailChangeInput) (ConfirmEmailChangeOutput, error) {
	now := uc.d.Now().UTC()
	resolved, err := resolveForEmailChange(ctx, uc.d, in.Bearer, now)
	if err != nil {
		return ConfirmEmailChangeOutput{}, err
	}
	presented := domain.PresentedVerificationCode(in.Code)
	if presented.IsZero() {
		uc.d.Observer.EmailChangeObserved(EmailChangeFieldRefused)
		return ConfirmEmailChangeOutput{}, FieldRequired("code")
	}
	bearer, err := domain.NewSessionBearer()
	if err != nil {
		uc.d.Observer.EmailChangeObserved(EmailChangeStoreFailed)
		return ConfirmEmailChangeOutput{}, ErrStoreUnavailable
	}
	user := resolved.User

	w, err := uc.d.Store.EmailChangeWriter(ctx, user.ID)
	if err != nil {
		uc.d.Observer.EmailChangeObserved(EmailChangeStoreFailed)
		return ConfirmEmailChangeOutput{}, ErrStoreUnavailable
	}
	defer func() { _ = w.Rollback(ctx) }()

	outcome, newEmail, err := w.PresentEmailChangeCode(ctx, user.ID, presented.Digest(), now, uc.d.Pace.Attempts)
	if err != nil {
		return ConfirmEmailChangeOutput{}, uc.storeFailed("code application not answered", user.ID, err)
	}
	switch outcome {
	case CodeMismatched, CodeExhausted:
		// Попытка засчитана оператором предъявления и фиксируется: предел
		// попыток — свойство кода, а не запроса.
		if err := w.Commit(ctx); err != nil {
			return ConfirmEmailChangeOutput{}, uc.storeFailed("attempt not committed", user.ID, err)
		}
		cell := EmailChangeCodeMismatched
		if outcome == CodeExhausted {
			cell = EmailChangeCodeExhausted
		}
		uc.d.Observer.EmailChangeObserved(cell)
		return ConfirmEmailChangeOutput{}, ErrAuthenticationFailed
	case CodeMatched:
	default:
		uc.d.Observer.EmailChangeObserved(EmailChangeCodeNotFound)
		return ConfirmEmailChangeOutput{}, ErrAuthenticationFailed
	}

	// (1) Адрес — новый. Занятость решает ключ базы; отказ откатывает исход
	// целиком, и код остаётся неприменённым (Р4).
	previous, err := w.ChangeEmail(ctx, user.ID, newEmail)
	switch {
	case errors.Is(err, ErrEmailInUse):
		uc.d.Observer.EmailChangeObserved(EmailChangeInUse)
		return ConfirmEmailChangeOutput{}, ErrEmailInUse
	case err != nil:
		return ConfirmEmailChangeOutput{}, uc.storeFailed("address not written", user.ID, err)
	}
	// (2) Отметка — момент этого предъявления, существующим оператором: триггер
	// снял её на смене значения той же транзакцией (Р8 п. 2).
	marked, err := w.MarkEmailVerified(ctx, user.ID, newEmail, now)
	if err != nil {
		return ConfirmEmailChangeOutput{}, uc.storeFailed("mark not written", user.ID, err)
	}
	if !marked {
		// Адрес строки сменился в этой же транзакции на newEmail, и оператор
		// отметки его не нашёл: это дефект хранилища, а не исход человека.
		uc.d.Observer.EmailChangeObserved(EmailChangeMarkNotReapplied)
		uc.d.Logger.Error("email change confirm: the mark was not reapplied to the new address; outcome rolled back",
			"user_id", string(user.ID))
		return ConfirmEmailChangeOutput{}, ErrStoreUnavailable
	}
	// (3) Новый носитель текущей сессии; прежний больше не годен.
	if err := w.RotateBearer(ctx, resolved.Session.ID, bearer.Digest(), now); err != nil {
		return ConfirmEmailChangeOutput{}, uc.storeFailed("bearer not rotated", user.ID, err)
	}
	// (4) Прочие сессии сняты причиной `email-changed`.
	if _, err := w.EndOtherSessions(ctx, user.ID, resolved.Session.ID, now, domain.RevokeReasonEmailChanged); err != nil {
		return ConfirmEmailChangeOutput{}, uc.storeFailed("other sessions not ended", user.ID, err)
	}
	// (5) Живые коды восстановления сняты: код, выданный на прежний адрес, после
	// смены не подходит.
	if _, err := w.SupersedeRecoveryCodes(ctx, user.ID); err != nil {
		return ConfirmEmailChangeOutput{}, uc.storeFailed("recovery codes not withdrawn", user.ID, err)
	}
	// (6) Уведомление на прежний адрес — без нового адреса.
	if err := w.EmitEmailChangedMail(ctx, EmailChangedMailIntent{
		UserID: user.ID, AccountID: user.AccountID, To: previous, ChangedAt: now,
	}); err != nil {
		return ConfirmEmailChangeOutput{}, uc.storeFailed("notice not queued", user.ID, err)
	}
	// (7) Событие — без адресов.
	if err := w.EmitAudit(ctx, outboxtypes.AuditEvent{
		EventType:       AuditEmailChanged,
		TenantAccountID: string(user.AccountID),
		Payload: map[string]any{
			"user_id":    string(user.ID),
			"session_id": string(resolved.Session.ID),
		},
	}); err != nil {
		return ConfirmEmailChangeOutput{}, uc.storeFailed("audit event not written", user.ID, err)
	}
	// (8) Строка очереди смены субъекта: край сбрасывает кеш решений о человеке
	// тем же потоком, что на выдачах.
	if err := w.EmitSubjectChangeEvent(ctx, SubjectChange{
		SubjectID: string(user.ID), SubjectType: string(domain.SubjectTypeUser), Op: SubjectChangeUserEmail,
	}); err != nil {
		return ConfirmEmailChangeOutput{}, uc.storeFailed("subject change not written", user.ID, err)
	}
	if err := w.Commit(ctx); err != nil {
		if errors.Is(err, ErrEmailInUse) {
			uc.d.Observer.EmailChangeObserved(EmailChangeInUse)
			return ConfirmEmailChangeOutput{}, ErrEmailInUse
		}
		return ConfirmEmailChangeOutput{}, uc.storeFailed("outcome not committed", user.ID, err)
	}
	uc.d.Observer.EmailChangeObserved(EmailChangeConfirmed)
	user.Email = newEmail
	s := resolved.Session
	s.LastPresentedAt = now
	return ConfirmEmailChangeOutput{
		View:   SessionView{User: user, Session: s, EmailVerified: true},
		Bearer: bearer,
	}, nil
}

func (uc *ConfirmEmailChangeUseCase) storeFailed(what string, user domain.UserID, err error) error {
	uc.d.Observer.EmailChangeObserved(EmailChangeStoreFailed)
	uc.d.Logger.Error("email change confirm: "+what+"; outcome rolled back", "err", err.Error(), "user_id", string(user))
	return ErrStoreUnavailable
}
