// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// recovery_complete.go — ПРЕДЪЯВЛЕНИЕ КОДА С НОВЫМ ПАРОЛЕМ (Ф5-03…08,
// Ф5-16…19; Р1, Р4, Р5, Р7; Ф1-27, Ф1-59).
//
// # Почему код и новый пароль — ОДНИМ обращением
//
// Ф1-27 требует задать новый пароль до любого иного действия, а Ф5-17 и Ф1-59 —
// чтобы заблокированная личность прошла восстановление до конца (учётные
// данные сменены), не получив сессии. Сессии у неё нет — значит шага «задать
// пароль из сессии» у неё быть не может; пароль задаётся тем же обращением, что
// предъявляет код. Требование «до любого иного действия» тем самым держится
// построением: сессии до записи пароля не существует, и отвергать «иное
// действие» нечему. Расхождение этой формы с прежней прозой Ф3 Р8 / Ф5-03
// разрешено решением `kacho#2697` (исход 1): форма одного обращения — выбранная,
// поле сессии «требование сменить пароль» снято с контракта вместе с
// читателями (kaname#201), приёмки приведены новыми редакциями.
//
// # Порядок внутри обращения — несущий
//
//	форма → частота (обе оси) → правило нового пароля → ЧТЕНИЕ адреса →
//	ОДНА транзакция: применить код (один оператор) — ТОЧКА РЕШЕНИЯ; дальше
//	только у применённого кода: записать материал · снять записи ВСЕХ прежних
//	сессий · отсечка «смена пароля» актором-человеком · журнал по ключу потока ·
//	у незаблокированной — выдача сессии, чтение заведённых способов входа ЭТОЙ
//	ЖЕ транзакцией и решение о счёте по адресу местом решения входа · событие ·
//	фиксация
//
// Правило пароля судится ДО применения кода: негодный пароль называет поле и
// не тратит код. До точки решения полосы «адрес есть» и «адреса нет» делают
// ОДНУ И ТУ ЖЕ работу хранилища — чтение адреса, открытие транзакции, оператор
// применения, отказ: у второй оператор ищет код у пустой личности и не находит,
// как не нашёл бы неверный (Р5, Р7, §8 инв. 4). Поэтому работа, нужная только
// найденной личности, — чтение заведённых способов входа в том числе — стоит
// ПОСЛЕ точки решения: до неё она удлиняла бы полосу «адрес есть» на обходы
// базы, и время отказа называло бы, существует ли адрес. Проб времени у полосы
// завершения нет (Ф5-20…22 меряют запрос кода), поэтому равенство держит ряд
// обращений к портам хранилища —
// `TestRecovery_WrongCodeRefusalDoesTheSameStoreWorkForNobodyAndForSomeone`.
//
// # Счёт по адресу решает МЕСТО РЕШЕНИЯ ВХОДА, а не эта полоса
//
// Завершение выдаёт сессию и потому завершает вход; обнуляет ли оно счёт по
// адресу, решает `resetFailuresOnCompletedLogin` (`completed_login.go`) тем же
// правилом, что вход и церемония (Ф3 Р10, Ф12 Р7, Ф5 Р5; задача
// PRO-Robotech/kaname#305). Сессия восстановления — «1» (`recovery_code`, Ф11
// Р8), и исходов поэтому три:
//
//	без второго фактора, не заблокирована — счёт обнуляется: «1» и есть
//	                                        уровень всех её факторов;
//	второй фактор заведён                 — счёт НЕ обнуляется: это тот же
//	                                        счёт, что бюджет подбора его кода,
//	                                        и обнуляет его только вход, доведённый
//	                                        кодом до «2»;
//	заблокирована                         — сессии нет, вход не завершён: решения
//	                                        нет вовсе, а отказ завершения
//	                                        считается попыткой, как всякий отказ
//	                                        входа заблокированной (Ф1-59).
//
// Заведённое читается ПОСЛЕ применения кода соединением самой транзакции
// записи (`Writer.LoginMethod`): чтение пулом изнутри открытой транзакции дало
// бы вложенный захват соединения (шапка `completed_login.go`), а чтение ДО
// транзакции стояло бы до точки решения (выше). Отказ этого чтения — отказ
// исхода, как отказ любой записи той же транзакции: отказ оператора базы её
// обрывает, и продолжать её нечем. Исход откатывается целиком — код остаётся
// годным, учётные данные и счёт по адресу прежние.
//
// Отказ — ОДИН на все причины предъявления (Ф1 Р3, Ф1-59): «адреса нет», «код
// не тот», «истёк», «применён», «заблокирована» — наружу уходит тот же
// ErrAuthenticationFailed, что на входе; причина различима только клеткой.

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

// AuditRecoveryCompleted — событие завершения восстановления. ТО ЖЕ значение,
// что пишет приёмник обратного вызова поставщика (`internal/apps/kaname/api/user`,
// `auditEventUserRecoveryCompleted`): источника события два, событие одно (Р4).
const AuditRecoveryCompleted = "iam.user.recovery_completed"

// CompleteRecoveryInput — форма предъявления.
type CompleteRecoveryInput struct {
	Email       string
	Code        string
	NewPassword string
	Source      string
}

// CompleteRecoveryOutput — состав ответа и носитель выданной сессии.
type CompleteRecoveryOutput struct {
	View   SessionView
	Bearer domain.SessionBearer
}

// CompleteRecoveryUseCase — предъявление кода.
type CompleteRecoveryUseCase struct {
	store    Store
	hasher   Hasher
	rule     *PasswordRule
	ttl      time.Duration
	observer Observer
	now      func() time.Time
	logger   *slog.Logger
	gate     attemptGate
}

// CompleteRecoveryDeps — зависимости. Хранилища способов входа среди них нет:
// ось «заведено» места решения о счёте по адресу читается транзакцией записи
// (`Writer.LoginMethod`), после применения кода.
type CompleteRecoveryDeps struct {
	Store    Store
	Hasher   Hasher
	Rule     *PasswordRule
	Limits   Limits
	TTL      time.Duration
	Observer Observer
	Now      func() time.Time
	Logger   *slog.Logger
}

// NewCompleteRecoveryUseCase — построение с проверкой зависимостей.
func NewCompleteRecoveryUseCase(d CompleteRecoveryDeps) (*CompleteRecoveryUseCase, error) {
	switch {
	case d.Store == nil:
		return nil, fmt.Errorf("recovery completion: session store required")
	case d.Hasher == nil:
		return nil, fmt.Errorf("recovery completion: password hasher required")
	case d.Rule == nil:
		return nil, fmt.Errorf("recovery completion: password rule required")
	case d.TTL <= 0:
		return nil, fmt.Errorf("recovery completion: session ttl must be positive")
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
	return &CompleteRecoveryUseCase{
		store: d.Store, hasher: d.Hasher, rule: d.Rule, ttl: d.TTL, observer: d.Observer, now: d.Now, logger: d.Logger,
		gate: attemptGate{store: d.Store, limits: d.Limits, now: d.Now, observer: d.Observer},
	}, nil
}

// Execute — предъявление кода с новым паролем.
func (uc *CompleteRecoveryUseCase) Execute(ctx context.Context, in CompleteRecoveryInput) (CompleteRecoveryOutput, error) {
	addressKey := AddressKey(in.Email)
	if addressKey == "" {
		return CompleteRecoveryOutput{}, FieldRequired("email")
	}
	presented := domain.PresentedRecoveryCode(in.Code)
	if presented.IsZero() {
		return CompleteRecoveryOutput{}, FieldRequired("code")
	}
	if in.NewPassword == "" {
		return CompleteRecoveryOutput{}, FieldRequired("newPassword")
	}

	// (1) Частота — до всего (Ф5-08): отказ по частоте попыткой не считается.
	if hit, err := uc.gate.check(ctx, addressKey, in.Source); err != nil {
		uc.observer.RecoveryCompletionObserved(RecoveryCompletionStoreFailed)
		return CompleteRecoveryOutput{}, ErrStoreUnavailable
	} else if hit != nil {
		uc.observer.RecoveryCompletionObserved(RecoveryCompletionRateLimited)
		uc.observer.RateLimitObserved(hit.Scope)
		return CompleteRecoveryOutput{}, hit
	}

	// (2) Новый пароль — по правилу (Ф1-32…38), ДО применения кода: негодный
	// пароль называет поле и код не тратит. Правило от существования адреса не
	// зависит — оракула здесь нет.
	if err := uc.rule.Judge(ctx, addressKey, in.NewPassword); err != nil {
		uc.observer.RecoveryCompletionObserved(RecoveryCompletionPasswordRejected)
		return CompleteRecoveryOutput{}, err
	}
	fresh, err := uc.hasher.Hash(in.NewPassword)
	if err != nil {
		uc.logger.Error("recovery completion: hasher refused", "err", err.Error())
		uc.observer.RecoveryCompletionObserved(RecoveryCompletionStoreFailed)
		return CompleteRecoveryOutput{}, ErrStoreUnavailable
	}
	now := uc.now().UTC()

	// (3) Адрес — одно чтение на обеих полосах. До точки решения (4) обе
	// полосы делают одну и ту же работу хранилища (шапка).
	target, found, err := uc.store.RecoveryTarget(ctx, domain.Email(addressKey))
	if err != nil {
		uc.observer.RecoveryCompletionObserved(RecoveryCompletionStoreFailed)
		return CompleteRecoveryOutput{}, ErrStoreUnavailable
	}
	user := target.User

	// (4) Одна транзакция: применить код одним оператором — ТОЧКА РЕШЕНИЯ — и,
	// если применён, все записи завершения. Записи завершения снимают все
	// сессии, поэтому строка личности берётся первой — раньше строки кода и
	// способа входа (`SessionSetWriter`, kaname#340). У адреса без личности
	// строки нет, а оператор замка исполняется так же: до точки решения обе
	// полосы делают одну и ту же работу хранилища (шапка).
	w, err := uc.store.SessionSetWriter(ctx, user.ID)
	if err != nil {
		uc.observer.RecoveryCompletionObserved(RecoveryCompletionStoreFailed)
		return CompleteRecoveryOutput{}, ErrStoreUnavailable
	}
	defer func() { _ = w.Rollback(ctx) }()
	code, ok, err := w.ConsumeRecoveryCode(ctx, user.ID, presented.Digest(), now)
	if err != nil {
		uc.observer.RecoveryCompletionObserved(RecoveryCompletionStoreFailed)
		return CompleteRecoveryOutput{}, ErrStoreUnavailable
	}
	if !ok {
		_ = w.Rollback(ctx)
		outcome := RecoveryCompletionCodeRejected
		if !found {
			outcome = RecoveryCompletionNoRow
		}
		return CompleteRecoveryOutput{}, uc.refuse(ctx, outcome, addressKey, in.Source, now)
	}

	// Код применён: учётные данные сменяются у ЛЮБОЙ личности, включая
	// заблокированную (Ф5-17); сессия выдаётся только действующей (Ф1-59).
	blocked := user.InviteStatus != domain.InviteStatusActive
	out, err := uc.complete(ctx, w, user, code, fresh, now, blocked, target.EmailVerified)
	if err != nil {
		uc.observer.RecoveryCompletionObserved(RecoveryCompletionStoreFailed)
		return CompleteRecoveryOutput{}, ErrStoreUnavailable
	}
	if blocked {
		// Тот же отказ, что на входе заблокированной (Ф1-05, Ф1-59); попытка
		// считается, как у входа.
		return CompleteRecoveryOutput{}, uc.refuse(ctx, RecoveryCompletionBlocked, addressKey, in.Source, now)
	}
	uc.observer.RecoveryCompletionObserved(RecoveryCompletionIssued)
	return out, nil
}

// complete — записи завершения ОДНИМ исходом на открытой транзакции, после точки
// решения: материал · снятие записей всех прежних сессий · отсечка · журнал ·
// у незаблокированной — выдача, чтение заведённых способов этой транзакцией и
// решение о счёте по адресу местом решения входа · событие · фиксация.
func (uc *CompleteRecoveryUseCase) complete(
	ctx context.Context, w Writer, user domain.User, code domain.RecoveryCode, fresh domain.LoginVerifier,
	now time.Time, blocked, emailVerified bool,
) (CompleteRecoveryOutput, error) {
	replaced, err := w.ReplaceLoginVerifier(ctx, domain.LoginMethod{UserID: user.ID, Kind: domain.LoginMethodPassword, Verifier: fresh, State: domain.LoginMethodStateActive})
	if err != nil {
		return CompleteRecoveryOutput{}, err
	}
	if !replaced {
		// Строки способа входа паролем нет: восстанавливать нечего. Запись нового
		// способа — предмет Ф2 (ID-PW-1), а не этой фазы; заводить его здесь
		// значило бы завести второго писателя способа входа. Исход откатывается
		// целиком (код остаётся годным), причина — в журнале, а не в ответе.
		// Исход для человека решает владелец — `kacho#2698`.
		uc.logger.Error("recovery completion: the person has no password sign-in method to replace — recovery cannot set one (ID-PW-1 owns the write)",
			"user_id", string(user.ID))
		return CompleteRecoveryOutput{}, fmt.Errorf("recovery completion: user %s has no password sign-in method", user.ID)
	}
	// Все прежние сессии — снятием записей (в нашей посадке) и отсечкой (её
	// читает край на предъявлении, Ф3 Р7): Ф1 Р4, Ф5-19.
	if _, err := w.EndOtherSessions(ctx, user.ID, "", now, domain.RevokeReasonPasswordChange); err != nil {
		return CompleteRecoveryOutput{}, err
	}
	if err := w.UpsertCutoff(ctx, domain.UserTokenRevocation{
		UserID: user.ID, RevokeBefore: now, Reason: domain.RevokeReasonPasswordChange,
	}, user.ID); err != nil {
		return CompleteRecoveryOutput{}, err
	}
	// Журнал по ключу потока (Р4): ключ, уже стоящий при впервые применённом
	// коде, — наша несогласованность, а не повтор; исход откатывается целиком.
	inserted, err := w.InsertRecoveryCompletion(ctx, domain.RecoveryCompletion{
		RecoveryJTI: string(code.ID), UserID: user.ID, RevokedSessionCount: 1,
	})
	if err != nil {
		return CompleteRecoveryOutput{}, err
	}
	if !inserted {
		uc.logger.Error("recovery completion: ledger already holds the flow key of a code consumed just now — our data, not the caller's input",
			"user_id", string(user.ID), "recovery_jti", string(code.ID))
		return CompleteRecoveryOutput{}, fmt.Errorf("recovery completion: flow key %s already in the ledger", code.ID)
	}
	payload := map[string]any{
		"actor":                 "self",
		"user_id":               string(user.ID),
		"recovery_jti":          string(code.ID),
		"revoked_session_count": int32(1),
		"session_issued":        !blocked,
	}
	var out CompleteRecoveryOutput
	if !blocked {
		// Сессия аутентифицирована на единицу разрешения ПОЗЖЕ отсечки: иначе
		// при включающей границе она была бы негодна (Ф5-19, Ф1 §4.2).
		methods := []string{assurance.MethodRecoveryCode.String()}
		s, bearer, err := IssueSession(ctx, w, IssueInput{
			User:      user,
			Presented: presentationsOf(methods),
			At:        now.Add(time.Microsecond),
			TTL:       uc.ttl,
		})
		if err != nil {
			return CompleteRecoveryOutput{}, err
		}
		payload["session_id"] = string(s.ID)
		out = CompleteRecoveryOutput{View: SessionView{User: user, Session: s, EmailVerified: emailVerified}, Bearer: bearer}
		// Счёт по адресу обнуляет вход, ЗАВЕРШЁННЫЙ до уровня всех заведённых
		// у личности факторов (Ф3 Р10, Ф12 Р7, Ф5 Р5): сессия восстановления —
		// «1», и при заведённом втором факторе вход не завершён. У
		// заблокированной решения нет вовсе — сессии нет. Заведённое читается
		// ЭТОЙ транзакцией и только здесь, после точки решения (шапка).
		enrolled, err := enrolledMethods(ctx, w.LoginMethod, user.ID)
		if err != nil {
			uc.logger.ErrorContext(ctx, "recovery completion: enrolled login methods unreadable — the outcome is rolled back, the code stays usable",
				"user_id", string(user.ID), "err", err.Error())
			return CompleteRecoveryOutput{}, fmt.Errorf("recovery completion: enrolled login methods unreadable: %w", err)
		}
		if err := resetFailuresOnCompletedLogin(ctx, w, completedLogin{
			Enrolled: enrolled, EnrolledKnown: true,
			AddressKey: AddressKey(string(user.Email)), Presented: methods,
		}); err != nil {
			return CompleteRecoveryOutput{}, err
		}
	}
	if err := w.EmitAudit(ctx, outboxtypes.AuditEvent{
		EventType: AuditRecoveryCompleted, TenantAccountID: string(user.AccountID), Payload: payload,
	}); err != nil {
		return CompleteRecoveryOutput{}, err
	}
	if err := w.Commit(ctx); err != nil {
		return CompleteRecoveryOutput{}, err
	}
	return out, nil
}

// refuse — один отказ на все причины предъявления; попытка считается по обеим
// осям, как у входа (Ф5-08).
func (uc *CompleteRecoveryUseCase) refuse(ctx context.Context, outcome RecoveryCompletionOutcome, addressKey, source string, now time.Time) error {
	uc.observer.RecoveryCompletionObserved(outcome)
	w, err := uc.store.Writer(ctx)
	if err != nil {
		uc.observer.RecoveryCompletionObserved(RecoveryCompletionStoreFailed)
		return ErrAuthenticationFailed
	}
	defer func() { _ = w.Rollback(ctx) }()
	if err := recordFailure(ctx, w, addressKey, source, now); err != nil {
		uc.observer.RecoveryCompletionObserved(RecoveryCompletionStoreFailed)
		return ErrAuthenticationFailed
	}
	if err := w.Commit(ctx); err != nil {
		uc.observer.RecoveryCompletionObserved(RecoveryCompletionStoreFailed)
	}
	return ErrAuthenticationFailed
}
