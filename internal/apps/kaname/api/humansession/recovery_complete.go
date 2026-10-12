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
//	только у применённого кода: записать материал (заменить либо завести; у
//	заведённого впервые — отметка подтверждения адреса и снятие открытого пути,
//	Ф5 Р9 п. 3) · снять записи ВСЕХ прежних
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
// не тот», «истёк», «применён», «заблокирована» — наружу уходит
// ErrAccessNotRestored, свой у глагола и называющий шаг (Ф5 Р10 п. 2, Д22);
// причина различима только клеткой. Исключение одно — приглашение под строкой
// `PENDING` негодно после ГОДНОГО кода (kaname#458, Р6): ErrInviteNotValid
// называется только тому, кто доказал владение ящиком.
//
// # Переход записи к владельцу ящика (kaname#458, Р3, Р4)
//
// Ветвь исхода решает отметка подтверждения, прочитанная ЭТОЙ транзакцией
// после захвата строки личности (`AddressVerified`), а не чтение адреса до
// транзакции (запрет #10): запись, подтверждённая между выдачей кода и его
// предъявлением, — обычное восстановление (подтвердить её мог только владелец
// ящика). Отметки нет, а строка пароля у записи была — исход ПЕРЕХОДА той же
// транзакцией: отметка на значение адреса · снятие второго фактора, ключей
// доступа с испытаниями и личных токенов · снятие всех сессий и отсечка
// причиной `address-claimed` · активация строки `PENDING` той же функцией, что
// исход подтверждения · сессия владельцу ящика · событие с `address_claimed`.
// Отметки нет и пароль заведён впервые — Ф5 Р9 без перехода: прежнего
// держателя с паролем у такой записи не было. Отказ любого шага откатывает
// исход целиком: код годен, ничего не снято (Ф5-33).

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	"github.com/PRO-Robotech/kaname/internal/revocationpolicy"
)

// AuditRecoveryCompleted — событие завершения восстановления. Источник у
// события один — эта полоса: приёмник обратного вызова прежнего поставщика,
// писавший то же значение, снят вместе с поставщиком (kaname#564).
const AuditRecoveryCompleted = "iam.user.recovery_completed"

// CompleteRecoveryInput — форма предъявления.
type CompleteRecoveryInput struct {
	Email       string
	Code        string
	NewPassword string
	Source      string
	// Client — описание клиента выдающего запроса (kaname#634, Р3): идёт в
	// запись выдаваемой сессии и больше никуда.
	Client domain.ClientDescription
}

// CompleteRecoveryOutput — состав ответа и носитель выданной сессии.
type CompleteRecoveryOutput struct {
	View   SessionView
	Bearer domain.SessionBearer
}

// CompleteRecoveryUseCase — предъявление кода.
type CompleteRecoveryUseCase struct {
	store      Store
	completion RecoveryCompletionStore
	reconciler OwnerBindingReconciler
	hasher     Hasher
	rule       *PasswordRule
	ttl        time.Duration
	observer   Observer
	now        func() time.Time
	// clock — ОБЩИЙ для всех реплик источник момента отсечки и момента
	// выдаваемой сессии (kaname#589); now — часы процесса для срока кода и
	// счёта попыток.
	clock  revocationpolicy.Clock
	logger *slog.Logger
	gate   attemptGate
}

// CompleteRecoveryDeps — зависимости. Хранилища способов входа среди них нет:
// ось «заведено» места решения о счёте по адресу читается транзакцией записи
// (`Writer.LoginMethod`), после применения кода.
type CompleteRecoveryDeps struct {
	Store Store
	// Completion — транзакция исхода (kaname#458): операторы обычного
	// восстановления и перехода записи над одной транзакцией. Обязательна:
	// глагол без неё перехода не исполнил бы и молча не деградирует.
	Completion RecoveryCompletionStore
	// Reconciler — пост-коммитная материализация собственнической выдачи
	// личного аккаунта, заведённой активацией приглашения в исходе перехода; nil
	// — материализацию доводит уборка по намерениям (как у глагола
	// подтверждения).
	Reconciler OwnerBindingReconciler
	Hasher     Hasher
	Rule       *PasswordRule
	Limits     Limits
	TTL        time.Duration
	Observer   Observer
	Now        func() time.Time
	// CutoffClock — источник момента отсечки и момента сессии: тот же, что у
	// всех писателей моментов, сравниваемых с отсечкой (kaname#589). Обязателен.
	CutoffClock revocationpolicy.Clock
	Logger      *slog.Logger
}

// NewCompleteRecoveryUseCase — построение с проверкой зависимостей.
func NewCompleteRecoveryUseCase(d CompleteRecoveryDeps) (*CompleteRecoveryUseCase, error) {
	switch {
	case d.Store == nil:
		return nil, fmt.Errorf("recovery completion: session store required")
	case d.Completion == nil:
		return nil, fmt.Errorf("recovery completion: completion transaction store required")
	case d.Hasher == nil:
		return nil, fmt.Errorf("recovery completion: password hasher required")
	case d.Rule == nil:
		return nil, fmt.Errorf("recovery completion: password rule required")
	case d.TTL <= 0:
		return nil, fmt.Errorf("recovery completion: session ttl must be positive")
	case d.CutoffClock == nil:
		return nil, fmt.Errorf("recovery completion: %w", errNoCutoffClock)
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
		store: d.Store, completion: d.Completion, reconciler: d.Reconciler, hasher: d.Hasher, rule: d.Rule, ttl: d.TTL, observer: d.Observer, now: d.Now,
		clock: d.CutoffClock, logger: d.Logger,
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
	// Момент отсечки и сессии — из общего источника (kaname#589), до
	// транзакции и на обеих полосах одинаково: до точки решения обе делают
	// одну и ту же работу (шапка).
	at, err := sharedMoment(ctx, uc.clock, uc.logger, "recovery completion")
	if err != nil {
		uc.observer.RecoveryCompletionObserved(RecoveryCompletionStoreFailed)
		return CompleteRecoveryOutput{}, ErrStoreUnavailable
	}

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
	w, err := uc.completion.RecoveryCompletionWriter(ctx, user.ID)
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

	// Код применён. Ветвь исхода — по отметке подтверждения, прочитанной этой
	// транзакцией после захвата строки личности (kaname#458, Р4).
	verified, err := w.AddressVerified(ctx, user.ID)
	if err != nil {
		uc.observer.RecoveryCompletionObserved(RecoveryCompletionStoreFailed)
		return CompleteRecoveryOutput{}, ErrStoreUnavailable
	}
	// Учётные данные сменяются у ЛЮБОЙ личности, включая заблокированную
	// (Ф5-17); сессия выдаётся только действующей (Ф1-59).
	res, err := uc.complete(ctx, w, user, code, fresh, now, at, verified, in.Client)
	switch {
	case errors.Is(err, ErrInviteNotValid):
		// Приглашение под строкой `PENDING` негодно (Р6): исход откатан целиком
		// — код годен, пароль прежний, сессии прежнего держателя живы, отметки
		// нет. Попыткой не считается: код предъявлен верно.
		_ = w.Rollback(ctx)
		uc.observer.RecoveryCompletionObserved(RecoveryCompletionInviteNotValid)
		return CompleteRecoveryOutput{}, ErrInviteNotValid
	case errors.Is(err, errClaimAddressMoved):
		// Адрес строки сменился после выдачи кода (Р3 п. 1): исход откатан
		// целиком, наружу — единый отказ завершения.
		_ = w.Rollback(ctx)
		return CompleteRecoveryOutput{}, uc.refuse(ctx, RecoveryCompletionCodeRejected, addressKey, in.Source, now)
	case err != nil:
		uc.observer.RecoveryCompletionObserved(RecoveryCompletionStoreFailed)
		return CompleteRecoveryOutput{}, ErrStoreUnavailable
	}
	uc.reconcileOwnerBinding(ctx, res)
	if res.blocked {
		// Тот же отказ, что на входе заблокированной (Ф1-05, Ф1-59); попытка
		// считается, как у входа.
		return CompleteRecoveryOutput{}, uc.refuse(ctx, RecoveryCompletionBlocked, addressKey, in.Source, now)
	}
	if res.claimed {
		uc.observer.RecoveryCompletionObserved(RecoveryCompletionAddressClaimed)
	} else {
		uc.observer.RecoveryCompletionObserved(RecoveryCompletionIssued)
	}
	return res.out, nil
}

// errClaimAddressMoved — отметка перехода не легла: адрес строки уже не то
// значение, на которое выдан код (Р3 п. 1). Наружу не выходит.
var errClaimAddressMoved = errors.New("recovery completion: address of the record changed after the code was issued")

// completion — исход записей завершения после фиксации.
type completion struct {
	out CompleteRecoveryOutput
	// blocked — сессии нет: личность не `ACTIVE` после исхода.
	blocked bool
	// claimed — исход перехода записи к владельцу ящика (kaname#458, Р3).
	claimed bool
	// user — личность после исхода (у строки `PENDING`, переведённой
	// переходом, — уже `ACTIVE`).
	user domain.User
	// ownerBinding — собственническая выдача личного аккаунта, заведённая
	// активацией приглашения; пусто — активации не было.
	ownerBinding domain.AccessBindingID
}

// reconcileOwnerBinding — пост-коммитная материализация собственнической
// выдачи, заведённой активацией приглашения в исходе перехода: тем же
// согласователем, что у глагола подтверждения. Отказ — в журнал; доводит
// уборка по намерениям.
func (uc *CompleteRecoveryUseCase) reconcileOwnerBinding(ctx context.Context, res completion) {
	if uc.reconciler == nil || res.ownerBinding == "" {
		return
	}
	if rerr := uc.reconciler.ReconcileBinding(ctx, res.ownerBinding); rerr != nil {
		uc.logger.Error("recovery completion: owner-binding reconcile failed (sweep will retry)",
			"user_id", string(res.user.ID), "binding_id", string(res.ownerBinding), "err", rerr.Error())
	}
}

// complete — записи завершения ОДНИМ исходом на открытой транзакции, после точки
// решения: материал · снятие записей всех прежних сессий · отсечка · журнал ·
// у незаблокированной — выдача, чтение заведённых способов этой транзакцией и
// решение о счёте по адресу местом решения входа · событие · фиксация.
//
// at — момент общего источника (kaname#589): им ставятся отсечка и момент
// выдаваемой сессии, то есть всё, что сравнивается с отсечкой. now — часы
// процесса для отметок, которые с ней не сравниваются.
func (uc *CompleteRecoveryUseCase) complete(
	ctx context.Context, w RecoveryCompletionWriter, user domain.User, code domain.RecoveryCode, fresh domain.LoginVerifier,
	now, at time.Time, emailVerified bool, client domain.ClientDescription,
) (completion, error) {
	// Материал — «заменить либо завести» одним оператором (Р5 ветвь «строки
	// нет», Ф5-34): у личности без строки пароля завершение заводит первый
	// пароль, а не откатывается (`kacho#2698`, Р9 п. 3).
	created, err := w.PutLoginVerifier(ctx, domain.LoginMethod{UserID: user.ID, Kind: domain.LoginMethodPassword, Verifier: fresh, State: domain.LoginMethodStateActive})
	if err != nil {
		return completion{}, err
	}
	// Переход (kaname#458, Р3): отметки нет, а строка пароля была — запись
	// заводил кто-то, и чем он мог войти, неизвестно.
	claimed := !emailVerified && !created
	reason := domain.RevokeReasonPasswordChange
	var ownerBinding domain.AccessBindingID
	if !emailVerified {
		// Код дошёл до ящика, и предъявивший доказал владение адресом: отметка
		// подтверждения ставится на значение адреса, на которое выдан код, тем
		// же оператором, что у глагола подтверждения (Ф6) — и у первого пароля
		// (Ф5 Р9 п. 3), и у перехода записи (kaname#458, Р3 п. 1). Всё — той же
		// транзакцией: отказ любого шага откатывает исход целиком, код остаётся
		// годным (Ф5-33).
		marked, err := w.MarkEmailVerified(ctx, user.ID, user.Email, now)
		if err != nil {
			return completion{}, err
		}
		if !marked {
			// Адрес строки сменился между чтением и записью: подтверждать
			// нечего — код доставлен на прежнее значение.
			if claimed {
				return completion{}, errClaimAddressMoved
			}
			return completion{}, fmt.Errorf("recovery completion: address of user %s changed before the first password was set", user.ID)
		}
		emailVerified = true
	}
	if created {
		// Первый пароль (Р9 п. 3): отметка открытого пути снимается.
		if err := w.CloseRecoveryPath(ctx, user.ID); err != nil {
			return completion{}, err
		}
	}
	if claimed {
		activated, binding, err := uc.claim(ctx, w, user)
		if err != nil {
			return completion{}, err
		}
		user, ownerBinding, reason = activated, binding, domain.RevokeReasonAddressClaimed
	}
	// Сессия выдаётся только действующей (Ф1-59); строка `PENDING`, переведённая
	// переходом, к этому месту уже `ACTIVE`.
	blocked := user.InviteStatus != domain.InviteStatusActive
	// Все прежние сессии — снятием записей (в нашей посадке) и отсечкой (её
	// читает край на предъявлении, Ф3 Р7): Ф1 Р4, Ф5-19. У перехода — своей
	// причиной (Р7).
	if _, err := w.EndOtherSessions(ctx, user.ID, "", now, reason); err != nil {
		return completion{}, err
	}
	if err := w.UpsertCutoff(ctx, domain.UserTokenRevocation{
		UserID: user.ID, RevokeBefore: at, Reason: reason,
	}, user.ID); err != nil {
		return completion{}, err
	}
	// Журнал по ключу потока (Р4): ключ, уже стоящий при впервые применённом
	// коде, — наша несогласованность, а не повтор; исход откатывается целиком.
	inserted, err := w.InsertRecoveryCompletion(ctx, domain.RecoveryCompletion{
		RecoveryJTI: string(code.ID), UserID: user.ID, RevokedSessionCount: 1,
	})
	if err != nil {
		return completion{}, err
	}
	if !inserted {
		uc.logger.Error("recovery completion: ledger already holds the flow key of a code consumed just now — our data, not the caller's input",
			"user_id", string(user.ID), "recovery_jti", string(code.ID))
		return completion{}, fmt.Errorf("recovery completion: flow key %s already in the ledger", code.ID)
	}
	payload := map[string]any{
		"actor":                 "self",
		"user_id":               string(user.ID),
		"recovery_jti":          string(code.ID),
		"revoked_session_count": int32(1),
		"session_issued":        !blocked,
		// Переход записи к владельцу ящика (kaname#458, Р3 п. 6): адресов и
		// имён в событии нет.
		"address_claimed": claimed,
	}
	var out CompleteRecoveryOutput
	if !blocked {
		// Сессия аутентифицирована на единицу разрешения ПОЗЖЕ отсечки: иначе
		// при включающей границе она была бы негодна (Ф5-19, Ф1 §4.2).
		methods := []string{assurance.MethodRecoveryCode.String()}
		s, bearer, err := IssueSession(ctx, w, IssueInput{
			User:      user,
			Presented: presentationsOf(methods),
			At:        at.Add(time.Microsecond),
			TTL:       uc.ttl,
			Client:    client,
		})
		if err != nil {
			return completion{}, err
		}
		payload["session_id"] = string(s.ID)
		out = CompleteRecoveryOutput{View: SessionView{User: user, Session: s, EmailVerified: emailVerified}, Bearer: bearer}
		// Счёт по адресу обнуляет вход, ЗАВЕРШЁННЫЙ до уровня всех заведённых
		// у личности факторов (Ф3 Р10, Ф12 Р7, Ф5 Р5): сессия восстановления —
		// «1», и при заведённом втором факторе вход не завершён. У
		// заблокированной решения нет вовсе — сессии нет. Заведённое читается
		// ЭТОЙ транзакцией и только здесь, после точки решения (шапка).
		enrolled, err := enrolledForCompletion(ctx, w.LoginMethod, w.AccessKeyEnrolled, user.ID)
		if err != nil {
			uc.logger.ErrorContext(ctx, "recovery completion: enrolled login methods unreadable — the outcome is rolled back, the code stays usable",
				"user_id", string(user.ID), "err", err.Error())
			return completion{}, fmt.Errorf("recovery completion: enrolled login methods unreadable: %w", err)
		}
		if err := resetFailuresOnCompletedLogin(ctx, w, completedLogin{
			Enrolled: enrolled, EnrolledKnown: true,
			AddressKey: AddressKey(string(user.Email)), Level: s.AssuranceLevel,
		}); err != nil {
			return completion{}, err
		}
	}
	if err := w.EmitAudit(ctx, outboxtypes.AuditEvent{
		EventType: AuditRecoveryCompleted, TenantAccountID: string(user.AccountID), Payload: payload,
	}); err != nil {
		return completion{}, err
	}
	if err := w.Commit(ctx); err != nil {
		return completion{}, err
	}
	return completion{out: out, blocked: blocked, claimed: claimed, user: user, ownerBinding: ownerBinding}, nil
}

// claim — операторы перехода записи к владельцу ящика на открытой транзакции
// исхода (kaname#458, Р3 пп. 2, 4), после отметки подтверждения (п. 1, её
// ставит вызывающий): снятие всего, чем мог войти прежний держатель;
// активация строки `PENDING` той же функцией, что в исходе подтверждения, —
// после отметки: оператор активации судит её в своём условии. Отвечает
// личностью после исхода и собственнической выдачей, если активация её завела.
//
// Отказы: ErrInviteNotValid — приглашение негодно (Р6); прочие — отказ
// хранилища. Вызывающий откатывает исход целиком.
func (uc *CompleteRecoveryUseCase) claim(ctx context.Context, w RecoveryCompletionWriter, user domain.User) (domain.User, domain.AccessBindingID, error) {
	retired, err := w.RetireCredentialsOf(ctx, user.ID)
	if err != nil {
		return domain.User{}, "", err
	}
	var binding domain.AccessBindingID
	if user.InviteStatus == domain.InviteStatusPending {
		act, err := w.ActivateInviteOnVerification(ctx, user)
		if err != nil {
			return domain.User{}, "", err
		}
		user, binding = act.User, act.OwnerBindingID
	}
	uc.logger.InfoContext(ctx, "recovery completion: the record passes to the owner of the mailbox — credentials of the previous holder retired",
		"user_id", string(user.ID),
		"second_factor_rows", retired.SecondFactorRows, "access_key_challenge_rows", retired.AccessKeyChallengeRows,
		"access_key_rows", retired.AccessKeyRows, "user_token_rows", retired.UserTokenRows)
	return user, binding, nil
}

// refuse — один отказ на все причины предъявления; попытка считается по обеим
// осям, как у входа (Ф5-08).
func (uc *CompleteRecoveryUseCase) refuse(ctx context.Context, outcome RecoveryCompletionOutcome, addressKey, source string, now time.Time) error {
	uc.observer.RecoveryCompletionObserved(outcome)
	w, err := uc.store.Writer(ctx)
	if err != nil {
		uc.observer.RecoveryCompletionObserved(RecoveryCompletionStoreFailed)
		return ErrAccessNotRestored
	}
	defer func() { _ = w.Rollback(ctx) }()
	if err := recordFailure(ctx, w, addressKey, source, now); err != nil {
		uc.observer.RecoveryCompletionObserved(RecoveryCompletionStoreFailed)
		return ErrAccessNotRestored
	}
	if err := w.Commit(ctx); err != nil {
		uc.observer.RecoveryCompletionObserved(RecoveryCompletionStoreFailed)
	}
	return ErrAccessNotRestored
}
