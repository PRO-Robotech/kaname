// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// access_key_login.go — ВХОД БЕЗ ПАРОЛЯ ключом доступа (Ф13; задача
// PRO-Robotech/kacho#1282; приёмка
// `docs/engineering/acceptance/passwordless-login-with-access-key.md`,
// Р1…Р3, Р7, Р9, Р10, Р13).
//
// # Два глагола одной формы
//
//	begin — выдаёт испытание, НЕ НАЗВАВ человека: `allowCredentials` пуст,
//	        привязка — контекст формы;
//	login — принимает утверждение, находит человека по удостоверению,
//	        сверяет рукоятку, выдаёт сессию.
//
// # Почему полоса живёт здесь, а не в своём пакете
//
// Отказ входа ключом обязан быть ПОБАЙТОВО равен отказу входа паролём (Р7), а
// счёт неверных предъявлений — тем же счётом (Р9). Обе величины объявлены в
// этом пакете, и второй их держатель разошёлся бы с первым молча: каждая
// полоса по отдельности защитима, неверна их РАЗНИЦА, а разницу не видит ни
// проба одной полосы, ни проба другой.
//
// # Порядок внутри входа — несущий
//
//	форма (транспорт) → частота по источнику → СГОРАНИЕ ИСПЫТАНИЯ → строка
//	удостоверения (нет — приманка) → СВЕРКА ПРОВЕРЯЮЩИМ (всегда, даже когда
//	испытание негодно и удостоверение неизвестно) → приговор → сдвиг счётчика
//	→ выдача сессии одним исходом
//
// Испытание сгорает ДО приговора и независимо от него (Ф13-08): предъявленное
// не оживает ни отказом подписи, ни отказом рукоятки. Реализация, гасящая
// испытание только на успехе, зеленела бы на повторе годного и краснела бы
// лишь на «годное после негодного» — эта ветвь и названа в приёмке.
//
// Сверка идёт ВСЕГДА — над настоящим открытым ключом строки либо над приманкой
// того же семейства (Р7 «л»): иначе работа по неизвестному удостоверению
// стоила бы меньше, чем по известному, и разница отвечала бы на вопрос, на
// который ответ и скрывается.
//
// # Чего эта полоса не делает
//
// Строки способа «пароль» она не читает и не пишет: полосы независимы (Р6),
// и «откат к паролю» — свойство двух полос, а не механизм. Поля второго
// фактора у формы нет (Р5): лишнее поле отвергает разбор формы.

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/loginmethod"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify"
)

// AccessKeyLoginDeps — зависимости обоих глаголов полосы; все обязательны,
// кроме наблюдателя, часов и журнала.
type AccessKeyLoginDeps struct {
	// Store — хранилище сессий: выдача идёт его транзакцией (Д10).
	Store Store
	// Keys — испытания полосы, строки ключей и люди по ним.
	Keys AccessKeyLoginStore
	// Methods — подтверждённость адреса для состава ответа: ТОТ ЖЕ порт, что
	// у входа паролём, потому что поле ответа то же (Ф3-01).
	Methods loginmethod.Store
	// Binding — три ручки посадки Ф7: имя доверяющей стороны, происхождения,
	// алгоритмы. Своих ручек Ф13 не заводит (§7 инв. 5).
	Binding webauthnverify.Binding
	// ChallengeTTL — срок испытания: та же величина контракта, что у обеих
	// процедур Ф7. Третья процедура своей величины не заводит.
	ChallengeTTL time.Duration
	// UserVerification — требование проверки пользователя, литерал Ф7.
	UserVerification string
	Limits           Limits
	// TTL — срок выдаваемой сессии (величина профиля, Р3 Ф3).
	TTL      time.Duration
	Observer Observer
	Now      func() time.Time
	Logger   *slog.Logger
}

func (d AccessKeyLoginDeps) validate(verb string) (AccessKeyLoginDeps, error) {
	switch {
	case d.Store == nil:
		return d, fmt.Errorf("%s: session store required", verb)
	case d.Keys == nil:
		return d, fmt.Errorf("%s: access key store required", verb)
	case d.Methods == nil:
		return d, fmt.Errorf("%s: login method store required", verb)
	case d.Binding.RPID == "":
		return d, fmt.Errorf("%s: relying party id required", verb)
	case d.Binding.Origins == nil:
		return d, fmt.Errorf("%s: origin list required (empty list means nobody, nil means undeclared)", verb)
	case len(d.Binding.Algorithms) == 0:
		return d, fmt.Errorf("%s: algorithm list required", verb)
	case d.ChallengeTTL <= 0:
		return d, fmt.Errorf("%s: challenge ttl must be positive", verb)
	case d.UserVerification == "":
		return d, fmt.Errorf("%s: user verification literal required", verb)
	case d.TTL <= 0:
		return d, fmt.Errorf("%s: session ttl must be positive", verb)
	}
	if err := d.Limits.Validate(); err != nil {
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

// BeginAccessKeyLoginInput — контекст формы и адрес источника. Человека вход
// не называет: его ещё нет (Р2).
type BeginAccessKeyLoginInput struct {
	FormContext string
	Source      string
}

// BeginAccessKeyLoginOutput — испытание в форме `PublicKeyCredentialRequestOptions`.
// `AllowCredentials` отсутствует как ПОЛЕ у ответа: обнаружение идёт без имени,
// и транспорт печатает пустой массив СЛОВОМ (Ф13-01) — «никого не ограничивать»
// есть факт, а не умолчание.
type BeginAccessKeyLoginOutput struct {
	Challenge        []byte
	ExpiresAt        time.Time
	RPID             string
	UserVerification string
	// Timeout — срок испытания, как его назовёт браузеру транспорт.
	Timeout time.Duration
}

// BeginAccessKeyLoginUseCase — выдача испытания полосы входа.
type BeginAccessKeyLoginUseCase struct {
	deps AccessKeyLoginDeps
	gate attemptGate
}

// NewBeginAccessKeyLoginUseCase — построение с проверкой зависимостей.
func NewBeginAccessKeyLoginUseCase(d AccessKeyLoginDeps) (*BeginAccessKeyLoginUseCase, error) {
	d, err := d.validate("access key login begin")
	if err != nil {
		return nil, err
	}
	return &BeginAccessKeyLoginUseCase{
		deps: d,
		gate: attemptGate{store: d.Store, limits: d.Limits, now: d.Now, observer: d.Observer},
	}, nil
}

// Execute — испытание контексту формы.
//
// Выдача испытания — ПОПЫТКА по источнику (Р9): без этого полоса без имени
// давала бы неограниченный поток испытаний с одного адреса, а окна по адресу у
// неё нет by construction — адрес человека станет известен только после сверки.
// Окно по адресу здесь не спрашивается и не пишется.
func (uc *BeginAccessKeyLoginUseCase) Execute(ctx context.Context, in BeginAccessKeyLoginInput) (BeginAccessKeyLoginOutput, error) {
	if in.FormContext == "" {
		// Контекста нет — признак формы не мог подойти, и транспорт до сюда не
		// доводит; проверка оставлена как отказ построения запроса, а не как
		// вторая проверка признака.
		return BeginAccessKeyLoginOutput{}, FieldRequired("csrfToken")
	}
	if hit, err := uc.gate.check(ctx, "", in.Source); err != nil {
		uc.deps.Observer.AccessKeyLoginObserved(AccessKeyLoginStoreFailed)
		return BeginAccessKeyLoginOutput{}, ErrStoreUnavailable
	} else if hit != nil {
		uc.deps.Observer.AccessKeyLoginObserved(AccessKeyLoginRateLimited)
		uc.deps.Observer.RateLimitObserved(hit.Scope)
		return BeginAccessKeyLoginOutput{}, hit
	}
	now := uc.deps.Now().UTC()
	raw := make([]byte, domain.AccessKeyChallengeBytes)
	if _, err := rand.Read(raw); err != nil {
		uc.deps.Logger.Error("access key login: random source refused a challenge", "err", err.Error())
		return BeginAccessKeyLoginOutput{}, ErrStoreUnavailable
	}
	ch := domain.AccessKeyLoginChallenge{
		Challenge: raw, FormContext: in.FormContext, IssuedAt: now, ExpiresAt: now.Add(uc.deps.ChallengeTTL),
	}
	if err := ch.Validate(); err != nil {
		return BeginAccessKeyLoginOutput{}, err
	}
	if err := uc.deps.Keys.IssueChallenge(ctx, ch); err != nil {
		uc.deps.Observer.AccessKeyLoginObserved(AccessKeyLoginStoreFailed)
		return BeginAccessKeyLoginOutput{}, ErrStoreUnavailable
	}
	// Попытка по источнику пишется ПОСЛЕ выдачи: отказ хранилища попыткой не
	// является — он наша сторона, а не ввод вызывающего.
	uc.recordSourceAttempt(ctx, in.Source, now)
	uc.deps.Observer.AccessKeyLoginObserved(AccessKeyLoginChallengeIssued)
	return BeginAccessKeyLoginOutput{
		Challenge: raw, ExpiresAt: ch.ExpiresAt, RPID: uc.deps.Binding.RPID,
		UserVerification: uc.deps.UserVerification, Timeout: uc.deps.ChallengeTTL,
	}, nil
}

// recordSourceAttempt — след по оси источника своей транзакцией: у полосы без
// имени второй оси нет.
func (uc *BeginAccessKeyLoginUseCase) recordSourceAttempt(ctx context.Context, source string, at time.Time) {
	if source == "" {
		return
	}
	w, err := uc.deps.Store.Writer(ctx)
	if err != nil {
		uc.deps.Observer.AccessKeyLoginObserved(AccessKeyLoginStoreFailed)
		return
	}
	defer func() { _ = w.Rollback(ctx) }()
	if err := w.RecordFailure(ctx, FailureBySource, source, at); err != nil {
		uc.deps.Observer.AccessKeyLoginObserved(AccessKeyLoginStoreFailed)
		return
	}
	if err := w.Commit(ctx); err != nil {
		uc.deps.Observer.AccessKeyLoginObserved(AccessKeyLoginStoreFailed)
	}
}

// AccessKeyLoginInput — утверждение в байтах браузера и контекст запроса.
// Форму (поля, лишние поля, base64url) судит транспорт; сюда приходят байты.
type AccessKeyLoginInput struct {
	FormContext       string
	CredentialID      []byte
	ClientDataJSON    []byte
	AuthenticatorData []byte
	Signature         []byte
	// UserHandle — рукоятка, ОБЯЗАТЕЛЬНАЯ у этой формы (Р3): сравнение с
	// рукояткой строки безусловно, поэтому отсутствующее значение сравнивать
	// не с чем, и это отказ ФОРМЫ, а не отказ входа.
	UserHandle []byte
	Source     string
}

// AccessKeyLoginUseCase — вход ключом.
type AccessKeyLoginUseCase struct {
	deps  AccessKeyLoginDeps
	gate  attemptGate
	decoy webauthnverify.DecoyKey
}

// NewAccessKeyLoginUseCase — построение с проверкой зависимостей и приманкой
// выравнивания времени того же семейства, что первое объявленное посадкой.
func NewAccessKeyLoginUseCase(d AccessKeyLoginDeps) (*AccessKeyLoginUseCase, error) {
	d, err := d.validate("access key login")
	if err != nil {
		return nil, err
	}
	decoy, err := webauthnverify.NewDecoyKey(d.Binding.Algorithms[0])
	if err != nil {
		return nil, fmt.Errorf("access key login: %w", err)
	}
	return &AccessKeyLoginUseCase{
		deps:  d,
		gate:  attemptGate{store: d.Store, limits: d.Limits, now: d.Now, observer: d.Observer},
		decoy: decoy,
	}, nil
}

// Execute — вход.
func (uc *AccessKeyLoginUseCase) Execute(ctx context.Context, in AccessKeyLoginInput) (LoginOutput, error) {
	switch {
	case in.FormContext == "":
		return LoginOutput{}, FieldRequired("csrfToken")
	case len(in.CredentialID) == 0:
		return LoginOutput{}, FieldRequired("credential.id")
	case len(in.ClientDataJSON) == 0:
		return LoginOutput{}, FieldRequired("credential.response.clientDataJSON")
	case len(in.AuthenticatorData) == 0:
		return LoginOutput{}, FieldRequired("credential.response.authenticatorData")
	case len(in.Signature) == 0:
		return LoginOutput{}, FieldRequired("credential.response.signature")
	case len(in.UserHandle) == 0:
		// Отказ ФОРМЫ, а не входа: поле не прислано, сверять нечего. Отличать
		// его от несовпавшей рукоятки обязательно — иначе «поля нет» и «ключ
		// не тот» стали бы одним фактом, и клиент, забывший поле, получал бы
		// ответ о чужом ключе (Ф13-07 против Ф13-06 «з»).
		return LoginOutput{}, FieldRequired("credential.response.userHandle")
	}

	// (1) Частота — до всего: отказ по частоте не жжёт испытания и попыткой не
	// считается. Ось одна — источник: адрес человека до сверки неизвестен.
	if hit, err := uc.gate.check(ctx, "", in.Source); err != nil {
		uc.deps.Observer.AccessKeyLoginObserved(AccessKeyLoginStoreFailed)
		return LoginOutput{}, ErrStoreUnavailable
	} else if hit != nil {
		uc.deps.Observer.AccessKeyLoginObserved(AccessKeyLoginRateLimited)
		uc.deps.Observer.RateLimitObserved(hit.Scope)
		return LoginOutput{}, hit
	}

	now := uc.deps.Now().UTC()
	cd, cdErr := webauthnverify.ParseClientData(in.ClientDataJSON)

	// (2) СГОРАНИЕ — до приговора и независимо от него (Ф13-08). Годность и
	// потребление — один оператор: «посмотреть, живо ли, и погасить» под
	// конкуренцией дало бы два прохода по одному испытанию (ban #10).
	burnt := false
	if cdErr == nil {
		var err error
		burnt, err = uc.deps.Keys.ConsumeChallenge(ctx, cd.Challenge, in.FormContext, now)
		if err != nil {
			uc.deps.Observer.AccessKeyLoginObserved(AccessKeyLoginStoreFailed)
			return LoginOutput{}, ErrStoreUnavailable
		}
	}

	// (3) Строка удостоверения; её нет — сверка пойдёт над приманкой, чтобы
	// стоить столько же (Р7 «л»).
	key, known, err := uc.deps.Keys.KeyByCredentialID(ctx, in.CredentialID)
	if err != nil {
		uc.deps.Observer.AccessKeyLoginObserved(AccessKeyLoginStoreFailed)
		return LoginOutput{}, ErrStoreUnavailable
	}
	pub, alg := key.PublicKey, webauthnverify.Algorithm(key.Algorithm)
	if !known {
		pub, alg = uc.decoy.Public(), uc.decoy.Algorithm()
	}

	// (4) Сверка — ВСЕГДА, включая негодное испытание и неизвестное
	// удостоверение: отказ обязан прийти после той же работы.
	var verr error
	var res webauthnverify.AssertionResult
	if cdErr != nil {
		verr = cdErr
	} else {
		res, verr = webauthnverify.VerifyAssertion(webauthnverify.AssertionInput{
			Challenge: cd.Challenge, Binding: uc.deps.Binding,
			ClientDataJSON: in.ClientDataJSON, AuthenticatorData: in.AuthenticatorData,
			Signature: in.Signature, PublicKey: pub, Algorithm: alg,
		})
	}

	// (5) Приговор. Порядок ветвей контрактом не является: наружу они
	// неразличимы, а внутри различает клетка счётчика.
	switch {
	case !burnt:
		return LoginOutput{}, uc.refuse(ctx, AccessKeyLoginChallengeRefused, in.Source, now)
	case !known:
		// Снятый ключ и «удостоверения не было» — одно состояние (Р15).
		return LoginOutput{}, uc.refuse(ctx, AccessKeyLoginCredentialUnknown, in.Source, now)
	case !handleMatches(in.UserHandle, key.UserHandle):
		// Сравнение БЕЗУСЛОВНО: охрану присутствия полосы сессии вход не
		// наследует — там вызывающий уже назван, здесь его называет только
		// эта рукоятка. Строка без рукоятки совпасть не может.
		return LoginOutput{}, uc.refuse(ctx, AccessKeyLoginUserHandle, in.Source, now)
	case verr != nil:
		return LoginOutput{}, uc.refuse(ctx, AccessKeyLoginAssertionRefused, in.Source, now)
	}
	if webauthnverify.JudgeCounter(key.SignCount, res.SignCount) == webauthnverify.CounterRegressed {
		return LoginOutput{}, uc.refuse(ctx, AccessKeyLoginCounter, in.Source, now)
	}

	// (6) Человек — владелец строки: его называет ключ, а не вызывающий (Р3).
	user, err := uc.deps.Keys.UserOf(ctx, key.UserID)
	switch {
	case errors.Is(err, iamerr.ErrNotFound):
		return LoginOutput{}, uc.refuse(ctx, AccessKeyLoginCredentialUnknown, in.Source, now)
	case err != nil:
		uc.deps.Observer.AccessKeyLoginObserved(AccessKeyLoginStoreFailed)
		return LoginOutput{}, ErrStoreUnavailable
	case user.InviteStatus != domain.InviteStatusActive:
		return LoginOutput{}, uc.refuse(ctx, AccessKeyLoginBlocked, in.Source, now)
	}

	// (7) Сдвиг счётчика — атомарный, с условием на прежнее значение (Ф7 Р6):
	// полоса входа для ключа есть предъявление. Проигравший конкуренции
	// получает тот же один отказ.
	advanced, err := uc.deps.Keys.AdvanceSignCount(ctx, key.ID, key.SignCount, res.SignCount, now)
	if err != nil {
		uc.deps.Observer.AccessKeyLoginObserved(AccessKeyLoginStoreFailed)
		return LoginOutput{}, ErrStoreUnavailable
	}
	if !advanced {
		return LoginOutput{}, uc.refuse(ctx, AccessKeyLoginCounterRace, in.Source, now)
	}

	// (8) Выдача — одним исходом: запись, память первой аутентификации,
	// событие и обнуление счёта по адресу человека (адрес известен только
	// теперь — Р9).
	out, err := uc.issue(ctx, user, key.ID, res.Flags, now)
	if err != nil {
		uc.deps.Observer.AccessKeyLoginObserved(AccessKeyLoginStoreFailed)
		return LoginOutput{}, ErrStoreUnavailable
	}
	uc.deps.Observer.AccessKeyLoginObserved(AccessKeyLoginIssued)
	return out, nil
}

// handleMatches — сверка рукоятки: БЕЗУСЛОВНАЯ и в постоянное время. Строка,
// у которой рукоятки нет, совпасть не может — «пропустить сверку» исходом не
// является (Р3).
func handleMatches(presented, stored []byte) bool {
	if len(stored) == 0 {
		return false
	}
	// Длины сравнение и так различает (`ConstantTimeCompare` на разной длине
	// отвечает 0), поэтому отдельной ветви под них нет: вторая проверка того
	// же факта — лишняя работа, которую следующий читатель примет за смысл.
	return subtle.ConstantTimeCompare(presented, stored) == 1
}

// refuse — ЕДИНЫЙ отказ входа (Р7) с записью попытки по источнику. Тот же
// sentinel, что у входа паролём, — поэтому тело ответа побайтово равно Ф3-02
// by construction, а не по совпадению текстов.
func (uc *AccessKeyLoginUseCase) refuse(ctx context.Context, outcome AccessKeyLoginOutcome, source string, now time.Time) error {
	uc.deps.Observer.AccessKeyLoginObserved(outcome)
	if source == "" {
		return ErrAuthenticationFailed
	}
	w, err := uc.deps.Store.Writer(ctx)
	if err != nil {
		uc.deps.Observer.AccessKeyLoginObserved(AccessKeyLoginStoreFailed)
		return ErrAuthenticationFailed
	}
	defer func() { _ = w.Rollback(ctx) }()
	if err := w.RecordFailure(ctx, FailureBySource, source, now); err != nil {
		uc.deps.Observer.AccessKeyLoginObserved(AccessKeyLoginStoreFailed)
		return ErrAuthenticationFailed
	}
	if err := w.Commit(ctx); err != nil {
		uc.deps.Observer.AccessKeyLoginObserved(AccessKeyLoginStoreFailed)
	}
	return ErrAuthenticationFailed
}

// issue — выдача одним исходом. Уровень вычисляет правило Ф11 по флагам ЭТОГО
// утверждения: полоса не приносит уровня и не знает его — она приносит
// предъявленное.
func (uc *AccessKeyLoginUseCase) issue(ctx context.Context, user domain.User, keyID domain.AccessKeyID,
	flags webauthnverify.Flags, now time.Time) (LoginOutput, error) {
	w, err := uc.deps.Store.Writer(ctx)
	if err != nil {
		return LoginOutput{}, err
	}
	defer func() { _ = w.Rollback(ctx) }()
	s, bearer, err := IssueSession(ctx, w, IssueInput{
		User:        user,
		Presented:   []assurance.Presentation{assurance.KeyAssertion(flags.UserVerified, flags.BackupEligible)},
		At:          now,
		TTL:         uc.deps.TTL,
		EmitAudit:   true,
		AccessKeyID: keyID,
	})
	if err != nil {
		return LoginOutput{}, err
	}
	// Успешный вход обнуляет счёт по адресу человека — как всякий успешный
	// вход (Ф3 Р10). Счёт по источнику успех не трогает.
	if err := w.ResetFailures(ctx, FailureByAddress, AddressKey(string(user.Email))); err != nil {
		return LoginOutput{}, err
	}
	if err := w.Commit(ctx); err != nil {
		return LoginOutput{}, err
	}
	return LoginOutput{View: SessionView{User: user, Session: s, EmailVerified: uc.emailVerified(ctx, user)}, Bearer: bearer}, nil
}

// emailVerified — подтверждённость адреса для ответа. Источник не ответил —
// честнее сказать «не подтверждён», чем не ответить вовсе: сессия уже выдана.
func (uc *AccessKeyLoginUseCase) emailVerified(ctx context.Context, user domain.User) bool {
	_, verified, err := uc.deps.Methods.EmailVerification(ctx, user.ID)
	if err != nil {
		uc.deps.Logger.Error("access key login: e-mail verification state unreadable after issue", "err", err.Error())
		return false
	}
	return verified
}
