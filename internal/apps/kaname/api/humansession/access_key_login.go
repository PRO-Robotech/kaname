// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// access_key_login.go — ВХОД БЕЗ ПАРОЛЯ ключом доступа (Ф13, задача
// PRO-Robotech/kaname#613; приёмка
// `docs/engineering/acceptance/passwordless-login-with-access-key.md`, отпечаток
// 5fe6cca1…, Р1…Р4, Р7, Р9, Р10, Р13, Р15).
//
// # Два глагола, два вида формы
//
//	begin — выдаёт испытание, НЕ НАЗВАВ человека: `allowCredentials` пуст,
//	        привязка — контекст формы; сам считается попыткой по источнику;
//	login — принимает утверждение, находит человека по удостоверению,
//	        сверяет рукоятку, выдаёт сессию.
//
// Вид признака у каждого свой (`access-key-begin` · `access-key-login`) — его
// судит транспорт до этого места.
//
// # Почему полоса живёт здесь, а не в своём пакете
//
// Отказ входа ключом обязан быть ПОБАЙТОВО равен отказу входа паролем (Р7), а
// счёт неверных предъявлений — тем же счётом (Р9); обе величины объявлены в
// этом пакете, и второй их держатель разошёлся бы с первым молча.
//
// # Порядок внутри входа — несущий
//
//	форма → частота по источнику → СГОРАНИЕ ИСПЫТАНИЯ → строка удостоверения
//	(нет — приманка) → СВЕРКА ПРОВЕРЯЮЩИМ (всегда) → приговор → сдвиг
//	счётчика → выдача сессии одним исходом
//
// Испытание сгорает ДО приговора и независимо от него (Ф13-08): предъявленное
// не оживает ни отказом подписи, ни отказом рукоятки. Сверка идёт ВСЕГДА — над
// открытым ключом строки либо над приманкой того же семейства (Р7 «л»): работа
// по неизвестному удостоверению стоит столько же, сколько по известному.
//
// # Чего эта полоса не делает
//
// Строки способа «пароль» она не читает и не пишет (Р6); поля второго фактора у
// формы нет (Р5) — лишнее поле отвергает транспорт. Второй сверки утверждения в
// дереве не заводит (Р13): зовёт проверяющего Ф7 `webauthnverify.VerifyAssertion`.

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
	"github.com/PRO-Robotech/kaname/internal/revocationpolicy"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify"
)

// AccessKeyLoginDeps — зависимости обоих глаголов полосы; все обязательны,
// кроме наблюдателя, часов и журнала.
type AccessKeyLoginDeps struct {
	// Store — хранилище сессий: выдача и счёт частоты идут его транзакциями.
	Store Store
	// Keys — испытания полосы, строки ключей и люди по ним.
	Keys AccessKeyLoginStore
	// Methods — подтверждённость адреса для состава ответа (поле то же, что у
	// входа паролем — Ф3-01) и ось «заведено» для обнуления счёта по адресу.
	Methods loginmethod.Store
	// Binding — три ручки посадки Ф7: имя доверяющей стороны, происхождения,
	// алгоритмы. Своих ручек Ф13 не заводит (Р9).
	Binding webauthnverify.Binding
	// ChallengeTTL — срок испытания: та же величина контракта, что у обеих
	// процедур Ф7 (Ф7 §7 инв. 5).
	ChallengeTTL time.Duration
	// UserVerification — требование проверки пользователя, литерал Ф7 Р9.
	UserVerification string
	Limits           Limits
	// TTL — срок выдаваемой сессии (величина профиля, Ф3 Р3).
	TTL      time.Duration
	Observer Observer
	Now      func() time.Time
	// CutoffClock — источник момента аутентификации выдаваемой сессии: тот же,
	// что ставит отсечку отзыва-всех (kaname#589). Обязателен глаголу входа;
	// глагол начала сессии не выдаёт и его не читает.
	CutoffClock revocationpolicy.Clock
	Logger      *slog.Logger
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

func (d AccessKeyLoginDeps) gate() attemptGate {
	return attemptGate{store: d.Store, limits: d.Limits, now: d.Now, observer: d.Observer}
}

// recordSourceAttempt — след по оси источника своей транзакцией: у полосы без
// имени второй оси нет (Р9). Отказ хранилища здесь — клетка, а не отказ
// глагола: попытка не записалась, ответ уже решён.
func (d AccessKeyLoginDeps) recordSourceAttempt(ctx context.Context, source string, at time.Time) {
	if source == "" {
		return
	}
	w, err := d.Store.Writer(ctx)
	if err != nil {
		d.Observer.AccessKeyLoginObserved(AccessKeyLoginStoreFailed)
		return
	}
	defer func() { _ = w.Rollback(ctx) }()
	if err := recordFailure(ctx, w, "", source, at); err != nil {
		d.Observer.AccessKeyLoginObserved(AccessKeyLoginStoreFailed)
		return
	}
	if err := w.Commit(ctx); err != nil {
		d.Observer.AccessKeyLoginObserved(AccessKeyLoginStoreFailed)
	}
}

// BeginAccessKeyLoginInput — контекст формы и адрес источника. Человека вход
// не называет: его ещё нет (Р2).
type BeginAccessKeyLoginInput struct {
	FormContext string
	Source      string
}

// BeginAccessKeyLoginOutput — испытание в форме параметров предъявления
// браузерного интерфейса. `allowCredentials` полем не несётся: обнаружение идёт
// без имени, и транспорт печатает пустой массив СЛОВОМ (Ф13-01).
type BeginAccessKeyLoginOutput struct {
	Challenge        []byte
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
	return &BeginAccessKeyLoginUseCase{deps: d, gate: d.gate()}, nil
}

// Execute — испытание контексту формы.
//
// Выдача испытания — ПОПЫТКА по источнику (Р9): без этого полоса без имени
// давала бы неограниченный рост хранилища испытаний с одного источника, а окна
// по адресу у неё нет by construction.
func (uc *BeginAccessKeyLoginUseCase) Execute(ctx context.Context, in BeginAccessKeyLoginInput) (BeginAccessKeyLoginOutput, error) {
	if in.FormContext == "" {
		return BeginAccessKeyLoginOutput{}, FieldRequired("csrfToken")
	}
	// Контекст приходит печеньем КАК ЕСТЬ, и признак к нему выдаёт любой
	// `GET …/csrf`, поэтому его длина — ввод вызывающего, а не значение службы:
	// свой контекст служба чеканит 43 знаками (`NewFormContext`), и длиннее
	// предела строки испытания он быть не может. Такой контекст — отказ формы
	// здесь, до счёта попытки и до записи; дойди он до хранилища, его отказ
	// записи прочёлся бы отказом хранилища (503) — обвинением службы во вводе
	// клиента.
	if len(in.FormContext) > domain.AccessKeyLoginChallengeContextMax {
		return BeginAccessKeyLoginOutput{}, ErrFormTokenRejected
	}
	if hit, err := uc.gate.check(ctx, "", in.Source); err != nil {
		uc.deps.Observer.AccessKeyLoginObserved(AccessKeyLoginStoreFailed)
		return BeginAccessKeyLoginOutput{}, ErrStoreUnavailable
	} else if hit != nil {
		uc.deps.Observer.AccessKeyLoginObserved(AccessKeyLoginRateLimited)
		uc.deps.Observer.RateLimitObserved(hit.Scope)
		return BeginAccessKeyLoginOutput{}, hit
	}
	raw := make([]byte, domain.AccessKeyChallengeBytes)
	if _, err := rand.Read(raw); err != nil {
		uc.deps.Logger.Error("access key login: random source refused a challenge", "err", err.Error())
		return BeginAccessKeyLoginOutput{}, ErrStoreUnavailable
	}
	if err := uc.deps.Keys.IssueChallenge(ctx, domain.AccessKeyLoginChallenge{Challenge: raw, FormContext: in.FormContext}, uc.deps.ChallengeTTL); err != nil {
		uc.deps.Observer.AccessKeyLoginObserved(AccessKeyLoginStoreFailed)
		return BeginAccessKeyLoginOutput{}, ErrStoreUnavailable
	}
	// Попытка пишется ПОСЛЕ выдачи: отказ хранилища попыткой не является —
	// он наша сторона, а не ввод вызывающего.
	uc.deps.recordSourceAttempt(ctx, in.Source, uc.deps.Now().UTC())
	uc.deps.Observer.AccessKeyLoginObserved(AccessKeyLoginChallengeIssued)
	return BeginAccessKeyLoginOutput{
		Challenge: raw, RPID: uc.deps.Binding.RPID,
		UserVerification: uc.deps.UserVerification, Timeout: uc.deps.ChallengeTTL,
	}, nil
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
	// рукояткой строки безусловно, и отсутствующее значение — отказ ФОРМЫ.
	UserHandle []byte
	Source     string
	// Client — описание клиента выдающего запроса (kaname#634, Р3): идёт в
	// запись выдаваемой сессии и больше никуда.
	Client domain.ClientDescription
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
	if d.CutoffClock == nil {
		return nil, fmt.Errorf("access key login: %w", errNoCutoffClock)
	}
	decoy, err := webauthnverify.NewDecoyKey(d.Binding.Algorithms[0])
	if err != nil {
		return nil, fmt.Errorf("access key login: %w", err)
	}
	return &AccessKeyLoginUseCase{deps: d, gate: d.gate(), decoy: decoy}, nil
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
		// Отказ ФОРМЫ, а не входа: «поля нет» и «ключ не тот» — разные факты
		// (Ф13-07 против Ф13-06 «з»).
		return LoginOutput{}, FieldRequired("credential.response.userHandle")
	}

	// (1) Частота — до всего: отказ по частоте не жжёт испытания и попыткой
	// не считается. Ось одна — источник: адрес человека до сверки неизвестен.
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
	// потребление — один оператор хранилища (ban #10).
	burnt := false
	if cdErr == nil {
		var err error
		burnt, err = uc.deps.Keys.ConsumeChallenge(ctx, cd.Challenge, in.FormContext)
		if err != nil {
			uc.deps.Observer.AccessKeyLoginObserved(AccessKeyLoginStoreFailed)
			return LoginOutput{}, ErrStoreUnavailable
		}
	}

	// (3) Строка удостоверения; её нет — сверка пойдёт над приманкой.
	key, known, err := uc.deps.Keys.KeyByCredentialID(ctx, in.CredentialID)
	if err != nil {
		uc.deps.Observer.AccessKeyLoginObserved(AccessKeyLoginStoreFailed)
		return LoginOutput{}, ErrStoreUnavailable
	}
	pub, alg := key.PublicKey, webauthnverify.Algorithm(key.Algorithm)
	if !known {
		pub, alg = uc.decoy.Public(), uc.decoy.Algorithm()
	}

	// (4) Сверка — ВСЕГДА (Р7 «л»), тем же проверяющим, что Ф7 (Р13).
	var (
		res  webauthnverify.AssertionResult
		verr = cdErr
	)
	if cdErr == nil {
		res, verr = webauthnverify.VerifyAssertion(webauthnverify.AssertionInput{
			Challenge: cd.Challenge, Binding: uc.deps.Binding,
			ClientDataJSON: in.ClientDataJSON, AuthenticatorData: in.AuthenticatorData,
			Signature: in.Signature, PublicKey: pub, Algorithm: alg,
		})
	}

	// (5) Приговор. Порядок ветвей контрактом не является: наружу они
	// неразличимы, внутри различает клетка.
	switch {
	case !burnt:
		return LoginOutput{}, uc.refuse(ctx, AccessKeyLoginChallenge, in.Source, now)
	case !known:
		// Снятый ключ и «удостоверения не было» — одно состояние (Р15).
		return LoginOutput{}, uc.refuse(ctx, AccessKeyLoginCredentialUnknown, in.Source, now)
	case !handleMatches(in.UserHandle, key.UserHandle):
		// Сравнение БЕЗУСЛОВНО: охрану присутствия полосы сессии вход не
		// наследует — там вызывающий уже назван, здесь его называет только
		// рукоятка. Строка без рукоятки совпасть не может.
		return LoginOutput{}, uc.refuse(ctx, AccessKeyLoginUserHandle, in.Source, now)
	case verr != nil:
		return LoginOutput{}, uc.refuse(ctx, assertionRefusalOutcome(verr), in.Source, now)
	}
	if webauthnverify.JudgeCounter(key.SignCount, res.SignCount) == webauthnverify.CounterRegressed {
		return LoginOutput{}, uc.refuse(ctx, AccessKeyLoginCounter, in.Source, now)
	}

	// (6) Человек — владелец строки: его называет ключ (Р3).
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
	// полоса входа для ключа есть предъявление. Проигравший — тот же отказ.
	advanced, err := uc.deps.Keys.AdvanceSignCount(ctx, key.ID, key.SignCount, res.SignCount, now)
	if err != nil {
		uc.deps.Observer.AccessKeyLoginObserved(AccessKeyLoginStoreFailed)
		return LoginOutput{}, ErrStoreUnavailable
	}
	if !advanced {
		return LoginOutput{}, uc.refuse(ctx, AccessKeyLoginCounter, in.Source, now)
	}

	// (8) Выдача — одним исходом.
	out, outcome := uc.issue(ctx, user, key.ID, res.Flags, in.Client)
	switch outcome {
	case issueDone:
		uc.deps.Observer.AccessKeyLoginObserved(AccessKeyLoginIssued)
		return out, nil
	case issueNoRow:
		// Личность удалена после чтения строки ключа: строки ключа больше нет
		// тоже (каскад) — то же состояние, что «удостоверения нет» (Р15).
		return LoginOutput{}, uc.refuse(ctx, AccessKeyLoginCredentialUnknown, in.Source, now)
	case issueBeforeCutoff:
		// Момент входа не позже отсечки личности: доступ снят распорядителем
		// (блокировка, принудительный выход) либо сменой пароля в тот же
		// момент. Клетка — «блокировка»: отказ — о снятом доступе личности, не о
		// ключе; попыткой не считается — предъявление было верным (Ф3 Р3).
		uc.deps.Observer.AccessKeyLoginObserved(AccessKeyLoginBlocked)
		return LoginOutput{}, ErrAuthenticationFailed
	default:
		uc.deps.Observer.AccessKeyLoginObserved(AccessKeyLoginStoreFailed)
		return LoginOutput{}, ErrStoreUnavailable
	}
}

// assertionRefusalOutcome — клетка отказа проверяющего. Отказы без своей
// клетки (форма данных, тип клиентских данных, алгоритм) — клетка «подпись»:
// утверждение не сверено открытым ключом строки (шапка `observer.go`).
func assertionRefusalOutcome(err error) AccessKeyLoginOutcome {
	var r *webauthnverify.Refusal
	if !errors.As(err, &r) {
		return AccessKeyLoginSignature
	}
	switch r.Reason {
	case webauthnverify.ReasonOriginNotAllowed:
		return AccessKeyLoginOrigin
	case webauthnverify.ReasonRPIDHashMismatch:
		return AccessKeyLoginRPIDHash
	case webauthnverify.ReasonUserNotPresent:
		return AccessKeyLoginPresence
	default:
		return AccessKeyLoginSignature
	}
}

// handleMatches — сверка рукоятки: БЕЗУСЛОВНАЯ и в постоянное время. Строка,
// у которой рукоятки нет, совпасть не может (Р3).
func handleMatches(presented, stored []byte) bool {
	if len(stored) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare(presented, stored) == 1
}

// refuse — ЕДИНЫЙ отказ входа (Р7) с записью попытки по источнику. Тот же
// sentinel, что у входа паролем, — поэтому тело ответа побайтово равно Ф3-02
// by construction, а не по совпадению текстов.
func (uc *AccessKeyLoginUseCase) refuse(ctx context.Context, outcome AccessKeyLoginOutcome, source string, now time.Time) error {
	uc.deps.Observer.AccessKeyLoginObserved(outcome)
	uc.deps.recordSourceAttempt(ctx, source, now)
	return ErrAuthenticationFailed
}

// issue — выдача одним исходом: захват строки личности с её отсечкой,
// запись, память первой аутентификации, событие с `id` ключа и решение о счёте
// по адресу — одной транзакцией, в том же порядке замков, что у входа паролем
// (`LoginUseCase.issue`, kaname#382): строка личности — первым оператором,
// иначе выдача шла бы навстречу удалению личности. Уровень вычисляет правило
// Ф11 по флагам ЭТОГО утверждения (Р4): полоса приносит предъявленное.
func (uc *AccessKeyLoginUseCase) issue(ctx context.Context, user domain.User, keyID domain.AccessKeyID,
	flags webauthnverify.Flags, client domain.ClientDescription,
) (LoginOutput, issueOutcome) {
	// Момент сессии — из общего источника (kaname#589), до транзакции выдачи.
	m, err := sharedMoment(ctx, uc.deps.CutoffClock, uc.deps.Logger, "access key login")
	if err != nil {
		return LoginOutput{}, issueFailed
	}
	// Ось «заведено» — ДО транзакции записи (шапка `completed_login.go`).
	enrolled, enrolledKnown := enrollmentBeforeWrite(ctx, uc.deps.Methods, uc.deps.Logger, user.ID)
	w, err := uc.deps.Store.Writer(ctx)
	if err != nil {
		return LoginOutput{}, issueFailed
	}
	defer func() { _ = w.Rollback(ctx) }()
	cutoff, hasCutoff, err := w.LockPersonForLogin(ctx, user.ID)
	switch {
	case errors.Is(err, iamerr.ErrNotFound):
		return LoginOutput{}, issueNoRow
	case err != nil:
		return LoginOutput{}, issueFailed
	case hasCutoff && !m.After(cutoff):
		return LoginOutput{}, issueBeforeCutoff
	}
	s, bearer, err := IssueSession(ctx, w, IssueInput{
		User:        user,
		Presented:   []assurance.Presentation{assurance.KeyAssertion(flags.UserVerified, flags.BackupEligible)},
		At:          m,
		TTL:         uc.deps.TTL,
		EmitAudit:   true,
		AccessKeyID: keyID,
		Client:      client,
	})
	if err != nil {
		return LoginOutput{}, issueFailed
	}
	// Успешный вход обнуляет счёт по адресу человека — как всякий успешный
	// вход (Р9, Ф3 Р10); решает единственный писатель обнуления.
	if err := resetFailuresOnCompletedLogin(ctx, w, completedLogin{
		Enrolled: enrolled, EnrolledKnown: enrolledKnown,
		AddressKey: AddressKey(string(user.Email)), Level: s.AssuranceLevel,
	}); err != nil {
		return LoginOutput{}, issueFailed
	}
	if err := w.Commit(ctx); err != nil {
		return LoginOutput{}, issueFailed
	}
	return LoginOutput{View: SessionView{User: user, Session: s, EmailVerified: uc.emailVerified(ctx, user)}, Bearer: bearer}, issueDone
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
