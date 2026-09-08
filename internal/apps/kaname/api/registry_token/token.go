// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package registry_token — the IAM Docker Registry v2 auth-server use-case:
// authenticate the presented Basic credential and issue a registry token.
//
// # Принимаемый вид удостоверения ОДИН (задача #1143)
//
// Полоса принимает БАЗОВЫЙ ТОКЕН ДОСТУПА Kachō — однострочный секрет с маркой
// продукта (`pkg/credsecret`, задача #1142). Ключевой материал — приватную
// половину пары ключей служебной учётки — она принимала до этой работы и не
// принимает больше: приватная половина не должна ходить по сети и оседать в
// конфигурации клиента, где живёт `docker login`.
//
// Порядок снятия был обязателен и исполнен именно в нём: ввести новый вид
// (#1142) → перевести клиентов и документацию → снять приём (#1143). Обратный
// порядок сломал бы работающий вход раньше, чем появилась замена.
//
// Сужение адресатов, ОБЪЯВЛЕННОЕ ключом при выдаче (#1136/#1184), уходит с той
// полосой, на которой оно жило: у базового токена поля адресатов нет — оно
// отвергается на выдаче. Внешняя граница посадки (`Config.AllowedAudiences`)
// остаётся и остаётся обязательной.
//
// The token carries IDENTITY only (Вариант B): kacho-registry re-checks
// authorization per request against IAM, so no registry scope is embedded.
//
// Clean-arch: this package defines the ports (LocalMinter, AssertionSigner,
// TokenExchanger, basicCredentialResolver) and the use-case; the infra-touching
// halves live behind the ports, wired in the composition root.
package registry_token

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/PRO-Robotech/kacho/pkg/credsecret"
	"github.com/PRO-Robotech/kaname/internal/audiencepolicy"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/registrytoken"
)

// ErrInvalidCredentials — a validator's rejection (bad/unknown/expired/
// unsupported credential). Never surfaced verbatim to the client (no oracle);
// the use-case maps it to ErrUnauthenticated.
var ErrInvalidCredentials = errors.New("registry token: invalid credentials")

// ErrUnauthenticated — the use-case's outward auth-failure. The HTTP handler maps
// it to 401 + WWW-Authenticate (fail-closed; no distinction between missing,
// malformed and rejected credentials, and no distinction between a Hydra
// client/grant rejection and a local reject).
var ErrUnauthenticated = errors.New("registry token: unauthenticated")

// ErrAudienceNotAllowed — заказанный `?service=` вне того, чему эта полоса
// вправе чеканить: либо посадка такого адресата не объявляла, либо ключ
// выдавался не под него (задача #1184).
//
// Отдельный от ErrUnauthenticated исход, потому что чинится в другом месте, и
// отдельный от ErrIssuerUnavailable, потому что повтор его не исправит: издатель
// исправен, а вход валидным не станет никогда. Наружу обработчик отдаёт тот же
// 401-вызов, что и на всяком отказе аутентификации — различимость снаружи была
// бы оракулом; различимость нужна ЖУРНАЛУ, и она здесь.
var ErrAudienceNotAllowed = errors.New("registry token: requested audience is not allowed")

// Credential — личность, проверенная ПРЕЖНЕЙ полосой (ключевой материал).
//
// Живёт только ради окна перехода #1143 и уходит вместе с ним: предикат снятия
// — снятие ручки `api-server.registry-token.key-material-window-until`.
type Credential struct {
	// ClientID — the Hydra OAuth2 client_id; lands in the assertion iss & sub
	// and is the identity the data-plane resolves to a ServiceAccount.
	ClientID string
	// KeyID — the registered JWK kid (the SA-OAuth-client id); the assertion
	// protected-header kid so Hydra selects the right verification key.
	KeyID string
	// Subject — the owning ServiceAccount id (informational / audit).
	Subject string
	// DeclaredAudiences — сужение адресатов, ОБЪЯВЛЕННОЕ заказчиком при выдаче
	// ключа (`IssueSAKeyRequest.audience`, задача #1136). Внутренняя граница
	// выдачи: она говорит, для чего заведён ЭТОТ ключ.
	//
	// Пустой перечень означает «сужения не объявлено», а НЕ «любой адресат»:
	// внешняя граница (`Config.AllowedAudiences`) остаётся и требуется
	// непустой при сборке полосы.
	DeclaredAudiences []string
}

// CredentialValidator — verifies the presented Basic credential (client_id +
// SA-key private PEM) and resolves the assertion identity. An unsupported or
// invalid credential MUST return ErrInvalidCredentials (never a partial-detail
// error that leaks which half was wrong).
//
// Зовётся ТОЛЬКО при открытом окне перехода (#1143); разбор — key_material_window.go.
type CredentialValidator interface {
	Validate(ctx context.Context, clientID, privateKeyPEM string) (Credential, error)
}

// ErrCredentialKindNotAccepted — предъявлен вид удостоверения, которого эта
// полоса не принимает: в поле пароля приехал не базовый токен доступа, а
// что-то другое — прежде всего ключевой материал (задача #1143).
//
// Отдельный от ErrUnauthenticated исход нужен ЖУРНАЛУ и только ему: «клиент
// настроен по-старому» и «секрет неверен» чинятся в разных местах и разными
// людьми, а без этой строки они выглядят одинаково. Наружу обработчик отдаёт
// тот же 401-вызов и то же фиксированное тело — различимость снаружи сказала
// бы предъявителю, как именно разобран его вход, то есть была бы оракулом.
var ErrCredentialKindNotAccepted = errors.New("registry token: the presented credential kind is not accepted on this lane")

// ErrIssuerUnavailable — Hydra (the token issuer, a hard mint-path dependency)
// is unreachable / misbehaving. The handler maps it to 503 (fail-closed): peer
// unavailability must NOT yield a token and must NOT open-fail.
var ErrIssuerUnavailable = errors.New("registry token: issuer unavailable")

// AssertionInput — the RFC 7523 client_assertion parameters.
type AssertionInput struct {
	KeyID         string // protected-header kid.
	ClientID      string // iss & sub.
	Audience      string // aud — the Hydra token endpoint URL.
	PrivateKeyPEM string // the presented EC private key (signs the assertion).
	IssuedAt      int64  // iat — unix seconds.
	ExpiresAt     int64  // exp — unix seconds (short, ≤ MaxAssertionTTL).
	JTI           string // jti — unique assertion id.
}

// AssertionSigner — signs an ES256 client_assertion (JWS) from the presented
// private key. Pure crypto; no infra.
type AssertionSigner interface {
	Sign(in AssertionInput) (string, error)
}

// ExchangeInput — the token exchange request relayed to Hydra.
type ExchangeInput struct {
	ClientAssertion string // the signed ES256 assertion.
	Audience        string // requested token aud (the registry service).
	Scope           string // requested scope (may be empty).
}

// ExchangeOutput — Hydra's access_token relayed to the docker client.
type ExchangeOutput struct {
	AccessToken string
	ExpiresIn   int
}

// TokenExchanger — brokers the `client_credentials` + `private_key_jwt` exchange
// with Hydra. Implementations return ErrIssuerUnavailable when the issuer is
// unreachable (→ 503); any other error is collapsed to ErrUnauthenticated (401).
type TokenExchanger interface {
	Exchange(ctx context.Context, in ExchangeInput) (ExchangeOutput, error)
}

// Config — brokering policy.
type Config struct {
	// AssertionAudience — the `aud` of the client_assertion: the Hydra token
	// endpoint URL Hydra recognises (its external issuer's token endpoint).
	AssertionAudience string
	// AllowedAudiences — адресаты, которым ЭТА полоса вправе чеканить, —
	// внешняя граница выдачи, объявленная посадкой (задача #1184).
	//
	// Пустой перечень означал бы «любой адресат», поэтому сборка полосы его
	// отвергает: предъявитель называл бы себе аудиторию сам.
	AllowedAudiences []string
	// DefaultService — requested token `aud` fallback when ?service= is omitted.
	DefaultService string
	// AssertionTTL — client_assertion lifetime. <=0 or > MaxAssertionTTL is
	// clamped to MaxAssertionTTL.
	AssertionTTL time.Duration
	// Scope — optional scope requested from Hydra (empty → not requested).
	Scope string
	// Anonymous — the configured public-principal identity the shim authenticates
	// as for anonymous pull (RG-1 D-7 / B13). A zero ClientID/PrivateKeyPEM leaves
	// anonymous pull DISABLED (no-Basic-creds → 401 challenge, secure-by-default).
	Anonymous AnonymousIdentity
}

// AnonymousIdentity — the configured public-principal the shim authenticates as
// for anonymous pull. Its Hydra client_id is one the registry data-plane resolves
// to the FGA wildcard AnonymousSubject (`user:*`); the shim holds its signing key
// — NO user/SA credential is presented for the anonymous flow. Because `user:*`
// carries only the per-repo `v_get` wildcard grant emitted for PUBLIC repos, an
// anonymous token can pull a PUBLIC repo but can never write (B13/B14).
type AnonymousIdentity struct {
	// ClientID — the Hydra OAuth2 client_id the shim authenticates as; the
	// data-plane resolves its token to AnonymousSubject.
	ClientID string
	// KeyID — the anon client's registered JWK kid (assertion protected-header).
	KeyID string
	// PrivateKeyPEM — the EC private key the shim signs the anon client_assertion
	// with (IAM-held; never a presented credential).
	PrivateKeyPEM string
}

// MaxAssertionTTL — hard ceiling on the client_assertion lifetime (a short-lived
// bearer proving possession of the SA-key private half).
const MaxAssertionTTL = 60 * time.Second

const (
	// AnonymousSubject — the FGA principal an anonymous (no-credential) docker
	// pull resolves to on the registry data-plane. The anon Hydra client's token
	// is mapped to this wildcard subject; `user:*` holds ONLY the per-repo `v_get`
	// wildcard grant emitted for PUBLIC repositories, so it can pull a PUBLIC repo
	// but can never write (D-7). PRIVATE/absent repos deny uniformly (404).
	AnonymousSubject = "user:*"
	// AnonymousReadScope — the ONLY scope an anonymous token requests: a read
	// (pull) verb. The shim NEVER requests a write/push verb for `user:*` — the
	// read-only floor is enforced HERE (IAM half) AND by the data-plane FGA Check
	// on `user:*` (which carries no write relation). A push with an anon token is
	// therefore denied (403 DENIED) even in a pull-able PUBLIC repo (B14).
	AnonymousReadScope = "registry:pull"
)

// IssueInput — the parsed docker token request.
type IssueInput struct {
	// Username — Basic-auth user. Обязан совпадать с идентификатором, который
	// несёт сама строка секрета: разбор ниже это сверяет.
	Username string
	// Password — Basic-auth pass. ЕДИНСТВЕННЫЙ принимаемый вид — базовый токен
	// доступа Kachō (строка с маркой `credsecret.Mark`). Ключевой материал
	// здесь больше не принимается (#1143).
	Password string
	Service  string // ?service= — the registry service name (→ requested aud).

	// ConfirmationX5TS256 — отпечаток ПРОВЕРЕННОГО клиентского сертификата,
	// предъявленного на хопе выдачи (RFC 8705, Ф1б #926).
	//
	// Это МАТЕРИАЛ, а не пожелание вызывающего: значение выводит транспорт из
	// проверенной цепочки, и предъявитель его не выбирает. Пусто означает
	// «материал не предъявляли» — токен выходит предъявительским, и это
	// законно: привязка не появляется там, где её не просили.
	ConfirmationX5TS256 string
}

// IssueOutput — the Docker-compatible token response payload.
type IssueOutput struct {
	Token     string // the Hydra-issued access_token.
	ExpiresIn int    // seconds until exp (from Hydra).
	IssuedAt  int64  // unix seconds (informational).
}

// IssueRegistryTokenUseCase — verify the SA-key, sign a client_assertion, and
// broker a Hydra token.
type IssueRegistryTokenUseCase struct {
	cfg       Config
	signer    AssertionSigner
	exchanger TokenExchanger
	// minter — НАШ подписант. nil означает «контур ещё на прежнем издателе»;
	// это законное состояние до перевода, а не полусобранная зависимость.
	minter LocalMinter
	// basicResolver — авторитет о предъявленном базовом секрете (#1142).
	// nil → полосы нет.
	basicResolver basicCredentialResolver
	// kmValidator/kmWindowUntil — ОКНО ПЕРЕХОДА #1143: проверяющий прежней
	// полосы и мгновение, до которого она принимается. Разбор, цена обоих
	// умолчаний и предикат снятия — key_material_window.go. Порознь не
	// заполняются: их ставит один вызов WithKeyMaterialWindow.
	kmValidator   CredentialValidator
	kmWindowUntil time.Time
	// kindObserver — счётчик исходов полос. nil → счёта нет.
	kindObserver CredentialKindObserver
	now          func() time.Time
	jti          func() (string, error)
}

// NewIssueRegistryTokenUseCase — builder. AssertionTTL is clamped to
// (0, MaxAssertionTTL].
//
// Подписант и обмен остаются параметрами: их зовёт АНОНИМНЫЙ поток на контуре,
// ещё не переведённом на нашу чеканку. Полоса предъявленного удостоверения ими
// не пользуется — подписывать утверждение нечем: ключевого материала у
// принимаемого вида не существует.
func NewIssueRegistryTokenUseCase(cfg Config, s AssertionSigner, ex TokenExchanger) *IssueRegistryTokenUseCase {
	if cfg.AssertionTTL <= 0 || cfg.AssertionTTL > MaxAssertionTTL {
		cfg.AssertionTTL = MaxAssertionTTL
	}
	return &IssueRegistryTokenUseCase{
		cfg:       cfg,
		signer:    s,
		exchanger: ex,
		now:       time.Now,
		jti:       registrytoken.NewJTI,
	}
}

// WithClock overrides the clock (tests / deterministic exp).
func (u *IssueRegistryTokenUseCase) WithClock(now func() time.Time) *IssueRegistryTokenUseCase {
	u.now = now
	return u
}

// WithJTIFunc overrides the jti generator (tests).
func (u *IssueRegistryTokenUseCase) WithJTIFunc(f func() (string, error)) *IssueRegistryTokenUseCase {
	u.jti = f
	return u
}

// Execute выдаёт удостоверение реестра по предъявленному Basic-удостоверению.
//
// Принимаемый вид ОДИН — базовый токен доступа Kachō. Всё прочее в поле пароля
// отвергается ЯВНО и до любого обращения к авторитету: ключевой материал,
// который эта полоса принимала до задачи #1143, среди прочего.
//
// Отсутствие удостоверения даёт ErrUnauthenticated (fail-closed); недоступный
// издатель — ErrIssuerUnavailable (503, без токена).
func (u *IssueRegistryTokenUseCase) Execute(ctx context.Context, in IssueInput) (IssueOutput, error) {
	if in.Username == "" || in.Password == "" {
		return IssueOutput{}, ErrUnauthenticated
	}

	// Классификация — ПО МАРКЕ в поле пароля, а не по неудаче разбора чего-то
	// другого: путь, срабатывающий на неудаче, превратил бы всякий негодный
	// вход во вход соседней полосы, а снятый приём — в тихий запасной путь.
	if !credsecret.HasMark(in.Password) {
		// ОКНО ПЕРЕХОДА (#1143). Открыто — прежний вид принимается, пока
		// оператор переводит клиентов; закрыто либо истекло — отвергается.
		// Спрашивается на КАЖДОМ запросе: окно закрывает время, а не
		// перезапуск. Разбор и цена умолчания — key_material_window.go.
		if u.keyMaterialWindowOpen() {
			return u.executeKeyMaterialInWindow(ctx, in)
		}
		// ЛОМАЮЩЕЕ ИЗМЕНЕНИЕ, объявленное задачей #1143: клиент, настроенный на
		// прежний вход, получает отказ. Причина уходит в журнал; наружу —
		// единый 401-вызов с фиксированным телом, называющим годный вид.
		//
		// Счёт ЗДЕСЬ, а не в журнале: вопрос оператора количественный —
		// «скольких я ещё не перевёл». Ноль по этому исходу вместе с ненулевым
		// знаменателем и означает, что окно больше никому не нужно.
		u.observeKind(OutcomeKeyMaterialRefused)
		return IssueOutput{}, fmt.Errorf("%w: %w", ErrUnauthenticated, ErrCredentialKindNotAccepted)
	}
	if u.basicResolver == nil {
		// Полоса собрана без авторитета — отвечать по существу нечем.
		// Fail-closed недоступностью издателя, а не отказом в удостоверении:
		// предъявитель ни при чём, и повтор после починки сборки осмыслен.
		return IssueOutput{}, fmt.Errorf(
			"%w: the basic-credential authority is not wired — this lane cannot answer for the presented credential",
			ErrIssuerUnavailable)
	}
	return u.executeBasic(ctx, in)
}

// basicCredentialResolver — порт авторитета о предъявленном базовом секрете.
type basicCredentialResolver interface {
	ResolveBasic(ctx context.Context, presented string) (domain.BasicCredential, error)
}

// WithBasicCredentialResolver провязывает полосу базового секрета.
//
// nil → отвечать по существу нечем, и Execute отдаёт НЕДОСТУПНОСТЬ ИЗДАТЕЛЯ, а
// не отказ в удостоверении: предъявитель ни при чём, и повтор после починки
// сборки осмыслен. Это посадка ДО появления авторитета, а не мягкий проход.
//
// (Здесь стояло «строка с нашей маркой уходит валидатору ключевого материала,
// где отвергается как негодный PEM» — верно до задачи #1143 и неверно после:
// того запасного пути в Execute нет, и комментарий про безопасность,
// противоречащий коду, провоцирует «починку» кода под себя.)
func (u *IssueRegistryTokenUseCase) WithBasicCredentialResolver(r basicCredentialResolver) *IssueRegistryTokenUseCase {
	u.basicResolver = r
	return u
}

// executeBasic — вход в реестр базовым секретом.
//
// ─────────────────────────────────────────────────────────────────────────────
// ИМЯ ОБЯЗАТЕЛЬНО И ОБЯЗАНО СОВПАДАТЬ — АСИММЕТРИЯ С КРАЕМ ОБЪЯВЛЕНА
//
// На крае личность несёт САМА строка, и второго поля не требуется. Протокол
// докера требует непустого имени и хранит пару целиком; поля, которое можно не
// заполнять, у него нет. Из трёх законных исходов выбран третий:
//
//	имя игнорируется       — «принято-и-проигнорировано», запрещено прямо;
//	имя — постоянный литерал — журнал и история команд перестают говорить,
//	                          КАКОЕ удостоверение в игре;
//	имя = идентификатор     — ✔ выбран.
//
// Это НЕ второе написание одного значения: идентификатор хранится в ОДНОМ
// месте — в строке реестра; на входе он предъявляется дважды НА ОДНОЙ
// поверхности. Роль второго предъявления та же, что у контрольной суммы:
// перепутанная вставка отвергается сразу и внятно.
//
// Цена названа: пользователь копирует два значения вместо одного. Отказ при
// расхождении ДОСЛОВНО ТОТ ЖЕ, что при неверном секрете, — иначе имя стало бы
// оракулом существования.
func (u *IssueRegistryTokenUseCase) executeBasic(ctx context.Context, in IssueInput) (IssueOutput, error) {
	p, perr := credsecret.Parse(in.Password)
	if perr != nil || p.CredentialID != in.Username {
		return IssueOutput{}, ErrUnauthenticated
	}

	cred, rerr := u.basicResolver.ResolveBasic(ctx, in.Password)
	if rerr != nil {
		if errors.Is(rerr, domain.ErrBasicCredentialRefused) {
			return IssueOutput{}, ErrUnauthenticated
		}
		// Недоступность авторитета — НЕ отказ в удостоверении: предъявитель ни
		// при чём, и повтор осмыслен.
		return IssueOutput{}, fmt.Errorf("%w: %w", ErrIssuerUnavailable, rerr)
	}
	if cred.PrincipalType != "service_account" || cred.PrincipalID == "" {
		// Докерная полоса выдаёт удостоверение реестра машинному принципалу.
		// Вид, не принимаемый ЭТОЙ поверхностью, отвергается ТЕМ ЖЕ отказом.
		return IssueOutput{}, ErrUnauthenticated
	}

	// Адресат решается ПОСЛЕ проверки: перечень адресатов — сведение о посадке,
	// и отвечать им неаутентифицированному незачем. Сужения на самом секрете
	// нет (поле адресатов у этого вида отвергается на выдаче), поэтому здесь
	// действует только внешняя граница посадки.
	service, aerr := u.resolveAudience(cred.PrincipalID, in.Service)
	if aerr != nil {
		return IssueOutput{}, aerr
	}

	// Обмена НЕТ и быть не может: подписывать утверждение нечем — ключевого
	// материала у этого вида не существует. Значит токен обязан чеканить НАШ
	// подписант; непереведённый контур честно отвечает недоступностью издателя,
	// а не тихо отдаёт что-нибудь.
	if !u.mintsLocally() {
		return IssueOutput{}, fmt.Errorf(
			"%w: basic credential requires our own minting — there is no key material to sign an assertion with",
			ErrIssuerUnavailable)
	}
	out, merr := u.minter.MintToken(ctx, MintInput{
		Subject:  cred.PrincipalID,
		Audience: service,
		Scope:    u.cfg.Scope,
		// Материала привязки у предъявительского вида нет НИКОГДА, и пустое
		// здесь — объявление, а не пропуск.
	})
	if merr != nil {
		return IssueOutput{}, fmt.Errorf("%w: %w", ErrIssuerUnavailable, merr)
	}
	// ЗНАМЕНАТЕЛЬ. Без него ноль отказов прежнему виду неотличим от полосы,
	// не обслужившей ни одного входа вообще.
	u.observeKind(OutcomeBasicAccepted)
	return IssueOutput{Token: out.AccessToken, ExpiresIn: out.ExpiresIn, IssuedAt: u.now().Unix()}, nil
}

// executeKeyMaterialInWindow — ПРЕЖНЯЯ полоса, доступная только через открытое
// окно перехода (#1143). Тело восстановлено ДОСЛОВНО из ревизии до снятия:
// окно обязано принимать ровно то, что принимала прежняя полоса, а не
// «похожее». Уходит вместе с ручкой окна одним изменением.
func (u *IssueRegistryTokenUseCase) executeKeyMaterialInWindow(ctx context.Context, in IssueInput) (IssueOutput, error) {
	cred, err := u.kmValidator.Validate(ctx, in.Username, in.Password)
	if err != nil || cred.ClientID == "" || cred.KeyID == "" {
		// Collapse every validator error to ErrUnauthenticated — the client must
		// not learn whether the subject exists or which half of the credential
		// was wrong (no auth oracle).
		//
		// Счёта здесь НЕТ намеренно: предъявлен прежний вид, окно его приняло,
		// и отказ этот — «негодные учётные данные», а не «вид не принимается».
		// Смешав их, мы получили бы счётчик отказов вида, растущий на обычном
		// переборе пароля, — то есть тревогу без предмета.
		return IssueOutput{}, ErrUnauthenticated
	}

	// Адресат — ИЗ ЗАПРОСА, в пределах объявленного ПОСАДКОЙ перечня,
	// сужённого тем, что объявил при выдаче сам КЛЮЧ (#1136/#1184).
	// Решается ПОСЛЕ проверки учётных данных: перечень адресатов — сведение о
	// посадке, и отвечать им неаутентифицированному незачем.
	service, err := u.resolveAudienceDeclared(cred.Subject, cred.DeclaredAudiences, in.Service)
	if err != nil {
		return IssueOutput{}, err
	}
	now := u.now()

	// Контур переведён на НАШУ чеканку — токен выпускает наш подписант, и
	// утверждение для прежнего издателя не строится вовсе.
	if u.mintsLocally() {
		out, merr := u.minter.MintToken(ctx, MintInput{
			Subject:  cred.Subject,
			Audience: service,
			Scope:    u.cfg.Scope,
			// Материал привязки — ровно тот, что предъявлен транспортом.
			ConfirmationX5TS256: in.ConfirmationX5TS256,
		})
		if merr != nil {
			// Неисправность СВОЕЙ чеканки — недоступность издателя, а не
			// негодные учётные данные: предъявитель ни при чём, и повтор
			// осмыслен.
			return IssueOutput{}, fmt.Errorf("%w: %w", ErrIssuerUnavailable, merr)
		}
		u.observeKind(OutcomeKeyMaterialAcceptedInWindow)
		return IssueOutput{Token: out.AccessToken, ExpiresIn: out.ExpiresIn, IssuedAt: now.Unix()}, nil
	}

	jti, jerr := u.jti()
	if jerr != nil {
		return IssueOutput{}, jerr
	}
	assertion, serr := u.signer.Sign(AssertionInput{
		KeyID:         cred.KeyID,
		ClientID:      cred.ClientID,
		Audience:      u.cfg.AssertionAudience,
		PrivateKeyPEM: in.Password,
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(u.cfg.AssertionTTL).Unix(),
		JTI:           jti,
	})
	if serr != nil {
		// The presented key could not sign — treat as an invalid credential
		// (fail-closed 401), never leaking the crypto failure detail.
		return IssueOutput{}, ErrUnauthenticated
	}

	out, xerr := u.exchanger.Exchange(ctx, ExchangeInput{
		ClientAssertion: assertion,
		Audience:        service,
		Scope:           u.cfg.Scope,
	})
	if xerr != nil {
		if errors.Is(xerr, ErrIssuerUnavailable) {
			// Причина ОБОРАЧИВАЕТСЯ: наружу обработчик всё равно отдаст
			// фиксированное тело, а вот в журнал без неё не уходило бы ничего.
			return IssueOutput{}, fmt.Errorf("%w: %w", ErrIssuerUnavailable, xerr)
		}
		// Провайдер отверг обмен (негодный/истёкший/отозванный ключ) — 401.
		return IssueOutput{}, ErrUnauthenticated
	}
	u.observeKind(OutcomeKeyMaterialAcceptedInWindow)
	return IssueOutput{Token: out.AccessToken, ExpiresIn: out.ExpiresIn, IssuedAt: now.Unix()}, nil
}

// AnonymousEnabled reports whether anonymous-pull issuance is configured. When
// false the shim MUST fall back to the 401 Bearer challenge (secure-by-default:
// anonymous pull is opt-in and requires a configured anon identity + its key).
func (u *IssueRegistryTokenUseCase) AnonymousEnabled() bool {
	return u.cfg.Anonymous.ClientID != "" && u.cfg.Anonymous.PrivateKeyPEM != ""
}

// ExecuteAnonymous brokers a short-lived, read-only Bearer for the public
// AnonymousSubject principal — the docker anonymous-pull flow (no Basic creds,
// RG-1 B13). It signs a client_assertion AS the configured anonymous identity
// (whose token the data-plane resolves to `user:*`) and exchanges it with Hydra
// requesting the registry data-plane audience and the read-only AnonymousReadScope
// — NEVER a write verb (B14). No user/SA credential is validated: an anonymous
// caller is the wildcard principal, not a specific subject. Bounded TTL is
// inherited from the assertion clamp + the anon Hydra client's configured token
// lifespan (RG-1 introduces no new expiry mechanism).
//
// A missing/rejected exchange yields ErrUnauthenticated (→ 401 challenge); an
// unreachable issuer yields ErrIssuerUnavailable (→ 503, no token). Anonymous
// pull being unconfigured also fails closed (ErrUnauthenticated → 401).
func (u *IssueRegistryTokenUseCase) ExecuteAnonymous(ctx context.Context, service string) (IssueOutput, error) {
	if !u.AnonymousEnabled() {
		// Anonymous pull not configured → fail-closed (handler issues 401).
		return IssueOutput{}, ErrUnauthenticated
	}

	// Сужения ключа здесь нет ПО ПОСТРОЕНИЮ — учётных данных не предъявляли, —
	// поэтому остаётся внешняя граница. Она действует и тут: анонимный поток
	// той же полосы адресата себе не назначает.
	service, err := u.resolveAudience(u.cfg.Anonymous.ClientID, service)
	if err != nil {
		return IssueOutput{}, err
	}
	now := u.now()

	// Анонимный поток переводится тем же решением: два издателя на ОДНОМ
	// контуре означали бы, что приёмная сторона обязана держать обе записи
	// ради одного и того же реестра.
	if u.mintsLocally() {
		out, merr := u.minter.MintToken(ctx, MintInput{
			Subject:  u.cfg.Anonymous.ClientID,
			Audience: service,
			// Пол чтения энфорсится ЗДЕСЬ и приёмной стороной: анонимный
			// токен никогда не просит глагола записи.
			Scope: AnonymousReadScope,
		})
		if merr != nil {
			return IssueOutput{}, fmt.Errorf("%w: %w", ErrIssuerUnavailable, merr)
		}
		return IssueOutput{Token: out.AccessToken, ExpiresIn: out.ExpiresIn, IssuedAt: now.Unix()}, nil
	}

	jti, err := u.jti()
	if err != nil {
		return IssueOutput{}, err
	}
	assertion, err := u.signer.Sign(AssertionInput{
		KeyID:         u.cfg.Anonymous.KeyID,
		ClientID:      u.cfg.Anonymous.ClientID,
		Audience:      u.cfg.AssertionAudience,
		PrivateKeyPEM: u.cfg.Anonymous.PrivateKeyPEM,
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(u.cfg.AssertionTTL).Unix(),
		JTI:           jti,
	})
	if err != nil {
		// The anon key could not sign — fail-closed 401, never leaking the detail.
		return IssueOutput{}, ErrUnauthenticated
	}

	out, err := u.exchanger.Exchange(ctx, ExchangeInput{
		ClientAssertion: assertion,
		Audience:        service,
		// Read-only floor — the anon token NEVER requests a write/push verb (B14).
		Scope: AnonymousReadScope,
	})
	if err != nil {
		if errors.Is(err, ErrIssuerUnavailable) {
			return IssueOutput{}, ErrIssuerUnavailable
		}
		// Hydra rejected the anon exchange — fail-closed 401.
		return IssueOutput{}, ErrUnauthenticated
	}
	return IssueOutput{
		Token:     out.AccessToken,
		ExpiresIn: out.ExpiresIn,
		IssuedAt:  now.Unix(),
	}, nil
}

// resolveAudience выбирает адресат выпускаемого токена докерной полосы.
//
// # Почему предикат общий, а не свой
//
// Полос выдачи по ключу служебной учётки ДВЕ, и до задачи #1184 сверка
// действовала на одной: эта писалась под фиксированный адресат реестра, и
// значение `?service=` уезжало в адресат токена как есть — то есть предъявитель
// называл себе аудиторию сам. Расхождение никто не решал.
//
// Копия предиката здесь разошлась бы с соседней снова и разошлась бы молча:
// обе полосы по отдельности выглядят исправными, неверна их РАЗНИЦА. Поэтому
// решение принимает `audiencepolicy`, а здесь остаётся перевод входа и исхода.
//
// # Сужения, объявленного удостоверением, здесь больше нет
//
// Внутренняя граница (`Declared`) жила на ключе служебной учётки и уехала
// вместе с полосой, которая ключи принимала (#1143): у базового токена поля
// адресатов нет — оно отвергается на выдаче, — а анонимный поток удостоверения
// не предъявляет вовсе. Остаётся внешняя граница посадки, и она обязательна:
// сборка полосы без неё отвергается.
//
// # Почему пустой `?service=` — законный вход
//
// Докер-клиент шлёт то, что назвал ему реестр в вызове на аутентификацию, но
// параметр по протоколу необязателен. Пустое значение означает «не назвал», и
// адресат берётся из сужения ключа, а при его отсутствии — из умолчания
// посадки. Подставлять умолчание ДО этого места нельзя: тогда ключ, объявивший
// своё назначение, получал бы чужой адресат и отвергался собственной проверкой.
func (u *IssueRegistryTokenUseCase) resolveAudience(subject, requested string) (string, error) {
	// Declared намеренно пуст: см. разбор выше. Пустой перечень тут —
	// объявление «сужения не бывает у этого вида», а не пропуск.
	return u.resolveAudienceDeclared(subject, nil, requested)
}

// resolveAudienceDeclared — тот же резолв, но с сужением, ОБЪЯВЛЕННЫМ ключом
// при выдаче (#1136). Зовётся прежней полосой из окна перехода #1143: сужение
// приезжает той же строкой реестра, что и ключевой материал, и уронить его
// значило бы задним числом снять то, что объявил заказчик.
//
// Реализация ОДНА на обе полосы: свойство, обязательное для одной, держится
// общим источником, а не одинаковой проверкой в двух местах.
func (u *IssueRegistryTokenUseCase) resolveAudienceDeclared(subject string, declared []string, requested string) (string, error) {
	var want []string
	if requested != "" {
		want = []string{requested}
	}
	out, err := audiencepolicy.Resolve(audiencepolicy.Scope{
		Landing:  u.cfg.AllowedAudiences,
		Default:  u.cfg.DefaultService,
		Declared: declared,
		Subject:  subject,
	}, want)
	if err != nil {
		// Причина ОБОРАЧИВАЕТСЯ: наружу уйдёт единый 401-вызов, а в журнал —
		// то, какая из двух границ отвергла. Голый sentinel здесь означал бы
		// пересказ собственного решения об отказе.
		return "", fmt.Errorf("%w: %w", ErrAudienceNotAllowed, err)
	}
	// Заказан был один адресат либо ни одного, поэтому и вернулся ровно один:
	// перечень выдачи докерной полосы одноэлементен по форме запроса.
	return out[0], nil
}
