// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package clientassertion — принимающая сторона аутентификации клиента
// подписанным утверждением (RFC 7523 §2.2, задача #898).
//
// # Чем эта сторона отличается от предъявляющей
//
// Утверждение этого вида дерево уже подписывает и предъявляет; вся та работа
// стоит на стороне КЛИЕНТА. Здесь заводится сторона СЕРВЕРА, и цена ошибки у неё
// противоположна: у предъявителя неверное утверждение даёт отказ, видимый
// сразу, — у принимающего неверная проверка даёт ПРИНЯТОЕ ЧУЖОЕ утверждение, не
// видимое никогда. Успешная аутентификация выглядит одинаково независимо от
// того, что именно она проверила.
//
// Отсюда правило работ, которому подчинён весь порядок ниже: на каждой развилке,
// где неясно, отвергать или пропускать, выбирается ОТВЕРГАТЬ.
//
// # Почему разбор идёт над той же библиотекой, а не своей
//
// Стеков разбора JOSE в дереве и без нас несколько, и решения, принятые здесь
// (закрытый словарь алгоритмов, отказ на подмену алгоритма, дублирующееся имя
// члена заголовка, член, помеченный обязательным к пониманию), доехали бы
// только до одного из них. Второй библиотеки «ради удобства утверждения» не
// заводится: проверки, которых библиотека не делает, добавляются шагом НАД ней.
//
// # Что здесь делается ДО библиотеки и почему именно это
//
// Три вещи библиотека не делает by construction, и каждая из них — отказ:
//
//  1. **имя члена заголовка дважды.** Разбор объектной записи, встретив имя
//     дважды, берёт одно из значений и не возражает. Два значения одного члена
//     означают, что проверяющий и подписант МОГЛИ ПРОЧИТАТЬ РАЗНОЕ, а значит
//     проверенной оказалась не та половина (RFC 7515 §5.2);
//  2. **член, помеченный обязательным к пониманию.** Пометка означает «без
//     понимания этого члена подпись нельзя считать проверенной». Принять —
//     значит объявить проверенным то, чего не поняли;
//  3. **встроенный ключевой материал.** Ключ выбирается ТОЛЬКО из реестра;
//     перечень членов, из которых он выбираться не может, объявлен в
//     pkg/tokenpolicy одним местом.
package clientassertion

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
)

// presenterResponse — опознавательное слово стандартной формы, которое видит
// предъявитель.
//
// ОДНО И ТО ЖЕ для всех исходов отказа: нет такого клиента · клиент есть, но
// подпись не сошлась · алгоритм не тот · срок истёк · утверждение уже
// предъявлялось · владелец не активен. Различимый отказ есть ОРАКУЛ: по нему
// устанавливают, существует ли клиент, жив ли он, какой у него алгоритм и какие
// идентификаторы однократности уже заняты. Каждый ответ сам по себе безобиден, а
// вместе они дают карту.
//
// Различимость обязана существовать — но С ДРУГОЙ СТОРОНЫ ПРОВОДА: в журнале и в
// счётчиках, у каждого исхода свой.
const presenterResponse = "invalid_client"

// Outcome — исход проверки. Закрытый словарь: у КАЖДОГО значения свой счётчик,
// иначе мёртвый контроль невидим — проверка, не отказавшая ни разу за всё время
// жизни, неотличима от проверки, которая работает и просто не встречала
// нарушителя.
type Outcome string

const (
	OutcomeAccepted               Outcome = "accepted"
	OutcomeAssertionTypeMismatch  Outcome = "assertion-type-mismatch"
	OutcomeMalformedSerialization Outcome = "malformed-serialization"
	OutcomeDuplicateHeaderMember  Outcome = "duplicate-header-member"
	OutcomeUnsupportedCritical    Outcome = "unsupported-critical-member"
	// #nosec G101 -- машинный ПРИЗНАК ПРИЧИНЫ ОТКАЗА, уезжающий в журнал и в
	// счётчик, а не секрет: значения этого словаря наружу не выходят вовсе,
	// потому что ответ предъявителю у всех исходов один.
	OutcomeTokenTypeMismatch   Outcome = "token-type-mismatch"
	OutcomeAlgorithmNotAllowed Outcome = "algorithm-not-allowed"
	OutcomeAlgorithmMismatch   Outcome = "algorithm-mismatch"
	OutcomeIdentityMismatch    Outcome = "identity-mismatch"
	OutcomeClientUnknown       Outcome = "client-unknown"
	OutcomeClientCannotAssert  Outcome = "client-cannot-assert"
	// OutcomeIssuerUntrusted — пара (издатель, субъект) не резолвится в нашем
	// перечне доверенных издателей. Один исход на все состояния «мы за это не
	// ручаемся»: различимые дали бы предъявителю оракул состава перечня.
	OutcomeIssuerUntrusted Outcome = "issuer-untrusted"
	// OutcomeTrustExpired — запись доверия найдена, её срок истёк. Отдельный
	// счётчик от предыдущего: «доверия не было» и «доверие кончилось» суть
	// разные события эксплуатации, и слитые в один счётчик они делают
	// истечение невидимым.
	OutcomeTrustExpired           Outcome = "issuer-trust-expired"
	OutcomeSignatureMismatch      Outcome = "signature-mismatch"
	OutcomeAudienceMismatch       Outcome = "audience-mismatch"
	OutcomeExpiryMissing          Outcome = "expiry-missing"
	OutcomeIssuedAtMissing        Outcome = "issued-at-missing"
	OutcomeIssuedAtInFuture       Outcome = "issued-at-in-future"
	OutcomeLifetimeAboveCeiling   Outcome = "lifetime-above-ceiling"
	OutcomeExpired                Outcome = "expired"
	OutcomeNotYetValid            Outcome = "not-yet-valid"
	OutcomeAssertionIDMissing     Outcome = "assertion-id-missing"
	OutcomeReplayed               Outcome = "replayed"
	OutcomeRegistryUnavailable    Outcome = "registry-unavailable"
	OutcomeReplayStoreUnavailable Outcome = "replay-store-unavailable"

	// Исходы ниже производит НЕ проверяющий, а эндпоинт и выдача. Они живут в
	// этом же закрытом словаре намеренно: перечень исходов есть перечень
	// СЧЁТЧИКОВ, и разложи мы его по двум местам — «у каждого исхода свой
	// счётчик» перестало бы быть проверяемым одним предикатом, а исход,
	// заведённый в одном месте и забытый в другом, остался бы без счётчика.
	// Мёртвый контроль тогда снова стал бы невидимым.

	// OutcomeMethodNotAllowed — обращение методом, отличным от объявленного.
	OutcomeMethodNotAllowed Outcome = "method-not-allowed"
	// OutcomeBodyAboveCeiling — объявленная длина либо само тело сверх потолка.
	OutcomeBodyAboveCeiling Outcome = "body-above-ceiling"
	// OutcomeMalformedRequest — тело не разбирается как форма запроса.
	OutcomeMalformedRequest Outcome = "malformed-request"
	// OutcomeMultipleAssertions — параметр с утверждением встретился дважды.
	// «Ровно одно утверждение» есть требование к НАШЕМУ разбору, а не описание
	// намерения клиента.
	OutcomeMultipleAssertions Outcome = "multiple-assertions"
	// OutcomeUnsupportedGrantType — вид выдачи вне закрытого перечня.
	OutcomeUnsupportedGrantType Outcome = "unsupported-grant-type"
	// OutcomeAudienceNotAllowed — запрошенный адресат вне объявленного
	// конфигурацией перечня адресатов платформы.
	OutcomeAudienceNotAllowed Outcome = "requested-audience-not-allowed"
	// OutcomeClientExpired — срок клиента истёк.
	OutcomeClientExpired Outcome = "client-expired"
	// OutcomeOwnerNotActive — владелец клиента не в состоянии ACTIVE.
	OutcomeOwnerNotActive Outcome = "owner-not-active"
	// OutcomeIssuanceFailed — аутентификация прошла, выпуск не состоялся.
	OutcomeIssuanceFailed Outcome = "issuance-failed"
)

// Outcomes возвращает закрытый словарь исходов целиком.
//
// ВЫВОДИТСЯ отсюда всяким, кому нужен перечень: набор счётчиков, проба переписи,
// текст отказа. Вторая копия словаря разошлась бы молча, и разошлась бы она в
// сторону «исход без счётчика» — то есть в сторону невидимости.
func Outcomes() []Outcome {
	return []Outcome{
		OutcomeAccepted,
		OutcomeAssertionTypeMismatch,
		OutcomeMalformedSerialization,
		OutcomeDuplicateHeaderMember,
		OutcomeUnsupportedCritical,
		OutcomeTokenTypeMismatch,
		OutcomeAlgorithmNotAllowed,
		OutcomeAlgorithmMismatch,
		OutcomeIdentityMismatch,
		OutcomeClientUnknown,
		OutcomeClientCannotAssert,
		OutcomeIssuerUntrusted,
		OutcomeTrustExpired,
		OutcomeSignatureMismatch,
		OutcomeAudienceMismatch,
		OutcomeExpiryMissing,
		OutcomeIssuedAtMissing,
		OutcomeIssuedAtInFuture,
		OutcomeLifetimeAboveCeiling,
		OutcomeExpired,
		OutcomeNotYetValid,
		OutcomeAssertionIDMissing,
		OutcomeReplayed,
		OutcomeRegistryUnavailable,
		OutcomeReplayStoreUnavailable,
		OutcomeMethodNotAllowed,
		OutcomeBodyAboveCeiling,
		OutcomeMalformedRequest,
		OutcomeMultipleAssertions,
		OutcomeUnsupportedGrantType,
		OutcomeAudienceNotAllowed,
		OutcomeClientExpired,
		OutcomeOwnerNotActive,
		OutcomeIssuanceFailed,
	}
}

// Refuse собирает отказ названного исхода за пределами проверяющего — на
// эндпоинте и на выдаче.
//
// Экспортирована, чтобы отказ СОБИРАЛСЯ ОДНИМ СПОСОБОМ везде: вторая сборка
// разошлась бы с этой в том, что видит предъявитель, и разошлась бы молча.
func Refuse(o Outcome, format string, args ...any) (Result, error) { return refuse(o, format, args...) }

// PresenterResponseFor — опознавательное слово стандартной формы.
//
// Одно и то же для ВСЕХ исходов отказа аутентификации. Функция, а не константа:
// вызывающему нужен именно ответ, а не строка, и подмена одного другим на
// каком-то из путей была бы ровно тем расхождением, которого мы избегаем.
func PresenterResponseFor(Outcome) string { return presenterResponse }

// Result — исход проверки вместе с тем, что вправе узнать вызывающий.
type Result struct {
	// Outcome — что именно решило исход. Для ЖУРНАЛА и СЧЁТЧИКА, никогда для
	// ответа предъявителю.
	Outcome Outcome
	// Client — разрешённая строка реестра. Заполняется только при приёме.
	Client domain.AssertionClient
	// AssertionID — погашенный идентификатор однократности.
	AssertionID string
	// ExpiresAt — момент истечения предъявленного утверждения.
	ExpiresAt time.Time
}

// PresenterResponse — опознавательное слово, которое уходит предъявителю.
//
// Метод, а не поле: поле пришлось бы заполнять на каждом пути отказа, и путь,
// забывший его заполнить, отдавал бы пустую строку — то есть отличался бы от
// остальных ровно тем, чего мы избегаем.
func (r Result) PresenterResponse() string { return presenterResponse }

// Policy — объявленная настройка проверяющего.
//
// Каждое поле ОБЯЗАТЕЛЬНО, и это не педантизм: незаданный ожидаемый адресат
// означает «принимаем любой», незаданный потолок длительности — «любую»,
// неподанные часы — «читаем окружение». Пустое значение здесь означает «не
// сужаем», а не «по умолчанию».
type Policy struct {
	// ExpectedAudience — идентификатор НАШЕГО издателя. Единственная
	// принимаемая форма адресата утверждения.
	ExpectedAudience string
	// MaxLifetime — потолок разницы «срок − момент выпуска» на полосе клиента.
	MaxLifetime time.Duration
	// MaxFederatedLifetime — тот же потолок на федеративной полосе.
	//
	// Отдельное поле, а не то же число: утверждение полосы клиента выписывает
	// НАШ клиент специально для нас и вправе дать ему минуты, а внешний
	// издатель выпускает своей нагрузке токен со своим сроком и о нашем
	// потолке не знает. Одно число на две полосы означало бы либо отказ
	// каждому внешнему издателю, либо месячное окно у собственного клиента.
	MaxFederatedLifetime time.Duration
	// ClockSkew — допуск расхождения часов. Действует на ОБЕ стороны: и на
	// истечение, и на момент выпуска в будущем.
	ClockSkew time.Duration
	// Clock — источник времени. Вход, а не окружение: граничные сценарии
	// (ровно в момент истечения, ровно в момент начала действия) на системных
	// часах поставить нельзя вовсе, и их отсутствие неотличимо от полноты.
	Clock func() time.Time
}

// ClientResolver — порт реестра, СПОСОБНОГО к утверждению.
//
// «Способного» здесь несущее слово: разрешение идёт только по таблицам,
// несущим ключевой материал. Вид клиента, у которого нет способа доказать
// владение ключом by construction, не резолвится ни во что, и отказ наступает
// на том же шаге, что для несуществующего.
type ClientResolver interface {
	ResolveAssertionClient(ctx context.Context, clientID string) (domain.AssertionClient, error)
}

// TrustedIssuerResolver — порт НАШЕГО перечня доверенных издателей.
//
// Возвращает и запись доверия, и строку, которую она уполномочивает, ОДНИМ
// обращением. Два обращения дали бы разную длительность ответа у пары, дошедшей
// до второго чтения, и у пары, отвергнутой на первом, — то есть оракул,
// сообщающий, доверен ли издатель, ничего не отвечая по существу.
type TrustedIssuerResolver interface {
	ResolveTrustedIssuer(ctx context.Context, issuer, subject string) (
		domain.TrustedIssuer, domain.AssertionClient, error)
}

// ReplayGuard — порт однократности.
type ReplayGuard interface {
	Redeem(ctx context.Context, clientID, assertionID string, expiresAt time.Time) error
}

// Verifier — проверяющий утверждение клиента.
type Verifier struct {
	policy  Policy
	clients ClientResolver
	issuers TrustedIssuerResolver
	replay  ReplayGuard
}

// New строит проверяющего. Неполная настройка — ОТКАЗ ПОСТРОЕНИЯ.
//
// Проверяющий, собранный наполовину, принимал бы утверждения, которые обязан
// отвергнуть, — и узналось бы это не на старте, а на первом принятом чужом
// предъявлении, то есть никогда.
func New(p Policy, clients ClientResolver, issuers TrustedIssuerResolver, replay ReplayGuard) (*Verifier, error) {
	switch {
	case strings.TrimSpace(p.ExpectedAudience) == "":
		return nil, fmt.Errorf("clientassertion: expected audience is required (empty means 'accept any')")
	case p.MaxLifetime <= 0:
		return nil, fmt.Errorf("clientassertion: assertion lifetime ceiling must be declared as a positive number")
	case p.MaxFederatedLifetime <= 0:
		return nil, fmt.Errorf("clientassertion: federated assertion lifetime ceiling must be declared as a positive number")
	case p.ClockSkew < 0:
		return nil, fmt.Errorf("clientassertion: clock skew allowance must not be negative")
	case p.Clock == nil:
		return nil, fmt.Errorf("clientassertion: clock is required (time source is an input, not the environment)")
	case clients == nil:
		return nil, fmt.Errorf("clientassertion: client resolver is required")
	case issuers == nil:
		// Проверяющий без перечня доверенных издателей не «работает без
		// федерации»: он отвергает КАЖДОЕ федеративное утверждение, и посадка,
		// забывшая провязать перечень, выглядит исправной. Возможность,
		// объявленная и не работающая ни при каком входе, — это отказ
		// построения, а не режим.
		return nil, fmt.Errorf("clientassertion: trusted issuer resolver is required " +
			"(a verifier without one refuses every federated assertion while looking healthy)")
	case replay == nil:
		return nil, fmt.Errorf("clientassertion: replay guard is required")
	}
	return &Verifier{policy: p, clients: clients, issuers: issuers, replay: replay}, nil
}

// refuse собирает отказ. Ответ предъявителю у всех исходов один; различает их
// только исход, уезжающий в журнал и счётчик.
func refuse(o Outcome, format string, args ...any) (Result, error) {
	return Result{Outcome: o}, fmt.Errorf("clientassertion [%s]: "+format, append([]any{o}, args...)...)
}

// Verify проверяет предъявленное утверждение.
//
// # Порядок проверок — часть решения, а не деталь
//
// Он выбран так, чтобы дорогое стояло после дешёвого, а решения о ключе — после
// того, как ключ разрешён по РЕЕСТРУ:
//
//	вид предъявления → форма → заголовок (дубли · пометки · ТИП) → алгоритм
//	словаря → личность → реестр → алгоритм КЛИЕНТА → подпись → адресат →
//	время → однократность
//
// Две границы в нём несущие. Сверка алгоритма с ЗАРЕГИСТРИРОВАННЫМ у клиента
// стоит ДО проверки подписи: перечень допустимых алгоритмов строится из строки
// реестра, никогда из заголовка предъявленного утверждения. И погашение
// однократности стоит ПОСЛЕДНИМ: гасить идентификатор утверждения, которое всё
// равно будет отвергнуто, значило бы дать предъявителю способ занимать чужие
// ключи ненадёжными утверждениями.
func (v *Verifier) Verify(ctx context.Context, assertionType, raw string) (Result, error) {
	// (1) Вид предъявления сравнивается ТОЧНО. Сравнение строк простое, без
	// нормализации: отличие регистром либо хвостовым пробелом — тоже отказ.
	if assertionType != tokenpolicy.ClientAssertionType {
		return refuse(OutcomeAssertionTypeMismatch, "declared assertion type is not the one named by the standard")
	}

	// (2)-(4) Форма, дублирующиеся имена членов и пометка «обязателен к
	// пониманию». Общее для ОБЕИХ полос — см. decodeEnvelope.
	env, res, err := decodeEnvelope(raw)
	if err != nil {
		return res, err
	}
	header := env.header

	// (5) Объявленный тип. ПЕРВЫЙ из трёх независимых признаков, отделяющих
	// утверждение клиента от токена доступа: с этой фазы один издатель работает
	// с обоими видами подписанного, и различать их обязано КАЖДОЕ из трёх, а не
	// какое-то одно (§2.6 приёмки F2).
	//
	// Тип требуется ЯВНО, и отсутствие типа отказом не прощается. Производитель
	// типа на этой полосе — не мы, а предъявитель, поэтому «типа нет» было бы
	// для него самым дешёвым способом снять признак целиком: принимая
	// отсутствие, мы объявили бы признаком то, что снимается пропуском поля.
	//
	// Сравнение точное, без нормализации: значение объявлено в pkg/tokenpolicy
	// рядом с типом токена доступа, и попарная различность двух объявлений есть
	// предмет отдельного утверждения — совпади они, признак исчез бы молча, а
	// положительный путь обоих видов остался бы зелёным.
	typ, err := stringMember(header, "typ")
	if err != nil || typ != tokenpolicy.TokenTypeClientAssertion {
		return refuse(OutcomeTokenTypeMismatch, "header does not declare the client-assertion type")
	}

	// (6) Алгоритм заголовка — из закрытого словаря. Общее для обеих полос.
	alg, res, err := declaredAlgorithm(header)
	if err != nil {
		return res, err
	}

	// Встроенный ключевой материал ключ НЕ ВЫБИРАЕТ — мы его попросту не
	// читаем. Ключ будет взят из реестра ниже, и это единственный его источник.

	claims, res, err := decodeClaims(env.payloadBytes)
	if err != nil {
		return res, err
	}

	// (7) Личность. Издатель и субъект обязаны совпадать между собой и оба
	// назвать НАШ идентификатор клиента. Сравнение простое, без нормализации и
	// без учёта регистра.
	issuer, errIss := stringMember(claims, "iss")
	subject, errSub := stringMember(claims, "sub")
	if errIss != nil || errSub != nil || issuer == "" || subject == "" || issuer != subject {
		return refuse(OutcomeIdentityMismatch, "issuer and subject must agree and both name the client")
	}

	// (8) Разрешение клиента по реестру. Зеркальное значение (идентификатор во
	// внешнем сервере) на этом пути НЕ УЧАСТВУЕТ вовсе — ни как второй ключ
	// поиска, ни как запасной.
	client, err := v.clients.ResolveAssertionClient(ctx, issuer)
	switch {
	case domain.IsAssertionClientUnknown(err):
		return refuse(OutcomeClientUnknown, "client does not resolve")
	case err != nil:
		// Недоступность реестра — ОТКАЗ, никогда «пропустить». Реестр лежит на
		// пути АУТЕНТИФИКАЦИИ, и мягкий проход здесь означал бы приём
		// утверждения, которое мы не проверяли ничем.
		return refuse(OutcomeRegistryUnavailable, "registry is unavailable: %v", err)
	}

	// (9) Пустой зарегистрированный алгоритм — законный вход схемы, и означает
	// он «ключа нет», а НЕ «любой алгоритм».
	if !client.CanPresentAssertion() {
		return refuse(OutcomeClientCannotAssert, "client carries no registered key material")
	}

	// (10) Алгоритм заголовка обязан равняться ЗАРЕГИСТРИРОВАННОМУ у клиента, и
	// сверка эта стоит ДО проверки подписи.
	//
	// Реализация, выбирающая проверяющего ПО ТИПУ КЛЮЧА, этой сверки не делает
	// и предмета для неё не имеет: у неё «подпись сошлась» уже означает «ключ
	// подошёл». У нас перечень допустимых алгоритмов строится из строки
	// реестра, поэтому подмена параметра внутри одного семейства (тот же ключ,
	// иной параметр) тоже отвергается.
	if alg != client.Algorithm {
		return refuse(OutcomeAlgorithmMismatch, "declared algorithm is not the one registered for this client")
	}

	pub, err := parsePublicKey(client.PublicKeyPEM)
	if err != nil {
		// Непригодный зарегистрированный ключ — это НАША неисправность, а не
		// вина предъявителя, но исход для него тот же: принять утверждение,
		// которое нечем проверить, нельзя.
		return refuse(OutcomeClientCannotAssert, "registered key material is unusable: %v", err)
	}

	// (11) Подпись. Разбор — той же библиотекой, что у прочих поверхностей
	// приёма; её собственная проверка утверждений ОТКЛЮЧЕНА намеренно, и это
	// решение, а не упущение: каждый исход ниже обязан иметь СВОЙ счётчик, а
	// библиотека сводит несколько разных отказов в один. Ни одна проверка при
	// этом не теряется — все они стоят ниже явными ветками.
	if _, err := jwt.Parse(raw,
		func(*jwt.Token) (any, error) { return pub, nil },
		jwt.WithValidMethods([]string{client.Algorithm}),
		jwt.WithoutClaimsValidation(),
	); err != nil {
		return refuse(OutcomeSignatureMismatch, "signature does not verify against the registered key")
	}

	// (12)-(15) Адресат, время, однократность. Общее для обеих полос — см.
	// admit. Потолок длительности подаётся полосой: он у них РАЗНЫЙ.
	return v.admit(ctx, claims, client, v.policy.MaxLifetime)
}

// admit — общий хвост обеих полос: адресат, время, однократность, погашение.
//
// # Почему он общий, а не выписан у каждой полосы
//
// Это ровно те проверки, различие в которых не видно: обе полосы по отдельности
// выглядели бы полными, а расхождение вылезло бы у той, которую реже читают.
// Полоса подаёт сюда ДВЕ вещи, которые у неё свои, — разрешённую строку и
// потолок длительности; всё остальное обязано совпадать дословно.
func (v *Verifier) admit(
	ctx context.Context,
	claims map[string]json.RawMessage,
	client domain.AssertionClient,
	maxLifetime time.Duration,
) (Result, error) {
	// (12) Адресат — идентификатор нашего издателя. Адрес эндпоинта в этом
	// качестве отвергается: он не одна строка, а несколько.
	if !audienceContains(claims, v.policy.ExpectedAudience) {
		return refuse(OutcomeAudienceMismatch, "audience is not our issuer identifier")
	}

	// (13) Время. Обязательность каждого поля включена ЯВНО: разбор, не
	// встретив срока, сам бы не возразил.
	exp, ok := numericDate(claims, "exp")
	if !ok {
		return refuse(OutcomeExpiryMissing, "assertion carries no expiry")
	}
	iat, ok := numericDate(claims, "iat")
	if !ok {
		return refuse(OutcomeIssuedAtMissing, "assertion carries no issued-at")
	}

	now := v.policy.Clock().UTC()
	skew := v.policy.ClockSkew

	// Момент выпуска в будущем сверх допуска — отказ; в пределах допуска —
	// приём. Клиент со спешащими часами обязан аутентифицироваться, иначе
	// допуск существовал бы для одного поля и не действовал для соседнего.
	if iat.After(now.Add(skew)) {
		return refuse(OutcomeIssuedAtInFuture, "issued-at is in the future beyond the declared skew")
	}

	// Потолок длительности — арифметика над ОБЪЯВЛЕННЫМ числом. Отсчёт от
	// момента выпуска, а не от «сейчас»: разница `exp − iat` есть свойство
	// самого утверждения и не зависит от задержки доставки.
	if exp.Sub(iat) > maxLifetime {
		return refuse(OutcomeLifetimeAboveCeiling,
			"assertion lifetime %s exceeds the declared ceiling %s", exp.Sub(iat), maxLifetime)
	}

	// Граница истечения ВКЛЮЧИТЕЛЬНА: ровно в момент истечения — отказ.
	if !now.Before(exp.Add(skew)) {
		return refuse(OutcomeExpired, "assertion has expired")
	}

	// Момент начала действия необязателен; если назван — граница
	// НЕвключительна: ровно в момент начала действия утверждение принимается.
	if nbf, ok := numericDate(claims, "nbf"); ok {
		if now.Add(skew).Before(nbf) {
			return refuse(OutcomeNotYetValid, "assertion is not valid yet")
		}
	}

	// (14) Идентификатор однократности. Обязателен по НАШЕЙ политике: стандарт
	// его не требует, а без него однократность невыразима.
	assertionID, _ := stringMember(claims, "jti")
	if err := domain.ValidateAssertionID(assertionID); err != nil {
		return refuse(OutcomeAssertionIDMissing, "%v", err)
	}

	// (15) Погашение — ПОСЛЕДНИМ, и одним оператором на стороне хранилища.
	// Недоступность хранилища есть ОТКАЗ: «пропустить, погасим потом» — это та
	// же пара «проверить и записать», разнесённая на неопределённый срок.
	if err := v.replay.Redeem(ctx, client.ID, assertionID, exp); err != nil {
		if domain.IsAssertionReplayed(err) {
			return refuse(OutcomeReplayed, "single-use identifier has already been redeemed by this client")
		}
		return refuse(OutcomeReplayStoreUnavailable, "replay store is unavailable: %v", err)
	}

	return Result{
		Outcome:     OutcomeAccepted,
		Client:      client,
		AssertionID: assertionID,
		ExpiresAt:   exp,
	}, nil
}

// ── Разбор, общий для обеих полос ───────────────────────────────────────────

// assertionEnvelope — разобранная оболочка предъявленного утверждения.
type assertionEnvelope struct {
	header       map[string]json.RawMessage
	payloadBytes []byte
}

// decodeEnvelope — форма, дублирующиеся имена членов, пометка «обязателен к
// пониманию».
//
// Вынесено ради того, чтобы полосы не разошлись: три эти проверки не зависят от
// того, кто подписал утверждение, и выписанные дважды они разъехались бы там,
// где расхождение не видно.
func decodeEnvelope(raw string) (assertionEnvelope, Result, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		res, err := refuse(OutcomeMalformedSerialization, "not a compact serialization with exactly one signature")
		return assertionEnvelope{}, res, err
	}
	headerBytes, decErr := base64.RawURLEncoding.DecodeString(parts[0])
	if decErr != nil {
		res, err := refuse(OutcomeMalformedSerialization, "header segment is not base64url")
		return assertionEnvelope{}, res, err
	}
	payloadBytes, decErr := base64.RawURLEncoding.DecodeString(parts[1])
	if decErr != nil {
		res, err := refuse(OutcomeMalformedSerialization, "payload segment is not base64url")
		return assertionEnvelope{}, res, err
	}
	// Дублирующееся имя члена — отказ ДО использования ЛЮБОГО значения.
	// Проверяется и в заголовке, и в нагрузке: два значения одного члена
	// означают, что прочитать могли разное, и предмет этот от места не зависит.
	if dup, ok := duplicateMember(headerBytes); ok {
		res, err := refuse(OutcomeDuplicateHeaderMember, "header member %q appears more than once", dup)
		return assertionEnvelope{}, res, err
	}
	if dup, ok := duplicateMember(payloadBytes); ok {
		res, err := refuse(OutcomeDuplicateHeaderMember, "claim %q appears more than once", dup)
		return assertionEnvelope{}, res, err
	}
	var header map[string]json.RawMessage
	if uErr := json.Unmarshal(headerBytes, &header); uErr != nil {
		res, err := refuse(OutcomeMalformedSerialization, "header is not a JSON object")
		return assertionEnvelope{}, res, err
	}
	// Член, помеченный обязательным к пониманию, которого мы не понимаем.
	if member, ok := unsupportedCritical(header); ok {
		res, err := refuse(OutcomeUnsupportedCritical,
			"header marks %q as must-understand and we do not understand it", member)
		return assertionEnvelope{}, res, err
	}
	return assertionEnvelope{header: header, payloadBytes: payloadBytes}, Result{}, nil
}

// declaredAlgorithm — объявленный алгоритм из ЗАКРЫТОГО словаря.
//
// Симметричное семейство, «без подписи» и всё, чего в словаре нет, отвергаются
// ЗДЕСЬ, до разрешения ключа: «прочее» не является корзиной приёма.
func declaredAlgorithm(header map[string]json.RawMessage) (string, Result, error) {
	alg, err := stringMember(header, "alg")
	if err != nil || !tokenpolicy.AlgorithmAllowed(alg) {
		res, rErr := refuse(OutcomeAlgorithmNotAllowed, "declared algorithm is not in the closed dictionary")
		return "", res, rErr
	}
	return alg, Result{}, nil
}

// decodeClaims — разбор полезной нагрузки. Дублирующиеся имена в ней уже
// отвергнуты оболочкой.
func decodeClaims(payloadBytes []byte) (map[string]json.RawMessage, Result, error) {
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		res, rErr := refuse(OutcomeMalformedSerialization, "payload is not a JSON object")
		return nil, res, rErr
	}
	return claims, Result{}, nil
}

// ── Разбор, которого библиотека не делает ───────────────────────────────────

// duplicateMember отвечает, встречается ли имя члена в объектной записи дважды.
//
// Разбор идёт ПОТОКОВЫМ читателем, а не через карту: карта схлопывает
// повторяющиеся имена ещё до того, как о них можно спросить, — то есть предмет
// проверки исчезает раньше самой проверки.
func duplicateMember(raw []byte) (string, bool) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	tok, err := dec.Token()
	if err != nil {
		return "", false
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return "", false
	}
	seen := map[string]bool{}
	for dec.More() {
		nameTok, err := dec.Token()
		if err != nil {
			return "", false
		}
		name, ok := nameTok.(string)
		if !ok {
			return "", false
		}
		if seen[name] {
			return name, true
		}
		seen[name] = true
		// Значение пропускается целиком, каким бы вложенным оно ни было.
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return "", false
		}
	}
	return "", false
}

// understoodCriticalMembers — члены заголовка, которые мы ПОНИМАЕМ и потому
// вправе принять помеченными обязательными.
//
// Перечень намеренно короткий: он должен содержать ровно то, чьё значение
// действительно меняет наше решение. Расширять его «на всякий случай» значит
// объявлять понятым то, что мы не читаем.
var understoodCriticalMembers = map[string]bool{
	"alg": true,
	"typ": true,
}

// unsupportedCritical отвечает, помечен ли обязательным к пониманию член,
// которого мы не понимаем.
//
// Пара требований здесь ПРОТИВОПОЛОЖНА и разлучать её нельзя: помеченный
// неизвестный член — отказ, НЕпомеченный неизвестный — игнорируется. Ужесточение
// первого до «отвергать всё незнакомое» ломает второе и рвёт совместимость с
// каждым клиентом, добавившим служебное поле; послабление второго до «игнорируем
// всё» молча теряет первое, оставаясь зелёным на любой пробе, подающей только
// известные члены.
func unsupportedCritical(header map[string]json.RawMessage) (string, bool) {
	rawCrit, ok := header["crit"]
	if !ok {
		return "", false
	}
	var members []string
	if err := json.Unmarshal(rawCrit, &members); err != nil {
		// Пометка, которую нельзя прочитать, — это пометка, которую нельзя
		// исполнить. Отказ, а не игнорирование.
		return "crit", true
	}
	if len(members) == 0 {
		// Пустая пометка запрещена стандартом; она же — признак сборки,
		// рассчитывающей на нашу снисходительность.
		return "crit", true
	}
	for _, m := range members {
		if !understoodCriticalMembers[m] {
			return m, true
		}
	}
	return "", false
}

// stringMember читает строковый член объектной записи.
func stringMember(obj map[string]json.RawMessage, name string) (string, error) {
	raw, ok := obj[name]
	if !ok {
		return "", fmt.Errorf("member %q is absent", name)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("member %q is not a string", name)
	}
	return s, nil
}

// audienceContains отвечает, назван ли наш идентификатор среди адресатов.
//
// Стандарт допускает и одну строку, и набор. Решение записано: набор
// принимается, если наш идентификатор среди него ПРИСУТСТВУЕТ. Обратное
// («ровно один адресат и он наш») отвергало бы законного клиента, чья
// библиотека кладёт набор всегда.
func audienceContains(claims map[string]json.RawMessage, want string) bool {
	raw, ok := claims["aud"]
	if !ok {
		return false
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return one == want
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return false
	}
	for _, a := range many {
		if a == want {
			return true
		}
	}
	return false
}

// numericDate читает временную отметку.
func numericDate(claims map[string]json.RawMessage, name string) (time.Time, bool) {
	raw, ok := claims[name]
	if !ok {
		return time.Time{}, false
	}
	var secs float64
	if err := json.Unmarshal(raw, &secs); err != nil {
		return time.Time{}, false
	}
	return time.Unix(int64(secs), 0).UTC(), true
}

// parsePublicKey разбирает зарегистрированный открытый ключ.
//
// Читается ТОЛЬКО то, что лежит в реестре. Встроенный в заголовок материал сюда
// не попадает by construction: у этой функции нет входа, через который он мог бы
// приехать.
func parsePublicKey(pemText string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("registered key is not PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("registered key is not a PKIX public key: %w", err)
	}
	return key, nil
}
