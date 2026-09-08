// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// verify_test.go — проверяющий утверждение клиента (приёмка F2, §11 A-D).
//
// # Асимметрия цены, из которой выведены ВСЕ утверждения этого файла
//
// Слишком строгая проверка даёт отказ, видимый сразу — на первом же
// предъявлении, с именем поля в журнале. Слишком слабая даёт ПРИНЯТОЕ ЧУЖОЕ
// утверждение, не видимое никогда: успешная аутентификация выглядит одинаково
// независимо от того, что именно она проверила. Поэтому у каждого отрицания
// здесь стоит положительный контроль: проба, все утверждения которой ждут
// отказа, зеленеет на проверяющем, отвергающем всё подряд, — и это не гипотеза,
// а способ, которым такие пробы ломаются чаще всего.
package clientassertion_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
	"github.com/PRO-Robotech/kaname/internal/clientassertion"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

const (
	testIssuerID = "https://kaname.kacho.local"
	testClientID = "uoc_0123456789abcdefg"
	testOwnerID  = "usr_0123456789abcdefg"
)

var testNow = time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

// stubRegistry — реестр, способный к утверждению.
//
// Дублёр НЕ снисходительнее настоящего: он отвечает `domain.ErrNotFound` там,
// где настоящий отвечает им же, и не выдумывает строки. Дублёр, молча глотающий
// вход, на котором настоящий отказывает, делает невидимым ровно тот дефект,
// ради которого его подставляют.
type stubRegistry struct {
	rows map[string]domain.AssertionClient
	err  error
}

func (s stubRegistry) ResolveAssertionClient(_ context.Context, id string) (domain.AssertionClient, error) {
	if s.err != nil {
		return domain.AssertionClient{}, s.err
	}
	row, ok := s.rows[id]
	if !ok {
		return domain.AssertionClient{}, domain.ErrAssertionClientUnknown
	}
	return row, nil
}

// stubReplay — однократность. По умолчанию принимает всё; проба, которой нужен
// повтор, гасит ключ заранее.
type stubReplay struct {
	seen map[string]bool
	err  error
}

func newReplay() *stubReplay { return &stubReplay{seen: map[string]bool{}} }

func (s *stubReplay) Redeem(_ context.Context, clientID, assertionID string, _ time.Time) error {
	if s.err != nil {
		return s.err
	}
	k := clientID + "\x00" + assertionID
	if s.seen[k] {
		return domain.ErrAssertionReplayed
	}
	s.seen[k] = true
	return nil
}

// fixture — собранный стенд одной пробы.
type fixture struct {
	verifier *clientassertion.Verifier
	registry stubRegistry
	// issuers — перечень доверенных издателей. На полосе клиента он ПУСТ, и
	// это утверждение: полоса клиента не резолвится через него ни при каком
	// входе, поэтому пустой перечень здесь ничего не ослабляет.
	issuers stubTrustedIssuers
	replay  *stubReplay
	key     testKey
}

func newFixture(t *testing.T, opts ...func(*domain.AssertionClient)) fixture {
	t.Helper()
	key := newKey(t, tokenpolicy.AlgES256)
	row := domain.AssertionClient{
		ID:           testClientID,
		Kind:         domain.AssertionClientUser,
		OwnerID:      testOwnerID,
		PublicKeyPEM: key.publicPEM,
		Algorithm:    key.alg,
		OwnerActive:  true,
	}
	for _, o := range opts {
		o(&row)
	}
	reg := stubRegistry{rows: map[string]domain.AssertionClient{testClientID: row}}
	iss := stubTrustedIssuers{rows: map[string]domain.TrustedIssuer{}}
	rep := newReplay()
	v, err := clientassertion.New(clientassertion.Policy{
		ExpectedAudience:     testIssuerID,
		MaxLifetime:          tokenpolicy.MaxAssertionLifetime,
		MaxFederatedLifetime: tokenpolicy.MaxFederatedAssertionLifetime,
		ClockSkew:            tokenpolicy.ClockSkew,
		Clock:                func() time.Time { return testNow },
	}, reg, iss, rep)
	require.NoError(t, err)
	return fixture{verifier: v, registry: reg, issuers: iss, replay: rep, key: key}
}

// goodClaims — полезная нагрузка, которая обязана приниматься. Всё, что проба
// портит, она портит ОТ НЕЁ — так видно, что различие ровно одно.
func goodClaims(jti string) map[string]any {
	return map[string]any{
		"iss": testClientID,
		"sub": testClientID,
		"aud": testIssuerID,
		"exp": testNow.Add(2 * time.Minute).Unix(),
		"iat": testNow.Unix(),
		"jti": jti,
	}
}

func goodHeader(alg string) string {
	return header(jsonString("alg"), jsonString(alg),
		jsonString("typ"), jsonString(tokenpolicy.TokenTypeClientAssertion))
}

// verify — предъявление законным видом. Вид предъявления проверяется отдельно
// (F2-01), поэтому здесь он всегда точный.
func (f fixture) verify(t *testing.T, raw string) (clientassertion.Result, error) {
	t.Helper()
	return f.verifier.Verify(context.Background(), tokenpolicy.ClientAssertionType, raw)
}

// requireOutcome — отказ наступил, и наступил ПО НАЗВАННОЙ причине.
//
// Наружу все отказы неразличимы (§7), но ВНУТРЬ различимость обязана
// существовать: без неё счётчик исхода не с чем связать, и мёртвый контроль
// становится невидимым. Поэтому проба утверждает исход, а не текст.
func requireOutcome(t *testing.T, want clientassertion.Outcome, res clientassertion.Result, err error) {
	t.Helper()
	require.Error(t, err, "вход обязан быть отвергнут")
	require.Equal(t, want, res.Outcome, "отказ наступил по другой причине: %v", err)
}

// ── A. Форма предъявления и разбор ──────────────────────────────────────────

// TestF2_01_AssertionTypeIsComparedExactly — вид предъявления равен объявленному
// стандартом ТОЧНО: сравнение строк простое, без нормализации.
func TestF2_01_AssertionTypeIsComparedExactly(t *testing.T) {
	f := newFixture(t)
	raw := assertion{headerJSON: goodHeader(f.key.alg), payloadJSON: claims(goodClaims("jti-01")), key: f.key}.sign(t)

	for _, wrong := range []string{
		strings.ToUpper(tokenpolicy.ClientAssertionType),
		tokenpolicy.ClientAssertionType + " ",
		" " + tokenpolicy.ClientAssertionType,
		"urn:ietf:params:oauth:client-assertion-type:saml2-bearer",
		"",
	} {
		res, err := f.verifier.Verify(context.Background(), wrong, raw)
		requireOutcome(t, clientassertion.OutcomeAssertionTypeMismatch, res, err)
	}

	// Положительный контроль: при точном равенстве вход принимается.
	res, err := f.verify(t, raw)
	require.NoError(t, err)
	require.Equal(t, clientassertion.OutcomeAccepted, res.Outcome)
}

// TestF2_03_OnlyCompactFormWithExactlyOneSignature — предъявленное значение
// обязано быть компактной последовательной формой ровно с одной подписью.
func TestF2_03_OnlyCompactFormWithExactlyOneSignature(t *testing.T) {
	f := newFixture(t)
	build := func(segments int) string {
		return assertion{
			headerJSON: goodHeader(f.key.alg), payloadJSON: claims(goodClaims("jti-03")),
			key: f.key, segments: segments,
		}.sign(t)
	}

	// Три разных входа, каждый отвергается: иная форма сериализации, сегментов
	// больше объявленного формой, сегментов меньше.
	generalJSON := `{"payload":"e30","signatures":[{"protected":"e30","signature":"AA"}]}`
	for _, raw := range []string{generalJSON, build(4), build(2)} {
		res, err := f.verify(t, raw)
		requireOutcome(t, clientassertion.OutcomeMalformedSerialization, res, err)
	}

	res, err := f.verify(t, build(0))
	require.NoError(t, err)
	require.Equal(t, clientassertion.OutcomeAccepted, res.Outcome)
}

// TestF2_04_DuplicateHeaderMemberIsRejectedBeforeAnyValueIsUsed — имя члена
// заголовка, встреченное дважды, отвергается ДО использования любого значения.
//
// Причина не формальная: два значения одного члена означают, что проверяющий и
// подписант МОГЛИ ПРОЧИТАТЬ РАЗНОЕ, а значит проверенной оказалась не та
// половина.
func TestF2_04_DuplicateHeaderMemberIsRejectedBeforeAnyValueIsUsed(t *testing.T) {
	f := newFixture(t)

	// Дублируется ИЗВЕСТНЫЙ член…
	dupKnown := header(
		jsonString("alg"), jsonString(f.key.alg),
		jsonString("typ"), jsonString(tokenpolicy.TokenTypeClientAssertion),
		jsonString("alg"), jsonString(tokenpolicy.AlgRS256),
	)
	// …и НЕИЗВЕСТНЫЙ. Реализация, проверяющая только известные, зелена на
	// половине класса.
	dupUnknown := header(
		jsonString("alg"), jsonString(f.key.alg),
		jsonString("typ"), jsonString(tokenpolicy.TokenTypeClientAssertion),
		jsonString("vendor"), jsonString("a"),
		jsonString("vendor"), jsonString("b"),
	)
	for _, h := range []string{dupKnown, dupUnknown} {
		raw := assertion{headerJSON: h, payloadJSON: claims(goodClaims("jti-04")), key: f.key}.sign(t)
		res, err := f.verify(t, raw)
		requireOutcome(t, clientassertion.OutcomeDuplicateHeaderMember, res, err)
	}

	// Положительный контроль: заголовок с уникальными именами принимается.
	raw := assertion{headerJSON: goodHeader(f.key.alg), payloadJSON: claims(goodClaims("jti-04-ok")), key: f.key}.sign(t)
	res, err := f.verify(t, raw)
	require.NoError(t, err)
	require.Equal(t, clientassertion.OutcomeAccepted, res.Outcome)
}

// TestF2_05_UnderstoodMandatoryHeaderMemberIsRefused — член, помеченный
// обязательным к пониманию, которого мы не понимаем, отвергается.
//
// Пометка означает «без понимания этого члена подпись нельзя считать
// проверенной»; принять — значит объявить проверенным то, чего не поняли.
func TestF2_05_UnderstoodMandatoryHeaderMemberIsRefused(t *testing.T) {
	f := newFixture(t)

	unknownCrit := header(
		jsonString("alg"), jsonString(f.key.alg),
		jsonString("typ"), jsonString(tokenpolicy.TokenTypeClientAssertion),
		jsonString("crit"), `["vendor_policy"]`,
		jsonString("vendor_policy"), jsonString("strict"),
	)
	raw := assertion{headerJSON: unknownCrit, payloadJSON: claims(goodClaims("jti-05")), key: f.key}.sign(t)
	res, err := f.verify(t, raw)
	requireOutcome(t, clientassertion.OutcomeUnsupportedCritical, res, err)

	// Пометка, перечисляющая член, который мы ПОНИМАЕМ, к отказу не приводит.
	knownCrit := header(
		jsonString("alg"), jsonString(f.key.alg),
		jsonString("typ"), jsonString(tokenpolicy.TokenTypeClientAssertion),
		jsonString("crit"), `["typ"]`,
	)
	raw = assertion{headerJSON: knownCrit, payloadJSON: claims(goodClaims("jti-05-ok")), key: f.key}.sign(t)
	res, err = f.verify(t, raw)
	require.NoError(t, err)
	require.Equal(t, clientassertion.OutcomeAccepted, res.Outcome)
}

// TestF2_06_UnknownHeaderMemberWithoutTheMarkIsIgnored — ПАРА к F2-05, стоит
// рядом намеренно.
//
// Ужесточение F2-05 до «отвергать всё неизвестное» роняет эту пробу — в этом её
// работа. Обратно: реализация, игнорирующая ВСЁ неизвестное, выполняет эту и
// молча теряет ту, оставаясь зелёной на любой пробе, подающей только известные
// члены.
func TestF2_06_UnknownHeaderMemberWithoutTheMarkIsIgnored(t *testing.T) {
	f := newFixture(t)
	withExtension := header(
		jsonString("alg"), jsonString(f.key.alg),
		jsonString("typ"), jsonString(tokenpolicy.TokenTypeClientAssertion),
		jsonString("vendor_hint"), jsonString("whatever"),
	)
	raw := assertion{headerJSON: withExtension, payloadJSON: claims(goodClaims("jti-06")), key: f.key}.sign(t)
	res, err := f.verify(t, raw)
	require.NoError(t, err, "заголовок открыт для расширения: непомеченный неизвестный член игнорируется")
	require.Equal(t, clientassertion.OutcomeAccepted, res.Outcome)

	// Общий положительный контроль пары: утверждение без расширений вовсе.
	raw = assertion{headerJSON: goodHeader(f.key.alg), payloadJSON: claims(goodClaims("jti-06-bare")), key: f.key}.sign(t)
	res, err = f.verify(t, raw)
	require.NoError(t, err)
	require.Equal(t, clientassertion.OutcomeAccepted, res.Outcome)
}

// TestF2_07_EmbeddedKeyMaterialNeverSelectsTheKey — §5, шов с соседним
// механизмом.
//
// Доверять ключу, приехавшему вместе с подписью, значит принимать ЛЮБУЮ
// подпись: предъявитель приложит тот ключ, которым подписал. В соседнем
// механизме дерева (доказательство владения) то же доверие законно и является
// его сутью — там ключ приходит в самом доказательстве и связывается с токеном
// по отпечатку. Здесь — недопустимо.
func TestF2_07_EmbeddedKeyMaterialNeverSelectsTheKey(t *testing.T) {
	f := newFixture(t)
	// Ключ, которого в реестре НЕТ, и утверждение подписано ИМ.
	foreign := newKey(t, tokenpolicy.AlgES256)

	// Каждый член встроенного материала подаётся ОТДЕЛЬНЫМ входом, а не один
	// за все: реализация, закрывшая один, зелена на остальных.
	for _, member := range tokenpolicy.KeySourceHeaderMembers() {
		var value string
		switch member {
		case "jwk":
			value = `{"kty":"EC","crv":"P-256","x":"AA","y":"BB"}`
		case "x5c":
			value = `["MIIB"]`
		default:
			value = jsonString("https://attacker.example/keys")
		}
		h := header(
			jsonString("alg"), jsonString(foreign.alg),
			jsonString("typ"), jsonString(tokenpolicy.TokenTypeClientAssertion),
			jsonString(member), value,
		)
		raw := assertion{headerJSON: h, payloadJSON: claims(goodClaims("jti-07-" + member)), key: foreign}.sign(t)
		res, err := f.verify(t, raw)
		require.Error(t, err, "встроенный материал %q ключ не выбирает", member)
		require.NotEqual(t, clientassertion.OutcomeAccepted, res.Outcome)
	}

	// То же утверждение, подписанное ключом ИЗ РЕЕСТРА, принимается — и
	// принимается по ключу из реестра, а не по встроенному.
	h := header(
		jsonString("alg"), jsonString(f.key.alg),
		jsonString("typ"), jsonString(tokenpolicy.TokenTypeClientAssertion),
		jsonString("jwk"), `{"kty":"EC","crv":"P-256","x":"AA","y":"BB"}`,
	)
	raw := assertion{headerJSON: h, payloadJSON: claims(goodClaims("jti-07-ok")), key: f.key}.sign(t)
	res, err := f.verify(t, raw)
	require.NoError(t, err)
	require.Equal(t, clientassertion.OutcomeAccepted, res.Outcome)
}

// TestF2_08_HeaderAlgorithmMustEqualTheRegisteredOne — НАШ сценарий, внешнего
// прообраза не имеет (§1.7).
//
// Зрелая чужая реализация выбирает проверяющего ПО ТИПУ КЛЮЧА, а не по
// объявленному в заголовке алгоритму, и у неё поэтому НЕТ пробы на подмену
// алгоритма — у неё нет и предмета. Перенеся её таблицу случаев, мы получили бы
// таблицу без этой защиты, и отсутствие было бы неотличимо от полноты:
// положительный путь работает, отрицательных утверждений просто нет.
func TestF2_08_HeaderAlgorithmMustEqualTheRegisteredOne(t *testing.T) {
	// Обе пары различий словаря: смена СЕМЕЙСТВА и смена параметра ВНУТРИ
	// семейства. Вторая — та, на которой ломается «проверяю по типу ключа».
	cases := []struct{ registered, declared string }{
		{tokenpolicy.AlgES256, tokenpolicy.AlgRS256}, // смена семейства
		{tokenpolicy.AlgRS256, tokenpolicy.AlgES256}, // смена семейства, обратно
		{tokenpolicy.AlgES256, tokenpolicy.AlgEdDSA}, // смена семейства
		{tokenpolicy.AlgRS256, "RS512"},              // тот же ключ, иной параметр
		{tokenpolicy.AlgES256, "ES384"},              // тот же ключ, иной параметр
	}
	for _, c := range cases {
		key := newKey(t, c.registered)
		f := newFixture(t, func(row *domain.AssertionClient) {
			row.Algorithm = c.registered
			row.PublicKeyPEM = key.publicPEM
		})
		// Подписано ЗАРЕГИСТРИРОВАННЫМ ключом, а заголовок объявляет другое.
		raw := assertion{
			headerJSON:  goodHeader(c.declared),
			payloadJSON: claims(goodClaims("jti-08")),
			key:         key,
		}.sign(t)
		res, err := f.verify(t, raw)
		require.Error(t, err, "зарегистрирован %s, объявлен %s", c.registered, c.declared)
		require.Contains(t,
			[]clientassertion.Outcome{clientassertion.OutcomeAlgorithmMismatch, clientassertion.OutcomeAlgorithmNotAllowed},
			res.Outcome)

		// Положительный контроль: заголовок, объявляющий ЗАРЕГИСТРИРОВАННЫЙ
		// алгоритм, принимается.
		raw = assertion{
			headerJSON:  goodHeader(c.registered),
			payloadJSON: claims(goodClaims("jti-08-ok")),
			key:         key,
		}.sign(t)
		res, err = f.verify(t, raw)
		require.NoError(t, err, "зарегистрирован и объявлен %s", c.registered)
		require.Equal(t, clientassertion.OutcomeAccepted, res.Outcome)
	}
}

// TestF2_09_SymmetricAndNoneAndOffDictionaryEachGetTheirOwnBranch — «прочее» не
// является корзиной приёма.
func TestF2_09_SymmetricAndNoneAndOffDictionaryEachGetTheirOwnBranch(t *testing.T) {
	f := newFixture(t)
	for _, alg := range []string{"HS256", "HS384", "HS512", "none", "NONE", "PS256", "", "ES256 "} {
		h := header(jsonString("alg"), jsonString(alg),
			jsonString("typ"), jsonString(tokenpolicy.TokenTypeClientAssertion))
		raw := assertion{headerJSON: h, payloadJSON: claims(goodClaims("jti-09")), key: f.key}.sign(t)
		res, err := f.verify(t, raw)
		require.Error(t, err, "алгоритм %q обязан быть отвергнут", alg)
		require.Equal(t, clientassertion.OutcomeAlgorithmNotAllowed, res.Outcome, "алгоритм %q", alg)
	}

	raw := assertion{headerJSON: goodHeader(f.key.alg), payloadJSON: claims(goodClaims("jti-09-ok")), key: f.key}.sign(t)
	res, err := f.verify(t, raw)
	require.NoError(t, err)
	require.Equal(t, clientassertion.OutcomeAccepted, res.Outcome)
}

// TestF2_10_EmptyRegisteredAlgorithmMeansNoKeyNotAnyKey — пустое значение
// закрытого словаря схемы означает «ключа нет», а НЕ «любой алгоритм».
func TestF2_10_EmptyRegisteredAlgorithmMeansNoKeyNotAnyKey(t *testing.T) {
	key := newKey(t, tokenpolicy.AlgES256)
	f := newFixture(t, func(row *domain.AssertionClient) {
		row.Algorithm = ""
		row.PublicKeyPEM = key.publicPEM
	})
	for _, alg := range tokenpolicy.Algorithms() {
		raw := assertion{headerJSON: goodHeader(alg), payloadJSON: claims(goodClaims("jti-10")), key: key}.sign(t)
		res, err := f.verify(t, raw)
		requireOutcome(t, clientassertion.OutcomeClientCannotAssert, res, err)
	}

	// Пустой КЛЮЧ при непустом алгоритме — тот же исход: и то и другое
	// означает «ключа нет».
	f = newFixture(t, func(row *domain.AssertionClient) { row.PublicKeyPEM = "" })
	raw := assertion{headerJSON: goodHeader(tokenpolicy.AlgES256), payloadJSON: claims(goodClaims("jti-10b")), key: key}.sign(t)
	res, err := f.verify(t, raw)
	requireOutcome(t, clientassertion.OutcomeClientCannotAssert, res, err)

	// Положительный контроль: тот же клиент с непустым зарегистрированным
	// алгоритмом и соответствующим ключом аутентифицируется.
	f = newFixture(t)
	raw = assertion{headerJSON: goodHeader(f.key.alg), payloadJSON: claims(goodClaims("jti-10-ok")), key: f.key}.sign(t)
	res, err = f.verify(t, raw)
	require.NoError(t, err)
	require.Equal(t, clientassertion.OutcomeAccepted, res.Outcome)
}

// ── B. Личность, адресат, ключ ──────────────────────────────────────────────

// TestF2_13_IssuerAndSubjectMustAgreeAndNameOurClient — сравнение строк простое,
// без нормализации и без учёта регистра.
func TestF2_13_IssuerAndSubjectMustAgreeAndNameOurClient(t *testing.T) {
	f := newFixture(t)
	sign := func(c map[string]any) string {
		return assertion{headerJSON: goodHeader(f.key.alg), payloadJSON: claims(c), key: f.key}.sign(t)
	}

	// Издатель и субъект не совпадают МЕЖДУ СОБОЙ.
	c := goodClaims("jti-13a")
	c["sub"] = "uoc_zzzzzzzzzzzzzzzzz"
	res, err := f.verify(t, sign(c))
	requireOutcome(t, clientassertion.OutcomeIdentityMismatch, res, err)

	// Совпадают между собой, но не равны нашему идентификатору клиента.
	c = goodClaims("jti-13b")
	c["iss"], c["sub"] = "uoc_zzzzzzzzzzzzzzzzz", "uoc_zzzzzzzzzzzzzzzzz"
	res, err = f.verify(t, sign(c))
	requireOutcome(t, clientassertion.OutcomeClientUnknown, res, err)

	// Различие ТОЛЬКО регистром — тоже отказ: сравнение простое.
	c = goodClaims("jti-13c")
	c["iss"], c["sub"] = strings.ToUpper(testClientID), strings.ToUpper(testClientID)
	res, err = f.verify(t, sign(c))
	require.Error(t, err)
	require.NotEqual(t, clientassertion.OutcomeAccepted, res.Outcome)

	// Пустые — тоже отказ.
	c = goodClaims("jti-13d")
	c["iss"], c["sub"] = "", ""
	res, err = f.verify(t, sign(c))
	require.Error(t, err)
	require.NotEqual(t, clientassertion.OutcomeAccepted, res.Outcome)

	// Положительный контроль.
	res, err = f.verify(t, sign(goodClaims("jti-13-ok")))
	require.NoError(t, err)
	require.Equal(t, clientassertion.OutcomeAccepted, res.Outcome)
}

// TestF2_15_AudienceIsOurIssuerIdentifierNotTheEndpointAddress — §2.2.
//
// Адрес эндпоинта — не одна строка, а несколько: он достижим по
// внутрикластерному адресу и по внешнему, с префиксом пути и без. Выбор «какой
// считать адресатом» пришлось бы делать при каждой новой посадке.
// Идентификатор издателя — ОДНА строка, объявленная один раз.
func TestF2_15_AudienceIsOurIssuerIdentifierNotTheEndpointAddress(t *testing.T) {
	f := newFixture(t)
	sign := func(aud any, jti string) string {
		c := goodClaims(jti)
		c["aud"] = aud
		return assertion{headerJSON: goodHeader(f.key.alg), payloadJSON: claims(c), key: f.key}.sign(t)
	}

	for _, aud := range []any{
		testIssuerID + "/oauth2/token",
		testIssuerID + "/iam/v1/token",
		"http://kaname.kacho-system.svc:9096/iam/v1/token",
		"",
	} {
		res, err := f.verify(t, sign(aud, "jti-15"))
		requireOutcome(t, clientassertion.OutcomeAudienceMismatch, res, err)
	}

	// Идентификатор нашего издателя принимается.
	res, err := f.verify(t, sign(testIssuerID, "jti-15-ok"))
	require.NoError(t, err)
	require.Equal(t, clientassertion.OutcomeAccepted, res.Outcome)

	// Несколько адресатов, среди которых есть наш, — решение записано:
	// принимается, если наш присутствует.
	res, err = f.verify(t, sign([]string{"https://other.example", testIssuerID}, "jti-15-multi"))
	require.NoError(t, err)
	require.Equal(t, clientassertion.OutcomeAccepted, res.Outcome)

	// Набор БЕЗ нашего — отвергается.
	res, err = f.verify(t, sign([]string{"https://other.example", "https://third.example"}, "jti-15-none"))
	requireOutcome(t, clientassertion.OutcomeAudienceMismatch, res, err)
}

// TestF2_17_UnknownClientIsRefusedInTheSameToneAsABadSignature — различимый
// ответ есть ОРАКУЛ СУЩЕСТВОВАНИЯ.
func TestF2_17_UnknownClientIsRefusedInTheSameToneAsABadSignature(t *testing.T) {
	f := newFixture(t)

	// Клиент, которому в реестре нет строки.
	c := goodClaims("jti-17a")
	c["iss"], c["sub"] = "uoc_qqqqqqqqqqqqqqqqq", "uoc_qqqqqqqqqqqqqqqqq"
	unknown := assertion{headerJSON: goodHeader(f.key.alg), payloadJSON: claims(c), key: f.key}.sign(t)
	resUnknown, errUnknown := f.verify(t, unknown)
	require.Error(t, errUnknown)

	// Существующий клиент, подпись не сошлась.
	badSig := assertion{
		headerJSON: goodHeader(f.key.alg), payloadJSON: claims(goodClaims("jti-17b")),
		key: f.key, tamper: true,
	}.sign(t)
	resBad, errBad := f.verify(t, badSig)
	require.Error(t, errBad)

	// ПОБАЙТОВОЕ совпадение ответа предъявителю в обоих случаях.
	require.Equal(t, resUnknown.PresenterResponse(), resBad.PresenterResponse(),
		"различимый ответ есть оракул существования")

	// ВНУТРЬ исходы различимы — иначе счётчик исхода не с чем связать.
	require.NotEqual(t, resUnknown.Outcome, resBad.Outcome)

	// Положительный контроль: существующий клиент со сошедшейся подписью
	// принимается.
	ok := assertion{headerJSON: goodHeader(f.key.alg), payloadJSON: claims(goodClaims("jti-17-ok")), key: f.key}.sign(t)
	res, err := f.verify(t, ok)
	require.NoError(t, err)
	require.Equal(t, clientassertion.OutcomeAccepted, res.Outcome)
}
