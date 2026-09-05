// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// issue_test.go — выдача по учётным данным клиента (приёмка F2, §11 E, G).
package client_token_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/client_token"
	"github.com/PRO-Robotech/kacho-iam/internal/clientassertion"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
	"github.com/PRO-Robotech/kacho-iam/internal/tokensigner"
	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
)

const (
	issuerID    = "https://iam.kacho.local"
	audResource = "https://api.kacho.cloud"
	audRegistry = "registry.kacho.local"
)

var now = time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

// stubKeys — ключница подписанта.
type stubKeys struct{ mat tokensigner.SigningMaterial }

func (s stubKeys) ActiveSigningKey(context.Context) (tokensigner.SigningMaterial, error) {
	return s.mat, nil
}

func newSigner(t *testing.T) *tokensigner.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(k)
	require.NoError(t, err)
	pubDER, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	require.NoError(t, err)
	s, err := tokensigner.New(tokensigner.Config{
		Issuer:      issuerID,
		Clock:       func() time.Time { return now },
		MaxTokenTTL: tokenpolicy.MaxTokenTTL,
	}, stubKeys{mat: tokensigner.SigningMaterial{
		KID:           "kacho-test",
		Algorithm:     domain.SigningAlgES256,
		PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		PublicKeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})),
	}})
	require.NoError(t, err)
	return s
}

// stubClaims — источник состава утверждений.
//
// Дублёр НЕ снисходительнее настоящего: он отказывает там, где настоящий
// отказывает (снятый владелец), и не выдумывает состава.
type stubClaims struct {
	set  map[string]any
	err  error
	seen service.TokenHookContext
}

func (s *stubClaims) ClaimsForAssertionClient(_ context.Context, c domain.AssertionClient, hookCtx service.TokenHookContext) (map[string]any, service.ResolvedPrincipal, error) {
	s.seen = hookCtx
	if s.err != nil {
		return nil, service.ResolvedPrincipal{}, s.err
	}
	out := map[string]any{"kacho_principal_id": c.OwnerID}
	for k, v := range s.set {
		out[k] = v
	}
	// Вид клиента различается ТАК ЖЕ, как настоящим объявлением состава:
	// у клиента ключа служебной учётки принципал машинный и поля пользователя
	// не несёт. Дублёр, отвечающий одинаково на оба вида, был бы снисходительнее
	// продукта — и скрыл бы ровно то расхождение путей, ради которого их и
	// подают по отдельности.
	switch c.Kind {
	case domain.AssertionClientServiceAccount:
		return out, service.ResolvedPrincipal{Kind: service.PrincipalServiceAccount}, nil
	case domain.AssertionClientUser:
		return out, service.ResolvedPrincipal{Kind: service.PrincipalUser, UserID: c.OwnerID}, nil
	default:
		// Словарь видов ЗАКРЫТ: «прочее» не является корзиной приёма.
		return nil, service.ResolvedPrincipal{}, fmt.Errorf("stub claims: unknown assertion client kind %q", c.Kind)
	}
}

// assertionClientKindsUnderTest — оба пути выдачи, поданные ОТДЕЛЬНЫМИ входами.
//
// Перечень ВЫВОДИТСЯ из закрытого словаря домена, а не выписывается: вид,
// заведённый в домене и забытый здесь, оставил бы свой путь без утверждения —
// молча, потому что «проверено» и «не перечислено» выглядят одинаково.
func assertionClientKindsUnderTest() []domain.AssertionClientKind {
	return domain.AssertionClientKinds()
}

// ownerFor — идентификатор владельца по виду клиента: у пути пользовательского
// токена владелец — участие человека, у пути ключа служебной учётки — учётка.
func ownerFor(kind domain.AssertionClientKind) string {
	if kind == domain.AssertionClientServiceAccount {
		return "sva_0123456789abcdefg"
	}
	return "usr_0123456789abcdefg"
}

// idFor — идентификатор клиента по виду: формы префиксов у двух реестров разные.
func idFor(kind domain.AssertionClientKind) string {
	if kind == domain.AssertionClientServiceAccount {
		return "soc_0123456789abcdefg"
	}
	return "uoc_0123456789abcdefg"
}

// ofKind — фикстура клиента названного вида.
func ofKind(kind domain.AssertionClientKind) func(*domain.AssertionClient) {
	return func(c *domain.AssertionClient) {
		c.Kind = kind
		c.ID = idFor(kind)
		c.OwnerID = ownerFor(kind)
	}
}

func newUseCase(t *testing.T, mutate ...func(*client_token.Config)) (*client_token.UseCase, *stubClaims) {
	t.Helper()
	cfg := client_token.Config{
		AllowedAudiences: []string{audResource, audRegistry},
		DefaultAudience:  audResource,
		TokenTTL:         15 * time.Minute,
		Clock:            func() time.Time { return now },
	}
	for _, m := range mutate {
		m(&cfg)
	}
	claims := &stubClaims{}
	uc, err := client_token.New(cfg, newSigner(t), claims)
	require.NoError(t, err)
	return uc, claims
}

func client(mutate ...func(*domain.AssertionClient)) domain.AssertionClient {
	c := domain.AssertionClient{
		ID:           "uoc_0123456789abcdefg",
		Kind:         domain.AssertionClientUser,
		OwnerID:      "usr_0123456789abcdefg",
		PublicKeyPEM: "pem",
		Algorithm:    tokenpolicy.AlgES256,
		OwnerActive:  true,
	}
	for _, m := range mutate {
		m(&c)
	}
	return c
}

// parse разбирает выпущенный токен без проверки подписи: проба спрашивает про
// СОСТАВ, а подпись закреплена своими пробами подписанта.
func parse(t *testing.T, raw string) (jwt.MapClaims, map[string]any) {
	t.Helper()
	tok, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
	require.NoError(t, err)
	return tok.Claims.(jwt.MapClaims), tok.Header
}

// TestF2_29_TokenExpiryNeverOutlivesTheClient — НЕРАВЕНСТВО, а не прилагательное,
// и оно утверждается по КАЖДОМУ из двух путей выдачи.
//
// «Выдаётся укороченный» / «выдаётся обычный» зеленеет на ЛЮБОЙ реализации с
// полем допуска: `min(обычный, остаток) + запас`, округление вверх, «грация»,
// добавленная через полгода. При малом остатке токен всё ещё «укороченный», при
// большом — «обычный», обе половины зелены, а токен, переживший клиента,
// существует. Прилагательное описывает НАПРАВЛЕНИЕ величины; требуется ГРАНИЦА.
//
// # Почему оба вида клиента подаются отдельными входами
//
// Приёмка ожидала, что пути выдачи — РАЗНЫЕ пакеты use-case, и требовала
// утверждения по каждому именно поэтому. В дереве они сведены в один: потолок
// стоит в ОДНОМ месте и достаётся обоим видам, то есть требование сегодня
// выполняется by construction.
//
// Проба всё равно подаёт оба, и это не церемония. Расщепление путей —
// правдоподобная следующая правка (у двух реестров разные таблицы, разные
// владельцы и разные состояния владельца), и после неё ограничение, оставленное
// в одной ветке, оставит вторую без него. Проба, спрашивающая один вид, в этот
// момент останется зелёной — то есть перестанет измерять ровно тогда, когда
// станет нужна.
func TestF2_29_TokenExpiryNeverOutlivesTheClient(t *testing.T) {
	const normal = 15 * time.Minute

	cases := []struct {
		name      string
		remaining time.Duration
		wantTTL   time.Duration
	}{
		// Остаток РОВНО равен обычному сроку: граница включительна, равенство
		// законно.
		{"остаток равен обычному сроку", normal, normal},
		// Остаток на шаг меньше: токен укорочен РОВНО до остатка.
		{"остаток на шаг меньше", normal - time.Second, normal - time.Second},
		{"остаток сильно меньше", time.Minute, time.Minute},
		// Остаток больше обычного срока: выдаётся обычный. Контроль против
		// выдачи, укорачивающей всё подряд.
		{"остаток больше обычного", 10 * normal, normal},
	}

	kinds := assertionClientKindsUnderTest()
	require.Len(t, kinds, 2, "путей выдачи ДВА; перечень выведен из закрытого словаря домена")

	for _, kind := range kinds {
		t.Run(string(kind), func(t *testing.T) {
			uc, _ := newUseCase(t)

			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					exp := now.Add(c.remaining)
					out, outcome, err := uc.Issue(context.Background(), client_token.Input{
						Client: client(ofKind(kind), func(cl *domain.AssertionClient) { cl.ExpiresAt = exp.Unix() }),
					})
					require.NoError(t, err)
					require.Equal(t, clientassertion.OutcomeAccepted, outcome)

					claims, _ := parse(t, out.AccessToken)
					tokenExp := time.Unix(int64(claims["exp"].(float64)), 0).UTC()

					// НЕРАВЕНСТВО: момент истечения токена НЕ ПОЗЖЕ момента
					// истечения клиента. Сравниваются две величины, а не
					// характеризуется одна.
					require.False(t, tokenExp.After(exp),
						"путь %s: токен истекает %s, клиент %s — токен пережил клиента", kind, tokenExp, exp)
					require.Equal(t, c.wantTTL, tokenExp.Sub(now), "путь %s", kind)
				})
			}

			// Клиент БЕЗ срока — выдаётся обычный: незаданный срок означает
			// «бессрочно», и это законное состояние схемы.
			out, outcome, err := uc.Issue(context.Background(), client_token.Input{Client: client(ofKind(kind))})
			require.NoError(t, err)
			require.Equal(t, clientassertion.OutcomeAccepted, outcome)
			claims, _ := parse(t, out.AccessToken)
			require.Equal(t, normal, time.Unix(int64(claims["exp"].(float64)), 0).UTC().Sub(now),
				"путь %s: бессрочный клиент обязан получать обычный срок", kind)

			// Истёкший клиент токена НЕ получает.
			_, outcome, err = uc.Issue(context.Background(), client_token.Input{
				Client: client(ofKind(kind), func(cl *domain.AssertionClient) { cl.ExpiresAt = now.Add(-time.Second).Unix() }),
			})
			require.Error(t, err, "путь %s", kind)
			require.Equal(t, clientassertion.OutcomeClientExpired, outcome, "путь %s", kind)
		})
	}
}

// TestF2_30_OwnerNotActiveGetsNoToken — оба не-`ACTIVE` состояния доезжают сюда
// одним признаком, и оба дают отказ.
func TestF2_30_OwnerNotActiveGetsNoToken(t *testing.T) {
	uc, _ := newUseCase(t)

	_, outcome, err := uc.Issue(context.Background(), client_token.Input{
		Client: client(func(cl *domain.AssertionClient) { cl.OwnerActive = false }),
	})
	require.Error(t, err)
	require.Equal(t, clientassertion.OutcomeOwnerNotActive, outcome)

	// Положительный контроль: активный владелец токен получает.
	_, outcome, err = uc.Issue(context.Background(), client_token.Input{Client: client()})
	require.NoError(t, err)
	require.Equal(t, clientassertion.OutcomeAccepted, outcome)
}

// TestF2_37_AssertionAudienceIsNotCarriedIntoTheIssuedToken — §2.7.
//
// Перенос выглядит естественно («адресат уже разобран, вот он») и положительный
// путь при нём РАБОТАЕТ: токен выпускается, подпись верна, клиент доволен.
// Ломается он у потребителя — токен оказывается адресован нашему издателю, то
// есть не той поверхности, которой предъявляется.
func TestF2_37_AssertionAudienceIsNotCarriedIntoTheIssuedToken(t *testing.T) {
	uc, _ := newUseCase(t)

	out, _, err := uc.Issue(context.Background(), client_token.Input{Client: client()})
	require.NoError(t, err)
	claims, _ := parse(t, out.AccessToken)
	aud := claims["aud"]

	require.NotContains(t, audienceStrings(aud), issuerID,
		"адресат выданного токена не может равняться идентификатору нашего издателя")
	require.Equal(t, []string{audResource}, audienceStrings(aud))

	// Запрошенный адресат уезжает в токен как есть.
	out, _, err = uc.Issue(context.Background(), client_token.Input{
		Client: client(), RequestedAudience: []string{audRegistry},
	})
	require.NoError(t, err)
	claims, _ = parse(t, out.AccessToken)
	require.Equal(t, []string{audRegistry}, audienceStrings(claims["aud"]))
}

// TestF2_38_RequestedAudienceMustBeInTheDeclaredPlatformList — перечень
// ПЛАТФОРМЫ есть ВНЕШНЯЯ граница выдачи, и расширить её нечем.
//
// Здесь стояло «а перечня у клиента нет, колонки в схеме не существует» — это
// перестало быть верным с задачей #1136: сужение ключа есть, оно действует
// (`issue_audience_narrowing_test.go`) и работает ВНУТРИ этой границы. Фикстура
// клиента сужения не объявляет, поэтому проба измеряет ровно внешнюю границу.
func TestF2_38_RequestedAudienceMustBeInTheDeclaredPlatformList(t *testing.T) {
	uc, _ := newUseCase(t)

	_, outcome, err := uc.Issue(context.Background(), client_token.Input{
		Client: client(), RequestedAudience: []string{"https://attacker.example"},
	})
	require.Error(t, err)
	require.Equal(t, clientassertion.OutcomeAudienceNotAllowed, outcome)

	// Набор, где ОДИН из адресатов вне перечня, отвергается целиком: приняв
	// его частично, мы выдали бы токен, адресованный туда, куда не объявляли.
	_, outcome, err = uc.Issue(context.Background(), client_token.Input{
		Client: client(), RequestedAudience: []string{audResource, "https://attacker.example"},
	})
	require.Error(t, err)
	require.Equal(t, clientassertion.OutcomeAudienceNotAllowed, outcome)

	// Положительный контроль: адресат ИЗ перечня выдаётся.
	_, outcome, err = uc.Issue(context.Background(), client_token.Input{
		Client: client(), RequestedAudience: []string{audRegistry},
	})
	require.NoError(t, err)
	require.Equal(t, clientassertion.OutcomeAccepted, outcome)
}

// TestF2_41_ConfirmationComesFromThePresentedProofNotTheAssertionKey — F1 §2.4.
func TestF2_41_ConfirmationComesFromThePresentedProofNotTheAssertionKey(t *testing.T) {
	uc, _ := newUseCase(t)

	// Привязка НЕ проставляется там, где её не запрашивали.
	out, _, err := uc.Issue(context.Background(), client_token.Input{Client: client()})
	require.NoError(t, err)
	claims, _ := parse(t, out.AccessToken)
	require.NotContains(t, claims, "cnf")

	// Отпечаток берётся из ПРЕДЪЯВЛЕННОГО доказательства владения. Ключ
	// утверждения и ключ доказательства здесь РАЗНЫЕ — при совпадении свойство
	// не измеряется вовсе.
	const proofJKT = "thumbprint-of-the-proof-key"
	out, _, err = uc.Issue(context.Background(), client_token.Input{
		Client:       client(),
		Confirmation: &tokensigner.Confirmation{JKT: proofJKT},
	})
	require.NoError(t, err)
	claims, _ = parse(t, out.AccessToken)
	cnf, ok := claims["cnf"].(map[string]any)
	require.True(t, ok, "привязка обязана быть в токене")
	require.Equal(t, proofJKT, cnf["jkt"])
}

// TestIssuedTokenCarriesOurTypeAndOurIssuer — первый и второй из трёх признаков
// разделения двух видов подписанного (§2.6).
func TestIssuedTokenCarriesOurTypeAndOurIssuer(t *testing.T) {
	uc, _ := newUseCase(t)
	out, _, err := uc.Issue(context.Background(), client_token.Input{Client: client()})
	require.NoError(t, err)

	claims, header := parse(t, out.AccessToken)
	require.Equal(t, tokenpolicy.TokenTypeAccess, header["typ"])
	require.NotEqual(t, tokenpolicy.TokenTypeClientAssertion, header["typ"])
	require.Equal(t, issuerID, claims["iss"])
	require.Equal(t, "Bearer", out.TokenType)
	require.Positive(t, out.ExpiresIn)
}

// TestClaimsComeFromTheSingleDeclarationAndCarryTheClientIdentifier — §2.11 и
// §2.10 (второй ключ отзыва).
//
// Состав собирает то же объявление, что и путь обратного вызова, и в нём
// присутствует идентификатор КЛИЕНТА: именно по нему читатель отзыва на пути
// запроса резолвит отсечку, порождённую отзывом клиента. Без этого утверждения
// второй ключ существующего механизма не с чем связать.
func TestClaimsComeFromTheSingleDeclarationAndCarryTheClientIdentifier(t *testing.T) {
	uc, claims := newUseCase(t)
	claims.set = map[string]any{"kacho_user_token_id": "uoc_0123456789abcdefg"}

	out, _, err := uc.Issue(context.Background(), client_token.Input{Client: client()})
	require.NoError(t, err)
	got, _ := parse(t, out.AccessToken)
	require.Equal(t, "uoc_0123456789abcdefg", got["kacho_user_token_id"])
	require.Equal(t, "usr_0123456789abcdefg", got["kacho_principal_id"])

	// Вид выдачи доезжает до объявления состава: путь обратного вызова
	// различает виды, и наш обязан назвать свой тем же словарём.
	require.Equal(t, tokenpolicy.GrantTypeClientCredentials, claims.seen.GrantType)
}

// TestIssuanceFailureIsNotSilentlySuccessful — отказ источника состава есть
// ОТКАЗ выдачи. Токен с пустым составом выглядит выданным и не несёт
// принципала: край принял бы его и не нашёл, за кого он говорит.
func TestIssuanceFailureIsNotSilentlySuccessful(t *testing.T) {
	uc, claims := newUseCase(t)
	claims.err = errors.New("source is down")
	_, outcome, err := uc.Issue(context.Background(), client_token.Input{Client: client()})
	require.Error(t, err)
	require.Equal(t, clientassertion.OutcomeIssuanceFailed, outcome)
}

// TestUseCaseRefusesToBuildOnDegenerateConfiguration — страж ПОСТРОЕНИЯ, и
// вырожденный вход подаётся отдельно от отсутствующего.
func TestUseCaseRefusesToBuildOnDegenerateConfiguration(t *testing.T) {
	full := client_token.Config{
		AllowedAudiences: []string{audResource},
		DefaultAudience:  audResource,
		TokenTTL:         15 * time.Minute,
		Clock:            func() time.Time { return now },
	}
	for name, brk := range map[string]func(*client_token.Config){
		"перечень адресатов пуст":          func(c *client_token.Config) { c.AllowedAudiences = nil },
		"перечень адресатов — пустой срез": func(c *client_token.Config) { c.AllowedAudiences = []string{} },
		"адресат по умолчанию не задан":    func(c *client_token.Config) { c.DefaultAudience = "" },
		"адресат по умолчанию — пробелы":   func(c *client_token.Config) { c.DefaultAudience = "  " },
		"срок токена не задан":             func(c *client_token.Config) { c.TokenTTL = 0 },
		"срок токена сверх потолка платформы": func(c *client_token.Config) {
			c.TokenTTL = tokenpolicy.MaxTokenTTL + time.Second
		},
		"часы не поданы": func(c *client_token.Config) { c.Clock = nil },
		// НЕИСПОЛНИМАЯ ВОЗМОЖНОСТЬ: умолчание вне собственного перечня. Обе
		// половины настройки по отдельности защитимы, а глагол не работает НИ
		// ПРИ КАКОМ входе — запрос без адресата отвергался бы собственным
		// умолчанием. Такое ловится только вызовом, и потому стоит здесь.
		"умолчание вне объявленного перечня": func(c *client_token.Config) {
			c.DefaultAudience = "https://not-declared.example"
		},
	} {
		cfg := full
		cfg.AllowedAudiences = append([]string(nil), full.AllowedAudiences...)
		brk(&cfg)
		_, err := client_token.New(cfg, newSigner(t), &stubClaims{})
		require.Error(t, err, "вырожденный вход %q обязан отвергнуть построение", name)
	}

	// Положительный контроль: полная настройка строится, и запрос БЕЗ адресата
	// проходит умолчанием — то есть умолчание исполнимо, а не только объявлено.
	uc, err := client_token.New(full, newSigner(t), &stubClaims{})
	require.NoError(t, err)
	_, outcome, err := uc.Issue(context.Background(), client_token.Input{Client: client()})
	require.NoError(t, err)
	require.Equal(t, clientassertion.OutcomeAccepted, outcome)
}

// audienceStrings приводит адресат к срезу строк.
func audienceStrings(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			out = append(out, e.(string))
		}
		return out
	case []string:
		return t
	default:
		return nil
	}
}
