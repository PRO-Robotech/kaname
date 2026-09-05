// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// both_lanes_agree_test.go — свойство, обязательное для одной полосы выдачи,
// утверждается СРАВНЕНИЕМ полос (задача #1184).
//
// # Почему сравнением, а не пробой каждой полосы отдельно
//
// Проба каждой полосы отдельно требует знать, каким свойство ДОЛЖНО быть, — а
// это и есть спорный вопрос: обе полосы по отдельности выглядели исправными,
// каждая со своими зелёными пробами. Неверна была их РАЗНИЦА, и никто её не
// решал: она возникла побочным эффектом того, что вторую полосу писали под
// фиксированный адресат реестра.
//
// Сравнение спрашивает другое: «решал ли кто-нибудь, что они различаются». На
// это ответ есть всегда.
//
// # Перепись печатает ОБЕ величины
//
// «Полос выдачи N · сверяют адресата M». Одно число скрыло бы ровно тот случай,
// ради которого проба заведена, — полосу, которую забыли завести в перечень.
//
// # Осей сравнения ДВЕ, и они охватывают разное (задача #1143)
//
// ВНЕШНЯЯ граница посадки есть у КАЖДОЙ полосы выдачи: она объявлена посадкой,
// а не удостоверением. Её сличают все.
//
// ВНУТРЕННЯЯ граница — сужение, объявленное при выдаче САМОГО удостоверения, —
// есть только там, где удостоверение её несёт. Докерная полоса реестра несла
// её, пока принимала ключ служебной учётки; приём ключевого материала снят
// (#1143), и у базового токена доступа поля адресатов нет — оно отвергается на
// выдаче. Полоса осталась в переписи, ось сузилась.
//
// Разница полос по этой оси — РЕШЕНИЕ, а не побочный эффект, и перепись
// печатает её числом: «полос N · из них несут сужение удостоверения M». Свести
// оси в одну значило бы либо потребовать от базового токена того, чего у него
// нет, либо снять требование с ключа, у которого оно есть.
package audiencepolicy_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/client_token"
	registrytokenuc "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/registry_token"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
	"github.com/PRO-Robotech/kacho-iam/internal/tokensigner"
	"github.com/PRO-Robotech/kacho/pkg/credsecret"
	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
)

const (
	audRegistry = "registry.kacho.local"
	audForeign  = "sts.example.com"
	clientID    = "soc_0123456789abcdefg"
)

// lane — полоса выдачи с точки зрения этой пробы: она умеет выпустить токен по
// ключу, объявившему сужение, на заказанный запросом адресат.
//
// Порт, а не две отдельные пробы: сравнение обязано подать ОДИН И ТОТ ЖЕ вход
// обеим и сверить исходы между собой.
type lane struct {
	name  string
	issue func(t *testing.T, declared []string, requested string) error
	// carriesDeclaredNarrowing — несёт ли УДОСТОВЕРЕНИЕ этой полосы сужение
	// адресатов, объявленное при его выдаче. false означает «у этого вида
	// такого поля нет», а не «сужение не проверяется».
	carriesDeclaredNarrowing bool
}

// lanesUnderTest — перечень полос выдачи по ключу служебной учётки.
//
// Перечень ВЫПИСАН, и это названо честно: вывести его из дерева нечем — полосы
// живут в разных пакетах и не объявляют себя общим типом. Цена названа тут же:
// третья полоса, заведённая и сюда не внесённая, останется без сравнения. Её
// автор увидит эту строку, потому что перепись ниже печатает число полос.
func lanesUnderTest() []lane {
	return []lane{
		{name: "токен-эндпоинт платформы", issue: issueViaClientToken, carriesDeclaredNarrowing: true},
		// Сужение удостоверения ушло вместе с приёмом ключевого материала
		// (#1143): базовый токен доступа поля адресатов не несёт.
		{name: "докерная полоса реестра", issue: issueViaRegistryToken, carriesDeclaredNarrowing: false},
	}
}

// TestBothIssuanceLanesRefuseTheSameForeignAudience — обе полосы отвергают один
// и тот же чужой адресат и принимают один и тот же объявленный.
func TestBothIssuanceLanesRefuseTheSameForeignAudience(t *testing.T) {
	type input struct {
		name      string
		declared  []string
		requested string
		wantErr   bool
	}
	// ВНЕШНЯЯ граница: сличается на ВСЕХ полосах — она объявлена посадкой.
	landing := []input{
		{"адресат вне объявленного посадкой", nil, audForeign, true},
		{"адресат посадки без сужения удостоверения", nil, audRegistry, false},
		{"запрос адресата не назвал", nil, "", false},
	}
	// ВНУТРЕННЯЯ граница: сличается только там, где удостоверение её несёт.
	declared := []input{
		{"удостоверение сужено на чужой адресат, заказан адресат посадки", []string{audForeign}, audRegistry, true},
		{"удостоверение сужено на адресат посадки, он же заказан", []string{audRegistry}, audRegistry, false},
		{"удостоверение сужено, заказан чужой адресат", []string{audRegistry}, audForeign, true},
		{"запрос адресата не назвал, удостоверение сужено", []string{audRegistry}, "", false},
	}

	lanes := lanesUnderTest()
	narrowing := make([]lane, 0, len(lanes))
	for _, l := range lanes {
		if l.carriesDeclaredNarrowing {
			narrowing = append(narrowing, l)
		}
	}

	compare := func(t *testing.T, over []lane, cases []input, axis string) int {
		t.Helper()
		sliced := 0
		for _, c := range cases {
			t.Run(axis+": "+c.name, func(t *testing.T) {
				verdicts := make(map[string]bool, len(over))
				for _, l := range over {
					err := l.issue(t, c.declared, c.requested)
					verdicts[l.name] = err != nil
					if c.wantErr {
						require.Error(t, err, "полоса %q обязана отвергнуть", l.name)
					} else {
						require.NoError(t, err, "полоса %q обязана принять", l.name)
					}
				}
				first := verdicts[over[0].name]
				for _, l := range over[1:] {
					require.Equal(t, first, verdicts[l.name],
						"полосы разошлись на входе %q: %q сказала %v, %q сказала %v — "+
							"расхождение полос одного механизма обязано быть решением, а не побочным эффектом",
						c.name, over[0].name, first, l.name, verdicts[l.name])
				}
			})
			sliced++
		}
		return sliced
	}

	slicedLanding := compare(t, lanes, landing, "внешняя граница")
	slicedDeclared := compare(t, narrowing, declared, "сужение удостоверения")

	require.NotZero(t, len(lanes), "перепись без полос — не перепись")
	require.NotZero(t, len(narrowing),
		"ни одна полоса не несёт сужения удостоверения — ось не измеряется вовсе, "+
			"и её пробы зеленеют, ничего не утверждая")
	require.NotZero(t, len(landing), "перепись без входов внешней границы — не перепись")
	require.NotZero(t, len(declared), "перепись без входов сужения — не перепись")
	t.Logf("перепись: полос выдачи %d · сверяют внешнюю границу %d · из них несут сужение удостоверения %d "+
		"· входов сличено: внешняя граница %d, сужение %d",
		len(lanes), len(lanes), len(narrowing), slicedLanding, slicedDeclared)
}

// ── полоса 1: токен-эндпоинт платформы ──────────────────────────────────────

func issueViaClientToken(t *testing.T, declared []string, requested string) error {
	t.Helper()
	uc, err := client_token.New(client_token.Config{
		AllowedAudiences: []string{audRegistry},
		DefaultAudience:  audRegistry,
		TokenTTL:         15 * time.Minute,
		Clock:            func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	}, newSigner(t), stubClaims{})
	require.NoError(t, err)

	var want []string
	if requested != "" {
		want = []string{requested}
	}
	_, _, err = uc.Issue(context.Background(), client_token.Input{
		Client: domain.AssertionClient{
			ID: clientID, Kind: domain.AssertionClientServiceAccount,
			OwnerID: "sva_0123456789abcdefg", PublicKeyPEM: "pem",
			Algorithm: tokenpolicy.AlgES256, OwnerActive: true,
			DeclaredAudiences: declared,
		},
		RequestedAudience: want,
	})
	return err
}

// stubClaims — источник состава утверждений. Дублёр НЕ снисходительнее
// настоящего: он не выдумывает состава и не решает за выдачу.
type stubClaims struct{}

func (stubClaims) ClaimsForAssertionClient(_ context.Context, c domain.AssertionClient, _ service.TokenHookContext) (map[string]any, service.ResolvedPrincipal, error) {
	// Принципал машинный: у ключа служебной учётки поля пользователя нет, и
	// дублёр, проставивший его, был бы снисходительнее настоящего объявления
	// состава — то есть скрыл бы расхождение путей.
	return map[string]any{"kacho_principal_id": c.OwnerID},
		service.ResolvedPrincipal{Kind: service.PrincipalServiceAccount}, nil
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
		Issuer:      "https://iam.kacho.local",
		Clock:       func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
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

type stubKeys struct{ mat tokensigner.SigningMaterial }

func (s stubKeys) ActiveSigningKey(context.Context) (tokensigner.SigningMaterial, error) {
	return s.mat, nil
}

// ── полоса 2: докерная полоса реестра ───────────────────────────────────────

// issueViaRegistryToken — докерная полоса. `declared` она не принимает и
// принять не может: у базового токена доступа поля адресатов нет (#1143),
// поэтому вызывающий и не подаёт ей входы оси сужения.
func issueViaRegistryToken(t *testing.T, declared []string, requested string) error {
	t.Helper()
	require.Empty(t, declared,
		"докерной полосе подан вход оси сужения — у принимаемого ею вида такого поля нет; "+
			"перечень полос и перечень входов разошлись")

	secret, _, err := credsecret.Mint(clientID)
	require.NoError(t, err)

	uc := registrytokenuc.NewIssueRegistryTokenUseCase(
		registrytokenuc.Config{
			AssertionAudience: "https://hydra.kacho.local/oauth2/token",
			AllowedAudiences:  []string{audRegistry},
			DefaultService:    audRegistry,
		},
		dockerSigner{}, dockerExchanger{},
	).WithLocalMinter(dockerMinter{}).WithBasicCredentialResolver(dockerAuthority{secret: secret})

	_, err = uc.Execute(context.Background(), registrytokenuc.IssueInput{
		Username: clientID, Password: secret, Service: requested,
	})
	return err
}

// dockerAuthority — авторитет о предъявленном базовом секрете. Форму разбирает
// тем же единственным объявлением, что и продукт.
type dockerAuthority struct{ secret string }

func (a dockerAuthority) ResolveBasic(_ context.Context, presented string) (domain.BasicCredential, error) {
	p, perr := credsecret.Parse(presented)
	if perr != nil || presented != a.secret {
		return domain.BasicCredential{}, domain.ErrBasicCredentialRefused
	}
	return domain.BasicCredential{
		PrincipalType: "service_account",
		PrincipalID:   "sva_0123456789abcdefg",
		CredentialID:  p.CredentialID,
	}, nil
}

type dockerSigner struct{}

func (dockerSigner) Sign(registrytokenuc.AssertionInput) (string, error) { return "assertion", nil }

type dockerExchanger struct{}

func (dockerExchanger) Exchange(context.Context, registrytokenuc.ExchangeInput) (registrytokenuc.ExchangeOutput, error) {
	return registrytokenuc.ExchangeOutput{AccessToken: "token", ExpiresIn: 300}, nil
}

type dockerMinter struct{}

func (dockerMinter) MintToken(context.Context, registrytokenuc.MintInput) (registrytokenuc.MintOutput, error) {
	return registrytokenuc.MintOutput{AccessToken: "token", ExpiresIn: 300}, nil
}
