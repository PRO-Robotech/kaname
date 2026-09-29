// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package service

// token_enrichment_claim_sets_match_test.go — F2-42 (уровень I): состав
// утверждений двух путей выдачи для ОДНОГО принципала совпадает МНОЖЕСТВАМИ.
//
// # Что здесь утверждается и почему множествами
//
// Токен принципалу выдают два пути: обратный вызов прежнего провайдера (пока он
// жив) и наш собственный эндпоинт. Проверка «есть поле X» зелена на токене,
// ПОТЕРЯВШЕМ поле Y, поэтому сверяются множества имён И значений целиком —
// равенство карт, а не присутствие отдельных ключей.
//
// # Почему обе стороны спрашиваются на ОДНОМ экземпляре и одним прогоном
//
// В составе есть величина, зависящая от часов (`kaname_issued_at`). Два
// экземпляра службы с двумя источниками времени разошлись бы по ней — и
// расхождение это было бы свойством пробы, а не продукта. Один экземпляр с
// одними часами оставляет расходиться только тому, что действительно
// принадлежит путям.
//
// # Чего эта проба НЕ делает
//
// Она не стережёт ЕДИНСТВЕННОСТЬ объявления перечня — это часть G сценария и
// предмет отдельного гейта дерева. Здесь спрашивается ИСХОД: два пути на одном
// принципале обязаны дать одно и то же.

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/tokenpolicy"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// stubOwnClientPort — чтение строки реестра по НАШЕМУ идентификатору.
//
// Дублёр отдаёт ТУ ЖЕ строку, что и порт прежнего пути: предмет сверки —
// состав, а не разрешение. Дублёр, подсовывающий разным путям разные строки,
// сверял бы два разных принципала и был бы зелен при любом расхождении
// составов.
type stubOwnClientPort struct {
	uoc    domain.UserOAuthClient
	uocErr error
	soc    domain.ServiceAccountOAuthClient
	socErr error
}

func (s stubOwnClientPort) GetUserToken(_ context.Context, _ domain.UserOAuthClientID) (domain.UserOAuthClient, error) {
	return s.uoc, s.uocErr
}

func (s stubOwnClientPort) GetSAKey(_ context.Context, _ domain.SAOAuthClientID) (domain.ServiceAccountOAuthClient, error) {
	return s.soc, s.socErr
}

// stubSAPortForClaimSets — порт служебных учёток для прежнего пути.
//
// Разрешение КЛЮЧУЕТСЯ идентификатором, как у настоящего репозитория. Дублёр,
// отдающий свою строку на любой вход, снисходительнее продукта: он разрешил бы
// субъекта, которого настоящий поиск не находит, и сверка составов прошла бы
// на принципале, которого нет.
type stubSAPortForClaimSets struct {
	clientID string
	soc      domain.ServiceAccountOAuthClient
	sa       domain.ServiceAccount
}

func (s stubSAPortForClaimSets) LookupByClientID(_ context.Context, id domain.SAOAuthClientID) (domain.ServiceAccountOAuthClient, error) {
	if string(id) != s.clientID {
		return domain.ServiceAccountOAuthClient{}, iamerr.ErrNotFound
	}
	return s.soc, nil
}

func (s stubSAPortForClaimSets) GetServiceAccount(_ context.Context, _ domain.ServiceAccountID) (domain.ServiceAccount, error) {
	return s.sa, nil
}

func (s stubSAPortForClaimSets) FindByExternalSubject(_ context.Context, _, _ string) (domain.ServiceAccountOAuthClient, error) {
	// Федеративный путь здесь не спрашивается: он входит только при
	// jwt-bearer, а сверяются два пути выдачи ПО УЧЁТНЫМ ДАННЫМ КЛИЕНТА.
	return domain.ServiceAccountOAuthClient{}, iamerr.ErrNotFound
}

// TestF2_42_ClaimSetsOfBothIssuancePathsMatchForTheSamePrincipal — §2.11.
//
// Путей, выпускающих токен одному принципалу, два у ключа служебной учётки:
// обратный вызов прежнего провайдера и наш токен-эндпоинт. Оба называют
// клиента ОДНИМ именем — идентификатором строки ключа (kaname#362). У
// персонального токена путь один — наш: прежний провайдер персональных токенов
// не регистрирует, и сверять его состав не с чем (его состав держит
// token_enrichment_usertoken_test.go).
func TestF2_42_ClaimSetsOfBothIssuancePathsMatchForTheSamePrincipal(t *testing.T) {
	fixed := time.Unix(1_700_000_000, 0).UTC()

	const (
		ourSAClientID = "soc_0123456789abcdefg"
		ownerSA       = "sva_0123456789abcdefg"
		accountID     = "acc_0123456789abcdefg"
	)

	soc := domain.ServiceAccountOAuthClient{
		// Вид ЗАПИСЫВАЕТСЯ каждым писателем (#1142): закрытый
		// словарь таблицы отвергает строку, вида не назвавшую.
		CredentialKind: domain.CredentialKindKeypair,
		ID:             domain.SAOAuthClientID(ourSAClientID),
		SvaID:          domain.ServiceAccountID(ownerSA),
	}
	sa := domain.ServiceAccount{
		ID:        domain.ServiceAccountID(ownerSA),
		AccountID: domain.AccountID(accountID),
		Enabled:   true,
	}

	// Одна служба, одни часы, оба входа. Порт прежнего пути и порт нашего
	// отдают ОДНУ И ТУ ЖЕ строку — иначе сверялись бы два разных принципала.
	svc := NewTokenEnrichmentService(
		TokenEnrichmentConfig{Domain: "kacho.cloud"},
		stubUserPort{t: t},
	).
		WithSAPort(stubSAPortForClaimSets{clientID: ourSAClientID, soc: soc, sa: sa}).
		WithOwnClientPort(stubOwnClientPort{soc: soc})
	svc.now = func() time.Time { return fixed }

	// Привязка подаётся НЕПУСТОЙ на обоих путях: её поля есть в составе, и на
	// пустых значениях расхождение по ним было бы неотличимо от совпадения.
	hc := TokenHookContext{
		GrantType:     tokenpolicy.GrantTypeClientCredentials,
		CnfJkt:        "jkt-thumb",
		CnfX5tS256:    "x5t-thumb",
		OAuthClientID: ourSAClientID,
	}
	client := domain.AssertionClient{
		ID: ourSAClientID, Kind: domain.AssertionClientServiceAccount,
		OwnerID: ownerSA, OwnerActive: true,
	}

	// Прежний путь: обратный вызов провайдера, субъект — имя клиента.
	legacy, legacyPrincipal, err := svc.EnrichClaims(context.Background(), ourSAClientID, hc)
	require.NoError(t, err, "прежний путь обязан выдать состав")

	// Наш путь: тем же прогоном, тот же принципал.
	ours, oursPrincipal, err := svc.ClaimsForAssertionClient(context.Background(), client, hc)
	require.NoError(t, err, "наш путь обязан выдать состав")

	// Положительный контроль: состав НЕПУСТ. Равенство двух пустых карт зелено
	// и не утверждает ничего.
	require.NotEmpty(t, ours, "состав пуст — сверять нечего")
	require.NotEmpty(t, legacy, "состав пуст — сверять нечего")

	// Множество ИМЁН — отдельным утверждением, чтобы отказ называл именно
	// потерянное поле, а не печатал две карты целиком.
	require.Equal(t, claimNames(legacy), claimNames(ours), "множества имён утверждений разошлись")

	// Множество ЗНАЧЕНИЙ — равенство карт целиком: имена могут совпасть при
	// разошедшихся значениях.
	require.Equal(t, legacy, ours, "значения утверждений разошлись")

	// Принципал, разрешённый двумя путями, — тот же, и сверяется ЦЕЛИКОМ.
	require.Equal(t, legacyPrincipal, oursPrincipal, "разрешённый принципал разошёлся")
	require.Equal(t, PrincipalServiceAccount, oursPrincipal.Kind)
}

// claimNames — множество имён состава, отсортированное для читаемого отказа.
func claimNames(claims map[string]any) []string {
	out := make([]string, 0, len(claims))
	for k := range claims {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
