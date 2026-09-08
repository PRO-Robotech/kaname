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

	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// stubOwnClientPort — чтение строки реестра по НАШЕМУ идентификатору.
//
// Дублёр отдаёт ТУ ЖЕ строку, что и порт прежнего пути отдаёт по зеркальному
// значению: предмет сверки — состав, а не разрешение. Дублёр, подсовывающий
// разным путям разные строки, сверял бы два разных принципала и был бы зелен
// при любом расхождении составов.
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
// отдающий свою строку на любой вход, снисходительнее продукта ровно там, где
// это ломает предмет пробы: прежний путь пробует служебную учётку ПЕРВОЙ, и
// всеядный дублёр разрешил бы клиента пользовательского токена как машинного —
// после чего проба сверяла бы составы ДВУХ РАЗНЫХ принципалов. Это и произошло
// на первом прогоне.
type stubSAPortForClaimSets struct {
	mirror string
	soc    domain.ServiceAccountOAuthClient
	sa     domain.ServiceAccount
}

func (s stubSAPortForClaimSets) LookupByOAuthClientID(_ context.Context, id domain.OAuthClientID) (domain.ServiceAccountOAuthClient, error) {
	if string(id) != s.mirror {
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

// stubUserTokenPortForClaimSets — порт клиентов пользовательского токена для
// прежнего пути, ключуемый идентификатором по той же причине.
type stubUserTokenPortForClaimSets struct {
	mirror string
	uoc    domain.UserOAuthClient
	user   domain.User
}

func (s stubUserTokenPortForClaimSets) LookupByOAuthClientID(_ context.Context, id domain.OAuthClientID) (domain.UserOAuthClient, error) {
	if string(id) != s.mirror {
		return domain.UserOAuthClient{}, iamerr.ErrNotFound
	}
	return s.uoc, nil
}

func (s stubUserTokenPortForClaimSets) GetUser(_ context.Context, _ domain.UserID) (domain.User, error) {
	return s.user, nil
}

// TestF2_42_ClaimSetsOfBothIssuancePathsMatchForTheSamePrincipal — §2.11.
func TestF2_42_ClaimSetsOfBothIssuancePathsMatchForTheSamePrincipal(t *testing.T) {
	fixed := time.Unix(1_700_000_000, 0).UTC()

	const (
		ourUserClientID = "uoc_0123456789abcdefg"
		ourSAClientID   = "soc_0123456789abcdefg"
		mirrorUser      = "kacho-usr-mirror-0001"
		mirrorSA        = "kacho-sak-mirror-0001"
		ownerUser       = "usr_0123456789abcdefg"
		ownerSA         = "sva_0123456789abcdefg"
		accountID       = "acc_0123456789abcdefg"
	)

	uoc := domain.UserOAuthClient{
		// Вид ЗАПИСЫВАЕТСЯ каждым писателем (#1142): закрытый
		// словарь таблицы отвергает строку, вида не назвавшую.
		CredentialKind: domain.CredentialKindKeypair,
		ID:             domain.UserOAuthClientID(ourUserClientID),
		UserID:         domain.UserID(ownerUser),
		OAuthClientID:  domain.OAuthClientID(mirrorUser),
	}
	user := domain.User{
		ID:           domain.UserID(ownerUser),
		AccountID:    domain.AccountID(accountID),
		InviteStatus: domain.InviteStatusActive,
	}
	soc := domain.ServiceAccountOAuthClient{
		// Вид ЗАПИСЫВАЕТСЯ каждым писателем (#1142): закрытый
		// словарь таблицы отвергает строку, вида не назвавшую.
		CredentialKind: domain.CredentialKindKeypair,
		ID:             domain.SAOAuthClientID(ourSAClientID),
		SvaID:          domain.ServiceAccountID(ownerSA),
		OAuthClientID:  domain.OAuthClientID(mirrorSA),
	}
	sa := domain.ServiceAccount{
		ID:        domain.ServiceAccountID(ownerSA),
		AccountID: domain.AccountID(accountID),
		Enabled:   true,
	}

	// Одна служба, одни часы, оба входа. Порт прежнего пути и порт нашего
	// отдают ОДНУ И ТУ ЖЕ строку — иначе сверялись бы два разных принципала.
	svc := NewTokenEnrichmentService(
		TokenEnrichmentConfig{Domain: "kacho.cloud", HydraIssuer: "https://hydra.kacho.local"},
		stubUserPort{t: t},
	).
		WithUserTokenPort(stubUserTokenPortForClaimSets{mirror: mirrorUser, uoc: uoc, user: user}).
		WithSAPort(stubSAPortForClaimSets{mirror: mirrorSA, soc: soc, sa: sa}).
		WithOwnClientPort(stubOwnClientPort{uoc: uoc, soc: soc})
	svc.now = func() time.Time { return fixed }

	// Привязка подаётся НЕПУСТОЙ на обоих путях: её поля есть в составе, и на
	// пустых значениях расхождение по ним было бы неотличимо от совпадения.
	hookCtx := TokenHookContext{
		GrantType:     tokenpolicy.GrantTypeClientCredentials,
		CnfJkt:        "jkt-thumb",
		CnfX5tS256:    "x5t-thumb",
		OAuthClientID: mirrorUser,
	}

	for _, tc := range []struct {
		kind domain.AssertionClientKind
		// mirror — чем принципала называет ПРЕЖНИЙ путь: зеркальным значением.
		mirror string
		// client — строка реестра для НАШЕГО пути.
		client domain.AssertionClient
	}{
		{
			kind:   domain.AssertionClientUser,
			mirror: mirrorUser,
			client: domain.AssertionClient{
				ID: ourUserClientID, Kind: domain.AssertionClientUser,
				OwnerID: ownerUser, OwnerActive: true,
			},
		},
		{
			kind:   domain.AssertionClientServiceAccount,
			mirror: mirrorSA,
			client: domain.AssertionClient{
				ID: ourSAClientID, Kind: domain.AssertionClientServiceAccount,
				OwnerID: ownerSA, OwnerActive: true,
			},
		},
	} {
		t.Run(string(tc.kind), func(t *testing.T) {
			hc := hookCtx
			hc.OAuthClientID = tc.mirror

			// Прежний путь: обратный вызов провайдера, принципал назван
			// зеркальным значением.
			legacy, legacyPrincipal, err := svc.EnrichClaims(context.Background(), tc.mirror, hc)
			require.NoError(t, err, "прежний путь обязан выдать состав")

			// Наш путь: тем же прогоном, тот же принципал, назван НАШИМ
			// идентификатором.
			ours, oursPrincipal, err := svc.ClaimsForAssertionClient(context.Background(), tc.client, hc)
			require.NoError(t, err, "наш путь обязан выдать состав")

			// Положительный контроль: состав НЕПУСТ. Равенство двух пустых
			// карт зелено и не утверждает ничего.
			require.NotEmpty(t, ours, "состав пуст — сверять нечего")
			require.NotEmpty(t, legacy, "состав пуст — сверять нечего")

			// Множество ИМЁН — отдельным утверждением, чтобы отказ называл
			// именно потерянное поле, а не печатал две карты целиком.
			require.Equal(t, claimNames(legacy), claimNames(ours),
				"путь %s: множества имён утверждений разошлись", tc.kind)

			// Множество ЗНАЧЕНИЙ — равенство карт целиком: имена могут
			// совпасть при разошедшихся значениях.
			require.Equal(t, legacy, ours,
				"путь %s: значения утверждений разошлись", tc.kind)

			// Принципал, разрешённый двумя путями, — тот же: состав может
			// совпасть у путей, разрешивших РАЗНЫХ принципалов, если оба
			// собраны из одной строки.
			require.Equal(t, legacyPrincipal.Kind, oursPrincipal.Kind, "путь %s: вид принципала разошёлся", tc.kind)
			require.Equal(t, legacyPrincipal.UserID, oursPrincipal.UserID, "путь %s: принципал разошёлся", tc.kind)
		})
	}
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
