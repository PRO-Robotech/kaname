// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// credential_revocation_test.go — отзыв удостоверения служебной учётки снимает
// и токен реестра, выданный ПО НЕМУ, сразу, а не по сроку (kaname#947).
//
// # Где разрыв
//
// Снятие строки удостоверения пишет отсечку ИДЕНТИФИКАТОРОМ СТРОКИ (триггер
// схемы `sa_oauth_client_removal_cuts_minted_tokens`), и правило отзыва
// (`tokenrevocation`) читает этот ключ из состава токена. Токен же докерной
// полосы называл только учётку-владельца: удостоверения, по которому он выдан,
// в нём не было, и отсечке было не за что его взять. Авторитет отзыва, которого
// спрашивает плоскость данных реестра, отвечал «действует» до конца срока.
//
// # Почему проба собрана из настоящих частей
//
// Токен выпускает НАСТОЯЩИЙ контур выдачи с НАСТОЯЩИМ подписантом, а судит
// его то самое правило, которое спрашивают обе принимающие поверхности.
// Фикстура, чеканящая состав сама, положила бы ключ отсечки за полосу — и
// осталась бы зелёной ровно на том дефекте, ради которого заведена.
package registrytokenwire

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/credsecret"
	registrytokenuc "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registry_token"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/tokenrevocation"
)

const (
	revSvaID    = "sva_0123456789abcdefg"
	revCredID   = "soc_0123456789abcdefg"
	revOtherID  = "soc_zzzzzzzzzzzzzzzzz"
	revRegistry = "registry.kacho.local"
)

// revBasicResolver — авторитет о базовом секрете: одна живая строка учётки.
type revBasicResolver struct{ live, credID string }

func (r revBasicResolver) ResolveBasic(_ context.Context, presented string) (domain.BasicCredential, error) {
	if presented != r.live {
		return domain.BasicCredential{}, domain.ErrBasicCredentialRefused
	}
	return domain.BasicCredential{
		PrincipalType: "service_account", PrincipalID: revSvaID, CredentialID: r.credID,
	}, nil
}

// revKeyValidator — проверяющий ключевого материала окна перехода: одна
// зарегистрированная строка.
type revKeyValidator struct{}

func (revKeyValidator) Validate(_ context.Context, clientID, _ string) (registrytokenuc.Credential, error) {
	if clientID != revCredID {
		return registrytokenuc.Credential{}, registrytokenuc.ErrInvalidCredentials
	}
	return registrytokenuc.Credential{ClientID: revCredID, KeyID: "kid-1", Subject: revSvaID}, nil
}

// revCutoffs — хранилище отсечек правила: ключ отсечки → момент.
type revCutoffs struct{ before map[string]time.Time }

func (c revCutoffs) RevokedBefore(_ context.Context, key string) (time.Time, bool, error) {
	t, ok := c.before[key]
	return t, ok, nil
}

func (revCutoffs) FamilyRevoked(context.Context, string) (bool, error) { return false, nil }

func (revCutoffs) PersonMarks(context.Context, []string) (map[string]bool, error) {
	return map[string]bool{}, nil
}

func revClaims(t *testing.T, raw string) jwt.MapClaims {
	t.Helper()
	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(raw, claims)
	require.NoError(t, err)
	return claims
}

func revLane(t *testing.T) *registrytokenuc.IssueRegistryTokenUseCase {
	t.Helper()
	uc, err := registrytokenuc.NewIssueRegistryTokenUseCase(registrytokenuc.Config{
		Scope:            "registry",
		AllowedAudiences: []string{revRegistry},
		DefaultService:   revRegistry,
	}, NewLocalMinter(f1bSigner(t), 5*time.Minute))
	require.NoError(t, err)
	return uc
}

// assertCutByItsCredentialOnly — токен действует без отсечек, отвергается
// отсечкой своего удостоверения и не трогается отсечкой чужого той же учётки.
func assertCutByItsCredentialOnly(t *testing.T, lane, raw string) {
	t.Helper()
	claims := revClaims(t, raw)
	ctx := context.Background()
	// Отсечка ПОЗЖЕ выпуска — так её пишет снятие строки в момент отзыва.
	revokedAt := time.Now().Add(time.Minute)

	revoked, err := tokenrevocation.Revoked(ctx, revCutoffs{before: map[string]time.Time{}}, claims)
	require.NoError(t, err)
	require.False(t, revoked, "%s: токен без единой отсечки отвергнут — правило отвергает всё, проба ничего не меряет", lane)

	revoked, err = tokenrevocation.Revoked(ctx, revCutoffs{before: map[string]time.Time{revCredID: revokedAt}}, claims)
	require.NoError(t, err)
	require.True(t, revoked,
		"%s: удостоверение %s снято, а выданный по нему токен реестра действует до срока — состав токена "+
			"не несёт ключа отсечки, которым снятие строки его отзывает", lane, revCredID)

	revoked, err = tokenrevocation.Revoked(ctx, revCutoffs{before: map[string]time.Time{revOtherID: revokedAt}}, claims)
	require.NoError(t, err)
	require.False(t, revoked, "%s: отзыв чужого удостоверения той же учётки снял токен — отзыв блокирует учётку целиком", lane)
}

// TestBasicLaneTokenIsCutByRevokingItsCredential — полоса базового секрета.
func TestBasicLaneTokenIsCutByRevokingItsCredential(t *testing.T) {
	secret, _, err := credsecret.Mint(revCredID)
	require.NoError(t, err)
	uc := revLane(t).WithBasicCredentialResolver(revBasicResolver{live: secret, credID: revCredID})

	out, err := uc.Execute(context.Background(), registrytokenuc.IssueInput{
		Username: revCredID, Password: secret, Service: revRegistry,
	})
	require.NoError(t, err, "положительный путь выдачи обязан выпускать токен")
	assertCutByItsCredentialOnly(t, "базовый секрет", out.Token)
}

// TestKeyMaterialWindowTokenIsCutByRevokingItsCredential — прежняя полоса окна
// перехода: тот же вопрос, та же отсечка.
func TestKeyMaterialWindowTokenIsCutByRevokingItsCredential(t *testing.T) {
	uc := revLane(t).WithKeyMaterialWindow(time.Now().Add(time.Hour), revKeyValidator{})

	out, err := uc.Execute(context.Background(), registrytokenuc.IssueInput{
		Username: revCredID, Password: "-----BEGIN PRIVATE KEY-----", Service: revRegistry,
	})
	require.NoError(t, err, "окно открыто — прежний вид обязан приниматься")
	assertCutByItsCredentialOnly(t, "окно ключевого материала", out.Token)
}
