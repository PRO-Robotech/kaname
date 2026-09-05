// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// assertion_issuance_harness_test.go — общая оснастка проб выдачи по учётным
// данным клиента против НАСТОЯЩЕЙ базы (приёмка F2, сценарии F2-31, F2-32).
//
// # Почему оснастка здесь, а не по копии у каждой пробы
//
// Обе пробы спрашивают одно и то же: реестр — настоящий, база — настоящая,
// выдача — настоящий use-case. Две копии оснастки разошлись бы молча, и
// разошлись бы они как раз в том, что делает пробу строгой: в подписанте, в
// часах и в составе утверждений.
//
// # Что здесь ПОДСТАВНОЕ и почему это не ослабляет вопрос
//
// Подставлен один порт — источник состава утверждений. Настоящее объявление
// состава читает строку реестра своим портом, у которого в дереве пока нет
// адаптера к базе (он приезжает своим изменением). Дублёр эмитит РОВНО ТО ЖЕ
// имя, которым настоящее объявление называет клиента, — `kacho_user_token_id`
// для клиента пользовательского токена и `kacho_sa_key_id` для клиента ключа
// служебной учётки, — потому что именно это имя читает вторая сторона отсечки.
// Совпадение множеств утверждений двух путей выдачи закреплено отдельно
// (F2-42), поэтому здесь оно не переизмеряется.
//
// Всё остальное — настоящее: разрешение клиента, подписант, хранилище отсечек,
// авторитет отзыва.
package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/client_token"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
	"github.com/PRO-Robotech/kacho-iam/internal/signingkeygen"
	"github.com/PRO-Robotech/kacho-iam/internal/tokensigner"
	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
)

const (
	assertionIssuer   = "https://iam.kacho.local"
	assertionAudience = "registry.kacho.local"
	assertionKID      = "kacho-assertion-probe"
	assertionTokenTTL = 15 * time.Minute
)

// issuanceKeys — ключница подписанта: один ключ на прогон пробы.
type issuanceKeys struct{ mat tokensigner.SigningMaterial }

func (k issuanceKeys) ActiveSigningKey(context.Context) (tokensigner.SigningMaterial, error) {
	return k.mat, nil
}

// PublishedSet — тот же ключ, что подписывает, отдаётся проверяющему. Один
// источник, а не второй: авторитет, судящий по другим ключам, чем подписант,
// отвергал бы наши собственные токены и выглядел бы при этом исправным.
func (k issuanceKeys) PublishedSet(context.Context) ([]domain.PublishedKey, error) {
	return []domain.PublishedKey{{
		KID:          k.mat.KID,
		Algorithm:    k.mat.Algorithm,
		PublicKeyPEM: k.mat.PublicKeyPEM,
	}}, nil
}

// issuanceClaims — источник состава утверждений.
//
// Имя, которым назван клиент, берётся из ЗАКРЫТОГО словаря видов: вид,
// заведённый в домене и не разобранный здесь, обязан дать ОТКАЗ, а не молчаливо
// пустой состав — иначе токен без имени клиента выглядел бы выданным и был бы
// неотзываем by construction.
type issuanceClaims struct{}

func (issuanceClaims) ClaimsForAssertionClient(
	_ context.Context, c domain.AssertionClient, _ service.TokenHookContext,
) (map[string]any, service.ResolvedPrincipal, error) {
	switch c.Kind {
	case domain.AssertionClientUser:
		return map[string]any{
			"kacho_principal_id":  c.OwnerID,
			"kacho_user_token_id": c.ID,
		}, service.ResolvedPrincipal{Kind: service.PrincipalUser, UserID: c.OwnerID}, nil
	case domain.AssertionClientServiceAccount:
		return map[string]any{
			"kacho_principal_id": c.OwnerID,
			"kacho_sa_key_id":    c.ID,
		}, service.ResolvedPrincipal{Kind: service.PrincipalServiceAccount}, nil
	default:
		return nil, service.ResolvedPrincipal{}, errUnknownAssertionKind
	}
}

// errUnknownAssertionKind — вид клиента вне закрытого словаря.
var errUnknownAssertionKind = &assertionKindError{}

type assertionKindError struct{}

func (*assertionKindError) Error() string {
	return "issuance harness: assertion client kind is outside the closed dictionary"
}

// issuanceRig — настоящая выдача и настоящий набор ключей.
type issuanceRig struct {
	uc   *client_token.UseCase
	keys issuanceKeys
	// issuedAt — момент выпуска, объявленный ЯВНО и лежащий в прошлом
	// относительно настенных часов базы.
	//
	// Иначе отсечка, которую база ставит своим `now()`, и отметка выпуска
	// токена попадали бы в одну секунду: отметка выпуска в токене — величина
	// СЕКУНДНОЙ точности, а отсечка — микросекундной, и порядок между ними
	// становился бы свойством прогона, а не предметом пробы.
	issuedAt time.Time
}

func newIssuanceRig(t *testing.T) issuanceRig {
	t.Helper()
	mat, err := signingkeygen.Generate(domain.SigningAlgES256)
	require.NoError(t, err, "порождение ключа подписанта")

	issuedAt := time.Now().UTC().Add(-time.Minute)
	keys := issuanceKeys{mat: tokensigner.SigningMaterial{
		KID:           domain.KeyID(assertionKID),
		Algorithm:     domain.SigningAlgES256,
		PrivateKeyPEM: mat.PrivateKeyPEM,
		PublicKeyPEM:  mat.PublicKeyPEM,
	}}
	signer, err := tokensigner.New(tokensigner.Config{
		Issuer:      assertionIssuer,
		Clock:       func() time.Time { return issuedAt },
		MaxTokenTTL: tokenpolicy.MaxTokenTTL,
	}, keys)
	require.NoError(t, err)

	uc, err := client_token.New(client_token.Config{
		AllowedAudiences: []string{assertionAudience},
		DefaultAudience:  assertionAudience,
		TokenTTL:         assertionTokenTTL,
		Clock:            func() time.Time { return issuedAt },
	}, signer, issuanceClaims{})
	require.NoError(t, err)

	return issuanceRig{uc: uc, keys: keys, issuedAt: issuedAt}
}
