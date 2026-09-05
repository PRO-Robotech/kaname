// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// client_token.go — приземление токен-эндпоинта платформы на живой путь выдачи
// (задача #898, приёмка F2 §9.1 п. 11).
//
// # Почему это отдельный файл композиционного корня
//
// Эндпоинт собирает четыре части, и у каждой свой отказ: проверяющий
// утверждение, реестр, способный к утверждению, хранилище однократности и
// выдача нашим подписантом. Собранные в теле общего пуска, они растворяются
// среди двух десятков соседних провязок, и первая же неполная из них проходит
// обзор незамеченной.
//
// # Что здесь ГЛАВНОЕ
//
// Эндпоинт получает ПРОИЗВОДСТВЕННОГО вызывающего. Проверяющий без него
// выглядит исправным ровно потому, что его пробы зелены: они подают ему то, что
// он умеет разобрать. Живой путь подаёт то, что присылает клиент.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"
	"github.com/PRO-Robotech/kacho-iam/internal/clienttokenwire"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/handler/clienttokenhttp"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho-iam/internal/tokensigner"
	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
)

// clientTokenPeerTimeout — предел времени ОДНОГО внешнего вызова этого пути.
//
// Назван здесь потому, что путь собирается в этом корне: две величины в двух
// местах — то, как они расходятся. Предмет предела — чтение реестра и допуск
// однократности; оба идут в свою базу, и оба обязаны кончаться отказом, а не
// ожиданием.
const clientTokenPeerTimeout = 3 * time.Second

// buildClientTokenEndpoint собирает токен-эндпоинт платформы.
//
// Возвращает nil, nil, когда эндпоинт выключен: выключенный контур — законное
// состояние, а не полусобранная зависимость. Всякий иной неполный вход —
// ОШИБКА, и она отказывает в старте.
func buildClientTokenEndpoint(
	pool *pgxpool.Pool,
	cfg config.Config,
	signer *tokensigner.Signer,
	logger *slog.Logger,
) (*clienttokenhttp.Handler, error) {
	if !cfg.AuthN.ClientToken.Enabled {
		return nil, nil
	}
	if signer == nil {
		// Страж настройки это уже требует; здесь — вторая, структурная
		// половина того же требования: выпускать нечем.
		return nil, fmt.Errorf("client token endpoint is enabled but our signer is not wired")
	}

	// Состав утверждений собирают ТЕ ЖЕ функции, что и на пути обратного
	// вызова, и ТА ЖЕ сборка, что у прочих полос нашей чеканки: перечень и
	// правила объявлены один раз (token_claims.go), и правка любого из них
	// доезжает до всех сторон by construction.
	claims := newAssertionClaimsComposer(pool, cfg)

	return clienttokenwire.FromPool(pool, clienttokenwire.BuildConfig{
		Logger: logger,
		// Ожидаемый адресат утверждения — идентификатор НАШЕГО издателя, а не
		// адрес эндпоинта: у адреса форм несколько, у издателя одна.
		ExpectedAudience: signer.Issuer(),
		// Величины объявлены числом ровно в одном месте и приезжают сюда
		// параметром: сборка обязана отличать поданную величину от неподанной,
		// а константа незаданной не бывает.
		AssertionLifetimeCeiling: tokenpolicy.MaxAssertionLifetime,
		FederatedLifetimeCeiling: tokenpolicy.MaxFederatedAssertionLifetime,
		ClockSkew:                tokenpolicy.ClockSkew,
		Clock:                    time.Now,
		AllowedAudiences:         cfg.AuthN.ClientToken.AudienceList(),
		DefaultAudience:          cfg.AuthN.ClientToken.DefaultAudience,
		TokenTTL:                 cfg.AuthN.ClientToken.TokenTTL,
		BodyCeiling:              cfg.AuthN.ClientToken.BodyCeiling,
		PeerTimeout:              clientTokenPeerTimeout,
	}, signer, claims)
}

// ownClientAdapter — чтение строки реестра по НАШЕМУ идентификатору.
//
// Отдельный адаптер, а не расширение прежних: те резолвят по зеркальному
// значению, и один порт с двумя разными вопросами рано или поздно получает не
// тот.
type ownClientAdapter struct {
	userClients *kachopg.UserOAuthClientRepo
	saClients   *kachopg.SAOAuthClientRepo
}

func (a *ownClientAdapter) GetUserToken(ctx context.Context, id domain.UserOAuthClientID) (domain.UserOAuthClient, error) {
	return a.userClients.Get(ctx, id)
}

func (a *ownClientAdapter) GetSAKey(ctx context.Context, id domain.SAOAuthClientID) (domain.ServiceAccountOAuthClient, error) {
	return a.saClients.Get(ctx, id)
}
